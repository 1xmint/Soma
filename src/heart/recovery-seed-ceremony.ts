/**
 * RecoverySeedCeremonyService — offline recovery-seed evidence verification
 * and ceremony orchestration.
 *
 * Handles the challenge-response protocol for recovery-seed evidence:
 *   1. Issue a signed recovery challenge to the frozen identity
 *   2. Verify the seed holder's Ed25519 signature over the challenge
 *   3. Advance the coordinator: frozen → pending (with time-lock)
 *   4. Support cancellation, time-lock expiry, and completion gates
 *
 * Recovery-seed factors are Layer 3 (recovery evidence) in the four-layer
 * identity model. They prove possession of an offline Ed25519 key but do
 * NOT grant immediate authority — the time-lock, authenticator
 * re-enrollment, and credential rotation must all complete before the
 * identity returns to nominal.
 *
 * Domain separation: challenges are signed under 'soma/recovery-challenge/v1',
 * evidence under 'soma/recovery-evidence/v1'. Cross-protocol signature replay
 * is structurally impossible.
 *
 * Replay protection: consumed challenge IDs are tracked in a Set. Expired
 * challenges are prunable via `pruneExpired`.
 */

import { domainSigningInput } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { FactorRegistry, WELL_KNOWN_FACTOR_TYPES } from './factor-registry.js';
import type { HeartbeatEventType } from './heartbeat.js';
import {
  IdentityRecoveryCoordinator,
  type RecoveryCeremony,
} from './recovery-coordinator.js';

// ─── Recovery Challenge ─────────────────────────────────────────────────────

export interface RecoveryChallenge {
  readonly id: string;
  readonly protocol: 'soma-recovery/1';
  readonly identityDid: string;
  readonly ceremonyId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
  readonly heartDid: string;
  readonly heartPublicKey: string;
  readonly signature: string;
}

// ─── Recovery Seed Evidence ─────────────────────────────────────────────────

export interface RecoverySeedEvidence {
  readonly challengeId: string;
  readonly factorId: string;
  readonly factorType: 'recovery-seed';
  /** Base64 Ed25519 signature over `domainSigningInput('soma/recovery-evidence/v1', challengePayload)`. */
  readonly rawSignature: string;
  readonly assertedAt: number;
}

// ─── Result Types ───────────────────────────────────────────────────────────

export type InitiateRecoveryResult =
  | { ok: true; ceremony: RecoveryCeremony }
  | { ok: false; reason: string };

export type AdvanceToVerifyingResult =
  | { ok: true; ceremony: RecoveryCeremony }
  | { ok: false; reason: string };

export type CompleteRecoveryResult =
  | { ok: true; ceremony: RecoveryCeremony }
  | { ok: false; reason: string };

// ─── Event Emitter ──────────────────────────────────────────────────────────

export type CeremonyEventEmitter = (
  eventType: HeartbeatEventType,
  eventData: string,
) => void;

// ─── Configuration ──────────────────────────────────────────────────────────

export interface RecoverySeedCeremonyConfig {
  heartDid: string;
  heartPublicKey: string;
  heartSigningKey: Uint8Array;
  factorRegistry: FactorRegistry;
  coordinator: IdentityRecoveryCoordinator;
  now?: () => number;
  /** Default challenge TTL in ms. Default: 10 minutes. */
  defaultChallengeTtlMs?: number;
  provider?: CryptoProvider;
  /** When provided, the service records heartbeat events for state transitions. */
  onEvent?: CeremonyEventEmitter;
  /**
   * Verifies that a credential rotation event actually occurred for the
   * identity. Required for `completeRecovery` — completion is rejected
   * if this callback is not configured.
   *
   * Wire this to `CredentialRotationController.getEvents()` to verify
   * the rotation event hash against the identity's rotation log.
   *
   * Optional on the config so the service can be constructed for
   * challenge/evidence/cancel flows without a rotation verifier, but
   * `completeRecovery` will refuse to advance to nominal without it.
   */
  verifyRotation?: (identityDid: string, rotationEventHash: string) => boolean;
}

// ─── Ceremony Service ───────────────────────────────────────────────────────

export class RecoverySeedCeremonyService {
  private readonly outstanding = new Map<string, RecoveryChallenge>();
  private readonly consumed = new Set<string>();
  private readonly provider: CryptoProvider;
  private readonly clock: () => number;

  constructor(private readonly config: RecoverySeedCeremonyConfig) {
    this.provider = config.provider ?? getCryptoProvider();
    this.clock = config.now ?? (() => Date.now());
  }

  // ─── Challenge Issuance ─────────────────────────────────────────────────

  createRecoveryChallenge(
    identityDid: string,
    opts?: { ttlMs?: number },
  ): RecoveryChallenge {
    const { coordinator, factorRegistry } = this.config;

    const status = coordinator.getStatus(identityDid);
    if (!status) {
      throw new Error(
        `identity ${identityDid} is not in recovery — cannot issue recovery challenge`,
      );
    }
    if (status.state !== 'frozen') {
      throw new Error(
        `identity ${identityDid} is in '${status.state}' state — recovery challenge requires 'frozen'`,
      );
    }

    const factors = factorRegistry.listActive(identityDid);
    const hasSeed = factors.some(
      f => f.factorType === WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
    );
    if (!hasSeed) {
      throw new Error(
        `identity ${identityDid} has no active recovery-seed factor`,
      );
    }

    const now = this.clock();
    const ttl = opts?.ttlMs ?? this.config.defaultChallengeTtlMs ?? 600_000;

    const id = `rc-${this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(12),
    )}`;
    const nonce = this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(16),
    );

    const payload = {
      id,
      protocol: 'soma-recovery/1' as const,
      identityDid,
      ceremonyId: status.ceremonyId,
      issuedAt: now,
      expiresAt: now + ttl,
      nonce,
      heartDid: this.config.heartDid,
      heartPublicKey: this.config.heartPublicKey,
    };

    const signingInput = domainSigningInput(
      'soma/recovery-challenge/v1',
      payload,
    );
    const signature = this.provider.signing.sign(
      signingInput,
      this.config.heartSigningKey,
    );

    const challenge: RecoveryChallenge = {
      ...payload,
      signature: this.provider.encoding.encodeBase64(signature),
    };

    this.outstanding.set(id, challenge);
    return challenge;
  }

  // ─── Evidence Submission ────────────────────────────────────────────────

  submitRecoveryEvidence(
    evidence: RecoverySeedEvidence,
    timeLockMs: number,
    opts?: { now?: number },
  ): InitiateRecoveryResult {
    const now = opts?.now ?? this.clock();

    if (this.consumed.has(evidence.challengeId)) {
      return { ok: false, reason: 'challenge already consumed' };
    }

    const challenge = this.outstanding.get(evidence.challengeId);
    if (!challenge) {
      return { ok: false, reason: 'unknown challenge id' };
    }

    if (now > challenge.expiresAt) {
      this.outstanding.delete(evidence.challengeId);
      return { ok: false, reason: 'challenge expired' };
    }

    if (evidence.factorType !== 'recovery-seed') {
      return {
        ok: false,
        reason: `invalid factor type: expected 'recovery-seed', got '${evidence.factorType}'`,
      };
    }

    const registered = this.config.factorRegistry.get(
      challenge.identityDid,
      evidence.factorId,
    );
    if (!registered) {
      return {
        ok: false,
        reason: 'recovery-seed factor not registered for identity',
      };
    }
    if (registered.revokedAt !== null) {
      return { ok: false, reason: 'recovery-seed factor is revoked' };
    }
    if (registered.factorType !== WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED) {
      return { ok: false, reason: 'factor is not a recovery-seed type' };
    }

    // Verify Ed25519 signature: seed signs the challenge payload (minus
    // heart's signature) under the 'soma/recovery-evidence/v1' domain.
    const { signature: _, ...challengePayload } = challenge;
    const evidenceSigningInput = domainSigningInput(
      'soma/recovery-evidence/v1',
      challengePayload,
    );
    const sigBytes = this.provider.encoding.decodeBase64(evidence.rawSignature);
    const pubKey = this.provider.encoding.decodeBase64(
      registered.publicMaterial,
    );

    if (
      !this.provider.signing.verify(evidenceSigningInput, sigBytes, pubKey)
    ) {
      return {
        ok: false,
        reason: 'recovery-seed signature verification failed',
      };
    }

    try {
      const ceremony = this.config.coordinator.initiatePending(
        challenge.identityDid,
        'recovery-seed',
        timeLockMs,
        { now },
      );

      this.outstanding.delete(evidence.challengeId);
      this.consumed.add(evidence.challengeId);

      this.config.factorRegistry.markUsed(
        challenge.identityDid,
        evidence.factorId,
        now,
      );

      this.emit('recovery_initiated', {
        identityDid: challenge.identityDid,
        ceremonyId: challenge.ceremonyId,
        evidenceType: 'recovery-seed',
        factorId: evidence.factorId,
        timeLockMs,
        timeLockExpiresAt: ceremony.timeLockExpiresAt,
        at: now,
      });

      return { ok: true, ceremony };
    } catch (err) {
      return { ok: false, reason: (err as Error).message };
    }
  }

  // ─── Cancellation ──────────────────────────────────────────────────────

  cancelRecovery(identityDid: string, opts?: { now?: number }): boolean {
    const now = opts?.now ?? this.clock();
    const result = this.config.coordinator.cancelRecovery(identityDid, { now });

    if (result) {
      this.emit('recovery_cancelled', { identityDid, at: now });
    }

    return result;
  }

  // ─── Advance to Verifying ──────────────────────────────────────────────

  advanceToVerifying(
    identityDid: string,
    opts?: { now?: number },
  ): AdvanceToVerifyingResult {
    try {
      const ceremony = this.config.coordinator.advanceToVerifying(
        identityDid,
        opts,
      );

      const now = opts?.now ?? this.clock();
      this.emit('recovery_verifying', {
        identityDid,
        ceremonyId: ceremony.id,
        at: now,
      });

      return { ok: true, ceremony };
    } catch (err) {
      return { ok: false, reason: (err as Error).message };
    }
  }

  // ─── Complete Recovery ─────────────────────────────────────────────────

  /**
   * Complete the recovery ceremony and return the identity to nominal.
   *
   * Three preconditions are enforced:
   *   1. At least one non-recovery-seed authenticator must be enrolled
   *   2. A credential rotation event hash must be provided
   *   3. `verifyRotation` must be configured and must confirm the hash
   *
   * Completion unfreezes accounts but does NOT rebind them. Bindings
   * dissolved during freeze must be re-established explicitly by the
   * caller (e.g. via `ProductAccountBindingStore.bind()` during a
   * subsequent login flow). This prevents a recovered identity from
   * silently re-inheriting authority over accounts without an explicit
   * rebinding ceremony.
   */
  completeRecovery(
    identityDid: string,
    opts: { rotationEventHash: string; now?: number },
  ): CompleteRecoveryResult {
    const activeFactors = this.config.factorRegistry.listActive(identityDid);
    const hasNonRecoveryFactor = activeFactors.some(
      f => f.factorType !== WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
    );
    if (!hasNonRecoveryFactor) {
      return {
        ok: false,
        reason:
          'cannot complete recovery: no non-recovery-seed authenticator enrolled — re-establish at least one authenticator before completion',
      };
    }

    if (!opts.rotationEventHash) {
      return {
        ok: false,
        reason:
          'cannot complete recovery: credential rotation event hash required — rotate credentials before completion',
      };
    }

    if (!this.config.verifyRotation) {
      return {
        ok: false,
        reason:
          'cannot complete recovery: verifyRotation callback not configured — recovery completion requires verified credential rotation',
      };
    }

    const rotationValid = this.config.verifyRotation(
      identityDid,
      opts.rotationEventHash,
    );
    if (!rotationValid) {
      return {
        ok: false,
        reason:
          'cannot complete recovery: credential rotation verification failed — rotation event not found or not effective',
      };
    }

    try {
      const ceremony = this.config.coordinator.completeRecovery(
        identityDid,
        { now: opts.now },
      );

      const now = opts.now ?? this.clock();
      this.emit('recovery_completed', {
        identityDid,
        ceremonyId: ceremony.id,
        rotationEventHash: opts.rotationEventHash,
        completedAt: ceremony.completedAt,
        at: now,
      });

      return { ok: true, ceremony };
    } catch (err) {
      return { ok: false, reason: (err as Error).message };
    }
  }

  // ─── Housekeeping ──────────────────────────────────────────────────────

  outstandingCount(): number {
    return this.outstanding.size;
  }

  pruneExpired(now?: number): number {
    const t = now ?? this.clock();
    let dropped = 0;
    for (const [id, ch] of this.outstanding) {
      if (t > ch.expiresAt) {
        this.outstanding.delete(id);
        dropped++;
      }
    }
    return dropped;
  }

  // ─── Internals ─────────────────────────────────────────────────────────

  private emit(
    eventType: HeartbeatEventType,
    data: Record<string, unknown>,
  ): void {
    this.config.onEvent?.(eventType, JSON.stringify(data));
  }
}
