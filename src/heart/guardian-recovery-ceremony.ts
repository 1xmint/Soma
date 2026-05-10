/**
 * GuardianRecoveryCeremonyService — M-of-N guardian quorum recovery.
 *
 * Handles the challenge-response protocol for guardian-mediated recovery:
 *   1. Issue a signed guardian challenge to each guardian of a frozen identity
 *   2. Collect and verify each guardian's Ed25519 approval signature
 *   3. When M-of-N quorum is reached, advance coordinator: frozen → pending
 *   4. Time-lock, cancellation, and completion follow the same gates as
 *      recovery-seed (R2): authenticator enrollment + verified rotation
 *
 * Guardians are Layer 3 (recovery evidence) in the four-layer identity
 * model — like recovery seeds, they prove social trust but do NOT grant
 * immediate authority.
 *
 * Domain separation:
 *   - challenges: 'soma/guardian-challenge/v1'
 *   - approvals:  'soma/guardian-approval/v1'
 * Cross-protocol replay with recovery-seed domains is structurally
 * impossible.
 *
 * Time-lock start: the time-lock begins when quorum is reached (the
 * M-th approval), not on the first approval. Partial approvals do not
 * start any clock.
 *
 * Replay protection: consumed challenge IDs are tracked per guardian.
 * A guardian cannot approve the same challenge twice.
 */

import { domainSigningInput } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import {
  FactorRegistry,
  WELL_KNOWN_FACTOR_TYPES,
  type GuardianConfig,
  validateGuardianConfig,
} from './factor-registry.js';
import type { HeartbeatEventType } from './heartbeat.js';
import {
  IdentityRecoveryCoordinator,
  type RecoveryCeremony,
} from './recovery-coordinator.js';
import type {
  AdvanceToVerifyingResult,
  CeremonyEventEmitter,
  CompleteRecoveryResult,
} from './recovery-seed-ceremony.js';

// ─── Guardian Challenge ────────────────────────────────────────────────────

export interface GuardianChallenge {
  readonly id: string;
  readonly protocol: 'soma-guardian-recovery/1';
  readonly identityDid: string;
  readonly ceremonyId: string;
  readonly guardianDid: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
  readonly heartDid: string;
  readonly heartPublicKey: string;
  readonly signature: string;
}

// ─── Guardian Approval ─────────────────────────────────────────────────────

export interface GuardianApproval {
  readonly challengeId: string;
  readonly guardianDid: string;
  /** Base64 Ed25519 signature over `domainSigningInput('soma/guardian-approval/v1', challengePayload)`. */
  readonly rawSignature: string;
  readonly approvedAt: number;
}

// ─── Result Types ──────────────────────────────────────────────────────────

export type SubmitApprovalResult =
  | { ok: true; quorumReached: false; approvalsReceived: number; threshold: number }
  | { ok: true; quorumReached: true; ceremony: RecoveryCeremony; approvalsReceived: number; threshold: number }
  | { ok: false; reason: string };

export type GuardianInitiateResult =
  | { ok: true; ceremony: RecoveryCeremony }
  | { ok: false; reason: string };

// ─── Quorum State ──────────────────────────────────────────────────────────

interface QuorumState {
  identityDid: string;
  ceremonyId: string;
  approvals: Map<string, GuardianApproval>;
  threshold: number;
}

// ─── Configuration ─────────────────────────────────────────────────────────

export interface GuardianRecoveryCeremonyConfig {
  heartDid: string;
  heartPublicKey: string;
  heartSigningKey: Uint8Array;
  factorRegistry: FactorRegistry;
  coordinator: IdentityRecoveryCoordinator;
  /** Resolve a guardian DID to its Ed25519 public key (base64). */
  resolveGuardianKey: (guardianDid: string) => string | null;
  /** Resolve a GuardianConfig for a subject identity. */
  getGuardianConfig: (subjectDid: string) => GuardianConfig | null;
  now?: () => number;
  defaultChallengeTtlMs?: number;
  provider?: CryptoProvider;
  onEvent?: CeremonyEventEmitter;
  /**
   * Required for `completeRecovery`. Same contract as R2: completion
   * is rejected if not configured.
   */
  verifyRotation?: (identityDid: string, rotationEventHash: string) => boolean;
}

// ─── Ceremony Service ──────────────────────────────────────────────────────

export class GuardianRecoveryCeremonyService {
  private readonly outstanding = new Map<string, GuardianChallenge>();
  private readonly consumed = new Set<string>();
  private readonly quorums = new Map<string, QuorumState>();
  private readonly provider: CryptoProvider;
  private readonly clock: () => number;

  constructor(private readonly config: GuardianRecoveryCeremonyConfig) {
    this.provider = config.provider ?? getCryptoProvider();
    this.clock = config.now ?? (() => Date.now());
  }

  // ─── Challenge Issuance ──────────────────────────────────────────────────

  createGuardianChallenge(
    identityDid: string,
    guardianDid: string,
    opts?: { ttlMs?: number },
  ): GuardianChallenge {
    const { coordinator } = this.config;

    const status = coordinator.getStatus(identityDid);
    if (!status) {
      throw new Error(
        `identity ${identityDid} is not in recovery — cannot issue guardian challenge`,
      );
    }
    if (status.state !== 'frozen') {
      throw new Error(
        `identity ${identityDid} is in '${status.state}' state — guardian challenge requires 'frozen'`,
      );
    }

    const guardianConfig = this.config.getGuardianConfig(identityDid);
    if (!guardianConfig) {
      throw new Error(
        `identity ${identityDid} has no guardian configuration`,
      );
    }
    validateGuardianConfig(guardianConfig);

    const isActiveGuardian = guardianConfig.guardians.some(
      g => g.guardianDid === guardianDid && g.revokedAt === null,
    );
    if (!isActiveGuardian) {
      throw new Error(
        `${guardianDid} is not an active guardian for ${identityDid}`,
      );
    }

    const now = this.clock();
    const ttl = opts?.ttlMs ?? this.config.defaultChallengeTtlMs ?? 600_000;

    const id = `gc-${this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(12),
    )}`;
    const nonce = this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(16),
    );

    const payload = {
      id,
      protocol: 'soma-guardian-recovery/1' as const,
      identityDid,
      ceremonyId: status.ceremonyId,
      guardianDid,
      issuedAt: now,
      expiresAt: now + ttl,
      nonce,
      heartDid: this.config.heartDid,
      heartPublicKey: this.config.heartPublicKey,
    };

    const signingInput = domainSigningInput(
      'soma/guardian-challenge/v1',
      payload,
    );
    const signature = this.provider.signing.sign(
      signingInput,
      this.config.heartSigningKey,
    );

    const challenge: GuardianChallenge = {
      ...payload,
      signature: this.provider.encoding.encodeBase64(signature),
    };

    this.outstanding.set(id, challenge);
    return challenge;
  }

  // ─── Approval Submission ─────────────────────────────────────────────────

  submitGuardianApproval(
    approval: GuardianApproval,
    timeLockMs: number,
    opts?: { now?: number },
  ): SubmitApprovalResult {
    const now = opts?.now ?? this.clock();

    if (this.consumed.has(approval.challengeId)) {
      return { ok: false, reason: 'challenge already consumed' };
    }

    const challenge = this.outstanding.get(approval.challengeId);
    if (!challenge) {
      return { ok: false, reason: 'unknown challenge id' };
    }

    if (now > challenge.expiresAt) {
      this.outstanding.delete(approval.challengeId);
      return { ok: false, reason: 'challenge expired' };
    }

    if (approval.guardianDid !== challenge.guardianDid) {
      return {
        ok: false,
        reason: `guardian DID mismatch: challenge issued to ${challenge.guardianDid}, approval from ${approval.guardianDid}`,
      };
    }

    const guardianConfig = this.config.getGuardianConfig(challenge.identityDid);
    if (!guardianConfig) {
      return { ok: false, reason: 'guardian configuration not found' };
    }

    const isActiveGuardian = guardianConfig.guardians.some(
      g => g.guardianDid === approval.guardianDid && g.revokedAt === null,
    );
    if (!isActiveGuardian) {
      return { ok: false, reason: 'guardian is no longer active' };
    }

    const guardianPubKeyB64 = this.config.resolveGuardianKey(approval.guardianDid);
    if (!guardianPubKeyB64) {
      return { ok: false, reason: 'guardian public key not resolvable' };
    }

    const { signature: _, ...challengePayload } = challenge;
    const approvalSigningInput = domainSigningInput(
      'soma/guardian-approval/v1',
      challengePayload,
    );
    const sigBytes = this.provider.encoding.decodeBase64(approval.rawSignature);
    const pubKey = this.provider.encoding.decodeBase64(guardianPubKeyB64);

    if (!this.provider.signing.verify(approvalSigningInput, sigBytes, pubKey)) {
      return { ok: false, reason: 'guardian signature verification failed' };
    }

    this.outstanding.delete(approval.challengeId);
    this.consumed.add(approval.challengeId);

    let quorum = this.quorums.get(challenge.identityDid);
    if (!quorum) {
      quorum = {
        identityDid: challenge.identityDid,
        ceremonyId: challenge.ceremonyId,
        approvals: new Map(),
        threshold: guardianConfig.threshold,
      };
      this.quorums.set(challenge.identityDid, quorum);
    }

    if (quorum.approvals.has(approval.guardianDid)) {
      return { ok: false, reason: 'guardian has already approved this recovery' };
    }

    quorum.approvals.set(approval.guardianDid, approval);

    this.emit('guardian_approval_received', {
      identityDid: challenge.identityDid,
      ceremonyId: challenge.ceremonyId,
      guardianDid: approval.guardianDid,
      approvalsReceived: quorum.approvals.size,
      threshold: quorum.threshold,
      at: now,
    });

    if (quorum.approvals.size >= quorum.threshold) {
      try {
        const ceremony = this.config.coordinator.initiatePending(
          challenge.identityDid,
          'guardian-quorum',
          timeLockMs,
          { now },
        );

        this.emit('recovery_initiated', {
          identityDid: challenge.identityDid,
          ceremonyId: challenge.ceremonyId,
          evidenceType: 'guardian-quorum',
          guardianCount: quorum.approvals.size,
          threshold: quorum.threshold,
          guardianDids: [...quorum.approvals.keys()],
          timeLockMs,
          timeLockExpiresAt: ceremony.timeLockExpiresAt,
          at: now,
        });

        return {
          ok: true,
          quorumReached: true,
          ceremony,
          approvalsReceived: quorum.approvals.size,
          threshold: quorum.threshold,
        };
      } catch (err) {
        return { ok: false, reason: (err as Error).message };
      }
    }

    return {
      ok: true,
      quorumReached: false,
      approvalsReceived: quorum.approvals.size,
      threshold: quorum.threshold,
    };
  }

  // ─── Quorum Status ───────────────────────────────────────────────────────

  getQuorumStatus(identityDid: string): {
    approvalsReceived: number;
    threshold: number;
    guardianDids: string[];
  } | null {
    const quorum = this.quorums.get(identityDid);
    if (!quorum) return null;
    return {
      approvalsReceived: quorum.approvals.size,
      threshold: quorum.threshold,
      guardianDids: [...quorum.approvals.keys()],
    };
  }

  // ─── Cancellation ────────────────────────────────────────────────────────

  cancelRecovery(identityDid: string, opts?: { now?: number }): boolean {
    const now = opts?.now ?? this.clock();
    const result = this.config.coordinator.cancelRecovery(identityDid, { now });

    if (result) {
      this.quorums.delete(identityDid);
      this.emit('recovery_cancelled', { identityDid, at: now });
    }

    return result;
  }

  // ─── Advance to Verifying ────────────────────────────────────────────────

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

  // ─── Complete Recovery ───────────────────────────────────────────────────

  /**
   * Complete the guardian recovery and return the identity to nominal.
   *
   * Enforces the same three gates as recovery-seed (R2):
   *   1. At least one non-recovery-seed authenticator must be enrolled
   *   2. A credential rotation event hash must be provided
   *   3. `verifyRotation` must be configured and must confirm the hash
   *
   * Completion unfreezes accounts but does NOT rebind them. Bindings
   * dissolved during freeze must be re-established explicitly.
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
      this.quorums.delete(identityDid);

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

  // ─── Housekeeping ────────────────────────────────────────────────────────

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

  // ─── Internals ───────────────────────────────────────────────────────────

  private emit(
    eventType: HeartbeatEventType,
    data: Record<string, unknown>,
  ): void {
    this.config.onEvent?.(eventType, JSON.stringify(data));
  }
}
