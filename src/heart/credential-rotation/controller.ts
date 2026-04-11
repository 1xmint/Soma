/**
 * CredentialRotationController — generic rotation primitive.
 *
 * Encodes the twelve invariants (§13c) and the three implementation locks
 * (§14 L1-L3) from the architecture spec. This class is the only
 * user-facing rotation API; backends are accessed only through it.
 *
 * Backends are isolated (invariant 7). The controller holds a Map of
 * backendId -> backend instance, but does not expose that map to callers
 * and never passes one backend's state to another.
 *
 * Pre-rotation (invariant 9, L1) is enforced by storing the manifest
 * commitment on the current credential and checking that the next
 * credential's full manifest hashes to that commitment at rotation time.
 *
 * Ratchet state (invariant 10) is held as an append-only chain: each
 * rotation event's `ratchetAnchor` is sha256 of the previous anchor plus
 * the new credential's public key. Losing the ratchet state forces
 * re-bootstrap via Tier 0 threshold (§14 D6).
 *
 * Verify-before-revoke (invariant 12) — the controller holds old
 * credentials in an `accepted` pool until either all subscribed verifiers
 * ack propagation of the rotation event or a grace TTL elapses. Fails
 * closed on verify failure.
 */

import { canonicalJson } from '../../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../../core/crypto-provider.js';

import {
  BackendNotAllowlisted,
  ChallengePeriodActive,
  DEFAULT_POLICY,
  NotYetEffective,
  POLICY_FLOORS,
  PreRotationMismatch,
  RateLimitExceeded,
  SuiteDowngradeRejected,
  VerifyBeforeRevokeFailed,
  type AlgorithmSuite,
  type ControllerPolicy,
  type Credential,
  type CredentialBackend,
  type CredentialManifest,
  type RotationEvent,
} from './types.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * L1 — compute the pre-rotation commitment over a full manifest.
 * Binds backend id and algorithm suite in addition to the public key.
 */
export function computeManifestCommitment(
  manifest: CredentialManifest,
  provider: CryptoProvider,
): string {
  const pkB64 = provider.encoding.encodeBase64(manifest.publicKey);
  const input = `soma-manifest:${manifest.backendId}|${manifest.algorithmSuite}|${pkB64}`;
  return provider.hashing.hash(input);
}

/** Compute the content-addressed hash of a rotation event. */
function computeEventHash(
  event: Omit<
    RotationEvent,
    'hash' | 'status' | 'pulseTreeRoot' | 'externalWitnessCount'
  >,
  provider: CryptoProvider,
): string {
  // Normalize the credential for hashing (publicKey is bytes).
  const normalized = {
    ...event,
    newCredential: {
      ...event.newCredential,
      publicKey: provider.encoding.encodeBase64(event.newCredential.publicKey),
    },
  };
  return provider.hashing.hash(`soma-rotation-event:${canonicalJson(normalized)}`);
}

/** Compute the next ratchet anchor from the previous anchor + new public key. */
function deriveRatchetAnchor(
  previousAnchor: string,
  newPublicKey: Uint8Array,
  provider: CryptoProvider,
): string {
  const pkB64 = provider.encoding.encodeBase64(newPublicKey);
  return provider.hashing.hash(`soma-ratchet:${previousAnchor}|${pkB64}`);
}

/** Genesis ratchet anchor for a fresh identity (§14 D6). */
function genesisRatchetAnchor(
  identityId: string,
  provider: CryptoProvider,
): string {
  return provider.hashing.hash(`soma-ratchet-genesis:${identityId}`);
}

// ─── Internal per-identity state ────────────────────────────────────────────

interface IdentityState {
  identityId: string;
  backendId: string;
  /** Chain of rotation events for this identity. Append-only. */
  events: RotationEvent[];
  /** The credential currently accepted for signing. */
  current: Credential | null;
  /** Old credentials still accepted during grace period (invariant 12). */
  accepted: Map<string, { credential: Credential; graceUntil: number }>;
  /** Last ratchet anchor (mixed into the next rotation, invariant 10). */
  ratchetAnchor: string;
  /** Rotation timestamps for rate limiting (token-bucket, D3). */
  rotationTimestamps: number[];
  /** If a destructive op is pending, unlock time (D2). */
  challengePeriodUnlockAt: number | null;
}

// ─── Controller ─────────────────────────────────────────────────────────────

/**
 * Clock interface so tests can pin time deterministically.
 * Production callers pass `() => Date.now()`.
 */
export type Clock = () => number;

export interface ControllerOptions {
  policy?: ControllerPolicy;
  provider?: CryptoProvider;
  clock?: Clock;
}

export class CredentialRotationController {
  private readonly provider: CryptoProvider;
  private readonly clock: Clock;
  private readonly backends = new Map<string, CredentialBackend>();
  private readonly identities = new Map<string, IdentityState>();
  private policyInner: ControllerPolicy;

  constructor(opts: ControllerOptions = {}) {
    this.provider = opts.provider ?? getCryptoProvider();
    this.clock = opts.clock ?? (() => Date.now());
    this.policyInner = this.validatePolicy(opts.policy ?? DEFAULT_POLICY);
  }

  /** Read-only view of the active policy. */
  get policy(): ControllerPolicy {
    return this.policyInner;
  }

  /** Registered backends (opaque to callers). */
  listBackendIds(): readonly string[] {
    return Array.from(this.backends.keys());
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  /**
   * Register a backend. Fails if the backend id is not in the allowlist
   * (invariant 6) or if its suite is not in the suite allowlist (invariant 1
   * downgrade protection).
   */
  registerBackend(backend: CredentialBackend): void {
    if (!this.policyInner.backendAllowlist.includes(backend.backendId)) {
      throw new BackendNotAllowlisted(backend.backendId);
    }
    if (!this.policyInner.suiteAllowlist.includes(backend.algorithmSuite)) {
      throw new SuiteDowngradeRejected(backend.algorithmSuite);
    }
    this.backends.set(backend.backendId, backend);
  }

  // ─── Inception ────────────────────────────────────────────────────────────

  /**
   * Mint the first credential for an identity. Returns the rotation event
   * (sequence 0) plus the new credential. The event starts in status
   * `pending` and must be advanced through `anchorEvent` + `witnessEvent`
   * before it becomes effective (L3).
   */
  async incept(args: {
    identityId: string;
    backendId: string;
  }): Promise<{ event: RotationEvent; credential: Credential }> {
    const backend = this.requireBackend(args.backendId);
    if (this.identities.has(args.identityId)) {
      throw new Error(`identity already inceptioned: ${args.identityId}`);
    }

    const now = this.clock();
    const ttlMs = this.policyInner.ttl[backend.class].defaultMs;
    const credential = await backend.issueCredential({
      identityId: args.identityId,
      issuedAt: now,
      ttlMs,
    });

    const genesisHash = this.provider.hashing.hash(
      `soma-rotation-genesis:${args.identityId}:${args.backendId}`,
    );
    const newRatchet = deriveRatchetAnchor(
      genesisRatchetAnchor(args.identityId, this.provider),
      credential.publicKey,
      this.provider,
    );

    // Inception: no old key to sign under, so we record the new key's PoP
    // over the event body as the authorising signature.
    const preEvent = {
      identityId: args.identityId,
      backendId: args.backendId,
      sequence: 0,
      previousEventHash: genesisHash,
      oldCredentialId: null,
      newCredential: credential,
      ratchetAnchor: newRatchet,
      timestamp: now,
      nonce: this.provider.encoding.encodeBase64(this.provider.random.randomBytes(12)),
      oldKeySignature: '',
      newKeyProofOfPossession: '',
    };
    const popBytes = await backend.signWithCredential(
      credential.credentialId,
      new TextEncoder().encode(canonicalJson({ ...preEvent, role: 'inception-pop' })),
    );
    const newKeyProofOfPossession = this.provider.encoding.encodeBase64(popBytes);

    const hashedEvent = { ...preEvent, newKeyProofOfPossession };
    const hash = computeEventHash(hashedEvent, this.provider);

    const event: RotationEvent = {
      ...hashedEvent,
      hash,
      status: 'pending',
      pulseTreeRoot: null,
      externalWitnessCount: 0,
    };

    this.identities.set(args.identityId, {
      identityId: args.identityId,
      backendId: args.backendId,
      events: [event],
      current: null, // NOT primary yet — must be anchored + witnessed first (L3)
      accepted: new Map(),
      ratchetAnchor: newRatchet,
      rotationTimestamps: [now],
      challengePeriodUnlockAt: null,
    });

    return { event, credential };
  }

  // ─── Rotation ─────────────────────────────────────────────────────────────

  /**
   * Rotate to a new credential. The old credential signs the rotation
   * event (L2); the new credential's manifest must match the pre-rotation
   * commitment stored on the old credential (invariant 9, L1).
   *
   * Rate-limited (D3). Fails if a challenge period is active (D2).
   */
  async rotate(identityId: string): Promise<{
    event: RotationEvent;
    credential: Credential;
  }> {
    const state = this.requireIdentity(identityId);
    const backend = this.requireBackend(state.backendId);
    const now = this.clock();

    if (!state.current) {
      throw new NotYetEffective(state.events[state.events.length - 1]!.status);
    }
    if (state.challengePeriodUnlockAt && now < state.challengePeriodUnlockAt) {
      throw new ChallengePeriodActive(state.challengePeriodUnlockAt);
    }
    this.enforceRateLimit(state, now);

    const oldCredential = state.current;
    const newCredential = await backend.revealNextCredential(oldCredential.credentialId);

    // L1 — verify the new credential's full manifest matches the prior commitment.
    const newManifest: CredentialManifest = {
      backendId: newCredential.backendId,
      algorithmSuite: newCredential.algorithmSuite,
      publicKey: newCredential.publicKey,
    };
    const rederived = computeManifestCommitment(newManifest, this.provider);
    if (rederived !== oldCredential.nextManifestCommitment) {
      throw new PreRotationMismatch();
    }
    // Suite downgrade protection (invariant 1).
    if (!this.policyInner.suiteAllowlist.includes(newCredential.algorithmSuite)) {
      throw new SuiteDowngradeRejected(newCredential.algorithmSuite);
    }

    const prior = state.events[state.events.length - 1]!;
    const newRatchet = deriveRatchetAnchor(
      state.ratchetAnchor,
      newCredential.publicKey,
      this.provider,
    );

    const preEvent = {
      identityId,
      backendId: state.backendId,
      sequence: prior.sequence + 1,
      previousEventHash: prior.hash,
      oldCredentialId: oldCredential.credentialId,
      newCredential,
      ratchetAnchor: newRatchet,
      timestamp: now,
      nonce: this.provider.encoding.encodeBase64(this.provider.random.randomBytes(12)),
      oldKeySignature: '',
      newKeyProofOfPossession: '',
    };

    // L2 — old key signs the rotation event body.
    const signingInput = new TextEncoder().encode(
      canonicalJson({ ...preEvent, role: 'rotation-sign' }),
    );
    const oldSigBytes = await backend.signWithCredential(
      oldCredential.credentialId,
      signingInput,
    );
    const oldKeySignature = this.provider.encoding.encodeBase64(oldSigBytes);

    // L2 — new key provides its first PoP over the event + old signature.
    const popInput = new TextEncoder().encode(
      canonicalJson({ ...preEvent, oldKeySignature, role: 'rotation-pop' }),
    );
    const popBytes = await backend.signWithCredential(
      newCredential.credentialId,
      popInput,
    );
    const newKeyProofOfPossession = this.provider.encoding.encodeBase64(popBytes);

    const hashedEvent = { ...preEvent, oldKeySignature, newKeyProofOfPossession };
    const hash = computeEventHash(hashedEvent, this.provider);

    const event: RotationEvent = {
      ...hashedEvent,
      hash,
      status: 'pending',
      pulseTreeRoot: null,
      externalWitnessCount: 0,
    };

    state.events.push(event);
    state.rotationTimestamps.push(now);
    // Old credential stays in `accepted` until verify-before-revoke clears it (invariant 12).
    state.accepted.set(oldCredential.credentialId, {
      credential: oldCredential,
      graceUntil: now + this.policyInner.challengePeriodMs,
    });
    state.ratchetAnchor = newRatchet;

    return { event, credential: newCredential };
  }

  // ─── Event lifecycle (L3) ─────────────────────────────────────────────────

  /**
   * L3.b — record that a pulse-tree root containing this event was published.
   * Advances the event from `pending` to `anchored`.
   */
  anchorEvent(identityId: string, eventHash: string, pulseTreeRoot: string): void {
    const event = this.findEvent(identityId, eventHash);
    if (event.status !== 'pending') {
      throw new Error(`cannot anchor event in status ${event.status}`);
    }
    event.pulseTreeRoot = pulseTreeRoot;
    event.status = 'anchored';
  }

  /**
   * L3.c — record an external witness cosignature on the anchoring root.
   * The first witness moves `anchored` to `witnessed`, and installs the new
   * credential as current (the event becomes `effective`).
   */
  witnessEvent(identityId: string, eventHash: string): void {
    const state = this.requireIdentity(identityId);
    const event = this.findEvent(identityId, eventHash);
    if (event.status !== 'anchored' && event.status !== 'witnessed') {
      throw new Error(`cannot witness event in status ${event.status}`);
    }
    event.externalWitnessCount += 1;
    if (event.status === 'anchored') {
      event.status = 'witnessed';
      // Become effective: install new credential as current.
      const priorCurrent = state.current;
      state.current = event.newCredential;
      event.status = 'effective';
      // Mark prior effective event as revoked (logical state, not removal).
      if (priorCurrent) {
        const priorEvent = state.events.find(
          e => e.newCredential.credentialId === priorCurrent.credentialId,
        );
        if (priorEvent && priorEvent !== event) priorEvent.status = 'revoked';
      }
    }
  }

  // ─── Sign / verify with current credential ───────────────────────────────

  /**
   * Sign a message with the current credential. Fails if no effective
   * credential exists yet (L3).
   */
  async sign(identityId: string, message: Uint8Array): Promise<Uint8Array> {
    const state = this.requireIdentity(identityId);
    if (!state.current) {
      const latest = state.events[state.events.length - 1]!;
      throw new NotYetEffective(latest.status);
    }
    const backend = this.requireBackend(state.backendId);
    return backend.signWithCredential(state.current.credentialId, message);
  }

  /**
   * Verify a signature. Accepts either the current credential or any
   * credential still in the `accepted` pool (grace period, invariant 12).
   */
  async verify(
    identityId: string,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    const state = this.requireIdentity(identityId);
    const backend = this.requireBackend(state.backendId);
    if (state.current) {
      if (await backend.verifyWithCredential(state.current.credentialId, message, signature)) {
        return true;
      }
    }
    const now = this.clock();
    for (const [id, entry] of state.accepted) {
      if (entry.graceUntil < now) {
        state.accepted.delete(id);
        continue;
      }
      if (await backend.verifyWithCredential(id, message, signature)) return true;
    }
    return false;
  }

  // ─── Verify-before-revoke (invariant 12) ─────────────────────────────────

  /**
   * Acknowledge that a verifier has propagated the rotation event. When
   * all subscribed verifiers ack OR the grace TTL elapses, the old
   * credential is actually revoked in the backend.
   *
   * For the MVP "all verifiers" is simulated by a single ack; the real
   * implementation will take a verifier-id set from the birth certificate.
   */
  async ackPropagation(identityId: string, oldCredentialId: string): Promise<void> {
    const state = this.requireIdentity(identityId);
    const entry = state.accepted.get(oldCredentialId);
    if (!entry) return; // already cleared
    const backend = this.requireBackend(state.backendId);
    await backend.revokeCredential(oldCredentialId);
    state.accepted.delete(oldCredentialId);
  }

  /**
   * Attempt to revoke an old credential without a verifier ack. Fails
   * unless the grace TTL has elapsed (verify-before-revoke, invariant 12).
   */
  async forceRevoke(identityId: string, oldCredentialId: string): Promise<void> {
    const state = this.requireIdentity(identityId);
    const entry = state.accepted.get(oldCredentialId);
    if (!entry) return;
    const now = this.clock();
    if (now < entry.graceUntil) {
      throw new VerifyBeforeRevokeFailed();
    }
    const backend = this.requireBackend(state.backendId);
    await backend.revokeCredential(oldCredentialId);
    state.accepted.delete(oldCredentialId);
  }

  // ─── Introspection (tests + runbook) ─────────────────────────────────────

  getEvents(identityId: string): readonly RotationEvent[] {
    return this.requireIdentity(identityId).events;
  }

  getCurrentCredential(identityId: string): Credential | null {
    return this.requireIdentity(identityId).current;
  }

  getRatchetAnchor(identityId: string): string {
    return this.requireIdentity(identityId).ratchetAnchor;
  }

  // ─── Internals ────────────────────────────────────────────────────────────

  private requireBackend(backendId: string): CredentialBackend {
    const backend = this.backends.get(backendId);
    if (!backend) throw new BackendNotAllowlisted(backendId);
    return backend;
  }

  private requireIdentity(identityId: string): IdentityState {
    const state = this.identities.get(identityId);
    if (!state) throw new Error(`unknown identity: ${identityId}`);
    return state;
  }

  private findEvent(identityId: string, eventHash: string): RotationEvent {
    const state = this.requireIdentity(identityId);
    const event = state.events.find(e => e.hash === eventHash);
    if (!event) throw new Error(`unknown event: ${eventHash}`);
    return event;
  }

  /**
   * D3 — token-bucket rate limit. `maxRotationsPerHour + rotationBurst` is
   * the effective ceiling in any hour. Trims old timestamps.
   */
  private enforceRateLimit(state: IdentityState, now: number): void {
    const windowStart = now - 60 * 60 * 1000;
    state.rotationTimestamps = state.rotationTimestamps.filter(t => t >= windowStart);
    const cap = this.policyInner.maxRotationsPerHour + this.policyInner.rotationBurst;
    if (state.rotationTimestamps.length >= cap) {
      throw new RateLimitExceeded();
    }
  }

  /** Enforce floors on policy values (§14 D2, D3). */
  private validatePolicy(policy: ControllerPolicy): ControllerPolicy {
    if (policy.challengePeriodMs < POLICY_FLOORS.challengePeriodMs) {
      throw new Error(
        `challengePeriodMs below floor: ${policy.challengePeriodMs} < ${POLICY_FLOORS.challengePeriodMs}`,
      );
    }
    if (policy.maxRotationsPerHour < POLICY_FLOORS.maxRotationsPerHour) {
      throw new Error(
        `maxRotationsPerHour below floor: ${policy.maxRotationsPerHour} < ${POLICY_FLOORS.maxRotationsPerHour}`,
      );
    }
    // Class TTL floor checks.
    for (const cls of ['A', 'B', 'C'] as const) {
      const t = policy.ttl[cls];
      if (t.defaultMs < t.floorMs) {
        throw new Error(
          `class ${cls} defaultMs ${t.defaultMs} below class floor ${t.floorMs}`,
        );
      }
    }
    return policy;
  }
}
