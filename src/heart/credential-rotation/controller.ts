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
 *
 * Rotation is transactional. The controller calls
 * `backend.stageNextCredential` first, verifies the manifest commitment and
 * suite allowlist, signs the event under the old key, collects the new
 * key's first PoP, and only then calls `backend.commitStagedRotation`. Any
 * failure in that window triggers `backend.abortStagedRotation`, so the
 * backend's durable state never advances unless the controller's view
 * advances with it.
 */

import { canonicalJson, domainSigningInput } from '../../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../../core/crypto-provider.js';

import {
  credentialFromWire,
  credentialToWire,
  rotationEventFromWire,
  rotationEventToWire,
  SNAPSHOT_VERSION,
  type ControllerSnapshot,
  type IdentityStateSnapshot,
} from './snapshot.js';
import {
  BackendNotAllowlisted,
  ChallengePeriodActive,
  CredentialExpired,
  DEFAULT_POLICY,
  DuplicateBackend,
  NotYetEffective,
  POLICY_FLOORS,
  PreRotationMismatch,
  RateLimitExceeded,
  SuiteDowngradeRejected,
  VerifyBeforeRevokeFailed,
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

/**
 * Normalize a credential for canonical JSON: its publicKey field is a
 * Uint8Array, which `canonicalJson` would walk into as a generic object.
 * We base64-encode the bytes so the signed bytes and the hashed bytes are
 * deterministic and portable across runtimes.
 */
function toWireCredential(
  credential: Credential,
  provider: CryptoProvider,
): Omit<Credential, 'publicKey'> & { publicKey: string } {
  return {
    ...credential,
    publicKey: provider.encoding.encodeBase64(credential.publicKey),
  };
}

/**
 * Normalize the shape of a pre-event (before we know its final
 * signatures/hash) so it is safe to canonicalize. The only non-JSON field
 * is `newCredential.publicKey`.
 */
function toWirePreEvent(
  preEvent: Omit<
    RotationEvent,
    'hash' | 'status' | 'pulseTreeRoot' | 'externalWitnessCount'
  >,
  provider: CryptoProvider,
): Record<string, unknown> {
  return {
    ...preEvent,
    newCredential: toWireCredential(preEvent.newCredential, provider),
  };
}

/** Compute the content-addressed hash of a rotation event. */
function computeEventHash(
  event: Omit<
    RotationEvent,
    'hash' | 'status' | 'pulseTreeRoot' | 'externalWitnessCount'
  >,
  provider: CryptoProvider,
): string {
  return provider.hashing.hash(
    `soma-rotation-event:${canonicalJson(toWirePreEvent(event, provider))}`,
  );
}

/** Build the signing input for a rotation-event role with domain separation. */
function eventSigningInput(
  role: 'inception-pop' | 'rotation-sign' | 'rotation-pop',
  preEvent: Omit<
    RotationEvent,
    'hash' | 'status' | 'pulseTreeRoot' | 'externalWitnessCount'
  >,
  provider: CryptoProvider,
): Uint8Array {
  return domainSigningInput(
    `soma/credential-rotation/${role}/v1`,
    toWirePreEvent(preEvent, provider),
  );
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

/** Genesis previous-event hash — deterministic per (identity, backend). */
function genesisEventHash(
  identityId: string,
  backendId: string,
  provider: CryptoProvider,
): string {
  return provider.hashing.hash(
    `soma-rotation-genesis:${identityId}:${backendId}`,
  );
}

/**
 * Standalone verification of a rotation-event chain. Recomputes every
 * event hash, checks `previousEventHash` linkage, verifies ratchet-anchor
 * derivation, and enforces monotonic sequence numbers. Does NOT check
 * backend signatures — that requires live backend access and is done by
 * the controller during rotate(). Useful for verifiers replaying a chain
 * published to a pulse tree.
 *
 * Returns `{ valid: true }` on success or `{ valid: false, reason }` on
 * the first failure.
 */
export function verifyRotationChain(
  events: readonly RotationEvent[],
  provider: CryptoProvider = getCryptoProvider(),
): { valid: true } | { valid: false, reason: string } {
  if (events.length === 0) {
    return { valid: false, reason: 'empty chain' };
  }
  let expectedRatchet = genesisRatchetAnchor(
    events[0]!.identityId,
    provider,
  );
  let expectedPrev = genesisEventHash(
    events[0]!.identityId,
    events[0]!.backendId,
    provider,
  );
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (e.sequence !== i) {
      return { valid: false, reason: `sequence ${e.sequence} at index ${i}` };
    }
    if (e.previousEventHash !== expectedPrev) {
      return { valid: false, reason: `previousEventHash mismatch at seq ${i}` };
    }
    expectedRatchet = deriveRatchetAnchor(
      expectedRatchet,
      e.newCredential.publicKey,
      provider,
    );
    if (e.ratchetAnchor !== expectedRatchet) {
      return { valid: false, reason: `ratchetAnchor mismatch at seq ${i}` };
    }
    const recomputedHash = computeEventHash(
      {
        identityId: e.identityId,
        backendId: e.backendId,
        sequence: e.sequence,
        previousEventHash: e.previousEventHash,
        oldCredentialId: e.oldCredentialId,
        newCredential: e.newCredential,
        ratchetAnchor: e.ratchetAnchor,
        timestamp: e.timestamp,
        nonce: e.nonce,
        oldKeySignature: e.oldKeySignature,
        newKeyProofOfPossession: e.newKeyProofOfPossession,
      },
      provider,
    );
    if (recomputedHash !== e.hash) {
      return { valid: false, reason: `event hash mismatch at seq ${i}` };
    }
    expectedPrev = e.hash;
  }
  return { valid: true };
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
  private readonly policyInner: ControllerPolicy;

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
   * (invariant 6), if its suite is not in the suite allowlist (invariant 1
   * downgrade protection), or if a backend with the same id is already
   * registered (invariant 7 — isolation; duplicate registration would let
   * the second backend observe the first's credentials).
   */
  registerBackend(backend: CredentialBackend): void {
    if (!this.policyInner.backendAllowlist.includes(backend.backendId)) {
      throw new BackendNotAllowlisted(backend.backendId);
    }
    if (!this.policyInner.suiteAllowlist.includes(backend.algorithmSuite)) {
      throw new SuiteDowngradeRejected(backend.algorithmSuite);
    }
    if (this.backends.has(backend.backendId)) {
      throw new DuplicateBackend(backend.backendId);
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
    if (!args.identityId) throw new Error('identityId required');
    if (!args.backendId) throw new Error('backendId required');
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

    // From here forward the backend has durable state for this identity.
    // Any throw must discard it before propagating — otherwise a retry
    // wedges at the backend's "already inceptioned" check.
    let event: RotationEvent;
    let newRatchet: string;
    try {
      const genesisHash = genesisEventHash(
        args.identityId,
        args.backendId,
        this.provider,
      );
      newRatchet = deriveRatchetAnchor(
        genesisRatchetAnchor(args.identityId, this.provider),
        credential.publicKey,
        this.provider,
      );

      // Inception: no old key to sign under, so we record the new key's PoP
      // over the event body as the authorising signature.
      const preEventNoPop = {
        identityId: args.identityId,
        backendId: args.backendId,
        sequence: 0,
        previousEventHash: genesisHash,
        oldCredentialId: null,
        newCredential: credential,
        ratchetAnchor: newRatchet,
        timestamp: now,
        nonce: this.provider.encoding.encodeBase64(
          this.provider.random.randomBytes(12),
        ),
        oldKeySignature: '',
        newKeyProofOfPossession: '',
      };
      const popBytes = await backend.signWithCredential(
        credential.credentialId,
        eventSigningInput('inception-pop', preEventNoPop, this.provider),
      );
      const newKeyProofOfPossession =
        this.provider.encoding.encodeBase64(popBytes);

      const hashedEvent = { ...preEventNoPop, newKeyProofOfPossession };
      const hash = computeEventHash(hashedEvent, this.provider);

      event = {
        ...hashedEvent,
        hash,
        status: 'pending',
        pulseTreeRoot: null,
        externalWitnessCount: 0,
      };
    } catch (err) {
      try {
        await backend.discardIdentity(args.identityId);
      } catch {
        /* swallow: original error is what the caller needs */
      }
      throw err;
    }

    this.identities.set(args.identityId, {
      identityId: args.identityId,
      backendId: args.backendId,
      events: [event],
      current: null, // NOT primary yet — must be anchored + witnessed first (L3)
      accepted: new Map(),
      ratchetAnchor: newRatchet,
      // D3: inception does NOT consume the rotation budget — the rate limit
      // is about constraining rotation churn, and every identity has exactly
      // one inception.
      rotationTimestamps: [],
      challengePeriodUnlockAt: null,
    });

    return { event, credential };
  }

  // ─── Rotation (transactional) ─────────────────────────────────────────────

  /**
   * Rotate to a new credential. Transactional:
   *   1. Stage the next credential (backend reveals its pre-committed pub).
   *   2. Verify manifest commitment (L1), suite allowlist (invariant 1),
   *      sign event body with old key (L2), collect new key PoP (L2).
   *   3. Commit the stage in the backend.
   * Any failure between (1) and (3) triggers an abort in the backend so
   * its durable state never diverges from the controller's.
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
    this.pruneAcceptedPool(state, now);

    const oldCredential = state.current;
    const newCredential = await backend.stageNextCredential({
      identityId,
      oldCredentialId: oldCredential.credentialId,
      issuedAt: now,
    });

    try {
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

      const preEventNoSigs = {
        identityId,
        backendId: state.backendId,
        sequence: prior.sequence + 1,
        previousEventHash: prior.hash,
        oldCredentialId: oldCredential.credentialId,
        newCredential,
        ratchetAnchor: newRatchet,
        timestamp: now,
        nonce: this.provider.encoding.encodeBase64(
          this.provider.random.randomBytes(12),
        ),
        oldKeySignature: '',
        newKeyProofOfPossession: '',
      };

      // L2 — old key signs the rotation event body.
      const oldSigBytes = await backend.signWithCredential(
        oldCredential.credentialId,
        eventSigningInput('rotation-sign', preEventNoSigs, this.provider),
      );
      const oldKeySignature = this.provider.encoding.encodeBase64(oldSigBytes);

      // L2 — new key provides its first PoP over the event + old signature.
      const preEventWithOldSig = { ...preEventNoSigs, oldKeySignature };
      const popBytes = await backend.signWithCredential(
        newCredential.credentialId,
        eventSigningInput('rotation-pop', preEventWithOldSig, this.provider),
      );
      const newKeyProofOfPossession = this.provider.encoding.encodeBase64(popBytes);

      const hashedEvent = {
        ...preEventWithOldSig,
        newKeyProofOfPossession,
      };
      const hash = computeEventHash(hashedEvent, this.provider);

      const event: RotationEvent = {
        ...hashedEvent,
        hash,
        status: 'pending',
        pulseTreeRoot: null,
        externalWitnessCount: 0,
      };

      await backend.commitStagedRotation(identityId);

      state.events.push(event);
      state.rotationTimestamps.push(now);
      // Old credential stays in `accepted` until verify-before-revoke clears it (invariant 12).
      state.accepted.set(oldCredential.credentialId, {
        credential: oldCredential,
        graceUntil: now + this.policyInner.challengePeriodMs,
      });
      state.ratchetAnchor = newRatchet;

      return { event, credential: newCredential };
    } catch (err) {
      // Best-effort abort — we prioritise the original error.
      try {
        await backend.abortStagedRotation(identityId);
      } catch {
        /* swallow: original error is what the caller needs */
      }
      throw err;
    }
  }

  // ─── Event lifecycle (L3) ─────────────────────────────────────────────────

  /**
   * L3.b — record that a pulse-tree root containing this event was published.
   * Advances the event from `pending` to `anchored`.
   */
  anchorEvent(identityId: string, eventHash: string, pulseTreeRoot: string): void {
    if (!eventHash) throw new Error('anchorEvent: eventHash required');
    if (!pulseTreeRoot) throw new Error('anchorEvent: pulseTreeRoot required');
    const event = this.findEvent(identityId, eventHash);
    if (event.status !== 'pending') {
      throw new Error(`cannot anchor event in status ${event.status}`);
    }
    event.pulseTreeRoot = pulseTreeRoot;
    event.status = 'anchored';
  }

  /**
   * L3.c — record an external witness cosignature on the anchoring root.
   * The first witness moves `anchored` directly to `effective` and installs
   * the new credential as current. Additional witness calls are no-ops for
   * the MVP single-witness quorum; the counter still increments so future
   * multi-witness policies can use it.
   */
  witnessEvent(identityId: string, eventHash: string): void {
    if (!eventHash) throw new Error('witnessEvent: eventHash required');
    const state = this.requireIdentity(identityId);
    const event = this.findEvent(identityId, eventHash);
    if (event.status === 'effective') {
      event.externalWitnessCount += 1;
      return;
    }
    if (event.status !== 'anchored') {
      throw new Error(`cannot witness event in status ${event.status}`);
    }
    event.externalWitnessCount += 1;
    const priorCurrent = state.current;
    state.current = event.newCredential;
    event.status = 'effective';
    if (priorCurrent) {
      const priorEvent = state.events.find(
        e => e.newCredential.credentialId === priorCurrent.credentialId,
      );
      if (priorEvent && priorEvent !== event) priorEvent.status = 'revoked';
    }
  }

  // ─── Sign / verify with current credential ───────────────────────────────

  /**
   * Sign a message with the current credential. Fails if no effective
   * credential exists yet (L3) or the current credential has expired
   * (invariant 2 — expired credentials must rotate, never sign).
   */
  async sign(identityId: string, message: Uint8Array): Promise<Uint8Array> {
    const state = this.requireIdentity(identityId);
    if (!state.current) {
      const latest = state.events[state.events.length - 1]!;
      throw new NotYetEffective(latest.status);
    }
    const now = this.clock();
    if (state.current.expiresAt <= now) {
      throw new CredentialExpired(
        state.current.credentialId,
        state.current.expiresAt,
        now,
      );
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

  // ─── Persistence ──────────────────────────────────────────────────────────

  /**
   * Serialize the controller's full state to a JSON-safe snapshot. Does
   * NOT include backend state — each backend has its own snapshot method.
   * The caller is responsible for bundling the controller snapshot with
   * each registered backend's snapshot and encrypting the whole thing
   * before writing to durable storage.
   *
   * The snapshot preserves everything required to keep producing
   * L1/L2/L3-correct events: event chain, current credential pointer,
   * ratchet anchor, accepted-pool grace windows, rate-limit bucket, and
   * any active challenge period.
   */
  snapshot(): ControllerSnapshot {
    const identities: IdentityStateSnapshot[] = [];
    for (const state of this.identities.values()) {
      identities.push({
        identityId: state.identityId,
        backendId: state.backendId,
        events: state.events.map(e => rotationEventToWire(e, this.provider)),
        currentCredentialId: state.current?.credentialId ?? null,
        accepted: Array.from(state.accepted.entries()).map(
          ([credentialId, entry]) => ({
            credentialId,
            credential: credentialToWire(entry.credential, this.provider),
            graceUntil: entry.graceUntil,
          }),
        ),
        ratchetAnchor: state.ratchetAnchor,
        rotationTimestamps: [...state.rotationTimestamps],
        challengePeriodUnlockAt: state.challengePeriodUnlockAt,
      });
    }
    return {
      version: SNAPSHOT_VERSION,
      policy: this.policyInner,
      identities,
    };
  }

  /**
   * Rebuild a controller from a snapshot. The caller must first restore
   * every backend referenced by the snapshot and pass them in — the
   * controller registers them under the restored policy, then rebuilds
   * its identity map. Fails if any referenced backend is missing from
   * the provided set, if a backend is not in the allowlist, or if the
   * snapshot version is unsupported.
   */
  static restore(
    snapshot: ControllerSnapshot,
    opts: {
      backends: readonly CredentialBackend[];
      provider?: CryptoProvider;
      clock?: Clock;
    },
  ): CredentialRotationController {
    if (snapshot.version !== SNAPSHOT_VERSION) {
      throw new Error(
        `CredentialRotationController: unsupported snapshot version ${snapshot.version}`,
      );
    }
    const controller = new CredentialRotationController({
      policy: snapshot.policy,
      provider: opts.provider,
      clock: opts.clock,
    });
    for (const backend of opts.backends) {
      controller.registerBackend(backend);
    }
    for (const ident of snapshot.identities) {
      if (!controller.backends.has(ident.backendId)) {
        throw new Error(
          `CredentialRotationController.restore: identity ${ident.identityId} references unknown backend ${ident.backendId}`,
        );
      }
      const events = ident.events.map(e =>
        rotationEventFromWire(e, controller.provider),
      );
      const current =
        ident.currentCredentialId === null
          ? null
          : events.find(
              e => e.newCredential.credentialId === ident.currentCredentialId,
            )?.newCredential ?? null;
      if (ident.currentCredentialId && !current) {
        throw new Error(
          `CredentialRotationController.restore: current credential ${ident.currentCredentialId} not found in event chain for identity ${ident.identityId}`,
        );
      }
      const accepted = new Map<
        string,
        { credential: Credential; graceUntil: number }
      >();
      for (const entry of ident.accepted) {
        accepted.set(entry.credentialId, {
          credential: credentialFromWire(entry.credential, controller.provider),
          graceUntil: entry.graceUntil,
        });
      }
      controller.identities.set(ident.identityId, {
        identityId: ident.identityId,
        backendId: ident.backendId,
        events,
        current,
        accepted,
        ratchetAnchor: ident.ratchetAnchor,
        rotationTimestamps: [...ident.rotationTimestamps],
        challengePeriodUnlockAt: ident.challengePeriodUnlockAt,
      });
    }
    return controller;
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
   * Drop any accepted-pool entries whose grace period has fully elapsed.
   * `verify()` already does this inline, but a long-lived rotating
   * identity with no verify traffic would accumulate entries between
   * verifies — calling this from rotate() caps the live set at roughly
   * the number of in-flight rotations.
   */
  private pruneAcceptedPool(state: IdentityState, now: number): void {
    for (const [id, entry] of state.accepted) {
      if (entry.graceUntil < now) state.accepted.delete(id);
    }
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
    if (policy.rotationBurst < 0) {
      throw new Error(`rotationBurst must be >= 0: ${policy.rotationBurst}`);
    }
    if (policy.backendAllowlist.length === 0) {
      throw new Error('backendAllowlist must contain at least one entry');
    }
    if (policy.suiteAllowlist.length === 0) {
      throw new Error('suiteAllowlist must contain at least one entry');
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
