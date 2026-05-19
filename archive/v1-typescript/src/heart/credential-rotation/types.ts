/**
 * Credential rotation — generic controller types.
 *
 * This module defines the contract between the generic
 * `CredentialRotationController` and its pluggable backends. The controller
 * encodes the v0.1 invariant set from SOMA-ROTATION-SPEC.md; backends
 * provide the algorithm-specific mint / sign / verify operations.
 *
 * The v0.1 invariant set (see SOMA-ROTATION-SPEC.md §14 for full text):
 *   1. Threshold mandatory for Tier 0.
 *   2. Session credentials always derived, never imported.
 *   3. Rotation events anchored before effect (§4.2).
 *   4. Reserved — removed from v0.1 (see §7.4). The invariant number is
 *      kept as a gap so existing `InvariantViolation` codes stay stable.
 *   5. Proof-of-possession mandatory per use.
 *   6. Backends come from a signed allowlist.
 *   7. Backends are isolated.
 *   8. Challenge period and rate limit for destructive operations (§8).
 *   9. Pre-rotation commitment (§3) — every credential commits to the
 *      full manifest of the next credential.
 *  10. Post-compromise security via durable ratchet state (§4.6).
 *  11. No legacy path — no coexistence with static auth.
 *  12. Verify before revoke (§6).
 *  13. Event chain retention (§4.7) — append-only, no pruning or
 *      compaction; every credential the chain has ever made `effective`
 *      stays recoverable by walking the chain. Structural constraint,
 *      enforced at controller-design level rather than via a runtime
 *      `InvariantViolation` code.
 *
 * Implementation locks (see SOMA-ROTATION-SPEC.md §3, §4.2, §4.3):
 *   L1 — Pre-rotation commits to sha256 of the canonical manifest
 *        encoding `soma-manifest:<backendId>|<algorithmSuite>|<base64(publicKey)>`
 *        (§3.2); every credential stores its next credential's commitment.
 *   L2 — Rotation events are signed under the OLD key, and the new key
 *        provides its first PoP over the event body (§4.3).
 *   L3 — An event is only `effective` after local log write + pulse-tree
 *        anchor + external witness (§4.2).
 */

// ─── Classes and suites ──────────────────────────────────────────────────────

/** Credential class governs default TTLs, floors, and alarm policy. */
export type CredentialClass = 'A' | 'B' | 'C';

/**
 * Algorithm suite identifier. Controller refuses to verify a credential whose
 * suite is not in its current allowlist (downgrade protection).
 *
 * Current MVP supports `ed25519` only. `ed25519+ml-dsa-65` and
 * `secp256k1+ml-dsa-65` are reserved identifiers for the post-quantum
 * migration; backends that declare these suites must pass a hybrid-verify
 * test before they are accepted into any allowlist.
 */
export type AlgorithmSuite =
  | 'ed25519'
  | 'ed25519+ml-dsa-65'
  | 'secp256k1'
  | 'secp256k1+ml-dsa-65';

// ─── Manifest and credential ────────────────────────────────────────────────

/**
 * Full description of a credential's public identity. This is what
 * pre-rotation commits to (L1): the canonical encoding
 * `soma-manifest:<backendId>|<algorithmSuite>|<base64(publicKey)>`
 * from SOMA-ROTATION-SPEC.md §3.2, hashed with sha256.
 *
 * Committing the whole manifest instead of just the public key closes a
 * cross-suite confusion attack where an adversary who obtains a future
 * private key could reuse its public key under a different suite or backend.
 */
export interface CredentialManifest {
  readonly backendId: string;
  readonly algorithmSuite: AlgorithmSuite;
  readonly publicKey: Uint8Array;
}

/**
 * A live credential issued by a backend. The controller stores this; the
 * matching secret material stays inside the backend (invariant 2).
 */
export interface Credential {
  /** Opaque backend-assigned id. Unique within (backendId, identityId). */
  readonly credentialId: string;
  /** Stable identity this credential belongs to. */
  readonly identityId: string;
  /** Which backend issued it. */
  readonly backendId: string;
  /** Algorithm suite used. */
  readonly algorithmSuite: AlgorithmSuite;
  /** Credential class — governs TTL and rotation policy. */
  readonly class: CredentialClass;
  /** Public material the backend exposes. */
  readonly publicKey: Uint8Array;
  /** Issuance timestamp (ms since epoch). */
  readonly issuedAt: number;
  /** Expiry timestamp (ms since epoch). */
  readonly expiresAt: number;
  /**
   * Commitment to the NEXT credential's full manifest (L1, §3). Computed
   * per SOMA-ROTATION-SPEC.md §3.2 over
   * `soma-manifest:<backendId>|<algorithmSuite>|<base64(publicKey)>`.
   * Pre-rotation requires the next key to be committed at issue time.
   */
  readonly nextManifestCommitment: string;
}

// ─── Rotation events ─────────────────────────────────────────────────────────

/**
 * Lifecycle state of a rotation event.
 *
 * `pending` — written to the local log but no pulse-tree anchor yet.
 * `anchored` — pulse-tree root contains the event hash.
 * `witnessed` — at least one external observer has cosigned the root.
 * `effective` — all three of the above; the new credential is now primary.
 * `revoked` — superseded by a later rotation event.
 */
export type RotationEventStatus =
  | 'pending'
  | 'anchored'
  | 'witnessed'
  | 'effective'
  | 'revoked';

/**
 * An append-only rotation event. Signed by the OLD credential's secret key
 * (L2); the new credential's first proof-of-possession is carried alongside.
 */
export interface RotationEvent {
  readonly identityId: string;
  readonly backendId: string;
  readonly sequence: number;
  /** Hash of the previous event, or a per-identity genesis hash at seq 0. */
  readonly previousEventHash: string;
  /** Credential being retired. Null at inception. */
  readonly oldCredentialId: string | null;
  /** The new credential taking over. */
  readonly newCredential: Credential;
  /**
   * Ratchet state mixed into the new credential's derivation (invariant 10).
   * Anchored in the pulse tree; an attacker who captures the old secret at
   * time t cannot derive the new credential without also capturing the
   * ratchet state at t.
   */
  readonly ratchetAnchor: string;
  readonly timestamp: number;
  readonly nonce: string;
  /** Signature by the OLD credential's secret key (L2). Empty at inception. */
  readonly oldKeySignature: string;
  /** First proof-of-possession from the new credential's secret key (L2). */
  readonly newKeyProofOfPossession: string;
  /** Content-addressed hash of this event. */
  readonly hash: string;
  /** Lifecycle status. Mutated by controller as anchoring proceeds. */
  status: RotationEventStatus;
  /** Pulse-tree root containing this event hash, or null while pending. */
  pulseTreeRoot: string | null;
  /** External witness count (verify-before-revoke, invariant 12). */
  externalWitnessCount: number;
  /**
   * Effective-transition timestamp (SOMA-ROTATION-SPEC.md §4.8). Clock
   * reading at the moment `witnessEvent` first advanced this event to
   * the `effective` state. `null` while the event is `pending` or
   * `anchored`; set exactly once on the first witness that transitions
   * to `effective`; never mutated thereafter (additional witnesses on
   * an already-`effective` event MAY increment `externalWitnessCount`
   * but MUST NOT overwrite `effectiveAt`). This is a post-hoc
   * lifecycle annotation — §4.8 excludes it from the signed
   * `rotation-sign` / `rotation-pop` inputs and from the
   * content-addressed event hash, so the hash stays stable across
   * the anchored→effective transition. It is the reference source of
   * truth for a credential's effective window, including the
   * historical-credential lookup required by
   * `SOMA-DELEGATION-SPEC.md` §Rotation Interaction's Slice D code
   * contract.
   */
  effectiveAt: number | null;
}

// ─── Historical-credential lookup ───────────────────────────────────────────

/**
 * Lookup key for `CredentialRotationController.lookupHistoricalCredential`.
 *
 * Implements the API shape required by `SOMA-DELEGATION-SPEC.md`
 * §Rotation Interaction's Slice D code contract: callers identify a
 * historical credential by either its opaque `credentialId` or by its
 * raw `publicKey` bytes. Public-key matching is byte-exact.
 */
export type HistoricalCredentialLookupKey =
  | { readonly kind: 'credentialId'; readonly credentialId: string }
  | { readonly kind: 'publicKey'; readonly publicKey: Uint8Array };

/**
 * Successful historical-credential lookup result.
 *
 * `effectiveFrom` / `effectiveUntil` are computed from §4.8
 * `effectiveAt` on the introducing event and on the superseding
 * event, per `SOMA-ROTATION-SPEC.md` §4.8. They are NOT derived from
 * the stage-time `timestamp` field — using `timestamp` as a proxy
 * would silently attribute the L3 anchor-before-effect window to the
 * new credential and admit delegations that `SOMA-DELEGATION-SPEC.md`
 * §Conforming verifier rule item 3 requires be rejected.
 *
 * A `null` `effectiveFrom` means the introducing event is still
 * `pending` or `anchored` and the credential has never been
 * authoritative — a delegation verifier MUST reject any delegation
 * whose `issued_at` falls on a hit with `effectiveFrom = null`.
 *
 * A `null` `effectiveUntil` means the credential is still current —
 * either there is no superseding event yet, or the superseding event
 * exists but has not itself reached `effective`.
 */
export interface HistoricalCredentialLookupHit {
  readonly found: true;
  readonly credential: Credential;
  readonly effectiveFrom: number | null;
  readonly effectiveUntil: number | null;
}

/**
 * Typed not-found result.
 *
 * `unknown-identity` — the identity has never been inceptioned under
 * this controller. `credential-not-in-chain` — the identity exists
 * but no event in its chain introduces a credential matching the
 * lookup key. A delegation verifier MUST treat both cases as
 * "not effective at `issued_at`" and fail closed.
 */
export interface HistoricalCredentialLookupMiss {
  readonly found: false;
  readonly reason: 'unknown-identity' | 'credential-not-in-chain';
}

export type HistoricalCredentialLookupResult =
  | HistoricalCredentialLookupHit
  | HistoricalCredentialLookupMiss;

// ─── Backend interface ──────────────────────────────────────────────────────

/**
 * A credential backend implements the algorithm-specific half of the
 * primitive: minting credentials, signing with them, verifying signatures.
 *
 * Backends MUST be isolated (invariant 7): no backend reads another
 * backend's state, and no cross-backend imports are allowed. Each backend is
 * declared in the heart's birth-certificate allowlist (invariant 6).
 */
export interface CredentialBackend {
  /** Opaque backend id, globally unique within a heart. */
  readonly backendId: string;
  /** Algorithm suite this backend mints. */
  readonly algorithmSuite: AlgorithmSuite;
  /** Credential class — controls default TTL. */
  readonly class: CredentialClass;

  /**
   * Mint a fresh credential at inception or rotation. The backend generates
   * a new keypair, retains the secret material internally, and returns the
   * public manifest plus the hash of the NEXT keypair's manifest (pre-rotation).
   *
   * `nextManifestCommitment` is what the returned credential commits to; the
   * backend MUST have already generated the next keypair at this point, or
   * pre-rotation is broken.
   */
  issueCredential(args: {
    identityId: string;
    issuedAt: number;
    ttlMs: number;
  }): Promise<Credential>;

  /**
   * Sign a message with the secret material of `credentialId`. Throws if the
   * credential is unknown, expired, or has been revoked.
   */
  signWithCredential(
    credentialId: string,
    message: Uint8Array,
  ): Promise<Uint8Array>;

  /** Verify a signature against a stored credential. */
  verifyWithCredential(
    credentialId: string,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;

  /** Verify a signature against a bare manifest (for pre-rotated next keys). */
  verifyWithManifest(
    manifest: CredentialManifest,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;

  /**
   * Stage the next pre-committed credential without committing it. The
   * backend reveals the public manifest of the next keypair so the
   * controller can verify it matches the prior commitment (L1), but does
   * NOT yet mutate any durable chain state (KeyHistory append, `current`
   * pointer, etc). The backend MUST be prepared to `signWithCredential`
   * against the returned credentialId so the controller can collect the
   * new key's first proof-of-possession before committing.
   *
   * The staged credential is identified by `identityId` — at most one
   * rotation may be staged per identity at a time. Callers must follow
   * `stageNextCredential` with exactly one of `commitStagedRotation` or
   * `abortStagedRotation` before another rotation can be staged.
   */
  stageNextCredential(args: {
    identityId: string;
    oldCredentialId: string;
    issuedAt: number;
  }): Promise<Credential>;

  /**
   * Commit a previously staged rotation: append to the backend's durable
   * log (if any), advance the current credential pointer, and generate the
   * next-next keypair so pre-rotation stays one step ahead.
   */
  commitStagedRotation(identityId: string): Promise<void>;

  /**
   * Abort a previously staged rotation: drop the staged credential, zero
   * any partial secret material it held, and leave the backend in the
   * exact state it was in before the stage call. Idempotent — aborting
   * when no rotation is staged is a no-op.
   */
  abortStagedRotation(identityId: string): Promise<void>;

  /**
   * Mark a credential revoked inside the backend. The controller calls this
   * only after verify-before-revoke has succeeded (invariant 12).
   */
  revokeCredential(credentialId: string): Promise<void>;

  /**
   * Discard all backend state for an identity. The controller calls this
   * only when an inception rolls back mid-flight (e.g. the backend issued
   * a credential but a subsequent signing step failed). Must be idempotent
   * and safe to call on an unknown identity. Implementations should
   * zeroise any secret material they were holding for the identity.
   */
  discardIdentity(identityId: string): Promise<void>;
}

// ─── Policy ─────────────────────────────────────────────────────────────────

/**
 * Per-class TTL defaults and floors. Defaults are non-normative
 * (SOMA-ROTATION-SPEC.md §9.3); the only normative requirement is that an
 * implementation choose a value that does not undercut its own floor.
 * Operators can override per-identity rows but never below the class floor.
 */
export interface TtlPolicy {
  readonly defaultMs: number;
  readonly floorMs: number;
}

export const DEFAULT_TTL_POLICY: Readonly<Record<CredentialClass, TtlPolicy>> = {
  // Class A — Soma-native mint path. Matches Fulcio.
  A: { defaultMs: 10 * 60 * 1000, floorMs: 60 * 1000 },
  // Class B — custody keys anchored on-chain. Gas makes shorter expensive.
  B: { defaultMs: 60 * 60 * 1000, floorMs: 5 * 60 * 1000 },
  // Class C — third-party vaulted (alarm-only, we cannot mint).
  C: { defaultMs: 24 * 60 * 60 * 1000, floorMs: 60 * 60 * 1000 },
};

/** Controller-wide policy. Set at bootstrap; mutation requires a rotation event. */
export interface ControllerPolicy {
  /** Allowed backend ids. A backend must be listed here to issue or verify. */
  readonly backendAllowlist: readonly string[];
  /** Allowed algorithm suites. Downgrade protection. */
  readonly suiteAllowlist: readonly AlgorithmSuite[];
  /** Challenge period for destructive ops (§8.1). Default 1h, floor 15min. */
  readonly challengePeriodMs: number;
  /** Maximum rotations per hour per identity (§8.2). Default 10, floor 2. */
  readonly maxRotationsPerHour: number;
  /** Token-bucket burst allowance (§8.2). */
  readonly rotationBurst: number;
  /** Per-class TTL policy. */
  readonly ttl: Readonly<Record<CredentialClass, TtlPolicy>>;
}

export const DEFAULT_POLICY: ControllerPolicy = {
  backendAllowlist: [],
  suiteAllowlist: ['ed25519'],
  challengePeriodMs: 60 * 60 * 1000, // 1 hour
  maxRotationsPerHour: 10,
  rotationBurst: 3,
  ttl: DEFAULT_TTL_POLICY,
};

export const POLICY_FLOORS = {
  challengePeriodMs: 15 * 60 * 1000, // 15 minutes
  maxRotationsPerHour: 2,
} as const;

// ─── Errors ─────────────────────────────────────────────────────────────────

/** Base class for controller-enforced invariant violations. */
export class InvariantViolation extends Error {
  constructor(
    public readonly invariant: number,
    message: string,
  ) {
    super(`invariant ${invariant}: ${message}`);
    this.name = 'InvariantViolation';
  }
}

export class BackendNotAllowlisted extends InvariantViolation {
  constructor(backendId: string) {
    super(6, `backend "${backendId}" not in birth-cert allowlist`);
  }
}

export class SuiteDowngradeRejected extends InvariantViolation {
  constructor(suite: string) {
    super(1, `algorithm suite "${suite}" not in allowlist (downgrade rejected)`);
  }
}

export class PreRotationMismatch extends InvariantViolation {
  constructor() {
    super(9, 'new credential manifest does not match prior commitment');
  }
}

export class NotYetEffective extends InvariantViolation {
  constructor(status: RotationEventStatus) {
    super(3, `rotation event not yet effective (status=${status})`);
  }
}

export class RateLimitExceeded extends InvariantViolation {
  constructor() {
    super(8, 'rotation rate limit exceeded');
  }
}

export class ChallengePeriodActive extends InvariantViolation {
  constructor(unlockAt: number) {
    super(8, `challenge period active until ${unlockAt}`);
  }
}

export class VerifyBeforeRevokeFailed extends InvariantViolation {
  constructor() {
    super(12, 'cannot revoke: propagation not acknowledged and grace TTL unelapsed');
  }
}

export class CredentialExpired extends InvariantViolation {
  constructor(credentialId: string, expiresAt: number, now: number) {
    super(
      2,
      `credential ${credentialId} expired at ${expiresAt} (now=${now}); rotation required`,
    );
  }
}

export class DuplicateBackend extends InvariantViolation {
  constructor(backendId: string) {
    super(7, `backend already registered: ${backendId}`);
  }
}

export class StagedRotationConflict extends InvariantViolation {
  constructor(identityId: string) {
    super(
      9,
      `identity ${identityId} already has a staged rotation; commit or abort it first`,
    );
  }
}
