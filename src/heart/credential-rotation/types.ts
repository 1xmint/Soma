/**
 * Credential rotation — generic controller types.
 *
 * This module defines the contract between the generic
 * `CredentialRotationController` and its pluggable backends. The controller
 * encodes the twelve invariants from the architecture spec; backends provide
 * the algorithm-specific mint / sign / verify operations.
 *
 * The twelve invariants (summarised, see architecture doc §13c for full text):
 *   1. Threshold mandatory for Tier 0.
 *   2. Session credentials always derived, never imported.
 *   3. Rotation events anchored before effect.
 *   4. Panic freeze requires M-of-N quorum.
 *   5. Proof-of-possession mandatory per use.
 *   6. Backends come from a signed allowlist in the birth certificate.
 *   7. Backends are isolated.
 *   8. Challenge period for destructive operations.
 *   9. Pre-rotation (every event commits to next public key manifest).
 *  10. Post-compromise security via durable ratchet state.
 *  11. No legacy path — no coexistence with static auth.
 *  12. Verify before revoke.
 *
 * Implementation locks (§14 L1-L3):
 *   L1. Pre-rotation commits to sha256(nextPubKey || nextAlgorithmSuite || nextBackendId).
 *   L2. Rotation events are signed under the OLD key; new key signs first PoP.
 *   L3. An event is only effective after local log write + pulse-tree anchor
 *       + external witness.
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
 * pre-rotation commits to (L1): `sha256(publicKey || algorithmSuite || backendId)`.
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
   * Commitment to the NEXT credential's full manifest (L1):
   * sha256(nextPublicKey || nextAlgorithmSuite || nextBackendId).
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
}

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
   * Return the next pre-committed credential. The backend reveals the keypair
   * it generated during the previous `issueCredential` call. After this
   * returns, the backend must immediately generate the credential *after*
   * the new one, so pre-rotation continues one step ahead.
   */
  revealNextCredential(oldCredentialId: string): Promise<Credential>;

  /**
   * Mark a credential revoked inside the backend. The controller calls this
   * only after verify-before-revoke has succeeded (invariant 12).
   */
  revokeCredential(credentialId: string): Promise<void>;
}

// ─── Policy ─────────────────────────────────────────────────────────────────

/**
 * Per-class TTL defaults and floors (§14 D7).
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
  /** Challenge period for destructive ops (D2). Default 1h, floor 15min. */
  readonly challengePeriodMs: number;
  /** Maximum rotations per hour per identity (D3). Default 10, floor 2. */
  readonly maxRotationsPerHour: number;
  /** Token-bucket burst allowance (D3). */
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
