/**
 * Threshold signing — M-of-N Ed25519 via Shamir share reconstruction.
 *
 * The goal: no single party can unilaterally sign as the heart. At
 * least M of N shareholders have to cooperate. The resulting signature
 * is a standard Ed25519 signature — any Ed25519 verifier accepts it
 * without knowing it was threshold-signed.
 *
 * Approach: generate a standard Ed25519 key pair, split the 64-byte
 * secret key into N Shamir shares (over GF(256), reusing key-escrow.ts),
 * hand one share to each party. To sign: collect ≥M shares, reconstruct
 * the secret, sign, scrub the reconstructed secret from memory.
 *
 * Trust model (read carefully):
 *   - This is NOT FROST. FROST-Ed25519 (RFC 9591) never reconstructs
 *     the secret — each party produces a partial signature and the
 *     shares are combined in the signature space. That's strictly
 *     stronger: even the signing coordinator never sees the key.
 *   - This scheme DOES reconstruct the secret, briefly, during signing.
 *     If the signing coordinator is compromised at exactly the wrong
 *     moment, the full key leaks. So the signing host must be trusted
 *     for the duration of the ceremony (TEE, HSM-enclosed process,
 *     or similar).
 *   - Dealer-free variants exist but require DKG — we use a trusted
 *     dealer that generates the key and distributes shares once.
 *
 * What you get:
 *   - Standard Ed25519 signatures verifiable by existing soma code
 *     (verifyRevocation, verifyAttestation, etc.).
 *   - M-of-N access control on signing.
 *   - Audit trail of which share IDs contributed to each signature.
 *   - A drop-in interface that a future FROST implementation can back,
 *     because the public API takes {shares, message} and returns bytes.
 *
 * What you don't get:
 *   - Security against a compromised signing coordinator. Use FROST or
 *     MPC for that threat model.
 *   - Proactive share refresh (shares don't rotate automatically; a
 *     compromised shareholder keeps their share valid until the whole
 *     key is rotated).
 *
 * Use this when: the operator runs signing in a trusted environment
 * (TEE, air-gapped host) but wants M-of-N authorization for offline
 * review / multi-party sign-off.
 */

import { getCryptoProvider, type CryptoProvider } from '../core/crypto-provider.js';
import {
  splitSecret,
  reconstructSecret,
  type SecretShare,
} from './key-escrow.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A threshold key: public half is visible, secret half is sharded. */
export interface ThresholdKeyPair {
  /** Standard Ed25519 public key — 32 bytes. */
  publicKey: Uint8Array;
  /** Shamir shares of the Ed25519 secret key. */
  shares: SecretShare[];
  /** Minimum shares required to sign. */
  threshold: number;
  /** Total shares issued. */
  totalShares: number;
  /** Stable identifier binding shares to this key. */
  keyId: string;
}

/** The output of a threshold signing ceremony. */
export interface ThresholdSignature {
  /** Standard Ed25519 signature — 64 bytes, verifiable by any Ed25519 code. */
  signature: Uint8Array;
  /** Audit trail: which share indices contributed (sorted asc). */
  contributingShareIds: number[];
  /** keyId of the threshold key used. */
  keyId: string;
}

/** Options for generating a fresh threshold key. */
export interface GenerateThresholdKeyOpts {
  threshold: number;
  totalShares: number;
  /** Identity binding for the share set. Prevents mix-and-match attacks. */
  keyId: string;
}

/** Options for sharding an existing secret key. */
export interface ShareExistingKeyOpts extends GenerateThresholdKeyOpts {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ─── Key generation ─────────────────────────────────────────────────────────

/**
 * Generate a fresh Ed25519 key pair and immediately shard its secret
 * key across N participants. Returns the public key plus all N shares.
 * Caller is responsible for distributing shares securely — once you
 * return from this function, the full secret key no longer exists in
 * the process (GC will reclaim it).
 */
export function generateThresholdKeyPair(
  opts: GenerateThresholdKeyOpts,
  provider?: CryptoProvider,
): ThresholdKeyPair {
  validateThresholdOpts(opts);
  const p = provider ?? getCryptoProvider();
  const kp = p.signing.generateKeyPair();
  const shares = splitSecret(kp.secretKey, {
    threshold: opts.threshold,
    totalShares: opts.totalShares,
    secretId: opts.keyId,
  });
  // Overwrite our local secret key reference (best-effort — JS/GC
  // provides no hard guarantees about memory scrubbing).
  kp.secretKey.fill(0);
  return {
    publicKey: kp.publicKey,
    shares,
    threshold: opts.threshold,
    totalShares: opts.totalShares,
    keyId: opts.keyId,
  };
}

/**
 * Shard an existing Ed25519 secret key into M-of-N shares. Useful for
 * taking an existing identity and converting it to threshold control
 * (e.g. after a hot wallet shift to threshold custody).
 */
export function shareExistingKey(opts: ShareExistingKeyOpts): ThresholdKeyPair {
  validateThresholdOpts(opts);
  if (opts.publicKey.length !== 32) {
    throw new Error(
      `expected 32-byte Ed25519 public key, got ${opts.publicKey.length}`,
    );
  }
  if (opts.secretKey.length !== 64) {
    throw new Error(
      `expected 64-byte Ed25519 secret key, got ${opts.secretKey.length}`,
    );
  }
  const shares = splitSecret(opts.secretKey, {
    threshold: opts.threshold,
    totalShares: opts.totalShares,
    secretId: opts.keyId,
  });
  return {
    publicKey: opts.publicKey,
    shares,
    threshold: opts.threshold,
    totalShares: opts.totalShares,
    keyId: opts.keyId,
  };
}

function validateThresholdOpts(opts: GenerateThresholdKeyOpts): void {
  if (!opts.keyId || opts.keyId.length === 0) {
    throw new Error('threshold key requires non-empty keyId');
  }
  if (opts.threshold < 2) {
    throw new Error(`threshold must be ≥ 2, got ${opts.threshold}`);
  }
  if (opts.totalShares < opts.threshold) {
    throw new Error(
      `totalShares (${opts.totalShares}) must be ≥ threshold (${opts.threshold})`,
    );
  }
}

// ─── Signing ────────────────────────────────────────────────────────────────

/**
 * Reconstruct the secret from M shares and sign `message`. Throws if
 * fewer than `expectedThreshold` shares are provided, or if shares
 * belong to different keys (keyId mismatch). The reconstructed secret
 * is zeroed before return.
 */
export function thresholdSign(
  shares: readonly SecretShare[],
  message: Uint8Array,
  expectedKey: { publicKey: Uint8Array; threshold: number; keyId: string },
  provider?: CryptoProvider,
): ThresholdSignature {
  const p = provider ?? getCryptoProvider();

  if (shares.length < expectedKey.threshold) {
    throw new Error(
      `need at least ${expectedKey.threshold} shares, got ${shares.length}`,
    );
  }
  // Validate all shares belong to this key (prevents mix-and-match).
  for (const share of shares) {
    if (share.secretId !== expectedKey.keyId) {
      throw new Error(
        `share secretId ${share.secretId} does not match keyId ${expectedKey.keyId}`,
      );
    }
  }
  // Reject duplicate share IDs — reconstructSecret already checks this,
  // but surfacing a clearer error here is kinder to ceremony coordinators.
  const seen = new Set<number>();
  for (const share of shares) {
    if (seen.has(share.index)) {
      throw new Error(`duplicate index in signing set: ${share.index}`);
    }
    seen.add(share.index);
  }

  let secretKey: Uint8Array | null = null;
  try {
    secretKey = reconstructSecret(shares);
    if (secretKey.length !== 64) {
      throw new Error(
        `reconstructed secret has wrong length: ${secretKey.length}`,
      );
    }
    // Sanity check: reconstructed secret produces a signature that
    // verifies against the EXPECTED public key. If not, someone handed
    // us bad shares (byzantine holder, corrupted share, etc.).
    const sig = p.signing.sign(message, secretKey);
    if (!p.signing.verify(message, sig, expectedKey.publicKey)) {
      throw new Error(
        'reconstructed key did not produce a valid signature — check share integrity',
      );
    }
    const contributingShareIds = shares
      .map((s) => s.index)
      .sort((a, b) => a - b);
    return {
      signature: sig,
      contributingShareIds,
      keyId: expectedKey.keyId,
    };
  } finally {
    // Best-effort secret scrub. JS has no real memory scrub, but
    // overwriting the bytes immediately limits the window.
    if (secretKey) secretKey.fill(0);
  }
}

/**
 * Verify a threshold signature. It's just Ed25519 verification — the
 * caller doesn't need to know whether the signature came from a single
 * signer or a threshold ceremony. This exists as a named export so
 * the "threshold" semantics are discoverable; implementation is the
 * standard signing provider.
 */
export function verifyThresholdSignature(
  message: Uint8Array,
  signature: Uint8Array | ThresholdSignature,
  publicKey: Uint8Array,
  provider?: CryptoProvider,
): boolean {
  const p = provider ?? getCryptoProvider();
  const sigBytes =
    signature instanceof Uint8Array ? signature : signature.signature;
  return p.signing.verify(message, sigBytes, publicKey);
}

// ─── Signing ceremony ───────────────────────────────────────────────────────

/**
 * Stateful coordinator for an M-of-N signing ceremony. Collects shares
 * one at a time, emits a signature once the threshold is reached. Use
 * when shareholders contribute asynchronously over a network / UI.
 *
 * The coordinator sees shares. If the coordinator is compromised, the
 * shares it has seen could be exfiltrated. Run the coordinator in a
 * trusted environment (TEE, isolated process) for the ceremony window.
 */
export class SigningCeremony {
  private readonly shares = new Map<number, SecretShare>();
  private signed = false;

  constructor(
    private readonly message: Uint8Array,
    private readonly expectedKey: {
      publicKey: Uint8Array;
      threshold: number;
      keyId: string;
    },
    private readonly provider?: CryptoProvider,
  ) {
    if (expectedKey.threshold < 2) {
      throw new Error(`ceremony threshold must be ≥ 2, got ${expectedKey.threshold}`);
    }
  }

  /**
   * Contribute one share. Returns true if the ceremony has reached
   * threshold (next call to `sign()` will succeed).
   */
  contribute(share: SecretShare): boolean {
    if (this.signed) {
      throw new Error('ceremony already signed — start a new one');
    }
    if (share.secretId !== this.expectedKey.keyId) {
      throw new Error(
        `share secretId ${share.secretId} does not match keyId ${this.expectedKey.keyId}`,
      );
    }
    if (this.shares.has(share.index)) {
      throw new Error(`index ${share.index} already contributed`);
    }
    this.shares.set(share.index, share);
    return this.shares.size >= this.expectedKey.threshold;
  }

  /** How many shares have been contributed so far. */
  get contributedCount(): number {
    return this.shares.size;
  }

  /** Has the ceremony reached threshold? */
  get ready(): boolean {
    return this.shares.size >= this.expectedKey.threshold;
  }

  /** Produce the threshold signature. Throws if below threshold. */
  sign(): ThresholdSignature {
    if (this.signed) {
      throw new Error('ceremony already signed');
    }
    if (!this.ready) {
      throw new Error(
        `below threshold: ${this.shares.size} < ${this.expectedKey.threshold}`,
      );
    }
    this.signed = true;
    return thresholdSign(
      Array.from(this.shares.values()),
      this.message,
      this.expectedKey,
      this.provider,
    );
  }

  /** Abandon the ceremony and scrub shares from memory. */
  abort(): void {
    this.shares.clear();
    this.signed = true; // prevent reuse
  }

  /** Audit: which indexs have contributed. */
  contributingShareIds(): number[] {
    return Array.from(this.shares.keys()).sort((a, b) => a - b);
  }
}
