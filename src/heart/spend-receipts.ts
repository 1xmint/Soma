/**
 * Spend receipts — cryptographic backing for budget caveats.
 *
 * Budget caveats on delegations declare a spend limit ("up to 1000 credits"),
 * but on their own they have no cryptographic evidence of HOW MUCH has been
 * spent. A verifier receives `ctx.cumulativeCreditsSpent = 987` and must
 * simply trust the invoker. This module closes audit limit #3: every spend
 * is a signed receipt in a per-delegation hash chain, the chain's cumulative
 * sum is verifiable, and the delegation issuer can sign heads to commit to
 * a canonical view that makes double-spend forks provable.
 *
 * Design:
 *   - One `SpendLog` per delegation (subject-maintained).
 *   - The subject signs each receipt (they're claiming authority to spend).
 *   - Receipts chain by `previousHash` with monotonic `sequence`.
 *   - `cumulative` is the running total — verified at append time and on import.
 *   - The issuer (who granted the delegation) can sign the current head.
 *     An earlier signed head + a later reorg = proof of double-spend.
 *
 * This parallels RevocationLog: both are append-only hash-chained logs with
 * optional signed heads. The separation is semantic — revocations are
 * issuer-signed kill switches, spends are subject-signed authorizations.
 *
 * Double-spend detection:
 *   - Subject signs chain: [r0, r1, r2] with head hash H2.
 *   - Issuer signs head committing to (sequence=2, hash=H2, cumulative=C).
 *   - Subject later presents [r0, r1', r2'] with different hashes.
 *   - Issuer's earlier signed head + new chain = proof of fork.
 *
 * Transport is out of scope (see revocation-gossip design for the pattern).
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { didToPublicKey, publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** One authorized spend against a delegation. */
export interface SpendReceipt {
  /** The delegation being spent against. */
  delegationId: string;
  /** Position in the per-delegation chain. First receipt = 0. */
  sequence: number;
  /** Hash of the previous receipt, or genesis hash for sequence=0. */
  previousHash: string;
  /** Amount spent in THIS receipt. */
  amount: number;
  /** Cumulative amount through and including this receipt. */
  cumulative: number;
  /** Capability being exercised. */
  capability: string;
  /** When the spend occurred. */
  timestamp: number;
  /** Anti-replay nonce. */
  nonce: string;
  /** Hash of this entry (binds all fields above + subject signature). */
  hash: string;
  /** Subject DID (holder of the delegation). */
  subjectDid: string;
  /** Subject's base64 public key. */
  subjectPublicKey: string;
  /** Subject's Ed25519 signature over the canonical payload. */
  subjectSignature: string;
}

/** Signed commitment by the delegation issuer to a subject's spend head. */
export interface SpendHead {
  /** The delegation this head commits for. */
  delegationId: string;
  /** Highest sequence in the chain, or -1 for empty chains. */
  sequence: number;
  /** Head hash — last receipt's `hash`, or genesis hash for empty. */
  hash: string;
  /** Total committed spend (0 for empty chains). */
  cumulative: number;
  /** When the issuer signed. */
  signedAt: number;
  /** Issuer DID (grantor of the delegation). */
  issuerDid: string;
  /** Issuer's base64 public key. */
  issuerPublicKey: string;
  /** Issuer's Ed25519 signature over the canonical payload. */
  signature: string;
}

export type SpendVerification =
  | { valid: true }
  | { valid: false; reason: string };

// ─── Constants ──────────────────────────────────────────────────────────────

const GENESIS_INPUT_PREFIX = 'soma-spend-log:genesis:';

// ─── Log ────────────────────────────────────────────────────────────────────

/** Append-only, hash-chained spend log — one per delegation. */
export class SpendLog {
  private readonly entries: SpendReceipt[] = [];
  private readonly provider: CryptoProvider;
  private readonly subjectSigningKey: Uint8Array;
  private readonly subjectPublicKeyBytes: Uint8Array;
  private readonly subjectPublicKeyB64: string;
  readonly delegationId: string;
  readonly subjectDid: string;
  readonly genesisHash: string;

  constructor(opts: {
    delegationId: string;
    subjectSigningKey: Uint8Array;
    subjectPublicKey: Uint8Array;
    provider?: CryptoProvider;
  }) {
    this.provider = opts.provider ?? getCryptoProvider();
    this.delegationId = opts.delegationId;
    this.subjectSigningKey = opts.subjectSigningKey;
    this.subjectPublicKeyBytes = opts.subjectPublicKey;
    this.subjectPublicKeyB64 = this.provider.encoding.encodeBase64(opts.subjectPublicKey);
    this.subjectDid = publicKeyToDid(opts.subjectPublicKey, this.provider);
    // Bind genesis to the delegationId so logs for different delegations
    // cannot be mixed up or transplanted.
    this.genesisHash = this.provider.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${this.delegationId}`,
    );
  }

  /** Append a new spend receipt. Throws if amount is non-positive. */
  append(opts: { amount: number; capability: string }): SpendReceipt {
    if (!Number.isFinite(opts.amount) || opts.amount <= 0) {
      throw new Error(`cannot append: amount must be positive (got ${opts.amount})`);
    }

    const sequence = this.entries.length;
    const previousHash =
      sequence === 0 ? this.genesisHash : this.entries[sequence - 1].hash;
    const previousCumulative =
      sequence === 0 ? 0 : this.entries[sequence - 1].cumulative;
    const cumulative = previousCumulative + opts.amount;
    const nonce = this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(12),
    );

    const payload = {
      delegationId: this.delegationId,
      sequence,
      previousHash,
      amount: opts.amount,
      cumulative,
      capability: opts.capability,
      timestamp: Date.now(),
      nonce,
      subjectDid: this.subjectDid,
      subjectPublicKey: this.subjectPublicKeyB64,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = this.provider.signing.sign(signingInput, this.subjectSigningKey);
    const signatureB64 = this.provider.encoding.encodeBase64(signature);
    const hash = computeReceiptHash(payload, signatureB64, this.provider);

    const entry: SpendReceipt = {
      ...payload,
      hash,
      subjectSignature: signatureB64,
    };
    this.entries.push(entry);
    return entry;
  }

  /** Current head — last receipt's hash, or genesis hash for empty. */
  get head(): string {
    return this.entries.length === 0
      ? this.genesisHash
      : this.entries[this.entries.length - 1].hash;
  }

  /** Total cumulative spend committed to this log. */
  get cumulative(): number {
    return this.entries.length === 0
      ? 0
      : this.entries[this.entries.length - 1].cumulative;
  }

  /** Number of receipts in the log. */
  get length(): number {
    return this.entries.length;
  }

  /** Read-only snapshot of all receipts. */
  getEntries(): readonly SpendReceipt[] {
    return this.entries;
  }

  /** Would adding `additional` credits exceed `budget`? */
  wouldExceed(additional: number, budget: number): boolean {
    return this.cumulative + additional > budget;
  }

  /** Verify this log's own chain integrity. */
  verify(): SpendVerification {
    return SpendLog.verifyChain(this.entries, {
      delegationId: this.delegationId,
      subjectDid: this.subjectDid,
      provider: this.provider,
    });
  }

  /**
   * Replace contents with an imported chain. Leaves the log untouched on
   * failure. Verifies delegationId and subject match this log.
   */
  replaceWith(entries: SpendReceipt[]): SpendVerification {
    const check = SpendLog.verifyChain(entries, {
      delegationId: this.delegationId,
      subjectDid: this.subjectDid,
      provider: this.provider,
    });
    if (!check.valid) return check;
    // Extra: genesis hash must match (binds to delegationId)
    if (entries.length > 0 && entries[0].previousHash !== this.genesisHash) {
      return { valid: false, reason: 'imported chain genesis hash mismatch' };
    }
    this.entries.length = 0;
    this.entries.push(...entries);
    return { valid: true };
  }

  // ─── Static verification ──────────────────────────────────────────────────

  /**
   * Verify a standalone chain of receipts. Checks:
   *   1. Non-empty? All receipts share delegationId + subjectDid.
   *   2. Monotonic sequence starting at 0.
   *   3. Hash chain linkage via previousHash.
   *   4. Each receipt's hash correctly computed.
   *   5. Each receipt's subject signature.
   *   6. Cumulative monotonically increasing and correct per amount.
   *   7. Amount positive.
   */
  static verifyChain(
    entries: SpendReceipt[],
    opts: {
      delegationId: string;
      subjectDid: string;
      provider?: CryptoProvider;
    },
  ): SpendVerification {
    const p = opts.provider ?? getCryptoProvider();
    if (entries.length === 0) return { valid: true };

    const genesisHash = p.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${opts.delegationId}`,
    );

    // Derive expected subject public key from subjectDid once
    let expectedSubjectKey: Uint8Array;
    try {
      expectedSubjectKey = didToPublicKey(opts.subjectDid, p);
    } catch (err) {
      return { valid: false, reason: `bad subjectDid: ${(err as Error).message}` };
    }

    let prevCumulative = 0;

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];

      if (e.delegationId !== opts.delegationId) {
        return { valid: false, reason: `entry ${i} delegationId mismatch` };
      }
      if (e.subjectDid !== opts.subjectDid) {
        return { valid: false, reason: `entry ${i} subjectDid mismatch` };
      }
      if (e.sequence !== i) {
        return { valid: false, reason: `entry ${i} sequence=${e.sequence}` };
      }
      if (!Number.isFinite(e.amount) || e.amount <= 0) {
        return { valid: false, reason: `entry ${i} amount not positive` };
      }
      if (e.cumulative !== prevCumulative + e.amount) {
        return { valid: false, reason: `entry ${i} cumulative mismatch` };
      }

      const expectedPrev = i === 0 ? genesisHash : entries[i - 1].hash;
      if (e.previousHash !== expectedPrev) {
        return { valid: false, reason: `entry ${i} previousHash broken` };
      }

      // Signature check — subject public key must match subjectDid
      const providedKey = p.encoding.decodeBase64(e.subjectPublicKey);
      if (
        providedKey.length !== expectedSubjectKey.length ||
        !timingEqual(providedKey, expectedSubjectKey)
      ) {
        return { valid: false, reason: `entry ${i} subjectPublicKey mismatch` };
      }

      const { hash, subjectSignature, ...payload } = e;
      const signingInput = new TextEncoder().encode(canonicalJson(payload));
      const sigBytes = p.encoding.decodeBase64(subjectSignature);
      if (!p.signing.verify(signingInput, sigBytes, expectedSubjectKey)) {
        return { valid: false, reason: `entry ${i} bad signature` };
      }

      const expectedHash = computeReceiptHash(payload, subjectSignature, p);
      if (hash !== expectedHash) {
        return { valid: false, reason: `entry ${i} hash mismatch` };
      }

      prevCumulative = e.cumulative;
    }

    return { valid: true };
  }
}

// ─── Head signing (by issuer) ───────────────────────────────────────────────

/**
 * The delegation issuer signs a commitment to the subject's current head.
 * Pass an empty entries array (or SpendLog with length=0) to commit to an
 * empty chain.
 */
export function signSpendHead(opts: {
  delegationId: string;
  sequence: number;
  hash: string;
  cumulative: number;
  issuerSigningKey: Uint8Array;
  issuerPublicKey: Uint8Array;
  provider?: CryptoProvider;
}): SpendHead {
  const p = opts.provider ?? getCryptoProvider();
  const issuerDid = publicKeyToDid(opts.issuerPublicKey, p);
  const issuerPublicKeyB64 = p.encoding.encodeBase64(opts.issuerPublicKey);
  const payload = {
    delegationId: opts.delegationId,
    sequence: opts.sequence,
    hash: opts.hash,
    cumulative: opts.cumulative,
    signedAt: Date.now(),
    issuerDid,
    issuerPublicKey: issuerPublicKeyB64,
  };
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const signature = p.signing.sign(signingInput, opts.issuerSigningKey);
  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

/** Verify a signed spend head — signature + DID consistency. */
export function verifySpendHead(
  head: SpendHead,
  provider?: CryptoProvider,
): SpendVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = head;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(head.issuerPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }
  const expectedDid = publicKeyToDid(pubKey, p);
  if (head.issuerDid !== expectedDid) {
    return { valid: false, reason: 'issuerDid does not match public key' };
  }
  if (head.sequence < -1) {
    return { valid: false, reason: 'sequence out of range' };
  }
  if (head.cumulative < 0) {
    return { valid: false, reason: 'cumulative out of range' };
  }
  return { valid: true };
}

// ─── Double-spend detection ─────────────────────────────────────────────────

export interface DoubleSpendProof {
  delegationId: string;
  sequence: number;
  commitmentA: SpendHead;
  commitmentB: SpendHead;
}

/**
 * Given two signed heads from the same issuer over the same delegation at
 * the same sequence but with divergent hashes, produce a proof. Anyone
 * holding both heads can present this as evidence of a double-spend fork.
 *
 * Both heads must independently verify. If either fails or they don't
 * conflict, returns null.
 */
export function detectDoubleSpend(
  a: SpendHead,
  b: SpendHead,
  provider?: CryptoProvider,
): DoubleSpendProof | null {
  if (!verifySpendHead(a, provider).valid) return null;
  if (!verifySpendHead(b, provider).valid) return null;
  if (a.delegationId !== b.delegationId) return null;
  if (a.issuerDid !== b.issuerDid) return null;
  if (a.sequence !== b.sequence) return null;
  if (a.hash === b.hash) return null;
  return {
    delegationId: a.delegationId,
    sequence: a.sequence,
    commitmentA: a,
    commitmentB: b,
  };
}

// ─── Internals ──────────────────────────────────────────────────────────────

function computeReceiptHash(
  payload: Omit<SpendReceipt, 'hash' | 'subjectSignature'>,
  signatureB64: string,
  provider: CryptoProvider,
): string {
  // Hash binds payload canonical form + signature, so tampering either
  // invalidates the hash.
  return provider.hashing.hash(
    `${canonicalJson(payload)}|${signatureB64}`,
  );
}

function timingEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
