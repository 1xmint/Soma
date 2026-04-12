/**
 * Revocation log — an append-only, hash-chained sequence of revocations.
 *
 * The `RevocationRegistry` is a flat set: tamper-evident ONLY on individual
 * revocation signatures. An operator who holds a registry can drop entries
 * before exporting it, and the consumer has no way to detect the omission.
 *
 * `RevocationLog` closes audit limit #2: every appended event links to the
 * previous one via a hash chain, and the operator's current head can be
 * committed to via a signed `LogHead`. Once two peers exchange signed heads,
 * either party can later prove the other omitted or reordered events by
 * showing the original signed head alongside their own chain.
 *
 * Three properties guaranteed:
 *   1. No silent drops within a chain — gaps break the hash linkage.
 *   2. No silent reordering — sequence numbers are monotonic & checked.
 *   3. Accountable commitment — operators sign their heads; divergence is
 *      provable with the old signature in hand.
 *
 * This module does NOT handle distribution (gossip / pub-sub). That is a
 * transport concern and is addressed in the design doc for limit #1.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';
import {
  verifyRevocation,
  type AuthorityResolver,
  type RevocationEvent,
} from './revocation.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** One link in the revocation log. */
export interface RevocationLogEntry {
  sequence: number;
  previousHash: string;
  revocation: RevocationEvent;
  hash: string;
}

/** Signed commitment to the current head of a log. */
export interface LogHead {
  /** Sequence number of the most recent entry (length - 1). Empty logs = -1. */
  sequence: number;
  /** Hash of the most recent entry, or genesis hash if empty. */
  hash: string;
  /** When the operator signed this head. */
  signedAt: number;
  /** DID of the operator (signer). */
  operatorDid: string;
  /** Operator's base64 public key. */
  operatorPublicKey: string;
  /** Ed25519 signature over the canonical payload. */
  signature: string;
}

export type LogVerification =
  | { valid: true }
  | { valid: false; reason: string };

// ─── Constants ──────────────────────────────────────────────────────────────

const GENESIS_INPUT = 'soma-revocation-log:genesis';

// ─── Log ────────────────────────────────────────────────────────────────────

/**
 * Append-only, hash-chained revocation log.
 *
 * **Threat model.** The log is a relay / audit layer. It verifies that each
 * appended revocation is *cryptographically valid* (signature, DID binding,
 * no duplicates) but does not by default enforce *authority* — that is, it
 * does not check "was this signer entitled to revoke this target?". Authority
 * is enforced at the {@link RevocationRegistry} layer, which is what actually
 * gates verification decisions. This split exists because gossip peers relay
 * events for delegations whose original issuer they may not know locally.
 *
 * Callers that do want authority enforcement at the log layer (e.g. the
 * operator's own private log, where authority is always the operator) can
 * pass an `authority` resolver at construction or use
 * {@link registerAuthority}. When authority information is present for a
 * target, the log enforces it; when absent, the log relays without checking.
 */
export class RevocationLog {
  private readonly entries: RevocationLogEntry[] = [];
  private readonly seenTargets = new Set<string>();
  private readonly provider: CryptoProvider;
  private readonly authority?: AuthorityResolver;
  private readonly internalAuthority = new Map<string, string>();
  /** Genesis hash (depends on active hash algorithm). */
  readonly genesisHash: string;

  constructor(
    opts: {
      provider?: CryptoProvider;
      /**
       * Optional authority resolver. When provided (or when authorities
       * are added via {@link registerAuthority}), {@link append} enforces
       * authority for targets with known authority records. Targets with
       * no known authority still append (relay semantics).
       */
      authority?: AuthorityResolver;
    } = {},
  ) {
    this.provider = opts.provider ?? getCryptoProvider();
    this.authority = opts.authority;
    this.genesisHash = this.provider.hashing.hash(GENESIS_INPUT);
  }

  /**
   * Register the legitimate issuer for a target so that later appends for
   * that target are authority-checked. Targets with no registered authority
   * still relay unchecked.
   */
  registerAuthority(targetId: string, issuerDid: string): void {
    this.internalAuthority.set(targetId, issuerDid);
  }

  /**
   * Append a revocation to the log. Throws if:
   *   - the revocation signature is invalid
   *   - the target has a known authority and the revocation's issuerDid
   *     does not match it
   *   - the same target was already revoked in this log
   */
  append(revocation: RevocationEvent): RevocationLogEntry {
    const sigCheck = verifyRevocation(revocation, this.provider);
    if (!sigCheck.valid) {
      throw new Error(`cannot append: ${sigCheck.reason}`);
    }
    // Authority enforcement is opt-in per target. If we know the authority
    // for this target, enforce it; otherwise relay (registry layer enforces).
    const expected =
      this.internalAuthority.get(revocation.targetId) ??
      this.authority?.(revocation.targetId, revocation.targetKind);
    if (expected && expected !== revocation.issuerDid) {
      throw new Error(
        `cannot append: ${revocation.issuerDid} is not authorized to revoke ${revocation.targetId}`,
      );
    }
    if (this.seenTargets.has(revocation.targetId)) {
      throw new Error(`cannot append: target ${revocation.targetId} already revoked`);
    }

    const sequence = this.entries.length;
    const previousHash =
      sequence === 0 ? this.genesisHash : this.entries[sequence - 1].hash;
    const hash = computeEntryHash(sequence, previousHash, revocation, this.provider);

    const entry: RevocationLogEntry = {
      sequence,
      previousHash,
      revocation,
      hash,
    };
    this.entries.push(entry);
    this.seenTargets.add(revocation.targetId);
    return entry;
  }

  /** Current head hash (genesis hash for empty logs). */
  get head(): string {
    return this.entries.length === 0
      ? this.genesisHash
      : this.entries[this.entries.length - 1].hash;
  }

  /** Number of entries in the log. */
  get length(): number {
    return this.entries.length;
  }

  /** Is this target revoked? */
  isRevoked(targetId: string): boolean {
    return this.seenTargets.has(targetId);
  }

  /** Get a read-only snapshot of all entries. */
  getEntries(): readonly RevocationLogEntry[] {
    return this.entries;
  }

  /** Produce a signed commitment to the current head. */
  signHead(
    operatorSigningKey: Uint8Array,
    operatorPublicKey: Uint8Array,
  ): LogHead {
    const operatorDid = publicKeyToDid(operatorPublicKey, this.provider);
    const operatorPublicKeyB64 = this.provider.encoding.encodeBase64(operatorPublicKey);
    const payload = {
      sequence: this.entries.length - 1, // -1 for empty logs
      hash: this.head,
      signedAt: Date.now(),
      operatorDid,
      operatorPublicKey: operatorPublicKeyB64,
    };
    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = this.provider.signing.sign(signingInput, operatorSigningKey);
    return {
      ...payload,
      signature: this.provider.encoding.encodeBase64(signature),
    };
  }

  /** Verify chain integrity of this log. */
  verify(): LogVerification {
    return RevocationLog.verifyEntries(this.entries, this.provider);
  }

  /**
   * Replace this log's contents with an imported set of entries. Rejects
   * (and leaves log untouched) if the imported chain does not verify.
   * Use this for bootstrapping from a trusted peer. In steady state, prefer
   * `merge()` which preserves existing entries.
   */
  replaceWith(entries: RevocationLogEntry[]): LogVerification {
    const check = RevocationLog.verifyEntries(entries, this.provider);
    if (!check.valid) return check;
    this.entries.length = 0;
    this.seenTargets.clear();
    for (const e of entries) {
      this.entries.push(e);
      this.seenTargets.add(e.revocation.targetId);
    }
    return { valid: true };
  }

  // ─── Static verification ──────────────────────────────────────────────────

  /**
   * Verify a standalone sequence of log entries. Checks:
   *   1. Each entry's revocation signature
   *   2. Monotonic sequence numbers starting at 0
   *   3. Hash chain linkage (previousHash matches prior entry)
   *   4. Each entry's hash is correctly computed
   *   5. No duplicate targetIds
   */
  static verifyEntries(
    entries: RevocationLogEntry[],
    provider?: CryptoProvider,
  ): LogVerification {
    const p = provider ?? getCryptoProvider();
    if (entries.length === 0) return { valid: true };

    const genesisHash = p.hashing.hash(GENESIS_INPUT);
    const seenTargets = new Set<string>();

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];

      if (e.sequence !== i) {
        return { valid: false, reason: `entry ${i} has sequence=${e.sequence}` };
      }

      const expectedPrev = i === 0 ? genesisHash : entries[i - 1].hash;
      if (e.previousHash !== expectedPrev) {
        return { valid: false, reason: `entry ${i} previousHash broken` };
      }

      const expectedHash = computeEntryHash(e.sequence, e.previousHash, e.revocation, p);
      if (e.hash !== expectedHash) {
        return { valid: false, reason: `entry ${i} hash mismatch` };
      }

      const sig = verifyRevocation(e.revocation, p);
      if (!sig.valid) {
        return { valid: false, reason: `entry ${i} bad revocation: ${sig.reason}` };
      }

      if (seenTargets.has(e.revocation.targetId)) {
        return { valid: false, reason: `entry ${i} duplicate targetId` };
      }
      seenTargets.add(e.revocation.targetId);
    }

    return { valid: true };
  }

  /** Verify a signed log head — signature + DID consistency. */
  static verifyHead(
    head: LogHead,
    provider?: CryptoProvider,
  ): LogVerification {
    const p = provider ?? getCryptoProvider();
    const { signature, ...payload } = head;
    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const sigBytes = p.encoding.decodeBase64(signature);
    const pubKey = p.encoding.decodeBase64(head.operatorPublicKey);

    if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
      return { valid: false, reason: 'invalid signature' };
    }

    const expectedDid = publicKeyToDid(pubKey, p);
    if (head.operatorDid !== expectedDid) {
      return { valid: false, reason: 'operatorDid does not match public key' };
    }

    return { valid: true };
  }
}

// ─── Internals ──────────────────────────────────────────────────────────────

function computeEntryHash(
  sequence: number,
  previousHash: string,
  revocation: RevocationEvent,
  provider: CryptoProvider,
): string {
  // Hash binds sequence, previous link, and the revocation identity+signature.
  // The revocation is already canonical (signed blob) so we just hash its id+sig.
  return provider.hashing.hash(
    `${sequence}|${previousHash}|${revocation.id}|${revocation.signature}`,
  );
}
