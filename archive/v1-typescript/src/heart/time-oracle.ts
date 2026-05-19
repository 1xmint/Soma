/**
 * Time oracle — signed time witnesses and monotonic time sources.
 *
 * Most timestamps in the protocol come from `Date.now()`: when a delegation
 * was issued, when a revocation fires, when a key rotated. A malicious
 * operator can set their clock backwards to replay expired credentials or
 * forward to issue far-future credentials. Audit limit #4 calls this out:
 * there's no cryptographic anchor for time.
 *
 * This module offers two mechanisms:
 *
 *   1. `TimeSource` — abstract clock with a monotonic variant that refuses
 *      to go backwards within a process. Drop-in for `Date.now()`.
 *
 *   2. `TimeWitness` — a signed statement by a trusted authority that
 *      "at this moment, wall time was T". Operations that need bounded
 *      freshness can embed a witness (or a quorum of witnesses from
 *      independent authorities). A verifier checks the signature, that
 *      `observedAt` is fresh enough for their policy, and optionally that
 *      the witness binds a specific nonce (freshness challenge).
 *
 * This is deliberately lighter than Roughtime/NTS: no round-trip protocol,
 * no infrastructure. Authorities are application-chosen Ed25519 signers.
 * The value is that timestamps now carry CRYPTOGRAPHIC evidence of having
 * been witnessed, instead of being opaque numbers pulled from a clock that
 * the issuer controls alone.
 *
 * Usage patterns:
 *   - Single trusted authority: simple, fast, trust-anchored.
 *   - Quorum (M-of-N): each party holds M witnesses from N independent
 *     authorities; verifier accepts if M valid + clock drift within bound.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── TimeSource ─────────────────────────────────────────────────────────────

/** Abstract time source. Default uses wall-clock. */
export interface TimeSource {
  readonly kind: string;
  /** Current time in ms since epoch. */
  now(): number;
}

/** Wall-clock time from `Date.now()`. Vulnerable to clock changes. */
export class SystemTimeSource implements TimeSource {
  readonly kind = 'system';
  now(): number {
    return Date.now();
  }
}

/**
 * Monotonic time source: wraps another source and refuses to go backwards.
 * If the underlying source reports an earlier time than the last observed,
 * returns the last observed + 1ms. Pure defense-in-depth against clock
 * adjustments WITHIN a process lifetime; does not defend against restarts.
 */
export class MonotonicTimeSource implements TimeSource {
  readonly kind = 'monotonic';
  private lastObserved = 0;
  constructor(private readonly inner: TimeSource = new SystemTimeSource()) {}
  now(): number {
    const raw = this.inner.now();
    const next = raw > this.lastObserved ? raw : this.lastObserved + 1;
    this.lastObserved = next;
    return next;
  }
}

// ─── TimeWitness ────────────────────────────────────────────────────────────

/** A signed statement of the current time from an authority. */
export interface TimeWitness {
  /** Observed wall-clock time (ms since epoch). */
  observedAt: number;
  /** DID of the time authority (signer). */
  authorityDid: string;
  /** Authority's base64 public key. */
  authorityPublicKey: string;
  /** Optional nonce (client-supplied challenge for freshness). */
  nonce: string | null;
  /** Authority's Ed25519 signature over the canonical payload. */
  signature: string;
}

export type WitnessVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Issue a signed time witness. If `nonce` is supplied, callers who verify
 * the witness can check it matches their challenge (prevents replay of an
 * old witness).
 */
export function issueTimeWitness(opts: {
  authoritySecretKey: Uint8Array;
  authorityPublicKey: Uint8Array;
  nonce?: string;
  time?: TimeSource;
  provider?: CryptoProvider;
}): TimeWitness {
  const p = opts.provider ?? getCryptoProvider();
  const source = opts.time ?? new SystemTimeSource();
  const authorityDid = publicKeyToDid(opts.authorityPublicKey, p);
  const authorityPublicKeyB64 = p.encoding.encodeBase64(opts.authorityPublicKey);
  const payload = {
    observedAt: source.now(),
    authorityDid,
    authorityPublicKey: authorityPublicKeyB64,
    nonce: opts.nonce ?? null,
  };
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const signature = p.signing.sign(signingInput, opts.authoritySecretKey);
  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

/** Verify a time witness — signature + freshness + optional nonce match. */
export function verifyTimeWitness(
  witness: TimeWitness,
  opts?: {
    /** Reject witness older than this many ms (wall-clock check). */
    maxAgeMs?: number;
    /** Reject witness further in the future than this many ms. */
    maxSkewMs?: number;
    /** Expected nonce — must match witness.nonce exactly. */
    expectedNonce?: string;
    /** List of acceptable authority DIDs. Empty = accept any valid sig. */
    trustedAuthorities?: string[];
    /** Override current time (for testing). */
    now?: number;
    provider?: CryptoProvider;
  },
): WitnessVerification {
  const p = opts?.provider ?? getCryptoProvider();
  const { signature, ...payload } = witness;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(witness.authorityPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }
  const expectedDid = publicKeyToDid(pubKey, p);
  if (witness.authorityDid !== expectedDid) {
    return { valid: false, reason: 'authorityDid does not match public key' };
  }

  if (opts?.expectedNonce !== undefined && witness.nonce !== opts.expectedNonce) {
    return { valid: false, reason: 'nonce mismatch' };
  }

  if (opts?.trustedAuthorities && opts.trustedAuthorities.length > 0) {
    if (!opts.trustedAuthorities.includes(witness.authorityDid)) {
      return { valid: false, reason: 'authority not in trust set' };
    }
  }

  const now = opts?.now ?? Date.now();
  if (opts?.maxAgeMs !== undefined) {
    const age = now - witness.observedAt;
    if (age > opts.maxAgeMs) {
      return { valid: false, reason: `witness stale (age=${age}ms > ${opts.maxAgeMs})` };
    }
  }
  if (opts?.maxSkewMs !== undefined) {
    const skew = witness.observedAt - now;
    if (skew > opts.maxSkewMs) {
      return { valid: false, reason: `witness from future (skew=${skew}ms > ${opts.maxSkewMs})` };
    }
  }

  return { valid: true };
}

// ─── Quorum (M-of-N independent authorities) ────────────────────────────────

export type QuorumVerification =
  | { valid: true; acceptedAuthorities: string[]; medianTime: number }
  | { valid: false; reason: string; acceptedAuthorities: string[] };

/**
 * Verify a set of witnesses as an M-of-N quorum. Each witness is verified
 * individually with the same freshness/nonce policy; only DISTINCT
 * authority DIDs count toward the quorum. Clock drift across accepted
 * witnesses is bounded by `maxDriftMs`.
 */
export function verifyWitnessQuorum(
  witnesses: TimeWitness[],
  opts: {
    threshold: number;
    trustedAuthorities?: string[];
    expectedNonce?: string;
    maxAgeMs?: number;
    maxSkewMs?: number;
    /** Max spread between accepted witness observedAt values. */
    maxDriftMs?: number;
    now?: number;
    provider?: CryptoProvider;
  },
): QuorumVerification {
  if (opts.threshold <= 0) {
    return { valid: false, reason: 'threshold must be positive', acceptedAuthorities: [] };
  }
  const acceptedByAuthority = new Map<string, TimeWitness>();
  for (const w of witnesses) {
    const check = verifyTimeWitness(w, {
      expectedNonce: opts.expectedNonce,
      trustedAuthorities: opts.trustedAuthorities,
      maxAgeMs: opts.maxAgeMs,
      maxSkewMs: opts.maxSkewMs,
      now: opts.now,
      provider: opts.provider,
    });
    if (check.valid && !acceptedByAuthority.has(w.authorityDid)) {
      acceptedByAuthority.set(w.authorityDid, w);
    }
  }

  const accepted = Array.from(acceptedByAuthority.values());
  const acceptedDids = accepted.map((w) => w.authorityDid);

  if (accepted.length < opts.threshold) {
    return {
      valid: false,
      reason: `insufficient quorum (${accepted.length}/${opts.threshold})`,
      acceptedAuthorities: acceptedDids,
    };
  }

  const times = accepted.map((w) => w.observedAt).sort((a, b) => a - b);
  const drift = times[times.length - 1] - times[0];
  if (opts.maxDriftMs !== undefined && drift > opts.maxDriftMs) {
    return {
      valid: false,
      reason: `witness drift too high (${drift}ms > ${opts.maxDriftMs})`,
      acceptedAuthorities: acceptedDids,
    };
  }

  const medianTime = times[Math.floor(times.length / 2)];
  return { valid: true, acceptedAuthorities: acceptedDids, medianTime };
}
