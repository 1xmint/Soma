/**
 * Key escrow / recovery — Shamir's Secret Sharing over GF(256).
 *
 * Problem: a heart's signing key is the root of all its authority. Lose it
 * and the identity is dead forever. Hand it to one person and you've given
 * them full control. Both outcomes are operationally unacceptable.
 *
 * Solution: split the secret into N shares such that any K of them can
 * reconstruct it, and any K-1 of them reveal NOTHING. Distribute shares to
 * independent trustees (hardware vaults, family members, offline media,
 * legal custodians). Recovery needs a quorum but no single party is trusted.
 *
 * Properties (inherited from Shamir 1979):
 *   - Information-theoretic security: K-1 shares leak zero bits.
 *   - Linear: shares can be mixed/rotated without touching the secret.
 *   - No setup: pure polynomial math, no trusted dealer beyond split-time.
 *
 * Implementation notes:
 *   - Arithmetic in GF(256) with irreducible polynomial 0x11b (Rijndael).
 *     Matches AES's field so the log/exp tables are standard and audited.
 *   - Secret is processed byte-by-byte; each byte gets its own independent
 *     polynomial. This is the standard Shamir construction — the secret is
 *     just a sequence of independent GF(256) secrets.
 *   - Shares are tagged with index (1..255). Index 0 is reserved for the
 *     secret itself (f(0)).
 *   - We bind each share to a "secretId" so shares from different secrets
 *     can't be mixed. The id is also returned on reconstruction so callers
 *     can verify they're combining the right shares.
 *   - Threshold K must satisfy 2 ≤ K ≤ N ≤ 255.
 *
 * This implementation is NOT constant-time. Shamir over GF(256) with table
 * lookups has timing variance. For defense against sophisticated side-channel
 * attacks, do the share operations on a hardened device (HSM). For
 * operational key recovery — the main use case — table-lookup SSS is the
 * standard approach and is what libraries like SLIP-0039 use.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';

// ─── GF(256) log/exp tables (Rijndael, poly 0x11b) ─────────────────────────

const GF_EXP = new Uint8Array(512); // doubled to avoid modulo in multiply
const GF_LOG = new Uint8Array(256);
(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    // Multiply by generator (0x03 = x + 1 in Rijndael)
    x ^= x << 1;
    if (x & 0x100) x ^= 0x11b;
    x &= 0xff;
  }
  // Second half of EXP mirrors the first so mul can skip modulo.
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
  GF_LOG[0] = 0; // undefined but convenient — we guard against it
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('GF(256) division by zero');
  if (a === 0) return 0;
  // log(a/b) = log(a) - log(b) mod 255
  const diff = GF_LOG[a]! - GF_LOG[b]! + 255;
  return GF_EXP[diff]!;
}

/** Evaluate polynomial at x, coefficients[0] = constant term (the secret byte). */
function evalPoly(coeffs: Uint8Array, x: number): number {
  // Horner's method: y = coeffs[k-1]*x^(k-1) + ... + coeffs[0]
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    y = gfMul(y, x) ^ coeffs[i]!;
  }
  return y;
}

/**
 * Lagrange interpolation at x = 0, given k distinct points.
 * This is where the secret byte lives: f(0) = secret.
 */
function lagrangeInterpolateAtZero(
  points: readonly { x: number; y: number }[],
): number {
  let result = 0;
  for (let i = 0; i < points.length; i++) {
    const xi = points[i]!.x;
    const yi = points[i]!.y;
    // Compute Lagrange basis L_i(0) = prod over j!=i of (0 - xj)/(xi - xj)
    let basis = 1;
    for (let j = 0; j < points.length; j++) {
      if (j === i) continue;
      const xj = points[j]!.x;
      // Over GF(256), subtraction is XOR.
      const num = xj; // 0 ^ xj = xj
      const den = xi ^ xj;
      basis = gfMul(basis, gfDiv(num, den));
    }
    result ^= gfMul(yi, basis);
  }
  return result;
}

// ─── Public types ──────────────────────────────────────────────────────────

/** One piece of a split secret. Need K of these to reconstruct. */
export interface SecretShare {
  /** Opaque id binding this share to its siblings. Same across all shares. */
  secretId: string;
  /** Share index (1..255). Must be unique within the share set. */
  index: number;
  /** How many shares are needed to reconstruct (the threshold). */
  threshold: number;
  /** Total number of shares issued. */
  totalShares: number;
  /** Length of the original secret in bytes (included for integrity check). */
  secretLength: number;
  /** Base64-encoded share bytes — one byte per secret byte. */
  shareB64: string;
}

export interface SplitOptions {
  threshold: number;
  totalShares: number;
  /** Optional custom id (otherwise random). Lets callers label the share set. */
  secretId?: string;
  provider?: CryptoProvider;
}

// ─── Split ──────────────────────────────────────────────────────────────────

export function splitSecret(
  secret: Uint8Array,
  opts: SplitOptions,
): SecretShare[] {
  const { threshold, totalShares } = opts;
  const p = opts.provider ?? getCryptoProvider();

  if (secret.length === 0) {
    throw new Error('secret must not be empty');
  }
  if (threshold < 2) {
    throw new Error('threshold must be at least 2');
  }
  if (totalShares < threshold) {
    throw new Error('totalShares must be >= threshold');
  }
  if (totalShares > 255) {
    throw new Error('totalShares must be <= 255 (GF(256) limit)');
  }

  const secretId =
    opts.secretId ?? `sec-${p.encoding.encodeBase64(p.random.randomBytes(12))}`;

  // For each byte of the secret, build a polynomial of degree threshold-1
  // with constant term = secret byte, then evaluate at x=1..totalShares.
  const shareBytes: Uint8Array[] = Array.from(
    { length: totalShares },
    () => new Uint8Array(secret.length),
  );

  // Random coefficients are threshold-1 bytes per secret byte.
  const coeffs = new Uint8Array(threshold - 1);
  for (let b = 0; b < secret.length; b++) {
    // Fresh random coefficients PER BYTE (critical for security).
    const rand = p.random.randomBytes(threshold - 1);
    coeffs.set(rand);

    // Build the polynomial for this byte: [secret[b], coeffs[0], ..., coeffs[k-2]]
    const poly = new Uint8Array(threshold);
    poly[0] = secret[b]!;
    for (let i = 0; i < coeffs.length; i++) poly[i + 1] = coeffs[i]!;

    for (let shareIdx = 0; shareIdx < totalShares; shareIdx++) {
      const x = shareIdx + 1; // 1-indexed; index 0 is reserved for secret
      shareBytes[shareIdx]![b] = evalPoly(poly, x);
    }
  }

  // Zero out the coeffs buffer (best-effort — JS makes real erasure hard).
  coeffs.fill(0);

  const shares: SecretShare[] = [];
  for (let i = 0; i < totalShares; i++) {
    shares.push({
      secretId,
      index: i + 1,
      threshold,
      totalShares,
      secretLength: secret.length,
      shareB64: p.encoding.encodeBase64(shareBytes[i]!),
    });
  }
  return shares;
}

// ─── Reconstruct ────────────────────────────────────────────────────────────

export function reconstructSecret(
  shares: readonly SecretShare[],
  provider?: CryptoProvider,
): Uint8Array {
  const p = provider ?? getCryptoProvider();

  if (shares.length === 0) {
    throw new Error('shares must not be empty');
  }

  const first = shares[0]!;
  const { secretId, threshold, totalShares, secretLength } = first;

  // All shares must come from the same secret.
  for (const s of shares) {
    if (s.secretId !== secretId) {
      throw new Error('shares come from different secrets');
    }
    if (
      s.threshold !== threshold ||
      s.totalShares !== totalShares ||
      s.secretLength !== secretLength
    ) {
      throw new Error('share metadata mismatch');
    }
  }

  if (shares.length < threshold) {
    throw new Error(
      `need at least ${threshold} shares, got ${shares.length}`,
    );
  }

  // Deduplicate by index — reject duplicate share indexes.
  const indexSet = new Set<number>();
  for (const s of shares) {
    if (s.index < 1 || s.index > 255) {
      throw new Error(`share index out of range: ${s.index}`);
    }
    if (indexSet.has(s.index)) {
      throw new Error(`duplicate share index: ${s.index}`);
    }
    indexSet.add(s.index);
  }

  // Use the first K shares (extra ones don't hurt but aren't required).
  const used = shares.slice(0, threshold);
  const shareByteArrays = used.map((s) => p.encoding.decodeBase64(s.shareB64));
  for (const b of shareByteArrays) {
    if (b.length !== secretLength) {
      throw new Error('share length does not match secretLength');
    }
  }

  const secret = new Uint8Array(secretLength);
  for (let b = 0; b < secretLength; b++) {
    const points = used.map((s, i) => ({
      x: s.index,
      y: shareByteArrays[i]![b]!,
    }));
    secret[b] = lagrangeInterpolateAtZero(points);
  }
  return secret;
}

// ─── Verification helpers ───────────────────────────────────────────────────

/**
 * Check that a specific subset of shares reconstructs to a known secret.
 * Useful as a post-split sanity check, or as a test harness for trustees.
 * Returns true iff reconstruction yields bytes matching `expected`.
 */
export function verifyShares(
  shares: readonly SecretShare[],
  expected: Uint8Array,
  provider?: CryptoProvider,
): boolean {
  try {
    const got = reconstructSecret(shares, provider);
    if (got.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i]! ^ expected[i]!;
    return diff === 0;
  } catch {
    return false;
  }
}

/**
 * Exhaustively check that EVERY K-subset of the N shares reconstructs the
 * secret. N choose K grows fast — callers should limit to small parameter
 * sizes (e.g. 5-of-5 = 1 combination, 3-of-5 = 10 combinations). For larger
 * sets, random sampling is sufficient.
 */
export function verifyAllSubsetsReconstruct(
  shares: readonly SecretShare[],
  expected: Uint8Array,
  provider?: CryptoProvider,
): boolean {
  if (shares.length === 0) return false;
  const k = shares[0]!.threshold;
  if (shares.length < k) return false;

  // Generate all k-combinations of indices [0, shares.length)
  const n = shares.length;
  const indices = new Array(k).fill(0).map((_, i) => i);
  while (true) {
    const subset = indices.map((i) => shares[i]!);
    if (!verifyShares(subset, expected, provider)) return false;

    // Advance to next combination (lexicographic).
    let i = k - 1;
    while (i >= 0 && indices[i] === n - k + i) i--;
    if (i < 0) break;
    indices[i]++;
    for (let j = i + 1; j < k; j++) indices[j] = indices[j - 1]! + 1;
  }
  return true;
}
