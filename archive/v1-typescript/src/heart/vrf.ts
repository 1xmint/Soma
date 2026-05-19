/**
 * Verifiable Random Function (VRF) — unpredictable, unforgeable, verifiable.
 *
 * Given a key pair (sk, pk) and an input x, a VRF produces (output, proof):
 *   - output is deterministic for (sk, x): re-running yields the same bytes
 *   - anyone with pk can verify that (x, output, proof) was computed honestly
 *   - without sk, you can't forge a valid (output, proof) pair
 *   - output is unpredictable to parties who don't hold sk
 *
 * Use cases in Soma:
 *   - Leader election: each party evaluates vrf(sk, epochSeed); lowest wins.
 *   - Random beacons: aggregate VRF outputs from multiple parties for an
 *     unbiased, verifiable randomness source.
 *   - Lottery / assignment: deterministic-but-unpredictable IDs.
 *   - Commit-reveal: commit to output ahead of time; reveal proof later.
 *
 * Implementation: deterministic Ed25519 signature as the VRF proof, and
 * hash(signature) as the output. This is sometimes called an "Ed25519
 * signature-based VRF" or "EdDSA-VRF" in the literature — simpler than
 * ECVRF-EDWARDS25519-SHA512-ELL2 (RFC 9381) and easier to audit, at the
 * cost of revealing the full signature in the proof rather than a shorter
 * gamma point.
 *
 * Security properties (informal):
 *   - Uniqueness: Ed25519 signatures are deterministic (sign produces same
 *     output for same input + key), so output is unique per (sk, input).
 *   - Unforgeability: producing a valid proof without sk requires forging
 *     an Ed25519 signature, which is infeasible under EUF-CMA.
 *   - Pseudorandomness: output = H("vrf-output" || signature) — assuming
 *     SHA-256 is a random oracle, output is indistinguishable from random
 *     to parties without sk.
 *   - Domain separation: input is prefixed with "soma-vrf-input:v1:" so
 *     VRF proofs cannot be reused as general Ed25519 signatures.
 *
 * Non-goals:
 *   - RFC 9381 compatibility — that spec uses curve points as proofs,
 *     ~50% smaller. Migrate if interop with that ecosystem matters.
 *   - "Malicious verifier" resistance beyond standard signature model.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Domain separation prefixes ────────────────────────────────────────────

const INPUT_DOMAIN = 'soma-vrf-input:v1:';
const OUTPUT_DOMAIN = 'soma-vrf-output:v1:';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A VRF output + proof. The output is what you use; the proof lets others verify. */
export interface VrfOutput {
  /** Base64 output bytes (32 bytes = SHA-256). Deterministic per (sk, input). */
  outputB64: string;
  /** Base64 proof (64 bytes — the underlying Ed25519 signature). */
  proofB64: string;
  /** DID of the party that evaluated the VRF. */
  evaluatorDid: string;
  /** Base64 public key of the evaluator (redundant with DID but convenient). */
  evaluatorPublicKey: string;
}

export type VrfVerification =
  | { valid: true; output: Uint8Array }
  | { valid: false; reason: string };

// ─── Internal helpers ───────────────────────────────────────────────────────

function buildSigningInput(input: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(INPUT_DOMAIN);
  const out = new Uint8Array(prefix.length + input.length);
  out.set(prefix, 0);
  out.set(input, prefix.length);
  return out;
}

function hashProofToOutput(
  proof: Uint8Array,
  p: CryptoProvider,
): Uint8Array {
  // Hash the proof into the output space with domain separation.
  // We use the provider's hash (returns hex string) and convert.
  const hex = p.hashing.hash(
    OUTPUT_DOMAIN + p.encoding.encodeBase64(proof),
  );
  // hex → bytes
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─── Evaluate (hold the secret key) ─────────────────────────────────────────

export function evaluateVrf(opts: {
  input: Uint8Array;
  signingKey: Uint8Array;
  publicKey: Uint8Array;
  provider?: CryptoProvider;
}): VrfOutput {
  const p = opts.provider ?? getCryptoProvider();
  const signingInput = buildSigningInput(opts.input);
  const proof = p.signing.sign(signingInput, opts.signingKey);
  const output = hashProofToOutput(proof, p);
  return {
    outputB64: p.encoding.encodeBase64(output),
    proofB64: p.encoding.encodeBase64(proof),
    evaluatorDid: publicKeyToDid(opts.publicKey, p),
    evaluatorPublicKey: p.encoding.encodeBase64(opts.publicKey),
  };
}

// ─── Verify (have only the public key) ──────────────────────────────────────

export function verifyVrf(
  input: Uint8Array,
  vrf: VrfOutput,
  provider?: CryptoProvider,
): VrfVerification {
  const p = provider ?? getCryptoProvider();

  let pubKey: Uint8Array;
  let proof: Uint8Array;
  let claimedOutput: Uint8Array;
  try {
    pubKey = p.encoding.decodeBase64(vrf.evaluatorPublicKey);
    proof = p.encoding.decodeBase64(vrf.proofB64);
    claimedOutput = p.encoding.decodeBase64(vrf.outputB64);
  } catch {
    return { valid: false, reason: 'malformed base64' };
  }

  // DID/key binding.
  if (publicKeyToDid(pubKey, p) !== vrf.evaluatorDid) {
    return { valid: false, reason: 'evaluatorDid does not match public key' };
  }

  // Verify the underlying signature (the proof).
  const signingInput = buildSigningInput(input);
  if (!p.signing.verify(signingInput, proof, pubKey)) {
    return { valid: false, reason: 'invalid VRF proof (signature failed)' };
  }

  // Recompute output and compare.
  const expectedOutput = hashProofToOutput(proof, p);
  if (expectedOutput.length !== claimedOutput.length) {
    return { valid: false, reason: 'output length mismatch' };
  }
  let diff = 0;
  for (let i = 0; i < expectedOutput.length; i++) {
    diff |= expectedOutput[i]! ^ claimedOutput[i]!;
  }
  if (diff !== 0) {
    return { valid: false, reason: 'output does not match proof' };
  }

  return { valid: true, output: claimedOutput };
}

// ─── Utilities ──────────────────────────────────────────────────────────────

/**
 * Convert VRF output bytes to a uniformly-distributed integer in [0, bound).
 * Uses rejection sampling to avoid modulo bias. Bound must be 1..2^32.
 */
export function outputToInt(output: Uint8Array, bound: number): number {
  if (bound < 1 || bound > 2 ** 32) {
    throw new Error('bound must be in [1, 2^32]');
  }
  // Use first 4 bytes as a 32-bit uint, rejection-sample to avoid bias.
  // Max multiple of bound that fits in 2^32:
  const limit = Math.floor(2 ** 32 / bound) * bound;
  // Walk through output in 4-byte chunks; fall back to mod if we run out.
  for (let off = 0; off + 4 <= output.length; off += 4) {
    const v =
      ((output[off]! << 24) |
        (output[off + 1]! << 16) |
        (output[off + 2]! << 8) |
        output[off + 3]!) >>>
      0;
    if (v < limit) return v % bound;
  }
  // Fell through: all chunks landed in the bias zone. Extremely rare; just
  // use the last chunk with modulo (negligible bias for typical bounds).
  const off = output.length - 4;
  const v =
    ((output[off]! << 24) |
      (output[off + 1]! << 16) |
      (output[off + 2]! << 8) |
      output[off + 3]!) >>>
    0;
  return v % bound;
}

/**
 * Combine multiple VRF outputs into a single beacon value.
 * Use case: N parties each publish a VRF output; the beacon is a hash of
 * all of them, so the final randomness can't be biased by any single party.
 * Order-independent (outputs are sorted by hex representation before hashing).
 */
export function combineBeacon(
  outputs: readonly VrfOutput[],
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  if (outputs.length === 0) {
    throw new Error('beacon requires at least one output');
  }
  const sorted = [...outputs].map((o) => o.outputB64).sort();
  return p.hashing.hash(`soma-vrf-beacon:v1:${sorted.join(',')}`);
}
