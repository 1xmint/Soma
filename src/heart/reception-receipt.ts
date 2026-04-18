/**
 * Reception receipts — accountability primitive for capability verification.
 *
 * A verifier issues a ReceiptPayload attesting: "I (verifierId) evaluated
 * request (requestId) against heartDid's capability class (capabilityClass)
 * and the outcome was (pass | fail | inconclusive)."  The receipt is signed
 * with the verifier's Ed25519 key, producing a SignedReceipt that any
 * downstream party can independently verify.
 *
 * Design goals:
 *   - Deterministic canonical serialization (JCS-style sorted keys) so the
 *     bytes the signer commits to are reproducible by any verifier.
 *   - No chain linkage here — receipts are standalone atoms. Aggregation,
 *     hash-chaining, and transport are out of scope for this primitive.
 *   - evidenceSummary is capped at 512 chars to keep receipts small and
 *     prevent embedding arbitrary data blobs.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';

// ─── Types ───────────────────────────────────────────────────────────────────

export type ReceiptOutcome = 'pass' | 'fail' | 'inconclusive';

export interface ReceiptPayload {
  /** DID of the verifier issuing this receipt. */
  verifierId: string;
  /** Opaque identifier for the request being verified. */
  requestId: string;
  /** DID of the heart (agent) whose capability was evaluated. */
  heartDid: string;
  /** The capability class evaluated (e.g. "tool:db", "action:write"). */
  capabilityClass: string;
  /** Outcome of the verification. */
  outcome: ReceiptOutcome;
  /** Unix epoch milliseconds when this receipt was produced. */
  timestamp: number;
  /** Human-readable summary of evidence. Max 512 chars. */
  evidenceSummary: string;
}

export interface SignedReceipt {
  payload: ReceiptPayload;
  /** Base64-encoded Ed25519 signature over canonical(payload). */
  signature: string;
  /** Base64-encoded verifier public key — must match verifierId DID. */
  signerPublicKey: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

export const EVIDENCE_SUMMARY_MAX = 512;

// ─── Core functions ───────────────────────────────────────────────────────────

/**
 * Sign a receipt payload. Throws if evidenceSummary exceeds 512 chars.
 * Returns a SignedReceipt with the payload, signature, and signer public key.
 */
export function signReceipt(
  payload: ReceiptPayload,
  signingKey: Uint8Array,
  publicKey: Uint8Array,
  provider?: CryptoProvider,
): SignedReceipt {
  if (payload.evidenceSummary.length > EVIDENCE_SUMMARY_MAX) {
    throw new Error(
      `evidenceSummary too long: ${payload.evidenceSummary.length} chars (max ${EVIDENCE_SUMMARY_MAX})`,
    );
  }

  const p = provider ?? getCryptoProvider();
  const canonical = receiptCanonical(payload);
  const signingInput = new TextEncoder().encode(canonical);
  const sigBytes = p.signing.sign(signingInput, signingKey);

  return {
    payload,
    signature: p.encoding.encodeBase64(sigBytes),
    signerPublicKey: p.encoding.encodeBase64(publicKey),
  };
}

/**
 * Verify a signed receipt. Returns true only if the signature is valid over
 * the canonical serialization of the payload.
 */
export function verifyReceipt(
  signed: SignedReceipt,
  provider?: CryptoProvider,
): boolean {
  const p = provider ?? getCryptoProvider();
  const canonical = receiptCanonical(signed.payload);
  const signingInput = new TextEncoder().encode(canonical);

  let sigBytes: Uint8Array;
  let pubKeyBytes: Uint8Array;
  try {
    sigBytes = p.encoding.decodeBase64(signed.signature);
    pubKeyBytes = p.encoding.decodeBase64(signed.signerPublicKey);
  } catch {
    return false;
  }

  return p.signing.verify(signingInput, sigBytes, pubKeyBytes);
}

// ─── Internals ───────────────────────────────────────────────────────────────

/** Deterministic canonical serialization of a ReceiptPayload for signing. */
export function receiptCanonical(payload: ReceiptPayload): string {
  return canonicalJson(payload);
}
