/**
 * Proof-of-possession — prove the holder has the private key, not just the token.
 *
 * Classic macaroons are bearer tokens: anyone who steals the serialized token
 * can use it. Delegations in soma-heart bind a subject DID, but a stolen
 * delegation + its issuer's signature is still usable unless we force the
 * holder to prove possession of the subject's private key.
 *
 * Protocol (challenge-response):
 *   1. Verifier calls `issueChallenge()` — generates a 32-byte random nonce
 *      and binds it to the delegation's id.
 *   2. Holder calls `proveChallenge()` — signs (nonce || delegation.id) with
 *      the subject's private key.
 *   3. Verifier calls `verifyProof()` — checks the signature against the
 *      public key derived from `delegation.subjectDid`.
 *
 * The nonce MUST be stored by the verifier and marked used on success. Replays
 * of the same nonce MUST be rejected to prevent captured-proof reuse. This
 * module is challenge-only — nonce lifetime/storage is up to the verifier.
 *
 * This closes audit limit #7. Opt-in via `InvocationContext.requireProof` so
 * existing integrations don't break.
 */

import { didToPublicKey } from '../core/genome.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import type { Delegation } from './delegation.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A challenge issued by a verifier to a delegation holder. */
export interface Challenge {
  /** Base64-encoded random nonce (32 bytes). */
  nonceB64: string;
  /** The delegation ID this challenge binds to. */
  delegationId: string;
  /** When the challenge was issued (ms since epoch). */
  issuedAt: number;
}

/** A proof produced by the holder in response to a challenge. */
export interface PossessionProof {
  /** Echoes the challenge nonce. */
  nonceB64: string;
  /** Delegation ID this proof covers. */
  delegationId: string;
  /** Base64-encoded Ed25519 signature over (nonce || delegationId). */
  signatureB64: string;
}

export type ProofVerification =
  | { valid: true }
  | { valid: false; reason: string };

// ─── Challenge / Prove / Verify ─────────────────────────────────────────────

/** Issue a challenge for a given delegation. */
export function issueChallenge(
  delegation: Pick<Delegation, 'id'>,
  provider?: CryptoProvider,
): Challenge {
  const p = provider ?? getCryptoProvider();
  const nonce = p.random.randomBytes(32);
  return {
    nonceB64: p.encoding.encodeBase64(nonce),
    delegationId: delegation.id,
    issuedAt: Date.now(),
  };
}

/**
 * Default maximum age of a challenge, in ms. Challenges older than this are
 * rejected as stale — an attacker who captures an old proof cannot replay
 * it beyond this window even if nonce tracking is missing or delayed.
 */
export const DEFAULT_MAX_CHALLENGE_AGE_MS = 60_000;

/**
 * The exact bytes that get signed — kept in one place for test parity.
 * `issuedAt` is bound into the payload so a captured proof cannot be
 * replayed against a newer challenge that happens to share the same
 * (nonce, delegationId) pair. Without this, the nonce alone does not
 * commit the holder to the challenge's freshness.
 */
function proofPayload(nonceB64: string, delegationId: string, issuedAt: number): Uint8Array {
  return new TextEncoder().encode(`soma-pop:${nonceB64}:${delegationId}:${issuedAt}`);
}

/**
 * Holder responds to a challenge by signing (nonce || delegationId || issuedAt)
 * with the subject's private key. Caller must pass the key matching subjectDid.
 */
export function proveChallenge(
  challenge: Challenge,
  subjectSigningKey: Uint8Array,
  provider?: CryptoProvider,
): PossessionProof {
  const p = provider ?? getCryptoProvider();
  const payload = proofPayload(challenge.nonceB64, challenge.delegationId, challenge.issuedAt);
  const signature = p.signing.sign(payload, subjectSigningKey);
  return {
    nonceB64: challenge.nonceB64,
    delegationId: challenge.delegationId,
    signatureB64: p.encoding.encodeBase64(signature),
  };
}

/**
 * Verifier checks a proof against the delegation's subjectDid.
 * Returns { valid: true } only if the signature was produced by the key
 * belonging to delegation.subjectDid AND the challenge is still fresh.
 *
 * The caller is responsible for tracking nonces and rejecting replays.
 * This function additionally rejects challenges older than `maxAgeMs`
 * (default `DEFAULT_MAX_CHALLENGE_AGE_MS`) so that even if nonce tracking
 * is absent or delayed, captured proofs have a hard expiration.
 */
export function verifyProof(
  challenge: Challenge,
  proof: PossessionProof,
  delegation: Pick<Delegation, 'id' | 'subjectDid'>,
  provider?: CryptoProvider,
  options?: { maxAgeMs?: number; now?: number },
): ProofVerification {
  const p = provider ?? getCryptoProvider();
  const maxAgeMs = options?.maxAgeMs ?? DEFAULT_MAX_CHALLENGE_AGE_MS;
  const now = options?.now ?? Date.now();

  if (proof.delegationId !== delegation.id) {
    return { valid: false, reason: 'proof delegationId mismatch' };
  }
  if (proof.delegationId !== challenge.delegationId) {
    return { valid: false, reason: 'challenge/proof delegationId mismatch' };
  }
  if (proof.nonceB64 !== challenge.nonceB64) {
    return { valid: false, reason: 'nonce mismatch' };
  }
  const age = now - challenge.issuedAt;
  if (age < 0) {
    return { valid: false, reason: 'challenge issuedAt is in the future' };
  }
  if (age > maxAgeMs) {
    return { valid: false, reason: `challenge expired (age ${age}ms > maxAgeMs ${maxAgeMs}ms)` };
  }

  let subjectPubKey: Uint8Array;
  try {
    subjectPubKey = didToPublicKey(delegation.subjectDid, p);
  } catch (err) {
    return {
      valid: false,
      reason: `cannot derive subject public key: ${(err as Error).message}`,
    };
  }

  const payload = proofPayload(challenge.nonceB64, challenge.delegationId, challenge.issuedAt);
  const sigBytes = p.encoding.decodeBase64(proof.signatureB64);

  if (!p.signing.verify(payload, sigBytes, subjectPubKey)) {
    return { valid: false, reason: 'invalid signature (not signed by subject key)' };
  }

  return { valid: true };
}
