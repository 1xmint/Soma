/**
 * Attack harness — shared primitives for multi-primitive adversary tests.
 *
 * Each file in `tests/attacks/` stages an adversarial scenario that composes
 * 2-5 primitives and asserts the defensive controls catch the attack.
 *
 * The point is NOT unit-test coverage (that's in `tests/heart/`). The point
 * is to prove primitives hold under COMPOSITION — when a delegation is
 * presented inside a session, backed by spend receipts, with a rotated key,
 * the system as a whole still says "no" to the adversary.
 *
 * Convention:
 *   - Each test names the attack in its describe() and the defense in its it().
 *   - Stage the adversary explicitly (who steals what, who forges what).
 *   - Execute the attack as a concrete sequence of legitimate API calls.
 *   - Assert the control fires (`valid: false`, throws, returns null, etc.)
 *     with a reason that matches the attack's failure mode.
 */

import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";

export const crypto = getCryptoProvider();

/** A fully-materialized identity with keys + DID + base64 public key. */
export interface TestIdentity {
  did: string;
  publicKey: string;          // base64
  publicKeyBytes: Uint8Array;
  signingKey: Uint8Array;
}

/** Mint a fresh identity for an attack scenario. */
export function makeIdentity(): TestIdentity {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    publicKeyBytes: kp.publicKey,
    signingKey: kp.secretKey,
  };
}

/** Mint N identities at once. */
export function makeIdentities(n: number): TestIdentity[] {
  return Array.from({ length: n }, () => makeIdentity());
}

/** Convenience: is a DelegationVerification the expected failure reason? */
export function failedWith<T extends { valid: boolean; reason?: string }>(
  r: T,
  expectedSubstring: string,
): boolean {
  return !r.valid && (r.reason ?? "").toLowerCase().includes(expectedSubstring.toLowerCase());
}

/** Deep-clone a JSON-serializable object (for tamper scenarios). */
export function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}

/** Encode a plain string as UTF-8 bytes. */
export function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
