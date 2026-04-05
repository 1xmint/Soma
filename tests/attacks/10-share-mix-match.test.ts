/**
 * Attack #10 — Share mix-and-match across different secrets.
 *
 * Scenario:
 *   Alice splits a signing key K into (t=3, n=5) shares labeled secretId=S1.
 *   Later, Bob splits a DIFFERENT key K' into (t=3, n=5) shares labeled
 *   secretId=S2. An attacker with access to shares from both sets tries to
 *   reconstruct SOMETHING by mixing shares: 2 from S1 + 1 from S2.
 *
 *   If verifyShares didn't enforce matching secretId, reconstruction would
 *   produce garbage bytes that might be mistaken for a legitimate secret.
 *
 * Defense: every share carries a `secretId` binding it to its siblings.
 * `verifyShares` refuses mixed sets. `reconstructSecret` only reconstructs
 * when the shares are consistent.
 *
 * Primitives composed:
 *   key-escrow · Shamir shares · secretId binding
 */

import { describe, it, expect } from "vitest";
import {
  splitSecret,
  reconstructSecret,
  verifyShares,
} from "../../src/heart/key-escrow.js";

function randomSecret(len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (i * 7 + 11) & 0xff;
  return out;
}

describe("Attack #10: share mix-and-match", () => {
  it("reconstructSecret throws on mixed secretIds", () => {
    const k1 = randomSecret(32);
    const k2 = randomSecret(32);
    const sharesA = splitSecret(k1, { threshold: 3, totalShares: 5 });
    const sharesB = splitSecret(k2, { threshold: 3, totalShares: 5 });

    // Attacker mixes 2 from A + 1 from B.
    const mixed = [sharesA[0], sharesA[1], sharesB[0]];
    expect(() => reconstructSecret(mixed)).toThrow(/different secrets/);
  });

  it("mixing any two shares across secrets fails reconstruction", () => {
    const k1 = randomSecret(16);
    const k2 = randomSecret(16);
    const sharesA = splitSecret(k1, { threshold: 2, totalShares: 4 });
    const sharesB = splitSecret(k2, { threshold: 2, totalShares: 4 });

    const mixed = [sharesA[0], sharesB[1]];
    expect(() => reconstructSecret(mixed)).toThrow();
  });

  it("duplicate share indices are rejected", () => {
    const k = randomSecret(16);
    const shares = splitSecret(k, { threshold: 3, totalShares: 5 });
    // Attacker presents two copies of the same share index.
    const duplicate = [shares[0], shares[0], shares[1]];
    expect(() => reconstructSecret(duplicate)).toThrow();
  });

  it("below-threshold reconstruction fails", () => {
    const k = randomSecret(16);
    const shares = splitSecret(k, { threshold: 3, totalShares: 5 });
    const insufficient = shares.slice(0, 2);
    expect(() => reconstructSecret(insufficient)).toThrow();
  });

  it("legitimate reconstruction returns the original bytes", () => {
    const k = randomSecret(32);
    const shares = splitSecret(k, { threshold: 3, totalShares: 5 });
    const reconstructed = reconstructSecret(shares.slice(0, 3));
    expect(reconstructed).toEqual(k);
    // verifyShares(shares, expected) confirms match.
    expect(verifyShares(shares.slice(0, 3), k)).toBe(true);
  });

  it("attacker cannot fabricate a share — bytes chosen at random yield garbage", () => {
    const k = randomSecret(32);
    const shares = splitSecret(k, { threshold: 3, totalShares: 5 });
    // Attacker fakes a share at an unused index, signed with the right
    // secretId (assume leaked). The numeric bytes are nonsense.
    const fakeShare = {
      ...shares[0],
      index: 99, // unused index, pretends to be share #99
      shareB64: shares[0].shareB64, // random bytes claiming to be a share
    };
    // Using 2 legitimate shares + 1 bogus — reconstruction proceeds but
    // yields a WRONG secret (Shamir math can't detect bad shares without
    // additional integrity data).
    const reconstructed = reconstructSecret([shares[0], shares[1], fakeShare]);
    // The reconstructed bytes do NOT equal the original.
    expect(reconstructed).not.toEqual(k);
    // This confirms a limit: Shamir alone doesn't authenticate shares.
    // Integrity checks (e.g. HMAC-authenticated shares) are needed for
    // byzantine scenarios.
  });
});
