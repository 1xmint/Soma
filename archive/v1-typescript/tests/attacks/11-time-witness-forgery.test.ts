/**
 * Attack #11 — Time witness forgery.
 *
 * Scenario:
 *   A verifier demands proof of freshness via a time witness from a trusted
 *   authority. Eve wants to replay an expired credential by either:
 *     - Forging a witness with her OWN key but claiming an authority DID.
 *     - Replaying an old witness nonce against a fresh challenge.
 *     - Presenting a witness from a rogue authority not in the trust set.
 *     - Manipulating observedAt to pretend "now" is 2 years ago.
 *
 * Defense: `verifyTimeWitness` checks signature + DID/key binding + nonce
 * match + trusted-authority membership + maxAgeMs. All four attack variants
 * are blocked.
 *
 * Primitives composed:
 *   time-oracle · TimeWitness · trusted-authority policy
 */

import { describe, it, expect } from "vitest";
import {
  issueTimeWitness,
  verifyTimeWitness,
} from "../../src/heart/time-oracle.js";
import { makeIdentity, failedWith } from "./_harness.js";

describe("Attack #11: time witness forgery", () => {
  it("witness with a bogus signature is rejected", () => {
    const authority = makeIdentity();

    // Eve presents a witness with authority's pk but a garbage signature.
    const forged = {
      observedAt: Date.now(),
      authorityDid: authority.did,
      authorityPublicKey: authority.publicKey,
      nonce: null,
      signature: Buffer.alloc(64, 0).toString("base64"), // zero sig
    };
    const result = verifyTimeWitness(forged);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "signature")).toBe(true);
  });

  it("issuing with one key, labeling with another, fails the DID/key binding", () => {
    // Using issueTimeWitness legitimately — but mismatch public key vs DID.
    const authority = makeIdentity();
    const eve = makeIdentity();

    // We sign with eve's key but present authority's public key. The DID
    // derived from authority's pub key won't match eve's signature.
    // Simulate by hand (issueTimeWitness enforces a sane binding).
    const witness = issueTimeWitness({
      authoritySecretKey: eve.signingKey,
      authorityPublicKey: authority.publicKeyBytes, // mismatched
    });
    // The sig is over the payload containing authority.did (derived from
    // authority's pub key) but signed with eve.secretKey. Verify will
    // attempt to check with authority's pub key (which is declared), fail.
    const result = verifyTimeWitness(witness);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "signature")).toBe(true);
  });

  it("witness with mismatched nonce is rejected", () => {
    const authority = makeIdentity();
    const witness = issueTimeWitness({
      authoritySecretKey: authority.signingKey,
      authorityPublicKey: authority.publicKeyBytes,
      nonce: "challenge-123",
    });
    const result = verifyTimeWitness(witness, {
      expectedNonce: "challenge-456", // different
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "nonce")).toBe(true);
  });

  it("witness from authority not in trust set is rejected", () => {
    const legit = makeIdentity();
    const rogue = makeIdentity();
    const witness = issueTimeWitness({
      authoritySecretKey: rogue.signingKey,
      authorityPublicKey: rogue.publicKeyBytes,
    });
    const result = verifyTimeWitness(witness, {
      trustedAuthorities: [legit.did],
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "trust set")).toBe(true);
  });

  it("stale witness beyond maxAgeMs is rejected", () => {
    const authority = makeIdentity();
    const witness = issueTimeWitness({
      authoritySecretKey: authority.signingKey,
      authorityPublicKey: authority.publicKeyBytes,
    });
    const result = verifyTimeWitness(witness, {
      maxAgeMs: 1000,
      now: witness.observedAt + 10_000, // 10s after witness issued
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "stale")).toBe(true);
  });

  it("future-dated witness beyond maxSkewMs is rejected", () => {
    const authority = makeIdentity();
    const witness = issueTimeWitness({
      authoritySecretKey: authority.signingKey,
      authorityPublicKey: authority.publicKeyBytes,
    });
    const result = verifyTimeWitness(witness, {
      maxSkewMs: 100,
      now: witness.observedAt - 10_000, // witness is "from the future"
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "future")).toBe(true);
  });

  it("legitimate witness with matching nonce + freshness passes", () => {
    const authority = makeIdentity();
    const witness = issueTimeWitness({
      authoritySecretKey: authority.signingKey,
      authorityPublicKey: authority.publicKeyBytes,
      nonce: "fresh-nonce-abc",
    });
    const result = verifyTimeWitness(witness, {
      expectedNonce: "fresh-nonce-abc",
      trustedAuthorities: [authority.did],
      maxAgeMs: 60_000,
    });
    expect(result.valid).toBe(true);
  });
});
