/**
 * Attack #1 — Stolen delegation used as a bearer token.
 *
 * Scenario:
 *   Alice delegates `tool:db:read` to Bob. Eve intercepts the delegation JSON
 *   in transit (leaky transport, misconfigured relay, whatever). Without PoP,
 *   anyone holding the blob can present it — Eve shows up at the verifier
 *   claiming to be Bob.
 *
 * Defense: proof-of-possession. Verifier issues a fresh challenge; only the
 * holder of Bob's private key can sign it. Eve has the delegation but not
 * the key, so her forged proof fails.
 *
 * Primitives composed:
 *   delegation · proof-of-possession
 */

import { describe, it, expect } from "vitest";
import {
  createDelegation,
  verifyDelegationSignature,
} from "../../src/heart/delegation.js";
import {
  issueChallenge,
  proveChallenge,
  verifyProof,
} from "../../src/heart/proof-of-possession.js";
import { makeIdentity, failedWith } from "./_harness.js";

describe("Attack #1: stolen bearer delegation", () => {
  it("PoP rejects a holder who doesn't possess the subject key", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const eve = makeIdentity();
    const verifier = makeIdentity();

    // Alice delegates to Bob.
    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:db:read"],
    });
    // Delegation itself is well-formed.
    expect(verifyDelegationSignature(delegation).valid).toBe(true);

    // Eve steals the JSON. She presents it to the verifier.
    // Verifier issues a challenge bound to the delegation ID.
    void verifier; // verifier is just context — it issues the challenge
    const challenge = issueChallenge(delegation);

    // Eve tries to answer the challenge with HER OWN key (not Bob's).
    const eveForgedProof = proveChallenge(challenge, eve.signingKey);
    const eveResult = verifyProof(challenge, eveForgedProof, delegation);
    expect(eveResult.valid).toBe(false);
    expect(failedWith(eveResult, "not signed by subject")).toBe(true);

    // But the legitimate holder (Bob) can answer.
    const bobProof = proveChallenge(challenge, bob.signingKey);
    expect(verifyProof(challenge, bobProof, delegation).valid).toBe(true);
  });

  it("PoP rejects a replay of a prior proof under a new challenge", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:weather"],
    });

    // Bob answers an old challenge legitimately.
    const oldChallenge = issueChallenge(delegation);
    const oldProof = proveChallenge(oldChallenge, bob.signingKey);
    expect(verifyProof(oldChallenge, oldProof, delegation).valid).toBe(true);

    // Eve captures Bob's old proof and tries to replay it against a new
    // challenge (with a fresh nonce).
    const newChallenge = issueChallenge(delegation);
    expect(newChallenge.nonceB64).not.toBe(oldChallenge.nonceB64);
    const replayResult = verifyProof(newChallenge, oldProof, delegation);
    expect(replayResult.valid).toBe(false);
    expect(failedWith(replayResult, "nonce")).toBe(true);
  });

  it("PoP rejects a proof crafted for a different delegation", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegationA = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:a"],
    });
    const delegationB = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:b"],
    });

    // Bob answers a challenge for delegationA.
    const challengeA = issueChallenge(delegationA);
    const proofForA = proveChallenge(challengeA, bob.signingKey);

    // Eve tries to use Bob's proof for delegationA as a proof for delegationB
    // (same subject — maybe she thinks the key is the only thing that matters).
    const challengeB = issueChallenge(delegationB);
    const swapped = { ...proofForA, delegationId: delegationB.id };
    // She has to rewrite the delegationId on the proof to pass the first check,
    // but then the signature no longer matches.
    const result = verifyProof(challengeB, swapped, delegationB);
    expect(result.valid).toBe(false);
  });
});
