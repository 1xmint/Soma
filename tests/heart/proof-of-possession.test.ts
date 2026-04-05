import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid, didToPublicKey } from "../../src/core/genome.js";
import { createDelegation } from "../../src/heart/delegation.js";
import {
  issueChallenge,
  proveChallenge,
  verifyProof,
} from "../../src/heart/proof-of-possession.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function makeDelegation(subjectDid: string) {
  const issuer = makeIdentity();
  return createDelegation({
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKey,
    issuerSigningKey: issuer.kp.secretKey,
    subjectDid,
    capabilities: ["tool:search"],
  });
}

describe("Proof-of-possession (audit limit #7)", () => {
  it("holder proves possession, verifier accepts", () => {
    const subject = makeIdentity();
    const d = makeDelegation(subject.did);

    const challenge = issueChallenge(d);
    const proof = proveChallenge(challenge, subject.kp.secretKey);
    const result = verifyProof(challenge, proof, d);

    expect(result.valid).toBe(true);
  });

  it("rejects proof signed by a different key (stolen token)", () => {
    const realHolder = makeIdentity();
    const thief = makeIdentity();
    const d = makeDelegation(realHolder.did);

    const challenge = issueChallenge(d);
    // Thief has the delegation bytes but not realHolder's key
    const fraudulentProof = proveChallenge(challenge, thief.kp.secretKey);
    const result = verifyProof(challenge, fraudulentProof, d);

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("invalid signature");
  });

  it("rejects replay: proof valid for challenge A cannot be used for challenge B", () => {
    const subject = makeIdentity();
    const d = makeDelegation(subject.did);

    const challengeA = issueChallenge(d);
    const proofA = proveChallenge(challengeA, subject.kp.secretKey);

    // Attacker captures proofA, tries to use it against a fresh challenge
    const challengeB = issueChallenge(d);
    // Verifier checks proofA against challengeB — nonce mismatch fails
    const result = verifyProof(challengeB, proofA, d);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("nonce mismatch");
  });

  it("rejects proof targeting a different delegation id", () => {
    const subject = makeIdentity();
    const dA = makeDelegation(subject.did);
    const dB = makeDelegation(subject.did);

    const challenge = issueChallenge(dA);
    // Subject signs proof for dA — attacker tries to use it against dB
    const proof = proveChallenge(challenge, subject.kp.secretKey);
    const result = verifyProof(challenge, proof, dB);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("delegationId mismatch");
  });

  it("challenge and proof nonces echo correctly", () => {
    const subject = makeIdentity();
    const d = makeDelegation(subject.did);
    const challenge = issueChallenge(d);
    const proof = proveChallenge(challenge, subject.kp.secretKey);
    expect(proof.nonceB64).toBe(challenge.nonceB64);
    expect(proof.delegationId).toBe(d.id);
  });

  it("didToPublicKey round-trips with publicKeyToDid", () => {
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const decoded = didToPublicKey(did);
    expect(decoded.length).toBe(kp.publicKey.length);
    for (let i = 0; i < kp.publicKey.length; i++) {
      expect(decoded[i]).toBe(kp.publicKey[i]);
    }
  });

  it("didToPublicKey rejects malformed DIDs", () => {
    expect(() => didToPublicKey("did:web:example.com")).toThrow(/did:key/);
    expect(() => didToPublicKey("did:key:y123")).toThrow(/did:key/);
  });
});
