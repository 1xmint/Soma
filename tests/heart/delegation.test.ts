import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createDelegation,
  attenuateDelegation,
  verifyDelegation,
  verifyDelegationSignature,
  checkCaveats,
} from "../../src/heart/delegation.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

describe("Delegation creation + signature", () => {
  it("creates a verifiable delegation", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const d = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ["tool:search"],
    });
    expect(verifyDelegationSignature(d).valid).toBe(true);
  });

  it("rejects tampered capabilities", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const d = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ["tool:search"],
    });
    const tampered = { ...d, capabilities: ["*"] };
    expect(verifyDelegationSignature(tampered).valid).toBe(false);
  });
});

describe("Caveats", () => {
  function makeDelegation(caveats: Parameters<typeof createDelegation>[0]["caveats"]) {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    return {
      subject,
      d: createDelegation({
        issuerDid: issuer.did,
        issuerPublicKey: issuer.publicKey,
        issuerSigningKey: issuer.kp.secretKey,
        subjectDid: subject.did,
        capabilities: ["tool:search"],
        caveats,
      }),
    };
  }

  it("expires-at: rejects after timestamp", () => {
    const { subject, d } = makeDelegation([{ kind: "expires-at", timestamp: Date.now() - 1000 }]);
    const check = checkCaveats(d, { invokerDid: subject.did, capability: "tool:search" });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("expired");
  });

  it("not-before: rejects before timestamp", () => {
    const { subject, d } = makeDelegation([{ kind: "not-before", timestamp: Date.now() + 60_000 }]);
    const check = checkCaveats(d, { invokerDid: subject.did, capability: "tool:search" });
    expect(check.valid).toBe(false);
  });

  it("audience: requires matching invokerDid", () => {
    const wrongAudience = "did:key:zWRONG";
    const { subject, d } = makeDelegation([{ kind: "audience", did: wrongAudience }]);
    const check = checkCaveats(d, { invokerDid: subject.did, capability: "tool:search" });
    expect(check.valid).toBe(false);
  });

  it("budget: rejects when cumulative spend exceeds cap", () => {
    const { subject, d } = makeDelegation([{ kind: "budget", credits: 100 }]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: "tool:search",
      creditsSpent: 60,
      cumulativeCreditsSpent: 50,
    });
    expect(check.valid).toBe(false);
  });

  it("budget: passes when under cap", () => {
    const { subject, d } = makeDelegation([{ kind: "budget", credits: 100 }]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: "tool:search",
      creditsSpent: 20,
      cumulativeCreditsSpent: 50,
    });
    expect(check.valid).toBe(true);
  });

  it("max-invocations: rejects at limit", () => {
    const { subject, d } = makeDelegation([{ kind: "max-invocations", count: 3 }]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: "tool:search",
      invocationCount: 3,
    });
    expect(check.valid).toBe(false);
  });
});

describe("Delegation attenuation", () => {
  it("attenuates with narrower capabilities", () => {
    const issuer = makeIdentity();
    const mid = makeIdentity();
    const leaf = makeIdentity();

    const parent = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: mid.did,
      capabilities: ["tool:search", "tool:db"],
    });

    const child = attenuateDelegation({
      parent,
      newSubjectDid: leaf.did,
      newSubjectSigningKey: mid.kp.secretKey,
      newSubjectPublicKey: mid.publicKey,
      narrowedCapabilities: ["tool:search"],
      additionalCaveats: [{ kind: "max-invocations", count: 5 }],
    });

    expect(child.capabilities).toEqual(["tool:search"]);
    expect(child.parentId).toBe(parent.id);
    expect(verifyDelegationSignature(child).valid).toBe(true);
  });

  it("rejects attempts to broaden scope", () => {
    const issuer = makeIdentity();
    const mid = makeIdentity();
    const leaf = makeIdentity();

    const parent = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: mid.did,
      capabilities: ["tool:search"],
    });

    expect(() =>
      attenuateDelegation({
        parent,
        newSubjectDid: leaf.did,
        newSubjectSigningKey: mid.kp.secretKey,
        newSubjectPublicKey: mid.publicKey,
        narrowedCapabilities: ["tool:search", "tool:db"], // broader!
      }),
    ).toThrow();
  });
});

describe("Full delegation verification", () => {
  it("enforces subject == invoker", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const other = makeIdentity();
    const d = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ["tool:search"],
    });

    const subjectOk = verifyDelegation(d, { invokerDid: subject.did, capability: "tool:search" });
    expect(subjectOk.valid).toBe(true);

    const otherBad = verifyDelegation(d, { invokerDid: other.did, capability: "tool:search" });
    expect(otherBad.valid).toBe(false);
  });
});
