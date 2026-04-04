import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  commitGenome,
  createGenome,
} from "../../src/core/genome.js";
import {
  createLineageCertificate,
  verifyLineageCertificate,
  verifyLineageChain,
  effectiveCapabilities,
  hasCapability,
  type HeartLineage,
} from "../../src/heart/lineage.js";

const crypto = getCryptoProvider();

function makeCommitment() {
  const kp = crypto.signing.generateKeyPair();
  const genome = createGenome({
    modelProvider: "test",
    modelId: "test-m",
    modelVersion: "1",
    systemPrompt: "p",
    toolManifest: "[]",
    runtimeId: "r",
  });
  return { kp, commitment: commitGenome(genome, kp) };
}

describe("Lineage certificates", () => {
  it("creates and verifies a valid cert", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
      capabilities: ["tool:search"],
      ttl: 60_000,
    });
    expect(verifyLineageCertificate(cert).valid).toBe(true);
  });

  it("rejects tampered cert", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
      capabilities: ["tool:search"],
    });
    const tampered = { ...cert, capabilities: ["*"] };
    expect(verifyLineageCertificate(tampered).valid).toBe(false);
  });

  it("rejects expired cert", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
      ttl: -1000, // already expired
    });
    const check = verifyLineageCertificate(cert);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("expired");
  });
});

describe("Lineage chain verification", () => {
  it("verifies a two-link chain", () => {
    const root = makeCommitment();
    const mid = makeCommitment();
    const leaf = makeCommitment();

    const cert1 = createLineageCertificate({
      parent: root.commitment,
      parentSigningKey: root.kp.secretKey,
      child: mid.commitment,
      capabilities: ["tool:*"],
    });
    const cert2 = createLineageCertificate({
      parent: mid.commitment,
      parentSigningKey: mid.kp.secretKey,
      child: leaf.commitment,
      capabilities: ["tool:search"],
    });

    const lineage: HeartLineage = {
      did: leaf.commitment.did,
      rootDid: root.commitment.did,
      chain: [cert1, cert2],
    };
    expect(verifyLineageChain(lineage).valid).toBe(true);
  });

  it("rejects a chain where parent doesn't match previous child", () => {
    const root = makeCommitment();
    const mid = makeCommitment();
    const bogus = makeCommitment();
    const leaf = makeCommitment();

    const cert1 = createLineageCertificate({
      parent: root.commitment,
      parentSigningKey: root.kp.secretKey,
      child: mid.commitment,
    });
    const cert2 = createLineageCertificate({
      parent: bogus.commitment, // wrong parent
      parentSigningKey: bogus.kp.secretKey,
      child: leaf.commitment,
    });

    const lineage: HeartLineage = {
      did: leaf.commitment.did,
      rootDid: root.commitment.did,
      chain: [cert1, cert2],
    };
    expect(verifyLineageChain(lineage).valid).toBe(false);
  });
});

describe("Capability resolution", () => {
  it("wildcards match prefixed capabilities", () => {
    expect(hasCapability(["tool:*"], "tool:search")).toBe(true);
    expect(hasCapability(["tool:*"], "data:api")).toBe(false);
    expect(hasCapability(["*"], "anything")).toBe(true);
    expect(hasCapability(["tool:search"], "tool:search")).toBe(true);
    expect(hasCapability(["tool:search"], "tool:other")).toBe(false);
  });

  it("effective capabilities narrow down the chain", () => {
    const root = makeCommitment();
    const mid = makeCommitment();
    const leaf = makeCommitment();

    const cert1 = createLineageCertificate({
      parent: root.commitment,
      parentSigningKey: root.kp.secretKey,
      child: mid.commitment,
      capabilities: ["tool:search", "tool:db", "data:api"],
    });
    const cert2 = createLineageCertificate({
      parent: mid.commitment,
      parentSigningKey: mid.kp.secretKey,
      child: leaf.commitment,
      capabilities: ["tool:search"], // narrowed
    });

    const lineage: HeartLineage = {
      did: leaf.commitment.did,
      rootDid: root.commitment.did,
      chain: [cert1, cert2],
    };
    const caps = effectiveCapabilities(lineage);
    expect(caps).toEqual(["tool:search"]);
  });

  it("empty capabilities at a step means inherit", () => {
    const root = makeCommitment();
    const mid = makeCommitment();
    const leaf = makeCommitment();

    const cert1 = createLineageCertificate({
      parent: root.commitment,
      parentSigningKey: root.kp.secretKey,
      child: mid.commitment,
      capabilities: ["tool:search", "tool:db"],
    });
    const cert2 = createLineageCertificate({
      parent: mid.commitment,
      parentSigningKey: mid.kp.secretKey,
      child: leaf.commitment,
      capabilities: [], // inherit
    });

    const lineage: HeartLineage = {
      did: leaf.commitment.did,
      rootDid: root.commitment.did,
      chain: [cert1, cert2],
    };
    const caps = effectiveCapabilities(lineage);
    expect(caps).toEqual(["tool:search", "tool:db"]);
  });
});
