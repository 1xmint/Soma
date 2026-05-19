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
import type {
  HistoricalKeyLookup,
  HistoricalKeyLookupResult,
} from "../../src/heart/historical-key-lookup.js";

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

// ─── HistoricalKeyLookup integration ───────────────────────────────────────

const mockLookup = (returnValue: HistoricalKeyLookupResult): HistoricalKeyLookup => ({
  resolve(_publicKey: Uint8Array, _timestamp: number) {
    return returnValue;
  },
});

describe("HistoricalKeyLookup integration", () => {
  it("verifyLineageCertificate with lookup — valid key at issuedAt", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
    });
    const lookup = mockLookup({
      found: true,
      effectiveFrom: cert.issuedAt - 1000,
      effectiveUntil: null,
    });
    const check = verifyLineageCertificate(cert, undefined, lookup);
    expect(check.valid).toBe(true);
  });

  it("verifyLineageCertificate with lookup — rotated-out key", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
    });
    const lookup = mockLookup({
      found: true,
      effectiveFrom: cert.issuedAt - 10000,
      effectiveUntil: cert.issuedAt - 5000,
    });
    const check = verifyLineageCertificate(cert, undefined, lookup);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("rotated out");
  });

  it("verifyLineageCertificate with lookup — key not found", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
    });
    const lookup = mockLookup({
      found: false,
      reason: "credential-not-in-chain",
    });
    const check = verifyLineageCertificate(cert, undefined, lookup);
    expect(check.valid).toBe(false);
  });

  it("verifyLineageCertificate with lookup — resolve throws", () => {
    const parent = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: parent.commitment,
      parentSigningKey: parent.kp.secretKey,
      child: child.commitment,
    });
    const lookup: HistoricalKeyLookup = {
      resolve() {
        throw new Error("lookup explosion");
      },
    };
    const check = verifyLineageCertificate(cert, undefined, lookup);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toBe("key lookup failed");
  });

  it("verifyLineageChain with lookup — valid chain", () => {
    const root = makeCommitment();
    const child = makeCommitment();
    const cert = createLineageCertificate({
      parent: root.commitment,
      parentSigningKey: root.kp.secretKey,
      child: child.commitment,
    });
    const lineage: HeartLineage = {
      did: child.commitment.did,
      rootDid: root.commitment.did,
      chain: [cert],
    };
    const lookup = mockLookup({
      found: true,
      effectiveFrom: cert.issuedAt - 1000,
      effectiveUntil: null,
    });
    const check = verifyLineageChain(lineage, undefined, lookup);
    expect(check.valid).toBe(true);
  });

  it("verifyLineageChain with lookup — one cert has rotated key", () => {
    const a = makeCommitment();
    const b = makeCommitment();
    const c = makeCommitment();

    const cert1 = createLineageCertificate({
      parent: a.commitment,
      parentSigningKey: a.kp.secretKey,
      child: b.commitment,
    });
    const cert2 = createLineageCertificate({
      parent: b.commitment,
      parentSigningKey: b.kp.secretKey,
      child: c.commitment,
    });

    const lineage: HeartLineage = {
      did: c.commitment.did,
      rootDid: a.commitment.did,
      chain: [cert1, cert2],
    };

    const lookup: HistoricalKeyLookup = {
      resolve(_publicKey: Uint8Array, _timestamp: number) {
        const pubKeyBase64 = crypto.encoding.encodeBase64(_publicKey);
        if (pubKeyBase64 === a.commitment.publicKey) {
          return {
            found: true,
            effectiveFrom: cert1.issuedAt - 1000,
            effectiveUntil: null,
          };
        }
        return {
          found: true,
          effectiveFrom: cert2.issuedAt - 10000,
          effectiveUntil: cert2.issuedAt - 5000,
        };
      },
    };

    const check = verifyLineageChain(lineage, undefined, lookup);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("chain[1]");
  });
});
