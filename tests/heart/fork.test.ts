import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { commitGenome, createGenome } from "../../src/core/genome.js";
import {
  createSomaHeart,
  type HeartConfig,
} from "../../src/heart/runtime.js";
import { verifyLineageChain } from "../../src/heart/lineage.js";

const crypto = getCryptoProvider();

function makeParentConfig(): HeartConfig {
  const kp = crypto.signing.generateKeyPair();
  const genome = commitGenome(
    createGenome({
      modelProvider: "test",
      modelId: "m",
      modelVersion: "1",
      systemPrompt: "p",
      toolManifest: "[]",
      runtimeId: "r",
    }),
    kp,
  );
  return {
    genome,
    signingKeyPair: kp,
    modelApiKey: "k",
    modelBaseUrl: "https://x",
    modelId: "m",
  };
}

describe("heart.fork()", () => {
  it("produces a valid lineage chain from root", () => {
    const parent = createSomaHeart(makeParentConfig());
    const { childGenome, lineageCertificate, childLineage } = parent.fork({
      systemPrompt: "child prompt",
      toolManifest: "[]",
      capabilities: ["tool:search"],
      ttl: 60_000,
    });

    expect(childGenome.genome.parentHash).toBe(parent.genomeCommitment.hash);
    expect(lineageCertificate.parentDid).toBe(parent.did);
    expect(lineageCertificate.childDid).toBe(childGenome.did);
    expect(childLineage.rootDid).toBe(parent.did);
    expect(childLineage.chain).toHaveLength(1);
    expect(verifyLineageChain(childLineage).valid).toBe(true);
  });

  it("child heart can be constructed with its lineage and enforces caps", () => {
    const parent = createSomaHeart(makeParentConfig());
    const { childKeyPair, childGenome, childLineage } = parent.fork({
      systemPrompt: "child",
      toolManifest: "[]",
      capabilities: ["tool:search"],
    });

    const child = createSomaHeart({
      genome: childGenome,
      signingKeyPair: childKeyPair,
      modelApiKey: "child-key",
      modelBaseUrl: "https://x",
      modelId: "m",
      toolCredentials: { search: "s", db: "d" },
      lineage: childLineage,
    });

    expect(child.can("tool:search")).toBe(true);
    expect(child.can("tool:db")).toBe(false); // not granted

    // callTool should throw for ungranted capability
    return expect(
      child.callTool("db", {}, async () => "ok"),
    ).rejects.toThrow(/capability "tool:db"/);
  });

  it("grandchild lineage extends chain correctly", () => {
    const root = createSomaHeart(makeParentConfig());
    const { childKeyPair, childGenome, childLineage } = root.fork({
      systemPrompt: "mid",
      toolManifest: "[]",
      capabilities: ["tool:*"],
    });
    const mid = createSomaHeart({
      genome: childGenome,
      signingKeyPair: childKeyPair,
      modelApiKey: "k",
      modelBaseUrl: "https://x",
      modelId: "m",
      lineage: childLineage,
    });

    const grand = mid.fork({
      systemPrompt: "grand",
      toolManifest: "[]",
      capabilities: ["tool:search"],
    });

    expect(grand.childLineage.rootDid).toBe(root.did);
    expect(grand.childLineage.chain).toHaveLength(2);
    expect(verifyLineageChain(grand.childLineage).valid).toBe(true);
  });

  it("fork refuses to grant capabilities the parent lacks", () => {
    const root = createSomaHeart(makeParentConfig());
    const { childKeyPair, childGenome, childLineage } = root.fork({
      systemPrompt: "mid",
      toolManifest: "[]",
      capabilities: ["tool:search"],
    });
    const mid = createSomaHeart({
      genome: childGenome,
      signingKeyPair: childKeyPair,
      modelApiKey: "k",
      modelBaseUrl: "https://x",
      modelId: "m",
      lineage: childLineage,
    });

    expect(() =>
      mid.fork({
        systemPrompt: "grand",
        toolManifest: "[]",
        capabilities: ["tool:db"], // mid only has tool:search
      }),
    ).toThrow(/not granted to this heart/);
  });
});

describe("heart.delegate() and heart.revoke()", () => {
  it("issues and revokes a delegation", () => {
    const heart = createSomaHeart(makeParentConfig());
    const subject = "did:key:zSUBJECT";

    const d = heart.delegate({
      subjectDid: subject,
      capabilities: ["tool:search"],
    });
    expect(d.issuerDid).toBe(heart.did);

    expect(heart.isRevoked(d.id)).toBe(false);
    const rev = heart.revoke({
      targetId: d.id,
      targetKind: "delegation",
      reason: "rotated",
    });
    expect(rev.targetId).toBe(d.id);
    expect(heart.isRevoked(d.id)).toBe(true);
  });
});
