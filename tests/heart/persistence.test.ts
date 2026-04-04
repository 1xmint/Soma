import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { commitGenome, createGenome } from "../../src/core/genome.js";
import {
  createSomaHeart,
  loadSomaHeart,
} from "../../src/heart/runtime.js";
import type { HeartConfig } from "../../src/heart/runtime.js";

const crypto = getCryptoProvider();

function makeConfig(): HeartConfig {
  const kp = crypto.signing.generateKeyPair();
  const genome = commitGenome(
    createGenome({
      modelProvider: "test",
      modelId: "test-m",
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
    modelApiKey: "sk-secret-abc",
    modelBaseUrl: "https://api.example.com/v1",
    modelId: "gpt-4",
    toolCredentials: { db: "db-secret", search: "search-secret" },
    dataSources: [
      {
        name: "market",
        url: "https://market.example.com",
        headers: { Authorization: "Bearer secret-token" },
      },
    ],
  };
}

describe("Heart persistence", () => {
  it("serializes and reloads preserving identity", () => {
    const heart = createSomaHeart(makeConfig());
    const originalDid = heart.did;
    const originalGenomeHash = heart.genomeCommitment.hash;

    const blob = heart.serialize("correct-horse-battery-staple");
    const reloaded = loadSomaHeart(blob, "correct-horse-battery-staple");

    expect(reloaded.did).toBe(originalDid);
    expect(reloaded.genomeCommitment.hash).toBe(originalGenomeHash);
  });

  it("rejects wrong password", () => {
    const heart = createSomaHeart(makeConfig());
    const blob = heart.serialize("correct-password");

    expect(() => loadSomaHeart(blob, "wrong-password")).toThrow(/wrong password/);
  });

  it("rejects tampered blob", () => {
    const heart = createSomaHeart(makeConfig());
    const blob = heart.serialize("password");
    const parsed = JSON.parse(blob);
    // Flip one byte in ciphertext
    parsed.ciphertextB64 = parsed.ciphertextB64.replace(/./, "Z");
    const tampered = JSON.stringify(parsed);

    expect(() => loadSomaHeart(tampered, "password")).toThrow();
  });

  it("preserves heartbeat chain continuity", () => {
    const heart = createSomaHeart(makeConfig());
    heart.heartbeats.record("session_start", "s1");
    heart.heartbeats.record("query_received", "q1");
    const originalHead = heart.heartbeats.head;
    const originalLength = heart.heartbeats.length;

    const blob = heart.serialize("pw");
    const reloaded = loadSomaHeart(blob, "pw");

    expect(reloaded.heartbeats.length).toBe(originalLength);
    expect(reloaded.heartbeats.head).toBe(originalHead);

    // New records continue from the restored head
    const newBeat = reloaded.heartbeats.record("response_sent", "r1");
    expect(newBeat.previousHash).toBe(originalHead);
    expect(newBeat.sequence).toBe(originalLength);
  });

  it("empty password is rejected", () => {
    const heart = createSomaHeart(makeConfig());
    expect(() => heart.serialize("")).toThrow(/password required/);
  });
});
