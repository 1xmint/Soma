import { describe, it, expect } from "vitest";
import { pbkdf2Sync } from "node:crypto";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { commitGenome, createGenome } from "../../src/core/genome.js";
import {
  createSomaHeart,
  loadSomaHeart,
} from "../../src/heart/runtime.js";
import type { HeartConfig } from "../../src/heart/runtime.js";
import { loadHeartState, serializeHeart } from "../../src/heart/persistence.js";
import type { HeartState } from "../../src/heart/persistence.js";

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
    // Flip first byte in ciphertext (guaranteed to change)
    const first = parsed.ciphertextB64[0];
    parsed.ciphertextB64 = (first === "Z" ? "A" : "Z") + parsed.ciphertextB64.slice(1);
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

describe("Heart persistence — KDF migration (audit limit #5)", () => {
  function makeState(): HeartState {
    const provider = getCryptoProvider();
    const kp = provider.signing.generateKeyPair();
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
      version: 1,
      genome,
      signingKey: {
        publicKeyB64: provider.encoding.encodeBase64(kp.publicKey),
        secretKeyB64: provider.encoding.encodeBase64(kp.secretKey),
      },
      modelId: "m",
      modelBaseUrl: "u",
      dataSources: [],
      credentials: [],
      heartbeats: [],
      revocations: [],
      savedAt: Date.now(),
    };
  }

  it("new writes use scrypt (memory-hard) by default", () => {
    const heart = createSomaHeart(makeConfig());
    const blob = heart.serialize("pw");
    const parsed = JSON.parse(blob);
    expect(parsed.kdf).toBe("scrypt");
    expect(parsed.N).toBeGreaterThanOrEqual(32768);
    expect(parsed.r).toBe(8);
    expect(parsed.p).toBeGreaterThanOrEqual(1);
    // No PBKDF2 fields on new writes
    expect(parsed.iterations).toBeUndefined();
  });

  it("accepts tuned scrypt parameters (lower N for test speed)", () => {
    const heart = createSomaHeart(makeConfig());
    const blob = heart.serialize("pw", { scrypt: { N: 16384, r: 8, p: 1 } });
    const parsed = JSON.parse(blob);
    expect(parsed.kdf).toBe("scrypt");
    expect(parsed.N).toBe(16384);
    const reloaded = loadSomaHeart(blob, "pw");
    expect(reloaded.did).toBe(heart.did);
  });

  it("still decrypts legacy PBKDF2 blobs (backward compat)", () => {
    const provider = getCryptoProvider();
    const state = makeState();
    const password = "legacy-password";
    const iterations = 210_000;
    const salt = provider.random.randomBytes(16);
    const key = new Uint8Array(
      pbkdf2Sync(password, Buffer.from(salt), iterations, 32, "sha256"),
    );
    const nonce = provider.random.randomBytes(provider.encryption.nonceLength);
    const plaintext = provider.encoding.decodeUTF8(JSON.stringify(state));
    const ciphertext = provider.encryption.encrypt(plaintext, nonce, key);
    key.fill(0);
    const legacyBlob = JSON.stringify({
      v: 1,
      kdf: "pbkdf2-sha256",
      iterations,
      saltB64: provider.encoding.encodeBase64(salt),
      nonceB64: provider.encoding.encodeBase64(nonce),
      ciphertextB64: provider.encoding.encodeBase64(ciphertext),
      alg: provider.encryption.algorithmId,
    });
    const reloaded = loadHeartState(legacyBlob, password);
    expect(reloaded.genome.hash).toBe(state.genome.hash);
    expect(reloaded.version).toBe(1);
    // Wrong password fails on legacy blobs too
    expect(() => loadHeartState(legacyBlob, "wrong")).toThrow(/wrong password/);
  });

  it("rejects blobs with unknown KDF type", () => {
    const heart = createSomaHeart(makeConfig());
    const blob = heart.serialize("pw");
    const parsed = JSON.parse(blob);
    parsed.kdf = "md5-lol";
    expect(() => loadHeartState(JSON.stringify(parsed), "pw")).toThrow(
      /unsupported KDF/,
    );
  });

  it("scrypt roundtrip preserves state via low-level API", () => {
    const state = makeState();
    const blob = serializeHeart(state, "pw", { scrypt: { N: 16384, r: 8, p: 1 } });
    const reloaded = loadHeartState(blob, "pw");
    expect(reloaded.genome.hash).toBe(state.genome.hash);
    expect(reloaded.modelId).toBe(state.modelId);
  });
});
