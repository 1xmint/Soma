import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  deriveSeed,
  applySeed,
  verifySeedInfluence,
  deriveHmacKey,
  computeTokenHmac,
  verifyTokenHmac,
} from "../../src/heart/seed.js";

const crypto = getCryptoProvider();

describe("HeartSeed — Dynamic Continuous Generation", () => {
  function makeSessionKey(): Uint8Array {
    return crypto.random.randomBytes(32);
  }

  describe("deriveSeed()", () => {
    it("produces a deterministic seed from same inputs", () => {
      const sessionKey = makeSessionKey();
      const seed1 = deriveSeed({ sessionKey, interactionCounter: 0 }, "query-hash-abc");
      const seed2 = deriveSeed({ sessionKey, interactionCounter: 0 }, "query-hash-abc");
      expect(seed1.nonce).toBe(seed2.nonce);
      expect(seed1.behavioralParams.verbosity).toBe(seed2.behavioralParams.verbosity);
      expect(seed1.behavioralParams.structure).toBe(seed2.behavioralParams.structure);
      expect(seed1.behavioralParams.formality).toBe(seed2.behavioralParams.formality);
      expect(seed1.promptModification).toBe(seed2.promptModification);
    });

    it("produces different seeds for different interaction counters", () => {
      const sessionKey = makeSessionKey();
      const seed0 = deriveSeed({ sessionKey, interactionCounter: 0 }, "query-hash");
      const seed1 = deriveSeed({ sessionKey, interactionCounter: 1 }, "query-hash");
      expect(seed0.nonce).not.toBe(seed1.nonce);
    });

    it("produces different seeds for different query hashes", () => {
      const sessionKey = makeSessionKey();
      const seedA = deriveSeed({ sessionKey, interactionCounter: 0 }, "hash-a");
      const seedB = deriveSeed({ sessionKey, interactionCounter: 0 }, "hash-b");
      expect(seedA.nonce).not.toBe(seedB.nonce);
    });

    it("produces different seeds for different session keys", () => {
      const key1 = makeSessionKey();
      const key2 = makeSessionKey();
      const seed1 = deriveSeed({ sessionKey: key1, interactionCounter: 0 }, "hash");
      const seed2 = deriveSeed({ sessionKey: key2, interactionCounter: 0 }, "hash");
      expect(seed1.nonce).not.toBe(seed2.nonce);
    });

    it("behavioral parameters are always in [0, 1] range", () => {
      for (let i = 0; i < 100; i++) {
        const key = crypto.random.randomBytes(32);
        const seed = deriveSeed({ sessionKey: key, interactionCounter: i }, `query-${i}`);
        expect(seed.behavioralParams.verbosity).toBeGreaterThanOrEqual(0);
        expect(seed.behavioralParams.verbosity).toBeLessThanOrEqual(1);
        expect(seed.behavioralParams.structure).toBeGreaterThanOrEqual(0);
        expect(seed.behavioralParams.structure).toBeLessThanOrEqual(1);
        expect(seed.behavioralParams.formality).toBeGreaterThanOrEqual(0);
        expect(seed.behavioralParams.formality).toBeLessThanOrEqual(1);
      }
    });

    it("expected behavioral region bins parameters correctly", () => {
      for (let i = 0; i < 50; i++) {
        const key = crypto.random.randomBytes(32);
        const seed = deriveSeed({ sessionKey: key, interactionCounter: i }, `q-${i}`);
        const { verbosityRange, structureRange, formalityRange } = seed.expectedBehavioralRegion;

        // Ranges should be 0.2 wide (5 bins)
        expect(verbosityRange[1] - verbosityRange[0]).toBeCloseTo(0.2, 5);
        expect(structureRange[1] - structureRange[0]).toBeCloseTo(0.2, 5);
        expect(formalityRange[1] - formalityRange[0]).toBeCloseTo(0.2, 5);

        // Parameter should fall within its range
        expect(seed.behavioralParams.verbosity).toBeGreaterThanOrEqual(verbosityRange[0]);
        expect(seed.behavioralParams.verbosity).toBeLessThan(verbosityRange[1]);
        expect(seed.behavioralParams.structure).toBeGreaterThanOrEqual(structureRange[0]);
        expect(seed.behavioralParams.structure).toBeLessThan(structureRange[1]);
        expect(seed.behavioralParams.formality).toBeGreaterThanOrEqual(formalityRange[0]);
        expect(seed.behavioralParams.formality).toBeLessThan(formalityRange[1]);
      }
    });

    it("covers the full parameter space across many derivations", () => {
      const verbosityBins = new Set<number>();
      const structureBins = new Set<number>();
      const formalityBins = new Set<number>();

      for (let i = 0; i < 500; i++) {
        const key = crypto.random.randomBytes(32);
        const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "q");
        verbosityBins.add(seed.expectedBehavioralRegion.verbosityRange[0]);
        structureBins.add(seed.expectedBehavioralRegion.structureRange[0]);
        formalityBins.add(seed.expectedBehavioralRegion.formalityRange[0]);
      }

      // With 500 random keys and 5 bins, we should hit all 5 bins per dimension
      expect(verbosityBins.size).toBe(5);
      expect(structureBins.size).toBe(5);
      expect(formalityBins.size).toBe(5);
    });

    it("stores the correct interaction counter", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 42 }, "hash");
      expect(seed.interactionCounter).toBe(42);
    });

    it("prompt modification contains session context", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "hash");
      expect(seed.promptModification).toContain("SOMA-");
      expect(seed.promptModification).toContain("Session context:");
    });
  });

  describe("applySeed()", () => {
    it("appends the seed modification to the system prompt", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "hash");
      const result = applySeed("You are a helpful assistant.", seed);
      expect(result).toContain("You are a helpful assistant.");
      expect(result).toContain(seed.promptModification);
    });

    it("preserves the original prompt content", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "hash");
      const original = "Complex system prompt with many instructions.\nMultiple lines.";
      const result = applySeed(original, seed);
      expect(result.startsWith(original)).toBe(true);
    });
  });

  describe("verifySeedInfluence()", () => {
    it("returns per-dimension scores and overall confidence", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "hash");
      const result = verifySeedInfluence("A response with some text.", seed, 10);
      expect(result).toHaveProperty("verified");
      expect(result).toHaveProperty("confidence");
      expect(result).toHaveProperty("details");
      expect(result).toHaveProperty("perDimension");
      expect(result.perDimension).toHaveProperty("verbosity");
      expect(result.perDimension).toHaveProperty("structure");
      expect(result.perDimension).toHaveProperty("formality");
    });

    it("returns reasonable confidence for aligned text", () => {
      const key = makeSessionKey();
      // Find a seed with high formality
      let seed;
      for (let i = 0; i < 200; i++) {
        seed = deriveSeed({ sessionKey: key, interactionCounter: i }, "hash");
        if (seed.behavioralParams.formality > 0.8) break;
      }
      if (!seed || seed.behavioralParams.formality <= 0.8) return;

      const formalText = "Specifically, the implementation architecture requires precise methodology. " +
        "The protocol mechanism configuration parameters are consequently aligned. " +
        "Furthermore, the algorithm implementation precisely addresses technical requirements.";
      const result = verifySeedInfluence(formalText, seed, 30);
      expect(result.perDimension.formality).toBeGreaterThan(0.3);
    });
  });

  describe("Token-Level HMAC Authentication", () => {
    it("deriveHmacKey produces deterministic key from session key", () => {
      const sessionKey = makeSessionKey();
      const key1 = deriveHmacKey(sessionKey);
      const key2 = deriveHmacKey(sessionKey);
      expect(Buffer.from(key1).toString("hex")).toBe(Buffer.from(key2).toString("hex"));
      expect(key1.length).toBe(32);
    });

    it("different session keys produce different HMAC keys", () => {
      const key1 = deriveHmacKey(makeSessionKey());
      const key2 = deriveHmacKey(makeSessionKey());
      expect(Buffer.from(key1).toString("hex")).not.toBe(Buffer.from(key2).toString("hex"));
    });

    it("computeTokenHmac is deterministic", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const h1 = computeTokenHmac(hmacKey, "Hello", 0, 42);
      const h2 = computeTokenHmac(hmacKey, "Hello", 0, 42);
      expect(h1).toBe(h2);
      expect(h1.length).toBe(64); // SHA-256 hex
    });

    it("different tokens produce different HMACs", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const h1 = computeTokenHmac(hmacKey, "Hello", 0, 0);
      const h2 = computeTokenHmac(hmacKey, "World", 0, 0);
      expect(h1).not.toBe(h2);
    });

    it("different sequences produce different HMACs", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const h1 = computeTokenHmac(hmacKey, "Hello", 0, 0);
      const h2 = computeTokenHmac(hmacKey, "Hello", 1, 0);
      expect(h1).not.toBe(h2);
    });

    it("different interaction counters produce different HMACs", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const h1 = computeTokenHmac(hmacKey, "Hello", 0, 0);
      const h2 = computeTokenHmac(hmacKey, "Hello", 0, 1);
      expect(h1).not.toBe(h2);
    });

    it("verifyTokenHmac accepts valid HMAC", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const hmac = computeTokenHmac(hmacKey, "test", 5, 10);
      expect(verifyTokenHmac(hmacKey, "test", 5, 10, hmac)).toBe(true);
    });

    it("verifyTokenHmac rejects wrong token", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const hmac = computeTokenHmac(hmacKey, "real", 0, 0);
      expect(verifyTokenHmac(hmacKey, "fake", 0, 0, hmac)).toBe(false);
    });

    it("verifyTokenHmac rejects wrong key", () => {
      const hmacKey1 = deriveHmacKey(makeSessionKey());
      const hmacKey2 = deriveHmacKey(makeSessionKey());
      const hmac = computeTokenHmac(hmacKey1, "test", 0, 0);
      expect(verifyTokenHmac(hmacKey2, "test", 0, 0, hmac)).toBe(false);
    });

    it("verifyTokenHmac rejects tampered HMAC", () => {
      const hmacKey = deriveHmacKey(makeSessionKey());
      const hmac = computeTokenHmac(hmacKey, "test", 0, 0);
      const tampered = "00" + hmac.slice(2);
      expect(verifyTokenHmac(hmacKey, "test", 0, 0, tampered)).toBe(false);
    });
  });
});
