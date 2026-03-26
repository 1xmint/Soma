import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";
import {
  deriveSeed,
  applySeed,
  verifySeedInfluence,
  getSeedModifications,
} from "../../src/heart/seed.js";

describe("HeartSeed", () => {
  function makeSessionKey(): Uint8Array {
    return nacl.randomBytes(32);
  }

  describe("deriveSeed()", () => {
    it("produces a deterministic seed from same inputs", () => {
      const sessionKey = makeSessionKey();
      const seed1 = deriveSeed({ sessionKey, interactionCounter: 0 }, "query-hash-abc");
      const seed2 = deriveSeed({ sessionKey, interactionCounter: 0 }, "query-hash-abc");
      expect(seed1.nonce).toBe(seed2.nonce);
      expect(seed1.modificationId).toBe(seed2.modificationId);
      expect(seed1.sessionContext).toBe(seed2.sessionContext);
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

    it("always selects a valid modification", () => {
      const mods = getSeedModifications();
      const modIds = new Set(mods.map((m) => m.id));

      for (let i = 0; i < 50; i++) {
        const sessionKey = nacl.randomBytes(32);
        const seed = deriveSeed({ sessionKey, interactionCounter: i }, `query-${i}`);
        expect(modIds.has(seed.modificationId)).toBe(true);
        expect(seed.promptModification).toContain("SOMA-");
        expect(seed.sessionContext).toMatch(/^SOMA-[0-9a-f]{8}$/);
      }
    });

    it("covers multiple modification types across many derivations", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 200; i++) {
        const key = nacl.randomBytes(32);
        const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "q");
        seen.add(seed.modificationId);
      }
      // With 8 modifications and 200 random keys, we should hit most of them
      expect(seen.size).toBeGreaterThanOrEqual(4);
    });

    it("stores the correct interaction counter", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 42 }, "hash");
      expect(seed.interactionCounter).toBe(42);
    });
  });

  describe("applySeed()", () => {
    it("appends the seed modification to the system prompt", () => {
      const key = makeSessionKey();
      const seed = deriveSeed({ sessionKey: key, interactionCounter: 0 }, "hash");
      const result = applySeed("You are a helpful assistant.", seed);
      expect(result).toContain("You are a helpful assistant.");
      expect(result).toContain(seed.promptModification);
      expect(result).toContain("SOMA-");
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
    it("verifies shorter_output when response is shorter than baseline", () => {
      const key = makeSessionKey();
      // Find a seed that produces shorter_output
      let seed;
      for (let i = 0; i < 100; i++) {
        seed = deriveSeed({ sessionKey: key, interactionCounter: i }, "hash");
        if (seed.expectedInfluence === "shorter_output") break;
      }
      if (!seed || seed.expectedInfluence !== "shorter_output") return;

      const result = verifySeedInfluence("Short response.", seed, 100);
      expect(result.verified).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it("verifies example_presence when examples are present", () => {
      const key = makeSessionKey();
      let seed;
      for (let i = 0; i < 100; i++) {
        seed = deriveSeed({ sessionKey: key, interactionCounter: i }, "hash");
        if (seed.expectedInfluence === "example_presence") break;
      }
      if (!seed || seed.expectedInfluence !== "example_presence") return;

      const withExamples = "Here is the concept. For example, consider a database that stores user data.";
      const result = verifySeedInfluence(withExamples, seed, 15);
      expect(result.verified).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it("verifies formatted_output when markdown is present", () => {
      const key = makeSessionKey();
      let seed;
      for (let i = 0; i < 100; i++) {
        seed = deriveSeed({ sessionKey: key, interactionCounter: i }, "hash");
        if (seed.expectedInfluence === "formatted_output") break;
      }
      if (!seed || seed.expectedInfluence !== "formatted_output") return;

      const formatted = "# Header\n\n- Point 1\n- Point 2\n\n**Bold text** here.";
      const result = verifySeedInfluence(formatted, seed, 10);
      expect(result.verified).toBe(true);
    });

    it("returns low confidence when influence is not observed", () => {
      const key = makeSessionKey();
      let seed;
      for (let i = 0; i < 100; i++) {
        seed = deriveSeed({ sessionKey: key, interactionCounter: i }, "hash");
        if (seed.expectedInfluence === "example_presence") break;
      }
      if (!seed || seed.expectedInfluence !== "example_presence") return;

      const noExamples = "This is a plain response without any illustrations.";
      const result = verifySeedInfluence(noExamples, seed, 10);
      expect(result.confidence).toBeLessThanOrEqual(0.5);
    });
  });

  describe("getSeedModifications()", () => {
    it("returns all 8 modifications", () => {
      const mods = getSeedModifications();
      expect(mods.length).toBe(8);
    });

    it("each modification has id, prompt, and expectedInfluence", () => {
      for (const mod of getSeedModifications()) {
        expect(mod.id).toBeTruthy();
        expect(mod.prompt).toBeTruthy();
        expect(mod.expectedInfluence).toBeTruthy();
      }
    });
  });
});
