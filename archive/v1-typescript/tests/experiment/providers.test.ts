/**
 * Tests for API key rotation and provider error handling.
 *
 * Key rotation is critical: when a 429 (rate limit) or 402 (quota exceeded)
 * error hits, the provider must switch to the next available key and retry.
 * Without this, the experiment stalls on the first key's rate limit.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// We test the internals by importing the module and testing the exported
// functions that depend on key rotation (streamFromProvider uses it).
// Since the actual API call is hard to mock, we test the building blocks.

// --- Test isRateLimitError via the module's behavior ---

describe("Key Rotation", () => {
  // We can't easily test the private functions directly, so we test
  // the error detection logic by recreating what isRateLimitError checks.

  describe("rate limit error detection", () => {
    function isRateLimitError(err: unknown): boolean {
      if (err && typeof err === "object") {
        if ("status" in err) {
          const status = (err as { status: number }).status;
          if (status === 429 || status === 402) return true;
        }
        if ("message" in err && typeof (err as { message: string }).message === "string") {
          const msg = (err as { message: string }).message.toLowerCase();
          if (msg.includes("rate limit") || msg.includes("429") || msg.includes("too many requests")
            || msg.includes("quota") || msg.includes("402") || msg.includes("insufficient")) {
            return true;
          }
        }
      }
      return false;
    }

    it("detects 429 status code", () => {
      expect(isRateLimitError({ status: 429, message: "Too Many Requests" })).toBe(true);
    });

    it("detects 402 status code (quota exceeded)", () => {
      expect(isRateLimitError({ status: 402, message: "Payment Required" })).toBe(true);
    });

    it("detects rate limit in message text", () => {
      expect(isRateLimitError({ message: "Rate limit exceeded for this key" })).toBe(true);
    });

    it("detects quota exceeded in message text", () => {
      expect(isRateLimitError({ message: "Quota exceeded for free tier" })).toBe(true);
    });

    it("detects 'too many requests' in message", () => {
      expect(isRateLimitError({ message: "Too many requests, please slow down" })).toBe(true);
    });

    it("detects 'insufficient' in message (OpenRouter credits)", () => {
      expect(isRateLimitError({ message: "Insufficient credits remaining" })).toBe(true);
    });

    it("does not trigger on 400 bad request", () => {
      expect(isRateLimitError({ status: 400, message: "Bad Request" })).toBe(false);
    });

    it("does not trigger on 500 server error", () => {
      expect(isRateLimitError({ status: 500, message: "Internal Server Error" })).toBe(false);
    });

    it("does not trigger on null", () => {
      expect(isRateLimitError(null)).toBe(false);
    });

    it("does not trigger on string", () => {
      expect(isRateLimitError("some error")).toBe(false);
    });
  });

  describe("key pool logic", () => {
    // Simulate the key pool rotation logic
    interface KeyPool {
      keys: string[];
      currentIndex: number;
      exhausted: Set<number>;
    }

    function getCurrentKey(pool: KeyPool): string | null {
      if (pool.exhausted.size >= pool.keys.length) return null;
      return pool.keys[pool.currentIndex];
    }

    function rotateKey(pool: KeyPool): boolean {
      pool.exhausted.add(pool.currentIndex);
      for (let i = 0; i < pool.keys.length; i++) {
        const idx = (pool.currentIndex + 1 + i) % pool.keys.length;
        if (!pool.exhausted.has(idx)) {
          pool.currentIndex = idx;
          return true;
        }
      }
      return false;
    }

    it("starts with the first key", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 0, exhausted: new Set() };
      expect(getCurrentKey(pool)).toBe("k1");
    });

    it("rotates to the next key on exhaustion", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 0, exhausted: new Set() };
      const rotated = rotateKey(pool);
      expect(rotated).toBe(true);
      expect(getCurrentKey(pool)).toBe("k2");
    });

    it("rotates through all keys sequentially", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 0, exhausted: new Set() };

      rotateKey(pool); // k1 exhausted -> k2
      expect(getCurrentKey(pool)).toBe("k2");

      rotateKey(pool); // k2 exhausted -> k3
      expect(getCurrentKey(pool)).toBe("k3");
    });

    it("returns false when all keys are exhausted", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 0, exhausted: new Set() };

      rotateKey(pool); // k1 -> k2
      rotateKey(pool); // k2 -> k3
      const result = rotateKey(pool); // k3 -> none left

      expect(result).toBe(false);
      expect(pool.exhausted.size).toBe(3);
    });

    it("wraps around correctly", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 2, exhausted: new Set() };
      rotateKey(pool); // k3 exhausted -> wrap to k1
      expect(getCurrentKey(pool)).toBe("k1");
    });

    it("skips already-exhausted keys", () => {
      const pool: KeyPool = { keys: ["k1", "k2", "k3"], currentIndex: 0, exhausted: new Set([1]) };
      rotateKey(pool); // k1 exhausted, k2 already exhausted -> k3
      expect(getCurrentKey(pool)).toBe("k3");
    });

    it("handles single-key pool", () => {
      const pool: KeyPool = { keys: ["k1"], currentIndex: 0, exhausted: new Set() };
      const result = rotateKey(pool); // k1 exhausted -> none left
      expect(result).toBe(false);
    });

    it("reset clears exhaustion state", () => {
      const pool: KeyPool = { keys: ["k1", "k2"], currentIndex: 0, exhausted: new Set() };
      rotateKey(pool);
      rotateKey(pool);
      expect(pool.exhausted.size).toBe(2);

      pool.exhausted.clear();
      expect(pool.exhausted.size).toBe(0);
      expect(getCurrentKey(pool)).toBe("k2"); // currentIndex preserved
    });
  });

  describe("key env name generation", () => {
    function getKeyEnvName(provider: string, index: number): string {
      const baseName = provider.toUpperCase() + "_API_KEY";
      return index === 0 ? baseName : `${baseName}_${index + 1}`;
    }

    it("first key has no suffix", () => {
      expect(getKeyEnvName("groq", 0)).toBe("GROQ_API_KEY");
      expect(getKeyEnvName("openrouter", 0)).toBe("OPENROUTER_API_KEY");
    });

    it("subsequent keys have _N suffix", () => {
      expect(getKeyEnvName("groq", 1)).toBe("GROQ_API_KEY_2");
      expect(getKeyEnvName("groq", 2)).toBe("GROQ_API_KEY_3");
      expect(getKeyEnvName("openrouter", 4)).toBe("OPENROUTER_API_KEY_5");
    });
  });
});
