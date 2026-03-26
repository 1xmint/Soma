import { describe, it, expect } from "vitest";
import {
  fromStreamingTrace,
  toStreamingTrace,
  computeIntervals,
  inferChunkBoundaries,
  computeChunkSizes,
  detectBursts,
  computeStreamStats,
  type TokenStreamCapture,
  type TokenLogprob,
} from "../../src/sensorium/stream-capture.js";
import type { StreamingTrace } from "../../src/experiment/signals.js";

// --- Helpers ---

function makeTrace(overrides?: Partial<StreamingTrace>): StreamingTrace {
  return {
    tokens: ["Hello", " world", "!", " How", " are", " you", "?"],
    tokenTimestamps: [100, 105, 106, 150, 155, 156, 200],
    startTime: 50,
    firstTokenTime: 100,
    endTime: 210,
    ...overrides,
  };
}

describe("Token Stream Capture", () => {
  describe("computeIntervals", () => {
    it("computes inter-token intervals from timestamps", () => {
      const intervals = computeIntervals([100, 105, 106, 150, 155]);
      expect(intervals).toEqual([5, 1, 44, 5]);
    });

    it("returns empty for single timestamp", () => {
      expect(computeIntervals([100])).toEqual([]);
    });

    it("returns empty for no timestamps", () => {
      expect(computeIntervals([])).toEqual([]);
    });
  });

  describe("inferChunkBoundaries", () => {
    it("detects chunk boundaries from timestamp gaps", () => {
      const tokens = ["a", "b", "c", "d", "e"];
      const timestamps = [100, 100.2, 100.3, 105, 105.1];
      const boundaries = inferChunkBoundaries(tokens, timestamps);
      // Token 0 starts chunk 1, token 3 starts chunk 2 (gap > 0.5ms)
      expect(boundaries).toEqual([0, 3]);
    });

    it("single chunk when all tokens arrive together", () => {
      const tokens = ["a", "b", "c"];
      const timestamps = [100, 100.1, 100.2];
      const boundaries = inferChunkBoundaries(tokens, timestamps);
      expect(boundaries).toEqual([0]); // all in one chunk
    });

    it("every token is its own chunk when well-spaced", () => {
      const tokens = ["a", "b", "c"];
      const timestamps = [100, 110, 120];
      const boundaries = inferChunkBoundaries(tokens, timestamps);
      expect(boundaries).toEqual([0, 1, 2]);
    });

    it("returns empty for no tokens", () => {
      expect(inferChunkBoundaries([], [])).toEqual([]);
    });
  });

  describe("computeChunkSizes", () => {
    it("computes sizes from boundaries", () => {
      const sizes = computeChunkSizes([0, 3, 5], 7);
      expect(sizes).toEqual([3, 2, 2]);
    });

    it("single chunk", () => {
      const sizes = computeChunkSizes([0], 5);
      expect(sizes).toEqual([5]);
    });
  });

  describe("detectBursts", () => {
    it("detects bursts below threshold", () => {
      // Mean = (5 + 1 + 44 + 5 + 1 + 44) / 6 ≈ 16.67
      // Threshold = 16.67 * 0.5 ≈ 8.33
      // Burst: indices where interval <= 8.33
      const intervals = [5, 1, 44, 5, 1, 44];
      const bursts = detectBursts(intervals);
      expect(bursts.length).toBe(2);
      expect(bursts[0].startIndex).toBe(0);
      expect(bursts[0].tokenCount).toBe(3); // intervals 0,1 → 3 tokens
      expect(bursts[1].startIndex).toBe(3);
    });

    it("returns empty for uniform intervals", () => {
      // All intervals equal → all below threshold (mean * 0.5)
      // Wait, if all equal, threshold = mean * 0.5 = 50, all intervals = 100
      // None below threshold
      const intervals = [100, 100, 100, 100];
      const bursts = detectBursts(intervals);
      expect(bursts.length).toBe(0);
    });

    it("single continuous burst", () => {
      // All very fast except one big pause
      const intervals = [1, 1, 1, 1, 100];
      // Mean = (1+1+1+1+100)/5 = 20.8, threshold = 10.4
      const bursts = detectBursts(intervals);
      expect(bursts.length).toBe(1);
      expect(bursts[0].tokenCount).toBe(5); // 4 intervals + 1
    });

    it("returns empty for empty intervals", () => {
      expect(detectBursts([])).toEqual([]);
    });
  });

  describe("fromStreamingTrace", () => {
    it("converts a StreamingTrace to TokenStreamCapture", () => {
      const trace = makeTrace();
      const capture = fromStreamingTrace(trace);

      expect(capture.tokens).toEqual(trace.tokens);
      expect(capture.timestamps).toEqual(trace.tokenTimestamps);
      expect(capture.startTime).toBe(trace.startTime);
      expect(capture.firstTokenTime).toBe(trace.firstTokenTime);
      expect(capture.endTime).toBe(trace.endTime);
      expect(capture.interTokenIntervals.length).toBe(trace.tokens.length - 1);
      expect(capture.chunkBoundaries.length).toBeGreaterThan(0);
      expect(capture.burstPattern).toBeDefined();
      expect(capture.logprobs).toBeNull();
      expect(capture.seedApplied).toBe("");
    });

    it("includes logprobs when provided", () => {
      const trace = makeTrace();
      const logprobs: TokenLogprob[] = [
        { token: "Hello", logprob: -0.5, topAlternatives: [{ token: "Hi", logprob: -1.2 }] },
      ];
      const capture = fromStreamingTrace(trace, logprobs);
      expect(capture.logprobs).toEqual(logprobs);
    });

    it("includes heart metadata when provided", () => {
      const trace = makeTrace();
      const capture = fromStreamingTrace(trace, null, undefined, {
        seedApplied: "concise",
        heartbeatCount: 5,
        birthCertificateCount: 2,
      });
      expect(capture.seedApplied).toBe("concise");
      expect(capture.heartbeatCount).toBe(5);
      expect(capture.birthCertificateCount).toBe(2);
    });
  });

  describe("toStreamingTrace", () => {
    it("round-trips through conversion", () => {
      const original = makeTrace();
      const capture = fromStreamingTrace(original);
      const roundTripped = toStreamingTrace(capture);

      expect(roundTripped.tokens).toEqual(original.tokens);
      expect(roundTripped.tokenTimestamps).toEqual(original.tokenTimestamps);
      expect(roundTripped.startTime).toBe(original.startTime);
      expect(roundTripped.firstTokenTime).toBe(original.firstTokenTime);
      expect(roundTripped.endTime).toBe(original.endTime);
    });
  });

  describe("computeStreamStats", () => {
    it("computes summary statistics", () => {
      const trace = makeTrace();
      const capture = fromStreamingTrace(trace);
      const stats = computeStreamStats(capture);

      expect(stats.tokenCount).toBe(7);
      expect(stats.chunkCount).toBeGreaterThan(0);
      expect(stats.hasLogprobs).toBe(false);
      expect(stats.meanInterval).toBeGreaterThan(0);
      expect(stats.stdInterval).toBeGreaterThan(0);
      expect(stats.medianInterval).toBeGreaterThan(0);
    });

    it("reports hasLogprobs correctly", () => {
      const trace = makeTrace();
      const logprobs: TokenLogprob[] = [
        { token: "Hi", logprob: -0.3, topAlternatives: [] },
      ];
      const capture = fromStreamingTrace(trace, logprobs);
      const stats = computeStreamStats(capture);
      expect(stats.hasLogprobs).toBe(true);
    });

    it("computes burst fraction", () => {
      // Create a trace with clear burst pattern
      const trace: StreamingTrace = {
        tokens: ["a", "b", "c", "d", "e", "f"],
        tokenTimestamps: [100, 101, 102, 200, 201, 202],
        startTime: 50,
        firstTokenTime: 100,
        endTime: 210,
      };
      const capture = fromStreamingTrace(trace);
      const stats = computeStreamStats(capture);
      expect(stats.burstFraction).toBeGreaterThan(0);
      expect(stats.burstCount).toBeGreaterThanOrEqual(1);
    });
  });
});
