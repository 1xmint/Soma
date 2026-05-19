import { describe, it, expect } from "vitest";
import {
  extractTemporalSignals,
  temporalToFeatureVector,
  TEMPORAL_FEATURE_NAMES,
} from "../../src/sensorium/senses/temporal.js";
import { fromStreamingTrace } from "../../src/sensorium/stream-capture.js";
import type { StreamingTrace } from "../../src/experiment/signals.js";

describe("Temporal Fingerprint (PRIMARY Sense)", () => {
  /** Create a synthetic token stream capture for testing. */
  function makeCapture(options: {
    tokenCount?: number;
    baseInterval?: number;
    variance?: number;
    ttft?: number;
  } = {}): ReturnType<typeof fromStreamingTrace> {
    const count = options.tokenCount ?? 50;
    const baseInterval = options.baseInterval ?? 12;
    const variance = options.variance ?? 2;
    const ttft = options.ttft ?? 450;

    const tokens: string[] = [];
    const timestamps: number[] = [];
    const startTime = 1000;
    let currentTime = startTime + ttft;

    for (let i = 0; i < count; i++) {
      tokens.push(i % 10 === 9 ? "word." : "word");
      timestamps.push(currentTime);
      // Add some variance to intervals
      const interval = baseInterval + (Math.sin(i * 0.7) * variance);
      currentTime += Math.max(1, interval);
    }

    const trace: StreamingTrace = {
      tokens,
      tokenTimestamps: timestamps,
      startTime,
      firstTokenTime: startTime + ttft,
      endTime: currentTime,
    };

    return fromStreamingTrace(trace);
  }

  describe("extractTemporalSignals()", () => {
    it("extracts all 22 temporal features", () => {
      const capture = makeCapture();
      const signals = extractTemporalSignals(capture);

      expect(signals.timeToFirstToken).toBeGreaterThan(0);
      expect(signals.meanInterval).toBeGreaterThan(0);
      expect(signals.medianInterval).toBeGreaterThan(0);
      expect(signals.stdInterval).toBeGreaterThanOrEqual(0);
      expect(signals.burstiness).toBeGreaterThanOrEqual(0);
      expect(signals.totalStreamingDuration).toBeGreaterThan(0);
      expect(signals.tokenCount).toBe(50);

      // Conditional timing surface
      expect(signals.earlyMeanInterval).toBeGreaterThan(0);
      expect(signals.midMeanInterval).toBeGreaterThan(0);
      expect(signals.lateMeanInterval).toBeGreaterThan(0);
      expect(typeof signals.acceleration).toBe("number");
      expect(typeof signals.sentenceBoundaryPauseRatio).toBe("number");

      // Burst topology
      expect(typeof signals.burstCount).toBe("number");
      expect(signals.burstFraction).toBeGreaterThanOrEqual(0);
      expect(signals.burstFraction).toBeLessThanOrEqual(1);

      // Distribution shape
      expect(signals.chunkCount).toBeGreaterThan(0);
      expect(typeof signals.timingEntropy).toBe("number");
      expect(signals.p90Interval).toBeGreaterThanOrEqual(signals.p10Interval);
      expect(typeof signals.intervalSkewness).toBe("number");
    });

    it("ttft reflects time to first token", () => {
      const fast = makeCapture({ ttft: 100 });
      const slow = makeCapture({ ttft: 1000 });
      expect(extractTemporalSignals(fast).timeToFirstToken).toBeLessThan(
        extractTemporalSignals(slow).timeToFirstToken
      );
    });

    it("mean interval reflects token delivery speed", () => {
      const fast = makeCapture({ baseInterval: 5 });
      const slow = makeCapture({ baseInterval: 25 });
      expect(extractTemporalSignals(fast).meanInterval).toBeLessThan(
        extractTemporalSignals(slow).meanInterval
      );
    });

    it("burstiness reflects timing variance relative to mean", () => {
      const smooth = makeCapture({ baseInterval: 10, variance: 0.5 });
      const bursty = makeCapture({ baseInterval: 10, variance: 5 });
      expect(extractTemporalSignals(smooth).burstiness).toBeLessThan(
        extractTemporalSignals(bursty).burstiness
      );
    });

    it("handles empty capture", () => {
      const trace: StreamingTrace = {
        tokens: [],
        tokenTimestamps: [],
        startTime: 1000,
        firstTokenTime: null,
        endTime: 1000,
      };
      const capture = fromStreamingTrace(trace);
      const signals = extractTemporalSignals(capture);

      expect(signals.tokenCount).toBe(0);
      expect(signals.meanInterval).toBe(0);
      expect(signals.timingEntropy).toBe(0);
    });

    it("sentence boundary pause ratio detects pauses at sentence ends", () => {
      // Create tokens where sentence endings have longer intervals
      const tokens: string[] = [];
      const timestamps: number[] = [];
      let time = 1000;

      for (let i = 0; i < 40; i++) {
        if (i % 10 === 9) {
          tokens.push("end.");
          timestamps.push(time);
          time += 50; // Long pause after sentence
        } else {
          tokens.push("word");
          timestamps.push(time);
          time += 10; // Short mid-sentence
        }
      }

      const trace: StreamingTrace = {
        tokens,
        tokenTimestamps: timestamps,
        startTime: 1000,
        firstTokenTime: 1000,
        endTime: time,
      };
      const capture = fromStreamingTrace(trace);
      const signals = extractTemporalSignals(capture);

      // Sentence boundary pause ratio should be > 1 (longer pauses at boundaries)
      expect(signals.sentenceBoundaryPauseRatio).toBeGreaterThan(1.0);
    });
  });

  describe("temporalToFeatureVector()", () => {
    it("produces vector with correct length matching feature names", () => {
      const capture = makeCapture();
      const signals = extractTemporalSignals(capture);
      const vector = temporalToFeatureVector(signals);

      expect(vector.length).toBe(TEMPORAL_FEATURE_NAMES.length);
      expect(vector.length).toBe(22);
    });

    it("all values are finite numbers", () => {
      const capture = makeCapture();
      const signals = extractTemporalSignals(capture);
      const vector = temporalToFeatureVector(signals);

      for (const value of vector) {
        expect(Number.isFinite(value)).toBe(true);
      }
    });
  });

  describe("TEMPORAL_FEATURE_NAMES", () => {
    it("all names start with temporal_ prefix", () => {
      for (const name of TEMPORAL_FEATURE_NAMES) {
        expect(name.startsWith("temporal_")).toBe(true);
      }
    });
  });
});
