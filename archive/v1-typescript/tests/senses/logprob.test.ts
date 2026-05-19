import { describe, it, expect } from "vitest";
import {
  extractLogprobSignals,
  logprobToFeatureVector,
  LOGPROB_FEATURE_NAMES,
} from "../../src/sensorium/senses/logprob.js";
import type { TokenLogprob } from "../../src/sensorium/stream-capture.js";

describe("Logprob Fingerprint", () => {
  function makeLogprobs(count: number, baseLp: number = -1.5): TokenLogprob[] {
    return Array.from({ length: count }, (_, i) => ({
      token: `token${i}`,
      logprob: baseLp + Math.sin(i * 0.5) * 0.5,
      topAlternatives: [
        { token: `alt1_${i}`, logprob: baseLp - 1.0 },
        { token: `alt2_${i}`, logprob: baseLp - 2.0 },
        { token: `alt3_${i}`, logprob: baseLp - 3.5 },
      ],
    }));
  }

  describe("extractLogprobSignals()", () => {
    it("returns null for null logprobs", () => {
      expect(extractLogprobSignals(null)).toBeNull();
    });

    it("returns null for empty logprobs", () => {
      expect(extractLogprobSignals([])).toBeNull();
    });

    it("extracts all 10 features from valid logprobs", () => {
      const logprobs = makeLogprobs(20);
      const signals = extractLogprobSignals(logprobs);

      expect(signals).not.toBeNull();
      expect(typeof signals!.logprobMean).toBe("number");
      expect(typeof signals!.logprobStd).toBe("number");
      expect(typeof signals!.logprobEntropyMean).toBe("number");
      expect(typeof signals!.logprobTop1Confidence).toBe("number");
      expect(typeof signals!.logprobAlternativeDiversity).toBe("number");
      expect(typeof signals!.logprobMedian).toBe("number");
      expect(typeof signals!.logprobEntropyStd).toBe("number");
      expect(typeof signals!.logprobRunnerUpMean).toBe("number");
      expect(typeof signals!.logprobConfidenceGap).toBe("number");
      expect(typeof signals!.logprobSurpriseRate).toBe("number");
    });

    it("logprobMean reflects average token confidence", () => {
      const confident = makeLogprobs(20, -0.5); // High confidence
      const uncertain = makeLogprobs(20, -4.0); // Low confidence

      const confSignals = extractLogprobSignals(confident)!;
      const uncertSignals = extractLogprobSignals(uncertain)!;

      expect(confSignals.logprobMean).toBeGreaterThan(uncertSignals.logprobMean);
    });

    it("top1Confidence is between 0 and 1", () => {
      const signals = extractLogprobSignals(makeLogprobs(20))!;
      expect(signals.logprobTop1Confidence).toBeGreaterThanOrEqual(0);
      expect(signals.logprobTop1Confidence).toBeLessThanOrEqual(1);
    });

    it("surprise rate detects low-probability tokens", () => {
      const mixed: TokenLogprob[] = [
        ...makeLogprobs(15, -1.0),
        // Add some surprising tokens
        { token: "rare1", logprob: -6.0, topAlternatives: [{ token: "a", logprob: -0.5 }] },
        { token: "rare2", logprob: -7.0, topAlternatives: [{ token: "b", logprob: -0.3 }] },
        { token: "rare3", logprob: -8.0, topAlternatives: [{ token: "c", logprob: -0.2 }] },
      ];

      const signals = extractLogprobSignals(mixed)!;
      expect(signals.logprobSurpriseRate).toBeGreaterThan(0);
    });

    it("confidence gap measures margin between chosen and runner-up", () => {
      // Wide gap — model is very confident
      const wideGap: TokenLogprob[] = Array.from({ length: 10 }, (_, i) => ({
        token: `t${i}`,
        logprob: -0.1,
        topAlternatives: [{ token: "alt", logprob: -5.0 }],
      }));

      // Narrow gap — model is uncertain
      const narrowGap: TokenLogprob[] = Array.from({ length: 10 }, (_, i) => ({
        token: `t${i}`,
        logprob: -1.0,
        topAlternatives: [{ token: "alt", logprob: -1.1 }],
      }));

      const wideSignals = extractLogprobSignals(wideGap)!;
      const narrowSignals = extractLogprobSignals(narrowGap)!;

      expect(wideSignals.logprobConfidenceGap).toBeGreaterThan(narrowSignals.logprobConfidenceGap);
    });
  });

  describe("logprobToFeatureVector()", () => {
    it("produces vector with correct length", () => {
      const signals = extractLogprobSignals(makeLogprobs(20))!;
      const vector = logprobToFeatureVector(signals);
      expect(vector.length).toBe(LOGPROB_FEATURE_NAMES.length);
      expect(vector.length).toBe(10);
    });

    it("all values are finite numbers", () => {
      const signals = extractLogprobSignals(makeLogprobs(20))!;
      const vector = logprobToFeatureVector(signals);
      for (const v of vector) {
        expect(Number.isFinite(v)).toBe(true);
      }
    });
  });

  describe("LOGPROB_FEATURE_NAMES", () => {
    it("all names start with logprob_ prefix", () => {
      for (const name of LOGPROB_FEATURE_NAMES) {
        expect(name.startsWith("logprob_")).toBe(true);
      }
    });
  });
});
