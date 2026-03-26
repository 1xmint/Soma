import { describe, it, expect } from "vitest";
import {
  extractConsistencySignals,
  consistencyToFeatureVector,
  CONSISTENCY_FEATURE_NAMES,
  type CategoryObservation,
} from "../../src/sensorium/senses/consistency.js";

describe("Consistency Manifold (Sense 7)", () => {
  function makeObs(overrides: Partial<CategoryObservation> & { category: string }): CategoryObservation {
    return {
      typeTokenRatio: 0.5,
      meanInterval: 10,
      avgSentenceLength: 15,
      hedgeCount: 2,
      responseWordCount: 100,
      promptWordCount: 20,
      responseText: "I think this is a reasonable response to the question.",
      ...overrides,
    };
  }

  it("returns defaults for insufficient data", () => {
    const signals = extractConsistencySignals([
      makeObs({ category: "normal" }),
    ]);
    expect(signals.consistVocabStability).toBe(0);
    expect(signals.consistTimingStability).toBe(0);
  });

  it("detects high stability (same behavior across categories)", () => {
    const obs: CategoryObservation[] = [];
    for (const cat of ["normal", "ambiguity", "edge_case"]) {
      for (let i = 0; i < 5; i++) {
        obs.push(makeObs({
          category: cat,
          typeTokenRatio: 0.5,
          meanInterval: 10,
          avgSentenceLength: 15,
          hedgeCount: 2,
        }));
      }
    }
    const signals = extractConsistencySignals(obs);
    expect(signals.consistVocabStability).toBe(0);
    expect(signals.consistTimingStability).toBe(0);
  });

  it("detects low stability (different behavior across categories)", () => {
    const obs: CategoryObservation[] = [];
    const settings = {
      normal: { typeTokenRatio: 0.3, meanInterval: 5 },
      ambiguity: { typeTokenRatio: 0.7, meanInterval: 20 },
      edge_case: { typeTokenRatio: 0.5, meanInterval: 50 },
    };
    for (const [cat, s] of Object.entries(settings)) {
      for (let i = 0; i < 5; i++) {
        obs.push(makeObs({ category: cat, ...s }));
      }
    }
    const signals = extractConsistencySignals(obs);
    expect(signals.consistVocabStability).toBeGreaterThan(0.1);
    expect(signals.consistTimingStability).toBeGreaterThan(5);
  });

  it("computes length calibration R²", () => {
    // Perfect correlation: longer prompts → longer responses
    const obs: CategoryObservation[] = [];
    for (const cat of ["normal", "ambiguity"]) {
      for (let i = 1; i <= 5; i++) {
        obs.push(makeObs({
          category: cat,
          promptWordCount: i * 10,
          responseWordCount: i * 50,
        }));
      }
    }
    const signals = extractConsistencySignals(obs);
    expect(signals.consistLengthCalibrationR2).toBeGreaterThan(0.9);
  });

  it("computes identity coherence", () => {
    const obs: CategoryObservation[] = [];
    for (const cat of ["normal", "ambiguity", "edge_case"]) {
      for (let i = 0; i < 3; i++) {
        obs.push(makeObs({
          category: cat,
          responseText: "I think this is good. As an AI, I believe this helps. Let me explain further.",
        }));
      }
    }
    const signals = extractConsistencySignals(obs);
    expect(signals.consistIdentityCoherence).toBeGreaterThan(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractConsistencySignals([]);
    const vector = consistencyToFeatureVector(signals);
    expect(vector.length).toBe(CONSISTENCY_FEATURE_NAMES.length);
    expect(vector.length).toBe(6);
  });
});
