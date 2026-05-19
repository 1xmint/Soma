import { describe, it, expect } from "vitest";
import {
  extractEntropySignals,
  entropyToFeatureVector,
  ENTROPY_FEATURE_NAMES,
} from "../../src/sensorium/senses/entropy.js";

describe("Entropic Fingerprint (Sense 6)", () => {
  function makeResponses(count: number, generator: (i: number) => string): string[] {
    return Array.from({ length: count }, (_, i) => generator(i));
  }

  it("returns defaults for fewer than 10 responses", () => {
    const signals = extractEntropySignals(
      ["Short response."],
      ["normal"]
    );
    expect(signals.entropyResponseLengthCv).toBe(0);
    expect(signals.entropyOpeningDiversity).toBe(0);
  });

  it("computes response length CV (high variance)", () => {
    const responses = makeResponses(12, (i) =>
      i % 2 === 0
        ? "Short."
        : "This is a much longer response with many more words to create high variance in length."
    );
    const categories = responses.map(() => "normal");
    const signals = extractEntropySignals(responses, categories);
    expect(signals.entropyResponseLengthCv).toBeGreaterThan(0.5);
  });

  it("computes response length CV (low variance)", () => {
    const responses = makeResponses(12, () =>
      "This is a response that has about ten words in it."
    );
    const categories = responses.map(() => "normal");
    const signals = extractEntropySignals(responses, categories);
    expect(signals.entropyResponseLengthCv).toBe(0);
  });

  it("computes opening diversity", () => {
    // All same opening → low diversity
    const sameOpening = makeResponses(12, () => "The answer is something different each time.");
    const sameCategories = sameOpening.map(() => "normal");
    const lowDiv = extractEntropySignals(sameOpening, sameCategories);

    // All different openings → high diversity
    const diffOpening = makeResponses(12, (i) => `Opening${i} is unique for this response number ${i}.`);
    const diffCategories = diffOpening.map(() => "normal");
    const highDiv = extractEntropySignals(diffOpening, diffCategories);

    expect(highDiv.entropyOpeningDiversity).toBeGreaterThan(lowDiv.entropyOpeningDiversity);
  });

  it("computes word predictability (Shannon entropy)", () => {
    const signals = extractEntropySignals(
      makeResponses(12, (i) => `Response ${i}: The cat sat on the mat and looked at the bird.`),
      makeResponses(12, () => "normal")
    );
    expect(signals.entropyWordPredictability).toBeGreaterThan(0);
  });

  it("computes formatting consistency", () => {
    // Inconsistent formatting → high variance
    const mixed = makeResponses(12, (i) =>
      i % 3 === 0
        ? "# Header\n\n- bullet\n- list\n\n```code```"
        : i % 3 === 1
          ? "Just plain text without any formatting at all."
          : "**Bold** and more **bold** text here."
    );
    const mixedCats = mixed.map(() => "normal");
    const inconsistent = extractEntropySignals(mixed, mixedCats);

    // Consistent formatting → low variance
    const uniform = makeResponses(12, () => "Just plain text response.");
    const uniformCats = uniform.map(() => "normal");
    const consistent = extractEntropySignals(uniform, uniformCats);

    expect(inconsistent.entropyFormattingConsistency).toBeGreaterThan(
      consistent.entropyFormattingConsistency
    );
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractEntropySignals(
      makeResponses(12, (i) => `Response ${i}.`),
      makeResponses(12, () => "normal")
    );
    const vector = entropyToFeatureVector(signals);
    expect(vector.length).toBe(ENTROPY_FEATURE_NAMES.length);
    expect(vector.length).toBe(7);
  });
});
