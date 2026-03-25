import { describe, it, expect } from "vitest";
import {
  extractVocabularySignals,
  vocabularyToFeatureVector,
  VOCABULARY_FEATURE_NAMES,
} from "../../src/sensorium/senses/vocabulary.js";

describe("Vocabulary Fingerprint (Sense 1)", () => {
  it("computes type-token ratio correctly", () => {
    // "the cat sat on the mat" — 6 words, 5 unique (the appears twice)
    const signals = extractVocabularySignals("The cat sat on the mat.");
    expect(signals.vocabTypeTokenRatio).toBeCloseTo(5 / 6, 1);
  });

  it("computes hapax ratio correctly", () => {
    // "the cat sat on the mat" — unique: cat, sat, on, mat (appear once = 4 hapax), the (appears twice)
    // 5 unique words, 4 hapax → ratio = 4/5 = 0.8
    const signals = extractVocabularySignals("The cat sat on the mat.");
    expect(signals.vocabHapaxRatio).toBeCloseTo(0.8, 1);
  });

  it("computes average word frequency rank", () => {
    // Common words should have low rank, rare words high rank
    const common = extractVocabularySignals("The the the the the");
    const rare = extractVocabularySignals("Juxtapose paradigm nomenclature articulate");
    expect(common.vocabAvgWordFrequencyRank).toBeLessThan(rare.vocabAvgWordFrequencyRank);
  });

  it("computes sentence starter entropy", () => {
    // All sentences start with "The" → low entropy (0)
    const low = extractVocabularySignals("The cat ran. The dog slept. The bird flew.");
    // Each sentence starts differently → higher entropy
    const high = extractVocabularySignals("The cat ran. A dog slept. One bird flew. Some fish swam.");
    expect(low.vocabSentenceStarterEntropy).toBeLessThan(high.vocabSentenceStarterEntropy);
  });

  it("counts filler phrases", () => {
    const text = "However, this is important. Moreover, we should consider that. Additionally, in other words, it matters.";
    const signals = extractVocabularySignals(text);
    expect(signals.vocabFillerPhraseCount).toBeGreaterThanOrEqual(4);
  });

  it("computes contraction ratio", () => {
    const withContractions = extractVocabularySignals("I don't think it's possible. We can't do it. They won't agree.");
    const without = extractVocabularySignals("I do not think it is possible. We cannot do it. They will not agree.");
    expect(withContractions.vocabContractionRatio).toBeGreaterThan(without.vocabContractionRatio);
  });

  it("detects passive voice", () => {
    const passive = extractVocabularySignals("The ball was thrown. The cake was eaten. The door was opened.");
    const active = extractVocabularySignals("John threw the ball. Mary ate the cake. Tom opened the door.");
    expect(passive.vocabPassiveVoiceRatio).toBeGreaterThan(active.vocabPassiveVoiceRatio);
  });

  it("computes question density", () => {
    const questions = extractVocabularySignals("What is this? How does it work? Why should we care?");
    const noQuestions = extractVocabularySignals("This is a statement. It works well. We should care.");
    expect(questions.vocabQuestionDensity).toBeGreaterThan(noQuestions.vocabQuestionDensity);
  });

  it("computes modal verb ratio", () => {
    const hedgy = extractVocabularySignals("You could try this. You should consider that. It might work. We may succeed.");
    const direct = extractVocabularySignals("Try this approach. Consider that option. It works. We succeed.");
    expect(hedgy.vocabModalVerbRatio).toBeGreaterThan(direct.vocabModalVerbRatio);
  });

  it("handles empty text gracefully", () => {
    const signals = extractVocabularySignals("");
    expect(signals.vocabTypeTokenRatio).toBe(0);
    expect(signals.vocabHapaxRatio).toBe(0);
    expect(signals.vocabAvgWordFrequencyRank).toBe(0);
    expect(signals.vocabTopBigramsHash).toBe(0);
    expect(signals.vocabSentenceStarterEntropy).toBe(0);
    expect(signals.vocabFillerPhraseCount).toBe(0);
    expect(signals.vocabContractionRatio).toBe(0);
    expect(signals.vocabPassiveVoiceRatio).toBe(0);
    expect(signals.vocabQuestionDensity).toBe(0);
    expect(signals.vocabModalVerbRatio).toBe(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractVocabularySignals("Hello world, this is a test.");
    const vector = vocabularyToFeatureVector(signals);
    expect(vector.length).toBe(VOCABULARY_FEATURE_NAMES.length);
    expect(vector.length).toBe(10);
    for (const v of vector) {
      expect(typeof v).toBe("number");
      expect(isNaN(v)).toBe(false);
    }
  });

  it("produces different fingerprints for different writing styles", () => {
    const formal = extractVocabularySignals(
      "Furthermore, it is imperative to consider the implications. " +
      "Moreover, the aforementioned methodology was employed to ascertain the validity. " +
      "Additionally, the results were found to be statistically significant."
    );
    const casual = extractVocabularySignals(
      "So yeah, I don't think it's gonna work. " +
      "Like, we can't just do that, you know? " +
      "It's pretty obvious that won't fly."
    );
    // Formal should have more fillers
    expect(formal.vocabFillerPhraseCount).toBeGreaterThan(casual.vocabFillerPhraseCount);
    // Casual should have more contractions
    expect(casual.vocabContractionRatio).toBeGreaterThan(formal.vocabContractionRatio);
  });
});
