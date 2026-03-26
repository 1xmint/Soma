import { describe, it, expect } from "vitest";
import {
  extractContextUtilizationSignals,
  contextUtilizationToFeatureVector,
  CONTEXT_UTILIZATION_FEATURE_NAMES,
} from "../../src/sensorium/senses/context-utilization.js";

describe("Context Utilization (Sense 8)", () => {
  it("computes echo ratio (prompt phrases in response)", () => {
    const high = extractContextUtilizationSignals(
      "The Machine Learning Algorithm performed well on Natural Language Processing tasks.",
      "The Machine Learning Algorithm showed good results. The Natural Language Processing tasks were completed."
    );
    const low = extractContextUtilizationSignals(
      "The Machine Learning Algorithm performed well.",
      "Something entirely different was discussed here."
    );
    expect(high.ctxEchoRatio).toBeGreaterThan(low.ctxEchoRatio);
  });

  it("computes response to prompt ratio", () => {
    const verbose = extractContextUtilizationSignals(
      "Short question here.",
      "This is a very long and detailed response that goes on and on with lots of words and explanations and details about the topic."
    );
    const terse = extractContextUtilizationSignals(
      "Long detailed question with many words about various topics and considerations.",
      "Yes."
    );
    expect(verbose.ctxResponseToPromptRatio).toBeGreaterThan(terse.ctxResponseToPromptRatio);
  });

  it("detects hallucination indicator (novel proper nouns)", () => {
    const halluc = extractContextUtilizationSignals(
      "Tell me about cats.",
      "According to Professor Smith at Harvard University, Dr. Johnson published a paper about cats."
    );
    const grounded = extractContextUtilizationSignals(
      "Tell me about Professor Smith at Harvard.",
      "Professor Smith at Harvard is known for research."
    );
    expect(halluc.ctxHallucinationIndicator).toBeGreaterThan(grounded.ctxHallucinationIndicator);
  });

  it("detects prompt adherence (numeric constraint)", () => {
    const adheres = extractContextUtilizationSignals(
      "Explain in 3 sentences.",
      "First point here. Second point here. Third point here."
    );
    const violates = extractContextUtilizationSignals(
      "Explain in 2 sentences.",
      "First. Second. Third. Fourth. Fifth."
    );
    expect(adheres.ctxPromptAdherence).toBe(1);
    expect(violates.ctxPromptAdherence).toBe(0);
  });

  it("returns -1 for prompt adherence when no constraint", () => {
    const signals = extractContextUtilizationSignals(
      "Tell me about cats.",
      "Cats are wonderful creatures."
    );
    expect(signals.ctxPromptAdherence).toBe(-1);
  });

  it("computes info ordering (Spearman correlation)", () => {
    // Same order → positive correlation
    const sameOrder = extractContextUtilizationSignals(
      "Discuss apples bananas cherries dates elderberries figs grapes honeydew.",
      "Apples are great. Bananas are yellow. Cherries are red. Dates are sweet. Elderberries make wine. Figs are tasty. Grapes grow on vines."
    );
    expect(sameOrder.ctxInfoOrdering).toBeGreaterThanOrEqual(0);
  });

  it("handles empty prompt gracefully", () => {
    const signals = extractContextUtilizationSignals("", "Some response text here.");
    expect(signals.ctxResponseToPromptRatio).toBe(0);
    expect(signals.ctxEchoRatio).toBe(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractContextUtilizationSignals("Prompt.", "Response.");
    const vector = contextUtilizationToFeatureVector(signals);
    expect(vector.length).toBe(CONTEXT_UTILIZATION_FEATURE_NAMES.length);
    expect(vector.length).toBe(5);
  });
});
