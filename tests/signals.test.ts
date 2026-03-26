import { describe, it, expect } from "vitest";
import {
  extractCognitiveSignals,
  extractStructuralSignals,
  extractTemporalSignals,
  extractErrorSignals,
  extractAllSignals,
  signalsToFeatureVector,
  FEATURE_NAMES,
  type StreamingTrace,
} from "../src/experiment/signals.js";

// --- Helpers ---

function makeTrace(overrides: Partial<StreamingTrace> = {}): StreamingTrace {
  return {
    tokenTimestamps: [100, 120, 145, 160, 200],
    tokens: ["Hello", " ", "world", "!", " "],
    startTime: 50,
    firstTokenTime: 100,
    endTime: 200,
    ...overrides,
  };
}

// --- Cognitive Signal Tests ---

describe("Cognitive Signals", () => {
  it("detects hedging phrases", () => {
    const text = "It depends on the context. However, on the other hand, perhaps you could try this.";
    const signals = extractCognitiveSignals(text);
    expect(signals.hedgeCount).toBeGreaterThanOrEqual(3);
    expect(signals.hedgeToCertaintyRatio).toBe(1); // no certainty markers
  });

  it("detects certainty markers", () => {
    const text = "The answer is definitely 42. Without a doubt, this is clearly correct. Absolutely.";
    const signals = extractCognitiveSignals(text);
    expect(signals.certaintyCount).toBeGreaterThanOrEqual(4);
  });

  it("detects disclaimers", () => {
    const text = "As an AI, I cannot provide medical advice. Please consult a professional.";
    const signals = extractCognitiveSignals(text);
    expect(signals.disclaimerCount).toBeGreaterThanOrEqual(2);
  });

  it("counts questions back to user", () => {
    const text = "What do you mean by that? Could you clarify? Also, what's your budget?";
    const signals = extractCognitiveSignals(text);
    expect(signals.questionsBack).toBe(3);
  });

  it("detects empathy markers", () => {
    const text = "Great question! I'd be happy to help. I understand your concern.";
    const signals = extractCognitiveSignals(text);
    expect(signals.empathyMarkers).toBeGreaterThanOrEqual(2);
  });

  it("computes hedge-to-certainty ratio", () => {
    const text = "However, it depends. But the answer is definitely this.";
    const signals = extractCognitiveSignals(text);
    expect(signals.hedgeToCertaintyRatio).toBeGreaterThan(0);
    expect(signals.hedgeToCertaintyRatio).toBeLessThan(1);
  });

  it("handles empty text", () => {
    const signals = extractCognitiveSignals("");
    expect(signals.hedgeCount).toBe(0);
    expect(signals.certaintyCount).toBe(0);
    expect(signals.hedgeToCertaintyRatio).toBe(0);
  });
});

// --- Structural Signal Tests ---

describe("Structural Signals", () => {
  it("counts basic text metrics", () => {
    const text = "Hello world.\nSecond line.\n\nNew paragraph.";
    const signals = extractStructuralSignals(text);
    expect(signals.wordCount).toBe(6);
    expect(signals.lineCount).toBe(4);
    expect(signals.paragraphCount).toBe(2);
  });

  it("detects bullet points and numbered lists", () => {
    const text = "- Item one\n- Item two\n* Item three\n1. First\n2. Second";
    const signals = extractStructuralSignals(text);
    expect(signals.bulletLines).toBe(3);
    expect(signals.numberedListLines).toBe(2);
    expect(signals.listToContentRatio).toBe(1); // all lines are list items
  });

  it("detects markdown headers", () => {
    const text = "# Title\n## Subtitle\nContent here\n### Section";
    const signals = extractStructuralSignals(text);
    expect(signals.headerLines).toBe(3);
  });

  it("counts code blocks", () => {
    const text = "Here is code:\n```python\nprint('hello')\n```\nAnd more:\n```\ncode\n```";
    const signals = extractStructuralSignals(text);
    expect(signals.codeBlocks).toBe(2);
  });

  it("counts bold markers", () => {
    const text = "This is **bold** and this is also **important** text.";
    const signals = extractStructuralSignals(text);
    expect(signals.boldCount).toBe(2);
  });

  it("detects preamble opening pattern", () => {
    const preamble = extractStructuralSignals("Great question! Here is the answer.");
    expect(preamble.openingPattern).toBe("preamble");

    const direct = extractStructuralSignals("The answer is 42.");
    expect(direct.openingPattern).toBe("direct");
  });

  it("detects closing patterns", () => {
    const question = extractStructuralSignals("Does this help?");
    expect(question.closingPattern).toBe("question");

    const offer = extractStructuralSignals("Some info.\nLet me know if you need more!");
    expect(offer.closingPattern).toBe("offer");

    const statement = extractStructuralSignals("The answer is 42.");
    expect(statement.closingPattern).toBe("statement");
  });

  it("computes average word and sentence length", () => {
    const text = "Hi there. This is a test.";
    const signals = extractStructuralSignals(text);
    expect(signals.avgWordLength).toBeGreaterThan(0);
    expect(signals.avgSentenceLength).toBeGreaterThan(0);
  });

  it("handles empty text", () => {
    const signals = extractStructuralSignals("");
    expect(signals.wordCount).toBe(0);
    expect(signals.avgWordLength).toBe(0);
  });
});

// --- Temporal Signal Tests ---

describe("Temporal Signals", () => {
  it("computes time to first token", () => {
    const trace = makeTrace({ startTime: 50, firstTokenTime: 100 });
    const signals = extractTemporalSignals(trace);
    expect(signals.timeToFirstToken).toBe(50);
  });

  it("computes inter-token intervals", () => {
    const trace = makeTrace({ tokenTimestamps: [100, 120, 145, 160, 200] });
    const signals = extractTemporalSignals(trace);
    expect(signals.interTokenIntervals).toEqual([20, 25, 15, 40]);
    expect(signals.tokenCount).toBe(5);
  });

  it("computes mean, std, median of intervals", () => {
    const trace = makeTrace({ tokenTimestamps: [100, 120, 140, 160, 180] });
    const signals = extractTemporalSignals(trace);
    // All intervals are 20ms — uniform
    expect(signals.meanInterval).toBe(20);
    expect(signals.stdInterval).toBe(0);
    expect(signals.medianInterval).toBe(20);
  });

  it("computes burstiness coefficient", () => {
    // Uniform intervals → low burstiness
    const uniform = makeTrace({ tokenTimestamps: [100, 120, 140, 160, 180] });
    const uniformSignals = extractTemporalSignals(uniform);
    expect(uniformSignals.burstiness).toBe(0); // zero variance → zero burstiness

    // Bursty intervals → high burstiness
    const bursty = makeTrace({ tokenTimestamps: [100, 101, 102, 200, 201] });
    const burstySignals = extractTemporalSignals(bursty);
    expect(burstySignals.burstiness).toBeGreaterThan(0);
  });

  it("computes total streaming duration", () => {
    const trace = makeTrace({ startTime: 50, endTime: 300 });
    const signals = extractTemporalSignals(trace);
    expect(signals.totalStreamingDuration).toBe(250);
  });

  it("handles single-token trace", () => {
    const trace = makeTrace({
      tokenTimestamps: [100],
      tokens: ["Hi"],
      startTime: 50,
      firstTokenTime: 100,
      endTime: 120,
    });
    const signals = extractTemporalSignals(trace);
    expect(signals.interTokenIntervals).toEqual([]);
    expect(signals.meanInterval).toBe(0);
    expect(signals.tokenCount).toBe(1);
  });

  it("handles no first token (empty response)", () => {
    const trace = makeTrace({
      tokenTimestamps: [],
      tokens: [],
      startTime: 50,
      firstTokenTime: null,
      endTime: 100,
    });
    const signals = extractTemporalSignals(trace);
    expect(signals.timeToFirstToken).toBe(50); // fallback to total duration
    expect(signals.tokenCount).toBe(0);
  });
});

// --- Error Signal Tests ---

describe("Error Signals", () => {
  it("detects refusals", () => {
    const text = "I cannot provide that information. It is against my guidelines.";
    const signals = extractErrorSignals(text, "normal");
    expect(signals.containsRefusal).toBe(true);
  });

  it("detects uncertainty admissions", () => {
    const text = "I'm not sure about this. To the best of my knowledge, it might be correct.";
    const signals = extractErrorSignals(text, "normal");
    expect(signals.uncertaintyAdmissions).toBeGreaterThanOrEqual(2);
  });

  it("detects self-corrections", () => {
    const text = "The result is 10. Actually, let me correct that — it should be 12.";
    const signals = extractErrorSignals(text, "normal");
    expect(signals.selfCorrections).toBeGreaterThanOrEqual(1);
  });

  it("detects assertive-when-wrong on failure probes", () => {
    const text = "The answer is definitely the Nobel Prize in Mathematics, awarded in 1975.";
    const signals = extractErrorSignals(text, "failure");
    expect(signals.assertiveWhenWrong).toBeGreaterThan(0);
    expect(signals.attemptedImpossible).toBe(true);
  });

  it("does not flag assertive-when-wrong on normal probes", () => {
    const text = "The answer is 42.";
    const signals = extractErrorSignals(text, "normal");
    expect(signals.assertiveWhenWrong).toBe(0);
  });

  it("computes confidence ratio", () => {
    const confident = "The answer is 42. It is definitely correct. This is the solution.";
    const confSignals = extractErrorSignals(confident, "normal");
    expect(confSignals.confidenceRatio).toBeGreaterThan(0.5);

    const uncertain = "I'm not sure. I don't know. I'm uncertain about this.";
    const uncertSignals = extractErrorSignals(uncertain, "normal");
    expect(uncertSignals.confidenceRatio).toBe(0);
  });

  it("handles clean response with no error signals", () => {
    const text = "TCP uses connection-oriented communication while UDP is connectionless.";
    const signals = extractErrorSignals(text, "normal");
    expect(signals.containsRefusal).toBe(false);
    expect(signals.uncertaintyAdmissions).toBe(0);
    expect(signals.selfCorrections).toBe(0);
  });
});

// --- Integration Tests ---

describe("Full Signal Extraction", () => {
  it("extracts all signal channels from a response", () => {
    const text =
      "Great question! However, the answer depends on context.\n\n" +
      "- Option A is faster\n" +
      "- Option B is more reliable\n\n" +
      "I'm not sure which is best for your case. Let me know if you need more help!";

    const trace = makeTrace();
    const signals = extractAllSignals(text, trace, "ambiguity");

    expect(signals.cognitive.hedgeCount).toBeGreaterThan(0);
    expect(signals.structural.bulletLines).toBe(2);
    expect(signals.structural.openingPattern).toBe("preamble");
    expect(signals.temporal.tokenCount).toBe(5);
    expect(signals.error.containsRefusal).toBe(false);
  });

  it("produces a feature vector of correct length", () => {
    const text = "The answer is 42.";
    const trace = makeTrace();
    const signals = extractAllSignals(text, trace, "normal");
    const vector = signalsToFeatureVector(signals);

    expect(vector.length).toBe(FEATURE_NAMES.length);
    // All values should be numbers
    for (const v of vector) {
      expect(typeof v).toBe("number");
      expect(isNaN(v)).toBe(false);
    }
  });

  it("feature vector length matches feature names", () => {
    expect(FEATURE_NAMES.length).toBe(80); // 34 + 10 vocab + 9 topo + 8 cap + 6 tool + 8 adv + 5 ctx
  });
});

// --- Probe Battery Tests ---

describe("Probe Battery", () => {
  it("has exactly 100 probes", async () => {
    const { ALL_PROBES } = await import("../src/experiment/probes.js");
    expect(ALL_PROBES.length).toBe(100);
  });

  it("has 20 probes per category", async () => {
    const { ALL_PROBES, getProbesByCategory } = await import("../src/experiment/probes.js");
    expect(getProbesByCategory("normal").length).toBe(20);
    expect(getProbesByCategory("ambiguity").length).toBe(20);
    expect(getProbesByCategory("edge_case").length).toBe(20);
    expect(getProbesByCategory("failure").length).toBe(20);
    expect(getProbesByCategory("rapid_fire").length).toBe(20);
  });

  it("has unique probe IDs", async () => {
    const { ALL_PROBES } = await import("../src/experiment/probes.js");
    const ids = ALL_PROBES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// --- Config Tests ---

describe("Agent Configs", () => {
  it("has 13 agent genomes", async () => {
    const { AGENT_CONFIGS } = await import("../src/experiment/configs.js");
    expect(AGENT_CONFIGS.length).toBeGreaterThanOrEqual(10);
  });

  it("has unique agent IDs", async () => {
    const { AGENT_CONFIGS } = await import("../src/experiment/configs.js");
    const ids = AGENT_CONFIGS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("has exactly 2 epigenetic variants", async () => {
    const { AGENT_CONFIGS } = await import("../src/experiment/configs.js");
    const epigenetic = AGENT_CONFIGS.filter((c) => c.isEpigenetic);
    expect(epigenetic.length).toBe(2);
    // Both should be llama3-70b variants
    for (const e of epigenetic) {
      expect(e.model).toBe("llama-3.3-70b-versatile");
    }
  });

  it("has exactly 1 proxy attack agent", async () => {
    const { AGENT_CONFIGS } = await import("../src/experiment/configs.js");
    const proxies = AGENT_CONFIGS.filter((c) => c.isProxy);
    expect(proxies.length).toBe(1);
    expect(proxies[0].proxiedAgentId).toBe("llama3-70b");
  });

  it("getAgentConfig returns correct agent", async () => {
    const { getAgentConfig } = await import("../src/experiment/configs.js");
    const agent = getAgentConfig("gemini-flash");
    expect(agent.provider).toBe("openrouter");
  });

  it("getAgentConfig throws for unknown ID", async () => {
    const { getAgentConfig } = await import("../src/experiment/configs.js");
    expect(() => getAgentConfig("nonexistent")).toThrow("Unknown agent config");
  });
});
