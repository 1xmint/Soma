import { describe, it, expect } from "vitest";
import {
  extractMultiTurnSignals,
  multiturnToFeatureVector,
  MULTITURN_FEATURE_NAMES,
  type MultiTurnConversation,
  type ConversationTurn,
} from "../../src/sensorium/senses/multiturn.js";

describe("Multi-Turn Dynamics (Sense 10)", () => {
  function makeTurn(role: "user" | "assistant", content: string, turnIndex: number, durationMs: number = 1000): ConversationTurn {
    return { role, content, durationMs, turnIndex };
  }

  it("returns defaults for empty conversations", () => {
    const signals = extractMultiTurnSignals([]);
    expect(signals.multiLengthDrift).toBe(0);
    expect(signals.multiLatencyDrift).toBe(0);
    expect(signals.multiContextReferenceRate).toBe(0);
  });

  it("detects increasing response length (positive drift)", () => {
    const conv: MultiTurnConversation = {
      id: "test-1",
      type: "deepening",
      turns: [
        makeTurn("user", "Tell me about cats.", 0),
        makeTurn("assistant", "Cats are pets.", 1, 500),
        makeTurn("user", "Tell me more.", 2),
        makeTurn("assistant", "Cats are domesticated animals that have been companions to humans for thousands of years across many civilizations.", 3, 1000),
        makeTurn("user", "Even more detail.", 4),
        makeTurn("assistant", "Cats are fascinating domesticated animals that have coexisted with humans for over ten thousand years. They were first domesticated in the Near East around 7500 BC. Modern cats come in many breeds with diverse characteristics and temperaments.", 5, 1500),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    expect(signals.multiLengthDrift).toBeGreaterThan(0);
  });

  it("detects latency drift", () => {
    const conv: MultiTurnConversation = {
      id: "test-2",
      type: "deepening",
      turns: [
        makeTurn("user", "Q1", 0),
        makeTurn("assistant", "A1", 1, 100),
        makeTurn("user", "Q2", 2),
        makeTurn("assistant", "A2", 3, 500),
        makeTurn("user", "Q3", 4),
        makeTurn("assistant", "A3", 5, 900),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    expect(signals.multiLatencyDrift).toBeGreaterThan(0);
  });

  it("detects context references", () => {
    const conv: MultiTurnConversation = {
      id: "test-3",
      type: "callback",
      turns: [
        makeTurn("user", "Explain quantum entanglement.", 0),
        makeTurn("assistant", "Quantum entanglement is a phenomenon where particles become correlated.", 1),
        makeTurn("user", "How does this relate to computing?", 2),
        makeTurn("assistant", "Building on quantum entanglement, quantum computing uses correlated particles to perform parallel computations.", 3),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    expect(signals.multiContextReferenceRate).toBeGreaterThan(0);
  });

  it("detects style adaptation (contraction change)", () => {
    const conv: MultiTurnConversation = {
      id: "test-4",
      type: "style_shift",
      turns: [
        makeTurn("user", "Explain in formal language.", 0),
        makeTurn("assistant", "The phenomenon of gravity is a fundamental force that governs the interactions between massive objects in the universe.", 1),
        makeTurn("user", "Now explain casually.", 2),
        makeTurn("assistant", "So basically, gravity's what keeps us from floating off. It's pretty cool — you can't really see it but it's always there pulling stuff together.", 3),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    // Last turn has contractions, first doesn't → positive adaptation
    expect(signals.multiStyleAdaptation).toBeGreaterThan(0);
  });

  it("detects correction response (apology)", () => {
    const conv: MultiTurnConversation = {
      id: "test-5",
      type: "correction",
      turns: [
        makeTurn("user", "What year was Python created?", 0),
        makeTurn("assistant", "Python was created in 1995.", 1),
        makeTurn("user", "That's not correct. It was 1991.", 2),
        makeTurn("assistant", "I apologize for the error. You're right, Python was first released in 1991 by Guido van Rossum.", 3),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    expect(signals.multiCorrectionResponse).toBe(3); // apologizes
  });

  it("detects correction response (maintains position)", () => {
    const conv: MultiTurnConversation = {
      id: "test-6",
      type: "correction",
      turns: [
        makeTurn("user", "The sky is green.", 0),
        makeTurn("assistant", "The sky actually appears blue due to Rayleigh scattering.", 1),
        makeTurn("user", "No, that's wrong, it's green.", 2),
        makeTurn("assistant", "I maintain my previous answer. Actually, the sky appears blue because shorter wavelengths of light are scattered more by the atmosphere.", 3),
      ],
    };
    const signals = extractMultiTurnSignals([conv]);
    expect(signals.multiCorrectionResponse).toBe(2); // maintains
  });

  it("handles multiple conversations", () => {
    const convs: MultiTurnConversation[] = [
      {
        id: "a", type: "deepening",
        turns: [
          makeTurn("user", "Q", 0),
          makeTurn("assistant", "Short answer.", 1, 100),
          makeTurn("user", "Q", 2),
          makeTurn("assistant", "A longer and more detailed answer with more words.", 3, 200),
        ],
      },
      {
        id: "b", type: "deepening",
        turns: [
          makeTurn("user", "Q", 0),
          makeTurn("assistant", "Brief.", 1, 50),
          makeTurn("user", "Q", 2),
          makeTurn("assistant", "Much more elaborate response with lots of detail and information.", 3, 300),
        ],
      },
    ];
    const signals = extractMultiTurnSignals(convs);
    expect(signals.multiLengthDrift).toBeGreaterThan(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractMultiTurnSignals([]);
    const vector = multiturnToFeatureVector(signals);
    expect(vector.length).toBe(MULTITURN_FEATURE_NAMES.length);
    expect(vector.length).toBe(5);
  });
});
