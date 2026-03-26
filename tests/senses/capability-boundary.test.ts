import { describe, it, expect } from "vitest";
import {
  extractCapabilityBoundarySignals,
  capabilityBoundaryToFeatureVector,
  CAPABILITY_BOUNDARY_FEATURE_NAMES,
} from "../../src/sensorium/senses/capability-boundary.js";

describe("Capability Boundary (Sense 3)", () => {
  it("detects hard refusal", () => {
    const signals = extractCapabilityBoundarySignals(
      "I cannot help with that request.",
      "normal"
    );
    expect(signals.capRefusalSoftness).toBe(1);
  });

  it("detects soft refusal", () => {
    const signals = extractCapabilityBoundarySignals(
      "I don't think I should answer that question.",
      "normal"
    );
    expect(signals.capRefusalSoftness).toBe(2);
  });

  it("detects redirect", () => {
    const signals = extractCapabilityBoundarySignals(
      "Instead, I can help you with something else entirely.",
      "normal"
    );
    expect(signals.capRefusalSoftness).toBe(3);
  });

  it("returns -1 for confidence when wrong on non-failure probes", () => {
    const signals = extractCapabilityBoundarySignals(
      "The answer is definitely 42.",
      "normal"
    );
    expect(signals.capConfidenceWhenWrong).toBe(-1);
  });

  it("counts confidence phrases on failure probes", () => {
    const signals = extractCapabilityBoundarySignals(
      "The answer is definitely correct. Absolutely, the Nobel Prize in Mathematics was awarded to Einstein.",
      "failure"
    );
    expect(signals.capConfidenceWhenWrong).toBeGreaterThanOrEqual(2);
  });

  it("detects graceful degradation", () => {
    const text = "I'm not sure about the exact details, but I believe the general concept involves " +
      "multiple factors that interact in complex ways. Let me share what I do know about this topic. " +
      "There are several important considerations to keep in mind when approaching this problem. " +
      "First, the underlying mechanism depends on the specific context and conditions involved. " +
      "Second, researchers have proposed various frameworks for understanding these dynamics.";
    const signals = extractCapabilityBoundarySignals(text, "edge_case");
    expect(signals.capGracefulDegradation).toBe(1);
  });

  it("detects correct rejection of false premise", () => {
    const signals = extractCapabilityBoundarySignals(
      "There is no Nobel Prize in Mathematics. You may be thinking of the Fields Medal.",
      "failure"
    );
    expect(signals.capHallucCorrectRejectionRate).toBe(1);
  });

  it("detects confabulation (fabricated details without uncertainty)", () => {
    const signals = extractCapabilityBoundarySignals(
      "The Nobel Prize in Mathematics was established in 1950 and according to research shows it is awarded annually in Stockholm.",
      "failure"
    );
    expect(signals.capHallucConfabulateRate).toBe(1);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractCapabilityBoundarySignals("Test response.", "normal");
    const vector = capabilityBoundaryToFeatureVector(signals);
    expect(vector.length).toBe(CAPABILITY_BOUNDARY_FEATURE_NAMES.length);
    expect(vector.length).toBe(8);
  });
});
