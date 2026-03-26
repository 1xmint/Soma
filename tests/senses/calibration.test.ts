import { describe, it, expect } from "vitest";
import {
  extractCalibrationSignals,
  calibrationToFeatureVector,
  CALIBRATION_FEATURE_NAMES,
  type CalibrationObservation,
} from "../../src/sensorium/senses/calibration.js";

describe("Response Calibration (Sense 9)", () => {
  function makeObs(category: string, text: string, durationMs: number = 1000): CalibrationObservation {
    return { category, responseText: text, durationMs };
  }

  it("returns defaults with no observations", () => {
    const signals = extractCalibrationSignals([]);
    expect(signals.calibLengthRatio).toBe(0);
    expect(signals.calibDetailRatio).toBe(0);
  });

  it("computes length ratio (complex / simple)", () => {
    const obs = [
      ...Array.from({ length: 5 }, () => makeObs("rapid_fire", "Short answer.")),
      ...Array.from({ length: 5 }, () => makeObs(
        "ambiguity",
        "This is a much longer and more detailed response discussing the nuances and complexities of the topic at hand with many considerations."
      )),
    ];
    const signals = extractCalibrationSignals(obs);
    expect(signals.calibLengthRatio).toBeGreaterThan(1);
    expect(signals.calibComplexAvgLength).toBeGreaterThan(signals.calibSimpleAvgLength);
  });

  it("computes detail ratio (sentences)", () => {
    const obs = [
      ...Array.from({ length: 5 }, () => makeObs("rapid_fire", "Yes.")),
      ...Array.from({ length: 5 }, () => makeObs(
        "ambiguity",
        "First point. Second point. Third point. Fourth point. Fifth point."
      )),
    ];
    const signals = extractCalibrationSignals(obs);
    expect(signals.calibDetailRatio).toBeGreaterThan(1);
  });

  it("computes latency ratio", () => {
    const obs = [
      ...Array.from({ length: 5 }, () => makeObs("rapid_fire", "Quick.", 100)),
      ...Array.from({ length: 5 }, () => makeObs("ambiguity", "Detailed response.", 500)),
    ];
    const signals = extractCalibrationSignals(obs);
    expect(signals.calibLatencyRatio).toBeGreaterThan(1);
  });

  it("computes refusal rate edge vs normal", () => {
    const obs = [
      ...Array.from({ length: 5 }, () => makeObs("normal", "Here is the answer.")),
      ...Array.from({ length: 5 }, (_, i) => makeObs(
        "edge_case",
        i < 3 ? "I cannot do that. It's not possible." : "Here is my attempt."
      )),
      ...Array.from({ length: 3 }, () => makeObs("rapid_fire", "Yes.")),
      ...Array.from({ length: 3 }, () => makeObs("ambiguity", "Complex answer.")),
    ];
    const signals = extractCalibrationSignals(obs);
    expect(signals.calibRefusalRateEdgeVsNormal).toBeGreaterThan(0);
  });

  it("computes formatting escalation", () => {
    const obs = [
      ...Array.from({ length: 5 }, () => makeObs("rapid_fire", "Plain text only.")),
      ...Array.from({ length: 5 }, () => makeObs(
        "ambiguity",
        "# Header\n\n- Bullet point\n- Another point\n\n**Bold** conclusion."
      )),
    ];
    const signals = extractCalibrationSignals(obs);
    expect(signals.calibFormattingEscalation).toBeGreaterThan(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractCalibrationSignals([]);
    const vector = calibrationToFeatureVector(signals);
    expect(vector.length).toBe(CALIBRATION_FEATURE_NAMES.length);
    expect(vector.length).toBe(9);
  });
});
