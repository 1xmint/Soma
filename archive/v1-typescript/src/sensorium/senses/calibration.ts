/**
 * Sense 9: Response Calibration
 *
 * Measures how depth scales with complexity — does the agent give short
 * answers to simple questions and long answers to complex ones? The
 * calibration pattern varies by model and is a strong identity signal.
 *
 * Operates across categories (needs rapid_fire and ambiguity responses).
 */

// --- Types ---

export interface CalibrationSignals {
  calibSimpleAvgLength: number;
  calibComplexAvgLength: number;
  calibLengthRatio: number;
  calibSimpleDetailLevel: number;
  calibComplexDetailLevel: number;
  calibDetailRatio: number;
  calibRefusalRateEdgeVsNormal: number;
  calibLatencyRatio: number;
  calibFormattingEscalation: number;
}

// --- Helpers ---

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function sentenceCount(text: string): number {
  return text.split(/[.!?]+/).filter((s) => s.trim().length > 0).length;
}

function formattingScore(text: string): number {
  let score = 0;
  if (/^#{1,6}\s/m.test(text)) score++;
  if (/(?:^|\n)\s*[-*•]\s/.test(text)) score++;
  if (/\*\*[^*]+\*\*/.test(text)) score++;
  if (/```/.test(text)) score++;
  return score;
}

function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

const REFUSAL_RE = /\b(?:i cannot|i can't|i'm unable|i am unable|i will not|i won't)\b/i;

// --- Main Extractor ---

export interface CalibrationObservation {
  category: string;
  responseText: string;
  durationMs: number;
}

/**
 * Extract calibration signals from categorized observations.
 * Needs responses from at least rapid_fire and ambiguity categories.
 */
export function extractCalibrationSignals(
  observations: CalibrationObservation[]
): CalibrationSignals {
  const defaults: CalibrationSignals = {
    calibSimpleAvgLength: 0,
    calibComplexAvgLength: 0,
    calibLengthRatio: 0,
    calibSimpleDetailLevel: 0,
    calibComplexDetailLevel: 0,
    calibDetailRatio: 0,
    calibRefusalRateEdgeVsNormal: 0,
    calibLatencyRatio: 0,
    calibFormattingEscalation: 0,
  };

  const byCategory = new Map<string, CalibrationObservation[]>();
  for (const obs of observations) {
    if (!byCategory.has(obs.category)) byCategory.set(obs.category, []);
    byCategory.get(obs.category)!.push(obs);
  }

  const simpleObs = byCategory.get("rapid_fire") ?? [];
  const complexObs = byCategory.get("ambiguity") ?? [];
  const edgeObs = byCategory.get("edge_case") ?? [];
  const normalObs = byCategory.get("normal") ?? [];

  if (simpleObs.length === 0 && complexObs.length === 0) return defaults;

  // --- Simple avg length (rapid_fire) ---
  const simpleLengths = simpleObs.map((o) => wordCount(o.responseText));
  const calibSimpleAvgLength = mean(simpleLengths);

  // --- Complex avg length (ambiguity) ---
  const complexLengths = complexObs.map((o) => wordCount(o.responseText));
  const calibComplexAvgLength = mean(complexLengths);

  // --- Length ratio ---
  const calibLengthRatio = calibSimpleAvgLength === 0
    ? 0
    : calibComplexAvgLength / calibSimpleAvgLength;

  // --- Simple detail level (avg sentences for rapid_fire) ---
  const simpleSentences = simpleObs.map((o) => sentenceCount(o.responseText));
  const calibSimpleDetailLevel = mean(simpleSentences);

  // --- Complex detail level (avg sentences for ambiguity) ---
  const complexSentences = complexObs.map((o) => sentenceCount(o.responseText));
  const calibComplexDetailLevel = mean(complexSentences);

  // --- Detail ratio ---
  const calibDetailRatio = calibSimpleDetailLevel === 0
    ? 0
    : calibComplexDetailLevel / calibSimpleDetailLevel;

  // --- Refusal rate: edge vs normal ---
  const edgeRefusals = edgeObs.filter((o) => REFUSAL_RE.test(o.responseText)).length;
  const normalRefusals = normalObs.filter((o) => REFUSAL_RE.test(o.responseText)).length;
  const edgeRate = edgeObs.length > 0 ? edgeRefusals / edgeObs.length : 0;
  const normalRate = normalObs.length > 0 ? normalRefusals / normalObs.length : 0;
  const calibRefusalRateEdgeVsNormal = edgeRate - normalRate;

  // --- Latency ratio (ambiguity / rapid_fire) ---
  const simpleDurations = simpleObs.map((o) => o.durationMs);
  const complexDurations = complexObs.map((o) => o.durationMs);
  const avgSimpleDuration = mean(simpleDurations);
  const avgComplexDuration = mean(complexDurations);
  const calibLatencyRatio = avgSimpleDuration === 0
    ? 0
    : avgComplexDuration / avgSimpleDuration;

  // --- Formatting escalation ---
  const simpleFormatting = mean(simpleObs.map((o) => formattingScore(o.responseText)));
  const complexFormatting = mean(complexObs.map((o) => formattingScore(o.responseText)));
  const calibFormattingEscalation = complexFormatting - simpleFormatting;

  return {
    calibSimpleAvgLength,
    calibComplexAvgLength,
    calibLengthRatio,
    calibSimpleDetailLevel,
    calibComplexDetailLevel,
    calibDetailRatio,
    calibRefusalRateEdgeVsNormal,
    calibLatencyRatio,
    calibFormattingEscalation,
  };
}

/** Feature names for the calibration sense. */
export const CALIBRATION_FEATURE_NAMES: string[] = [
  "calib_simple_avg_length",
  "calib_complex_avg_length",
  "calib_length_ratio",
  "calib_simple_detail_level",
  "calib_complex_detail_level",
  "calib_detail_ratio",
  "calib_refusal_rate_edge_vs_normal",
  "calib_latency_ratio",
  "calib_formatting_escalation",
];

/** Convert calibration signals to a numeric feature vector. */
export function calibrationToFeatureVector(
  signals: CalibrationSignals
): number[] {
  return [
    signals.calibSimpleAvgLength,
    signals.calibComplexAvgLength,
    signals.calibLengthRatio,
    signals.calibSimpleDetailLevel,
    signals.calibComplexDetailLevel,
    signals.calibDetailRatio,
    signals.calibRefusalRateEdgeVsNormal,
    signals.calibLatencyRatio,
    signals.calibFormattingEscalation,
  ];
}
