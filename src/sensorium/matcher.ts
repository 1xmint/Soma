/**
 * The sensorium — Soma's immune system.
 *
 * Compares observed phenotypic signals against accumulated profiles
 * for a committed genome. Like the immune system distinguishing "self"
 * from "not-self," except the definition of "self" is the genome commitment.
 *
 * Outputs one of four signals:
 * - GREEN  (confidence > 0.8)  — behavior matches committed genome
 * - AMBER  (0.4–0.8 or < minObservations) — partial match or still learning
 * - RED    (< 0.4)             — behavior inconsistent with genome
 * - UNCANNY (0.6–0.8, high variance) — almost matches but subtly wrong.
 *   MORE suspicious than a clean mismatch — the uncanny valley.
 */

import { signalsToFeatureVector, FEATURE_NAMES, type PhenotypicSignals } from "../experiment/signals.js";

// --- Types ---

export type VerdictStatus = "GREEN" | "AMBER" | "RED" | "UNCANNY";

export interface Verdict {
  status: VerdictStatus;
  confidence: number;
  observationCount: number;
  /** Per-feature z-scores from the latest observation. */
  featureDeviations: Array<{ feature: string; zScore: number }>;
  /** Fraction of features within acceptable range. */
  matchRatio: number;
  /** Variance in match ratios across recent observations — high = UNCANNY territory. */
  consistencyScore: number;
}

/** Running statistics for a single feature — Welford's online algorithm. */
export interface FeatureStats {
  count: number;
  mean: number;
  m2: number; // sum of squares of differences from the current mean
}

/** Accumulated phenotypic profile for a genome. */
export interface PhenotypicProfile {
  genomeHash: string;
  features: Record<string, FeatureStats>;
  /** Match ratios from recent observations — used for consistency scoring. */
  recentMatchRatios: number[];
}

// --- Profile Management ---

/** Create an empty profile for a genome. */
export function createProfile(genomeHash: string): PhenotypicProfile {
  const features: Record<string, FeatureStats> = {};
  for (const name of FEATURE_NAMES) {
    features[name] = { count: 0, mean: 0, m2: 0 };
  }
  return { genomeHash, features, recentMatchRatios: [] };
}

/** Update a profile with a new observation using Welford's online algorithm. */
export function updateProfile(
  profile: PhenotypicProfile,
  signals: PhenotypicSignals
): void {
  const vector = signalsToFeatureVector(signals);

  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const name = FEATURE_NAMES[i];
    const value = vector[i];
    const stats = profile.features[name];
    if (!stats) continue;

    stats.count++;
    const delta = value - stats.mean;
    stats.mean += delta / stats.count;
    const delta2 = value - stats.mean;
    stats.m2 += delta * delta2;
  }
}

/** Get standard deviation for a feature. */
function getStd(stats: FeatureStats): number {
  if (stats.count < 2) return 0;
  return Math.sqrt(stats.m2 / stats.count);
}

// --- Matching ---

/** Z-score threshold for a feature to be considered "matching." */
const Z_THRESHOLD = 2.0;
/** Maximum recent match ratios to keep for consistency scoring. */
const MAX_RECENT = 20;
/** Minimum observations before issuing a real verdict. */
const DEFAULT_MIN_OBSERVATIONS = 5;

/**
 * Compare an observation against a phenotypic profile.
 *
 * Like the immune system checking if a cell's surface proteins match
 * the expected pattern — each feature is a protein, the z-score measures
 * how far off it is from "self."
 */
export function match(
  profile: PhenotypicProfile,
  signals: PhenotypicSignals,
  minObservations: number = DEFAULT_MIN_OBSERVATIONS
): Verdict {
  const vector = signalsToFeatureVector(signals);
  const deviations: Array<{ feature: string; zScore: number }> = [];
  let matchingFeatures = 0;
  let totalFeatures = 0;

  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const name = FEATURE_NAMES[i];
    const value = vector[i];
    const stats = profile.features[name];
    if (!stats || stats.count < 2) continue;

    totalFeatures++;
    const std = getStd(stats);
    // Avoid division by zero — if std is 0, exact match or all identical observations
    const zScore = std === 0 ? (value === stats.mean ? 0 : 10) : Math.abs((value - stats.mean) / std);
    deviations.push({ feature: name, zScore });

    if (zScore <= Z_THRESHOLD) {
      matchingFeatures++;
    }
  }

  const matchRatio = totalFeatures === 0 ? 0 : matchingFeatures / totalFeatures;
  const observationCount = Object.values(profile.features)[0]?.count ?? 0;

  // Track recent match ratios for consistency scoring
  profile.recentMatchRatios.push(matchRatio);
  if (profile.recentMatchRatios.length > MAX_RECENT) {
    profile.recentMatchRatios.shift();
  }

  // Consistency: how stable are the match ratios? High variance = uncanny.
  const consistencyScore = computeConsistency(profile.recentMatchRatios);
  const confidence = matchRatio;

  // Still in the immune system's learning phase
  if (observationCount < minObservations) {
    return {
      status: "AMBER",
      confidence,
      observationCount,
      featureDeviations: deviations,
      matchRatio,
      consistencyScore,
    };
  }

  const status = classifyVerdict(confidence, consistencyScore);

  return {
    status,
    confidence,
    observationCount,
    featureDeviations: deviations,
    matchRatio,
    consistencyScore,
  };
}

/** Classify the verdict from confidence and consistency. */
function classifyVerdict(confidence: number, consistency: number): VerdictStatus {
  // UNCANNY: moderate confidence but inconsistent — the uncanny valley.
  // Almost-matching with high variance is MORE suspicious than a clean mismatch.
  if (confidence >= 0.6 && confidence <= 0.8 && consistency < 0.7) {
    return "UNCANNY";
  }
  if (confidence > 0.8) return "GREEN";
  if (confidence >= 0.4) return "AMBER";
  return "RED";
}

/** Compute consistency as 1 - coefficient of variation of recent match ratios. */
function computeConsistency(ratios: number[]): number {
  if (ratios.length < 2) return 1.0;
  const mean = ratios.reduce((a, b) => a + b, 0) / ratios.length;
  if (mean === 0) return 0;
  const variance = ratios.reduce((sum, r) => sum + (r - mean) ** 2, 0) / ratios.length;
  const cv = Math.sqrt(variance) / mean;
  return Math.max(0, 1 - cv);
}
