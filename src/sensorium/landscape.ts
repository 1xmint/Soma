/**
 * Behavioral Landscape — multi-dimensional identity map.
 *
 * Instead of a flat profile that averages all behavior, the landscape
 * maintains per-category profiles. An agent behaves differently on
 * different tasks — that's not noise, the PATTERN of variation IS
 * the identity.
 *
 * Uses landscape when sufficient per-category data exists (>5 per category).
 * Falls back to flat profile for new agents.
 */

import {
  signalsToFeatureVector,
  FEATURE_NAMES,
  type PhenotypicSignals,
} from "../experiment/signals.js";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Running statistics for a single feature — Welford's online algorithm. */
export interface FeatureStats {
  count: number;
  mean: number;
  m2: number; // sum of squares of differences from the current mean
}

/** Per-category behavioral profile. */
export interface CategoryProfile {
  category: string;
  featureStats: Record<string, FeatureStats>;
  observationCount: number;
}

/** How behavior shifts between task types. */
export interface TransitionSignature {
  fromCategory: string;
  toCategory: string;
  featureDelta: Record<string, number>;
  observationCount: number;
}

/** The full behavioral landscape — identity as a multi-dimensional map. */
export interface BehavioralLandscape {
  genomeHash: string;
  /** Per-category profiles — how the agent behaves on each task type. */
  categories: Map<string, CategoryProfile>;
  /** Cross-category stability metrics. */
  crossCategoryStability: Record<string, number>;
  /** How behavior shifts between task types. */
  transitions: TransitionSignature[];
  /** Flat profile across all categories (fallback for new agents). */
  flatFeatures: Record<string, FeatureStats>;
  /** Total observations across all categories. */
  totalObservations: number;
  /** Profile maturity based on observation depth. */
  maturity: "embryonic" | "juvenile" | "adult" | "elder";
  /** History of observation counts for drift detection. */
  observationTimestamps: number[];
}

// ─── Constants ──────────────────────────────────────────────────────────────

/** Minimum observations per category before using category-specific profiles. */
const MIN_CATEGORY_OBSERVATIONS = 5;

/** Maturity thresholds. */
const JUVENILE_THRESHOLD = 10;
const ADULT_THRESHOLD = 50;
const ELDER_THRESHOLD = 200;

// ─── Landscape Management ───────────────────────────────────────────────────

/** Create an empty landscape for a genome. */
export function createLandscape(genomeHash: string): BehavioralLandscape {
  const flatFeatures: Record<string, FeatureStats> = {};
  for (const name of FEATURE_NAMES) {
    flatFeatures[name] = { count: 0, mean: 0, m2: 0 };
  }
  return {
    genomeHash,
    categories: new Map(),
    crossCategoryStability: {},
    transitions: [],
    flatFeatures,
    totalObservations: 0,
    maturity: "embryonic",
    observationTimestamps: [],
  };
}

/** Update the landscape with a new observation. */
export function updateLandscape(
  landscape: BehavioralLandscape,
  signals: PhenotypicSignals,
  category: string,
  previousCategory?: string
): void {
  const vector = signalsToFeatureVector(signals);

  // Update flat profile (always)
  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    welfordUpdate(landscape.flatFeatures[FEATURE_NAMES[i]], vector[i]);
  }

  // Update category profile
  if (!landscape.categories.has(category)) {
    const featureStats: Record<string, FeatureStats> = {};
    for (const name of FEATURE_NAMES) {
      featureStats[name] = { count: 0, mean: 0, m2: 0 };
    }
    landscape.categories.set(category, {
      category,
      featureStats,
      observationCount: 0,
    });
  }
  const catProfile = landscape.categories.get(category)!;
  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    welfordUpdate(catProfile.featureStats[FEATURE_NAMES[i]], vector[i]);
  }
  catProfile.observationCount++;

  // Update transition signature
  if (previousCategory && previousCategory !== category) {
    updateTransition(landscape, previousCategory, category, vector);
  }

  landscape.totalObservations++;
  landscape.observationTimestamps.push(Date.now());

  // Update maturity
  landscape.maturity = computeMaturity(landscape.totalObservations);

  // Recompute cross-category stability
  if (landscape.categories.size >= 2) {
    landscape.crossCategoryStability = computeCrossCategoryStability(landscape);
  }
}

// ─── Landscape Matching ─────────────────────────────────────────────────────

/** Z-score threshold for a feature to be considered "matching." */
const Z_THRESHOLD = 2.0;

/**
 * Match an observation against the landscape.
 *
 * Uses category-specific profile if available (>5 observations for that category).
 * Falls back to flat profile otherwise.
 */
export function matchLandscape(
  landscape: BehavioralLandscape,
  signals: PhenotypicSignals,
  category: string
): LandscapeMatchResult {
  const vector = signalsToFeatureVector(signals);

  // Choose profile: category-specific if mature enough, else flat
  const catProfile = landscape.categories.get(category);
  const useCategoryProfile = catProfile && catProfile.observationCount >= MIN_CATEGORY_OBSERVATIONS;
  const profile = useCategoryProfile ? catProfile.featureStats : landscape.flatFeatures;

  const deviations: Array<{ feature: string; zScore: number }> = [];
  let matchingFeatures = 0;
  let totalFeatures = 0;

  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const name = FEATURE_NAMES[i];
    const value = vector[i];
    const stats = profile[name];
    if (!stats || stats.count < 2) continue;

    totalFeatures++;
    const std = getStd(stats);
    const zScore = std === 0 ? (value === stats.mean ? 0 : 10) : Math.abs((value - stats.mean) / std);
    deviations.push({ feature: name, zScore });

    if (zScore <= Z_THRESHOLD) {
      matchingFeatures++;
    }
  }

  const matchRatio = totalFeatures === 0 ? 0 : matchingFeatures / totalFeatures;

  return {
    matchRatio,
    featureDeviations: deviations,
    usedCategoryProfile: useCategoryProfile ?? false,
    landscapeDepth: landscape.categories.size,
    maturity: landscape.maturity,
    totalObservations: landscape.totalObservations,
  };
}

export interface LandscapeMatchResult {
  matchRatio: number;
  featureDeviations: Array<{ feature: string; zScore: number }>;
  usedCategoryProfile: boolean;
  landscapeDepth: number;
  maturity: "embryonic" | "juvenile" | "adult" | "elder";
  totalObservations: number;
}

// ─── Drift Detection ────────────────────────────────────────────────────────

/**
 * Compute drift velocity — rate of profile change over recent observations.
 *
 * Low drift = healthy. Sudden high drift = suspicious.
 * Measured as average absolute z-score of recent observations against the profile.
 */
export function computeDriftVelocity(
  landscape: BehavioralLandscape,
  recentResults: LandscapeMatchResult[],
  windowSize: number = 10
): number {
  const recent = recentResults.slice(-windowSize);
  if (recent.length < 2) return 0;

  // Average (1 - matchRatio) over the window — higher = more drift
  const avgMismatch = recent.reduce((sum, r) => sum + (1 - r.matchRatio), 0) / recent.length;

  // Compare first half to second half of window
  const mid = Math.floor(recent.length / 2);
  const firstHalf = recent.slice(0, mid);
  const secondHalf = recent.slice(mid);
  const firstAvg = firstHalf.reduce((s, r) => s + r.matchRatio, 0) / firstHalf.length;
  const secondAvg = secondHalf.reduce((s, r) => s + r.matchRatio, 0) / secondHalf.length;

  // Drift = magnitude of change between halves
  return Math.abs(secondAvg - firstAvg) + avgMismatch * 0.1;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Welford's online algorithm — update running mean and variance. */
function welfordUpdate(stats: FeatureStats, value: number): void {
  stats.count++;
  const delta = value - stats.mean;
  stats.mean += delta / stats.count;
  const delta2 = value - stats.mean;
  stats.m2 += delta * delta2;
}

/** Get standard deviation from Welford stats. */
function getStd(stats: FeatureStats): number {
  if (stats.count < 2) return 0;
  return Math.sqrt(stats.m2 / stats.count);
}

/** Compute profile maturity. */
function computeMaturity(
  totalObservations: number
): "embryonic" | "juvenile" | "adult" | "elder" {
  if (totalObservations >= ELDER_THRESHOLD) return "elder";
  if (totalObservations >= ADULT_THRESHOLD) return "adult";
  if (totalObservations >= JUVENILE_THRESHOLD) return "juvenile";
  return "embryonic";
}

/** Update a transition signature. */
function updateTransition(
  landscape: BehavioralLandscape,
  fromCategory: string,
  toCategory: string,
  currentVector: number[]
): void {
  let transition = landscape.transitions.find(
    (t) => t.fromCategory === fromCategory && t.toCategory === toCategory
  );
  if (!transition) {
    transition = {
      fromCategory,
      toCategory,
      featureDelta: {},
      observationCount: 0,
    };
    landscape.transitions.push(transition);
  }

  // Compute delta between current observation and the from-category mean
  const fromProfile = landscape.categories.get(fromCategory);
  if (fromProfile && fromProfile.observationCount > 0) {
    for (let i = 0; i < FEATURE_NAMES.length; i++) {
      const name = FEATURE_NAMES[i];
      const fromStats = fromProfile.featureStats[name];
      if (fromStats && fromStats.count > 0) {
        const delta = currentVector[i] - fromStats.mean;
        // Running average of deltas
        const prevDelta = transition.featureDelta[name] ?? 0;
        const n = transition.observationCount + 1;
        transition.featureDelta[name] = prevDelta + (delta - prevDelta) / n;
      }
    }
  }
  transition.observationCount++;
}

/** Compute cross-category stability (std of per-category feature means). */
function computeCrossCategoryStability(
  landscape: BehavioralLandscape
): Record<string, number> {
  const stability: Record<string, number> = {};
  const categories = [...landscape.categories.values()].filter(
    (c) => c.observationCount >= MIN_CATEGORY_OBSERVATIONS
  );

  if (categories.length < 2) return stability;

  for (const name of FEATURE_NAMES) {
    const means = categories.map((c) => c.featureStats[name]?.mean ?? 0);
    const avg = means.reduce((a, b) => a + b, 0) / means.length;
    const variance = means.reduce((sum, m) => sum + (m - avg) ** 2, 0) / means.length;
    stability[name] = Math.sqrt(variance);
  }

  return stability;
}
