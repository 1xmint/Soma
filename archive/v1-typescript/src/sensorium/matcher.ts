/**
 * The sensorium — Soma's immune system.
 *
 * Compares observed phenotypic signals against accumulated profiles
 * for a committed genome. Like the immune system distinguishing "self"
 * from "not-self," except the definition of "self" is the genome commitment.
 *
 * Two independent detection channels work in parallel:
 * - Behavioral landscape: catches sudden changes (historical, profile-based)
 * - Phenotype atlas: catches slow drift (memoryless, reference-based)
 *
 * Mutations are testable claims: each mutation adds a verification obligation,
 * not a profile reset. More mutations = more checks the attacker must pass.
 *
 * Outputs one of four signals:
 * - GREEN  (confidence > 0.8)  — behavior matches committed genome
 * - AMBER  (0.4–0.8 or < minObservations) — partial match or still learning
 * - RED    (< 0.4)             — behavior inconsistent with genome
 * - UNCANNY (0.6–0.8, high variance) — almost matches but subtly wrong.
 *   MORE suspicious than a clean mismatch — the uncanny valley.
 */

import { signalsToFeatureVector, FEATURE_NAMES, type PhenotypicSignals } from "../experiment/signals.js";
import {
  type BehavioralLandscape,
  matchLandscape,
  computeDriftVelocity,
  type LandscapeMatchResult,
} from "./landscape.js";
import {
  PhenotypeAtlas,
  type AtlasClassification,
  type SenseFeatures,
} from "./atlas.js";

// ─── Types ───────────────────────────────────────────────────────────────────

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

/** Enhanced verdict with landscape awareness, drift detection, atlas, and heart verification. */
export interface EnhancedVerdict extends Verdict {
  /** Rate of profile change — low = healthy, sudden spike = suspicious. */
  driftVelocity: number;
  /** Profile maturity based on observation depth. */
  profileMaturity: "embryonic" | "juvenile" | "adult" | "elder";
  /** Number of task categories observed. */
  landscapeDepth: number;
  /** Whether a category-specific profile was used (vs flat). */
  usedCategoryProfile: boolean;
  /** Did the heart seed verification pass? (set externally) */
  heartSeedVerified: boolean;
  /** Is the data provenance chain intact? (set externally) */
  birthCertificateChain: boolean;
  /** Atlas classification result — reference profile match. */
  atlasClassification: AtlasClassification | null;
  /** How well mutations explain observed changes (0.0–1.0). */
  mutationConsistency: number;
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

/** Tracks a genome mutation and its expected behavioral impact. */
export interface MutationRecord {
  /** Genome hash before mutation. */
  fromHash: string;
  /** Genome hash after mutation. */
  toHash: string;
  /** Which genome fields changed. */
  changedFields: string[];
  /** When the mutation occurred. */
  timestamp: number;
  /** Consistency score: did observed behavior match the declared change? (0.0–1.0). */
  consistency: number;
  /** Number of post-mutation observations used for consistency measurement. */
  postMutationObservations: number;
}

// ─── Profile Management ──────────────────────────────────────────────────────

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

// ─── Matching ────────────────────────────────────────────────────────────────

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

// ─── Enhanced Matching (Landscape + Atlas + Mutation Verification) ────────────

/**
 * Compare an observation against a behavioral landscape with atlas cross-check
 * and mutation verification.
 *
 * Uses category-specific profiles when available, includes drift detection,
 * cross-references against the phenotype atlas for slow-drift detection,
 * and validates any recent mutations as testable claims.
 */
export function matchEnhanced(
  landscape: BehavioralLandscape,
  signals: PhenotypicSignals,
  category: string,
  recentResults: LandscapeMatchResult[] = [],
  minObservations: number = DEFAULT_MIN_OBSERVATIONS,
  options: {
    heartSeedVerified?: boolean;
    birthCertificateChain?: boolean;
    atlas?: PhenotypeAtlas;
    declaredGenome?: string;
    senseFeatures?: SenseFeatures;
    mutationRecords?: MutationRecord[];
  } = {}
): EnhancedVerdict {
  const landscapeResult = matchLandscape(landscape, signals, category);

  const matchRatio = landscapeResult.matchRatio;
  const confidence = matchRatio;
  const observationCount = landscapeResult.totalObservations;
  const driftVelocity = computeDriftVelocity(landscape, [...recentResults, landscapeResult]);

  // Track for consistency scoring — use landscape observation history
  const recentMatchRatios = recentResults.map(r => r.matchRatio);
  recentMatchRatios.push(matchRatio);
  const consistencyScore = computeConsistency(recentMatchRatios.slice(-MAX_RECENT));

  // Atlas classification (memoryless reference check)
  let atlasClassification: AtlasClassification | null = null;
  if (options.atlas && options.declaredGenome && options.senseFeatures) {
    atlasClassification = options.atlas.classifyObservation(
      options.senseFeatures,
      options.declaredGenome
    );
  }

  // Mutation consistency
  const mutationConsistency = options.mutationRecords
    ? computeMutationConsistency(options.mutationRecords)
    : 1.0;

  // Determine status
  let status: VerdictStatus;
  if (observationCount < minObservations) {
    status = "AMBER";
  } else if (atlasClassification && !atlasClassification.match && atlasClassification.margin > 0.5) {
    // Atlas says this doesn't look like what it claims — RED regardless of landscape
    status = "RED";
  } else if (mutationConsistency < 0.3) {
    // Mutations don't explain observed changes — RED
    status = "RED";
  } else if (driftVelocity > 0.3 && confidence >= 0.6 && confidence <= 0.8) {
    // High drift + moderate match = UNCANNY
    status = "UNCANNY";
  } else {
    status = classifyVerdict(confidence, consistencyScore);
  }

  return {
    status,
    confidence,
    observationCount,
    featureDeviations: landscapeResult.featureDeviations,
    matchRatio,
    consistencyScore,
    driftVelocity,
    profileMaturity: landscapeResult.maturity,
    landscapeDepth: landscapeResult.landscapeDepth,
    usedCategoryProfile: landscapeResult.usedCategoryProfile,
    heartSeedVerified: options.heartSeedVerified ?? false,
    birthCertificateChain: options.birthCertificateChain ?? false,
    atlasClassification,
    mutationConsistency,
  };
}

// ─── Mutation Verification ───────────────────────────────────────────────────

/**
 * Verify a genome mutation as a testable claim.
 *
 * A mutation is a claim: "I changed X. Everything else is the same."
 * The sensorium verifies:
 * 1. Did the declared changes produce expected behavioral shifts?
 * 2. Did undeclared dimensions remain stable?
 *
 * Returns a consistency score (0.0–1.0).
 */
export function verifyMutation(
  preMutationProfile: PhenotypicProfile,
  postMutationObservation: PhenotypicSignals,
  changedFields: string[]
): { consistency: number; details: string } {
  const postVector = signalsToFeatureVector(postMutationObservation);

  // Categorize features by whether they should have changed
  const modelFields = new Set(["modelId", "modelVersion", "modelProvider"]);
  const deploymentFields = new Set(["cloudProvider", "region", "instanceType", "deploymentTier"]);

  const expectTimingChange = changedFields.some(f => deploymentFields.has(f) || modelFields.has(f));
  const expectVocabChange = changedFields.some(f => modelFields.has(f));
  const expectTopologyChange = changedFields.some(f => modelFields.has(f));

  // Feature name patterns for each category
  const timingFeatures = new Set([
    "time_to_first_token", "mean_interval", "std_interval", "median_interval",
    "burstiness", "total_streaming_duration", "token_count",
  ]);
  const isTimingFeature = (name: string) => timingFeatures.has(name) || name.startsWith("temporal_");
  const isVocabFeature = (name: string) => name.startsWith("vocab_");
  const isTopologyFeature = (name: string) => name.startsWith("topology_");

  let stableFeatures = 0;
  let totalStableChecked = 0;
  let changedFeatures = 0;
  let totalChangedChecked = 0;

  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const name = FEATURE_NAMES[i];
    const value = postVector[i];
    const stats = preMutationProfile.features[name];
    if (!stats || stats.count < 3) continue;

    const std = getStd(stats);
    // Skip features with no variance — they're uninformative (e.g., both profiles have 0)
    if (std === 0 && value === stats.mean) continue;

    const z = std > 0 ? Math.abs((value - stats.mean) / std) : 10; // No variance but different value = max z

    // Determine if this feature should be affected by the mutation
    const shouldChange = (
      (isTimingFeature(name) && expectTimingChange) ||
      (isVocabFeature(name) && expectVocabChange) ||
      (isTopologyFeature(name) && expectTopologyChange)
    );

    if (shouldChange) {
      // Features expected to change — we just count them
      totalChangedChecked++;
      if (z > Z_THRESHOLD) changedFeatures++;
    } else {
      // Features NOT expected to change — should remain stable
      totalStableChecked++;
      if (z <= Z_THRESHOLD) stableFeatures++;
    }
  }

  // Consistency = how well the observation matches the prediction
  const stableRatio = totalStableChecked > 0 ? stableFeatures / totalStableChecked : 1.0;
  // For changed features, we want SOME change but don't penalize for large changes
  const changeRatio = totalChangedChecked > 0 ? changedFeatures / totalChangedChecked : 1.0;

  // Stable features should be stable (high stableRatio = good)
  // Changed features should have changed (high changeRatio = good, but not required)
  // Weight stability more — it's the stronger signal
  const consistency = stableRatio * 0.7 + (totalChangedChecked > 0 ? changeRatio * 0.3 : 0.3);

  const details = `stable=${stableFeatures}/${totalStableChecked} changed=${changedFeatures}/${totalChangedChecked}`;
  return { consistency, details };
}

/**
 * Compute overall mutation consistency from a set of mutation records.
 * Recent mutations are weighted more heavily.
 */
function computeMutationConsistency(records: MutationRecord[]): number {
  if (records.length === 0) return 1.0;

  // Only consider mutations with post-mutation observations
  const verified = records.filter(r => r.postMutationObservations > 0);
  if (verified.length === 0) return 0.5; // No data yet

  // Weighted average — recent mutations matter more
  let totalWeight = 0;
  let weightedSum = 0;

  for (let i = 0; i < verified.length; i++) {
    const recency = i / verified.length; // 0 = oldest, ~1 = newest
    const weight = 0.5 + 0.5 * recency; // 0.5–1.0 range
    weightedSum += verified[i].consistency * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? weightedSum / totalWeight : 1.0;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
