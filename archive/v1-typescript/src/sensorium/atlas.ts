/**
 * Phenotype Atlas — reference classification (anti-drift defense).
 *
 * In addition to profile-based matching (comparing an agent against its own
 * history), the sensorium maintains a phenotype atlas: reference profiles for
 * all known agent genomes, populated from experiment data and community
 * observations.
 *
 * Every interaction is classified against the atlas independently of the
 * agent's own profile history. The question is not "has this agent changed?"
 * but "what does this agent look like right now?"
 *
 * If the current observation is closer to GPT-4o-mini's reference profile
 * than to Claude's, that's RED — regardless of how the agent's profile
 * evolved to get there.
 *
 * This defeats slow drift poisoning (Attack 7). An attacker who gradually
 * shifts from Claude to GPT-4o-mini over weeks doesn't trigger drift velocity
 * alerts — but the atlas classifier says "this looks like GPT-4o-mini" and
 * flags RED. The check is memoryless and instantaneous, like a biological
 * immune system checking self vs non-self markers.
 *
 * Two independent detection channels work in parallel:
 * - Behavioral landscape: catches sudden changes (historical, profile-based)
 * - Phenotype atlas: catches slow drift (memoryless, reference-based)
 */

import type { FeatureStats } from "./matcher.js";

// ─── Types ───────────────────────────────────────────────────────────────────

/** Welford stats used by atlas reference profiles (same as matcher). */
export type WelfordStats = FeatureStats;

/** A reference profile for a known genome in the atlas. */
export interface ReferenceProfile {
  /** The genome hash this profile describes. */
  genomeHash: string;
  /** Human-readable label (e.g., "claude-sonnet-4", "gpt-4o-mini"). */
  label: string;
  /** Per-sense feature statistics. Keys are feature names. */
  temporal: Record<string, WelfordStats>;
  topology: Record<string, WelfordStats>;
  vocabulary: Record<string, WelfordStats>;
  /** Total observations that built this profile. */
  observationCount: number;
}

/** Features extracted from a single observation, organized by sense. */
export interface SenseFeatures {
  temporal: Record<string, number>;
  topology: Record<string, number>;
  vocabulary: Record<string, number>;
}

/** Result of classifying an observation against the atlas. */
export interface AtlasClassification {
  /** Which reference profile is closest. */
  nearestGenome: string;
  /** Human-readable label of nearest. */
  nearestLabel: string;
  /** Weighted Mahalanobis-like distance to nearest. */
  distance: number;
  /** What the agent claims to be. */
  declaredGenome: string;
  /** Does nearest match declared? */
  match: boolean;
  /** Second-closest genome hash. */
  secondNearest: string;
  /** Second-closest label. */
  secondNearestLabel: string;
  /** Distance to second nearest. */
  secondDistance: number;
  /** Margin = secondDistance - distance. Larger margin = more confident classification. */
  margin: number;
}

/** Sense weights for the weighted classifier. */
export interface SenseWeights {
  temporal: number;
  topology: number;
  vocabulary: number;
}

// ─── Default weights (from CLAUDE.md) ────────────────────────────────────────

export const DEFAULT_SENSE_WEIGHTS: SenseWeights = {
  temporal: 5.0,   // 88.5% standalone — the dominant voice
  topology: 2.0,   // 25.1% standalone — response structure patterns
  vocabulary: 1.0, // 20.2% standalone — word choice distribution
};

// ─── Phenotype Atlas ─────────────────────────────────────────────────────────

export class PhenotypeAtlas {
  private readonly profiles: Map<string, ReferenceProfile> = new Map();
  private readonly weights: SenseWeights;

  constructor(weights?: SenseWeights) {
    this.weights = weights ?? DEFAULT_SENSE_WEIGHTS;
  }

  /** Number of reference profiles in the atlas. */
  get size(): number {
    return this.profiles.size;
  }

  /** Get all genome hashes in the atlas. */
  get genomeHashes(): string[] {
    return [...this.profiles.keys()];
  }

  /** Get a reference profile by genome hash. */
  getProfile(genomeHash: string): ReferenceProfile | undefined {
    return this.profiles.get(genomeHash);
  }

  /**
   * Add or update a reference profile in the atlas.
   * Typically populated from experiment data or community observations.
   */
  setProfile(profile: ReferenceProfile): void {
    this.profiles.set(profile.genomeHash, profile);
  }

  /**
   * Update a reference profile with a new observation using Welford's algorithm.
   * Creates the profile if it doesn't exist.
   */
  updateProfile(genomeHash: string, label: string, features: SenseFeatures): void {
    let profile = this.profiles.get(genomeHash);
    if (!profile) {
      profile = {
        genomeHash,
        label,
        temporal: {},
        topology: {},
        vocabulary: {},
        observationCount: 0,
      };
      this.profiles.set(genomeHash, profile);
    }

    updateStatsMap(profile.temporal, features.temporal);
    updateStatsMap(profile.topology, features.topology);
    updateStatsMap(profile.vocabulary, features.vocabulary);
    profile.observationCount++;
  }

  /**
   * Classify an observation against the atlas.
   *
   * Computes weighted distance to every reference profile and returns
   * the nearest match. The weighting ensures temporal features (5x) dominate
   * the classification, with topology (2x) and vocabulary (1x) refining it.
   *
   * This is memoryless — it doesn't care about the agent's history, only
   * what the agent looks like right now.
   */
  classifyObservation(features: SenseFeatures, declaredGenome: string): AtlasClassification {
    if (this.profiles.size === 0) {
      return {
        nearestGenome: "",
        nearestLabel: "unknown",
        distance: Infinity,
        declaredGenome,
        match: false,
        secondNearest: "",
        secondNearestLabel: "unknown",
        secondDistance: Infinity,
        margin: 0,
      };
    }

    // Compute weighted distance to each reference profile
    const distances: Array<{ genomeHash: string; label: string; distance: number }> = [];

    for (const profile of this.profiles.values()) {
      const temporalDist = computeFeatureDistance(profile.temporal, features.temporal);
      const topologyDist = computeFeatureDistance(profile.topology, features.topology);
      const vocabularyDist = computeFeatureDistance(profile.vocabulary, features.vocabulary);

      // Weighted combination
      const totalWeight = this.weights.temporal + this.weights.topology + this.weights.vocabulary;
      const weightedDist = (
        this.weights.temporal * temporalDist +
        this.weights.topology * topologyDist +
        this.weights.vocabulary * vocabularyDist
      ) / totalWeight;

      distances.push({ genomeHash: profile.genomeHash, label: profile.label, distance: weightedDist });
    }

    // Sort by distance
    distances.sort((a, b) => a.distance - b.distance);

    const nearest = distances[0];
    const second = distances.length > 1 ? distances[1] : { genomeHash: "", label: "unknown", distance: Infinity };

    return {
      nearestGenome: nearest.genomeHash,
      nearestLabel: nearest.label,
      distance: nearest.distance,
      declaredGenome,
      match: nearest.genomeHash === declaredGenome,
      secondNearest: second.genomeHash,
      secondNearestLabel: second.label,
      secondDistance: second.distance,
      margin: second.distance - nearest.distance,
    };
  }

  /** Serialize the atlas to a plain object for persistence. */
  toJSON(): { profiles: ReferenceProfile[]; weights: SenseWeights } {
    return {
      profiles: [...this.profiles.values()],
      weights: this.weights,
    };
  }

  /** Restore an atlas from serialized data. */
  static fromJSON(data: { profiles: ReferenceProfile[]; weights?: SenseWeights }): PhenotypeAtlas {
    const atlas = new PhenotypeAtlas(data.weights);
    for (const profile of data.profiles) {
      atlas.profiles.set(profile.genomeHash, profile);
    }
    return atlas;
  }
}

// ─── Distance Computation ────────────────────────────────────────────────────

/**
 * Compute the average standardized distance between an observation and a
 * reference profile across all shared features.
 *
 * Uses a Mahalanobis-like metric: for each feature, compute the z-score
 * (distance in standard deviations from the reference mean). The overall
 * distance is the mean absolute z-score across features.
 *
 * Features with fewer than 3 observations are skipped (insufficient data).
 */
function computeFeatureDistance(
  reference: Record<string, WelfordStats>,
  observed: Record<string, number>
): number {
  let totalZ = 0;
  let featureCount = 0;

  for (const [name, value] of Object.entries(observed)) {
    const stats = reference[name];
    if (!stats || stats.count < 3) continue;

    const std = getStd(stats);
    const z = std > 0
      ? Math.abs((value - stats.mean) / std)
      : (value === stats.mean ? 0 : 10); // If no variance, exact match or max distance

    totalZ += z;
    featureCount++;
  }

  return featureCount > 0 ? totalZ / featureCount : Infinity;
}

/** Get standard deviation from Welford stats. */
function getStd(stats: WelfordStats): number {
  if (stats.count < 2) return 0;
  return Math.sqrt(stats.m2 / stats.count);
}

// ─── Welford Update ──────────────────────────────────────────────────────────

/**
 * Update a stats map with new observation values using Welford's algorithm.
 */
function updateStatsMap(
  statsMap: Record<string, WelfordStats>,
  observations: Record<string, number>
): void {
  for (const [name, value] of Object.entries(observations)) {
    let stats = statsMap[name];
    if (!stats) {
      stats = { count: 0, mean: 0, m2: 0 };
      statsMap[name] = stats;
    }

    stats.count++;
    const delta = value - stats.mean;
    stats.mean += delta / stats.count;
    const delta2 = value - stats.mean;
    stats.m2 += delta * delta2;
  }
}
