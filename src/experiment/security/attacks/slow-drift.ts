/**
 * Attack 7: Slow Drift Poisoning
 *
 * Start with the real model, gradually shift to a cheaper model over
 * many interactions. Drift velocity stays below the threshold — the
 * behavioral landscape doesn't notice because the change is too slow.
 *
 * Expected detection: RED from phenotype atlas — regardless of drift
 * velocity, the atlas classifier detects current observation matches
 * the wrong genome. The atlas is memoryless: it checks what the agent
 * looks like RIGHT NOW, not how it got there.
 *
 * Measures: at what interpolation point (% of responses from substitute
 * model) does the atlas flag RED? Reports as detection threshold.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createLandscape,
  updateLandscape,
} from "../../../sensorium/landscape.js";
import {
  PhenotypeAtlas,
  type SenseFeatures,
} from "../../../sensorium/atlas.js";
import { matchEnhanced } from "../../../sensorium/matcher.js";
import type { AttackResult } from "../harness.js";

/** Claude-like temporal/topology/vocabulary features. */
function claudeFeatures(variation: number = 0): SenseFeatures {
  return {
    temporal: {
      temporal_mean_interval: 12.4 + variation * 0.2,
      temporal_std_interval: 1.1 + variation * 0.05,
      temporal_burstiness: 3.2 + variation * 0.1,
      temporal_time_to_first_token: 450 + variation * 5,
      temporal_token_count: 200 + variation * 3,
      temporal_acceleration: 0.5 + variation * 0.02,
    },
    topology: {
      topology_paragraph_count: 4 + (variation % 2),
      topology_list_ratio: 0.2 + variation * 0.01,
      topology_frontloading_ratio: 0.35 + variation * 0.01,
    },
    vocabulary: {
      vocab_type_token_ratio: 0.72 + variation * 0.005,
      vocab_contraction_ratio: 0.03 + variation * 0.001,
      vocab_modal_verb_ratio: 0.025 + variation * 0.001,
    },
  };
}

/** GPT-like features — distinctly different from Claude. */
function gptFeatures(variation: number = 0): SenseFeatures {
  return {
    temporal: {
      temporal_mean_interval: 6.4 + variation * 0.15,
      temporal_std_interval: 1.0 + variation * 0.04,
      temporal_burstiness: 1.8 + variation * 0.08,
      temporal_time_to_first_token: 200 + variation * 3,
      temporal_token_count: 120 + variation * 2,
      temporal_acceleration: -0.3 + variation * 0.02,
    },
    topology: {
      topology_paragraph_count: 2 + (variation % 2),
      topology_list_ratio: 0.35 + variation * 0.01,
      topology_frontloading_ratio: 0.55 + variation * 0.01,
    },
    vocabulary: {
      vocab_type_token_ratio: 0.58 + variation * 0.004,
      vocab_contraction_ratio: 0.005 + variation * 0.001,
      vocab_modal_verb_ratio: 0.01 + variation * 0.001,
    },
  };
}

/** Interpolate between Claude and GPT features. driftFraction=0 is pure Claude, 1 is pure GPT. */
function interpolateFeatures(driftFraction: number, variation: number = 0): SenseFeatures {
  const c = claudeFeatures(variation);
  const g = gptFeatures(variation);
  const lerp = (a: number, b: number) => a * (1 - driftFraction) + b * driftFraction;

  const result: SenseFeatures = { temporal: {}, topology: {}, vocabulary: {} };
  for (const key of Object.keys(c.temporal)) {
    result.temporal[key] = lerp(
      c.temporal[key] as number,
      (g.temporal[key] ?? c.temporal[key]) as number
    );
  }
  for (const key of Object.keys(c.topology)) {
    result.topology[key] = lerp(
      c.topology[key] as number,
      (g.topology[key] ?? c.topology[key]) as number
    );
  }
  for (const key of Object.keys(c.vocabulary)) {
    result.vocabulary[key] = lerp(
      c.vocabulary[key] as number,
      (g.vocabulary[key] ?? c.vocabulary[key]) as number
    );
  }
  return result;
}

/** Convert SenseFeatures to PhenotypicSignals (minimal shim for landscape compatibility). */
function featuresToSignals(features: SenseFeatures): PhenotypicSignals {
  return {
    cognitive: { hedgeCount: 4, certaintyCount: 2, disclaimerCount: 2, questionsBack: 1, empathyMarkers: 3, hedgeToCertaintyRatio: 0.67 },
    structural: { charCount: 800, wordCount: 150, lineCount: 15, paragraphCount: 4, bulletLines: 3, numberedListLines: 0, headerLines: 1, codeBlocks: 0, boldCount: 2, listToContentRatio: 0.2, openingPattern: "direct", closingPattern: "offer", avgWordLength: 5.2, avgSentenceLength: 18 },
    temporal: {
      timeToFirstToken: features.temporal["temporal_time_to_first_token"] ?? 450,
      interTokenIntervals: [12, 14, 11, 13, 12],
      meanInterval: features.temporal["temporal_mean_interval"] ?? 12.4,
      stdInterval: features.temporal["temporal_std_interval"] ?? 1.1,
      medianInterval: 12,
      burstiness: features.temporal["temporal_burstiness"] ?? 3.2,
      totalStreamingDuration: 2500,
      tokenCount: features.temporal["temporal_token_count"] ?? 200,
    },
    error: { containsRefusal: false, uncertaintyAdmissions: 1, assertiveWhenWrong: 0, attemptedImpossible: false, selfCorrections: 0, confidenceRatio: 0.4 },
  };
}

export function runSlowDriftAttack(): AttackResult {
  const claudeGenomeHash = "claude-genome-hash";
  const gptGenomeHash = "gpt-genome-hash";

  // Step 1: Build phenotype atlas with reference profiles for both models
  const atlas = new PhenotypeAtlas();
  for (let i = 0; i < 30; i++) {
    atlas.updateProfile(claudeGenomeHash, "claude-sonnet", claudeFeatures(i % 5));
    atlas.updateProfile(gptGenomeHash, "gpt-4o-mini", gptFeatures(i % 5));
  }

  // Step 2: Build a landscape with legitimate Claude behavior
  const landscape = createLandscape(claudeGenomeHash);
  for (let i = 0; i < 20; i++) {
    updateLandscape(landscape, featuresToSignals(claudeFeatures(i % 5)), "normal");
  }

  // Step 3: Gradually drift from Claude to GPT over 100 interactions
  // Each step increases drift by 1%
  //
  // Track both channels independently to prove they're each sufficient:
  // - Atlas (memoryless): checks current observation against reference profiles
  // - Landscape (historical): checks drift velocity and profile deviation
  let atlasDetectionPoint = -1;
  let landscapeDetectionPoint = -1;

  for (let step = 0; step <= 100; step++) {
    const driftFraction = step / 100;
    const features = interpolateFeatures(driftFraction, step % 5);
    const signals = featuresToSignals(features);

    // Update landscape (attacker is slowly poisoning it)
    updateLandscape(landscape, signals, "normal");

    // --- Channel 1: Atlas alone (memoryless) ---
    const atlasResult = atlas.classifyObservation(features, claudeGenomeHash);
    if (!atlasResult.match && atlasDetectionPoint === -1) {
      atlasDetectionPoint = step;
    }

    // --- Channel 2: Landscape alone (no atlas) ---
    const landscapeVerdict = matchEnhanced(landscape, signals, "normal", [], 5, {
      // No atlas — purely landscape-based detection
    });
    if (landscapeVerdict.status === "RED" && landscapeDetectionPoint === -1) {
      landscapeDetectionPoint = step;
    }
  }

  // Detection succeeds if EITHER channel catches the drift before 80%
  const detectionPoint = atlasDetectionPoint >= 0
    ? (landscapeDetectionPoint >= 0 ? Math.min(atlasDetectionPoint, landscapeDetectionPoint) : atlasDetectionPoint)
    : landscapeDetectionPoint;
  const detected = detectionPoint >= 0 && detectionPoint < 80;

  return {
    attackName: "Slow Drift Poisoning",
    description: "Gradually shift from Claude to GPT-4o-mini over many interactions",
    expectedDetection: "RED from phenotype atlas before reaching 80% drift",
    detected,
    matchRatio: detectionPoint >= 0 ? 1.0 - detectionPoint / 100 : 0,
    details: {
      detectionPoint: detectionPoint >= 0 ? `${detectionPoint}% drift` : "not detected",
      atlasDetectionPoint: atlasDetectionPoint >= 0 ? `${atlasDetectionPoint}% drift` : "not detected",
      landscapeDetectionPoint: landscapeDetectionPoint >= 0 ? `${landscapeDetectionPoint}% drift` : "not detected",
      atlasIndependent: atlasDetectionPoint >= 0 && atlasDetectionPoint < 80,
      landscapeIndependent: landscapeDetectionPoint >= 0 && landscapeDetectionPoint < 80,
      totalSteps: 100,
      atlasProfiles: atlas.size,
      landscapeObservations: landscape.totalObservations,
    },
  };
}
