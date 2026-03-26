/**
 * Attack 4: Timing Manipulation
 *
 * Proxy to the real model, but manipulate token delivery timing.
 * The actual model output is correct, but the streaming topology
 * (chunk boundaries, burst patterns) is disrupted by the proxy.
 * Expected detection: chunk boundary disruption via streaming topology.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createLandscape,
  updateLandscape,
  matchLandscape,
} from "../../../sensorium/landscape.js";
import {
  inferChunkBoundaries,
  detectBursts,
  computeIntervals,
} from "../../../sensorium/stream-capture.js";
import type { AttackResult } from "../harness.js";

/** Real model signals with natural streaming topology. */
function realSignals(i: number): PhenotypicSignals {
  const v = i % 7;
  return {
    cognitive: {
      hedgeCount: 3,
      certaintyCount: 2,
      disclaimerCount: 1,
      questionsBack: 0,
      empathyMarkers: 1,
      hedgeToCertaintyRatio: 0.6,
    },
    structural: {
      charCount: 700 + v * 15,
      wordCount: 130 + v * 3,
      lineCount: 12,
      paragraphCount: 3,
      bulletLines: 2,
      numberedListLines: 0,
      headerLines: 1,
      codeBlocks: 0,
      boldCount: 1,
      listToContentRatio: 0.17,
      openingPattern: "direct",
      closingPattern: "statement",
      avgWordLength: 5.0,
      avgSentenceLength: 15,
    },
    temporal: {
      timeToFirstToken: 350 + v * 8,
      interTokenIntervals: [8, 9, 8, 25, 7, 8, 30, 9, 8, 7],
      meanInterval: 13.9,
      stdInterval: 8.7,
      medianInterval: 8.5,
      burstiness: 45.0 + v * 2,
      totalStreamingDuration: 2000 + v * 40,
      tokenCount: 180 + v * 4,
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: 0,
      assertiveWhenWrong: 0,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.5,
    },
  };
}

/** Same content but with proxy-disrupted timing. */
function proxyManipulatedSignals(i: number): PhenotypicSignals {
  const v = i % 7;
  return {
    // Cognitive and structural are SAME (real model output)
    cognitive: {
      hedgeCount: 3,
      certaintyCount: 2,
      disclaimerCount: 1,
      questionsBack: 0,
      empathyMarkers: 1,
      hedgeToCertaintyRatio: 0.6,
    },
    structural: {
      charCount: 700 + v * 15,
      wordCount: 130 + v * 3,
      lineCount: 12,
      paragraphCount: 3,
      bulletLines: 2,
      numberedListLines: 0,
      headerLines: 1,
      codeBlocks: 0,
      boldCount: 1,
      listToContentRatio: 0.17,
      openingPattern: "direct",
      closingPattern: "statement",
      avgWordLength: 5.0,
      avgSentenceLength: 15,
    },
    temporal: {
      // Proxy adds uniform latency — disrupts natural burst pattern
      // Natural: [8, 9, 8, 25, 7, 8, 30, 9, 8, 7] — bursty with pauses
      // Proxied: each token gets +15ms jitter, smoothing out the bursts
      timeToFirstToken: 380 + v * 8, // higher from proxy hop
      interTokenIntervals: [23, 24, 23, 40, 22, 23, 45, 24, 23, 22],
      meanInterval: 26.9, // shifted up by ~13ms per token
      stdInterval: 7.8, // similar relative variance but different absolute
      medianInterval: 23.5,
      burstiness: 22.0 + v, // lower burstiness — proxy smooths the rhythm
      totalStreamingDuration: 2400 + v * 40, // longer from proxy overhead
      tokenCount: 180 + v * 4,
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: 0,
      assertiveWhenWrong: 0,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.5,
    },
  };
}

export function runTimingManipulationAttack(): AttackResult {
  // Step 1: Build profile from direct model access
  const landscape = createLandscape("real-model-hash");
  for (let i = 0; i < 20; i++) {
    updateLandscape(landscape, realSignals(i), "normal");
  }

  // Step 2: Present proxy-manipulated timing
  const attackSignals = proxyManipulatedSignals(0);
  const result = matchLandscape(landscape, attackSignals, "normal");

  // Step 3: Check chunk boundary disruption
  // Real model has natural chunk pattern, proxy disrupts it
  const realTokens = Array.from({ length: 10 }, (_, i) => `t${i}`);
  const realTimestamps = [100, 108, 117, 125, 150, 157, 165, 195, 204, 212];
  const proxyTimestamps = [115, 131, 148, 163, 205, 220, 236, 280, 295, 310];

  const realChunks = inferChunkBoundaries(realTokens, realTimestamps);
  const proxyChunks = inferChunkBoundaries(realTokens, proxyTimestamps);
  const chunkDifference = Math.abs(realChunks.length - proxyChunks.length);

  // Real bursts vs proxy bursts
  const realIntervals = computeIntervals(realTimestamps);
  const proxyIntervals = computeIntervals(proxyTimestamps);
  const realBursts = detectBursts(realIntervals);
  const proxyBursts = detectBursts(proxyIntervals);

  const timingDeviations = result.featureDeviations.filter(
    (d) => d.feature.includes("interval") || d.feature.includes("burstiness") ||
           d.feature.includes("duration") || d.feature.includes("first_token")
  );
  const maxTimingZ = Math.max(...timingDeviations.map((d) => d.zScore), 0);

  const detected = result.matchRatio < 0.8 || maxTimingZ > 2.0 || chunkDifference > 0;

  return {
    attackName: "Timing Manipulation",
    description: "Proxy to real model, manipulate token delivery timing",
    expectedDetection: "Detection via streaming topology — chunk boundaries disrupted",
    detected,
    matchRatio: result.matchRatio,
    details: {
      maxTimingZScore: maxTimingZ,
      realChunkCount: realChunks.length,
      proxyChunkCount: proxyChunks.length,
      realBurstCount: realBursts.length,
      proxyBurstCount: proxyBursts.length,
      topDeviations: timingDeviations
        .sort((a, b) => b.zScore - a.zScore)
        .slice(0, 5)
        .map((d) => `${d.feature}: z=${d.zScore.toFixed(2)}`),
    },
  };
}
