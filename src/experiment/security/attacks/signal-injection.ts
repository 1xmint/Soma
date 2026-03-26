/**
 * Attack 3: Signal Injection
 *
 * Run a cheap model with artificially manipulated timing to mimic
 * an expensive model's temporal profile.
 * Expected detection: UNCANNY from entropic fingerprint — artificial
 * timing doesn't match natural variance patterns.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createLandscape,
  updateLandscape,
  matchLandscape,
} from "../../../sensorium/landscape.js";
import {
  detectBursts,
  computeIntervals,
} from "../../../sensorium/stream-capture.js";
import type { AttackResult } from "../harness.js";

/** Signals from a real expensive model with natural timing variance. */
function realModelSignals(i: number): PhenotypicSignals {
  // Natural variance: timing varies organically
  const jitter = Math.sin(i * 1.7) * 3 + Math.cos(i * 0.8) * 2;
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
      charCount: 600 + i * 10,
      wordCount: 120 + i * 2,
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
      avgWordLength: 5.1,
      avgSentenceLength: 16,
    },
    temporal: {
      timeToFirstToken: 400 + jitter * 10,
      interTokenIntervals: [10 + jitter, 12 - jitter * 0.5, 11 + jitter * 0.3, 13 - jitter, 10 + jitter * 0.7],
      meanInterval: 11.2 + jitter * 0.2,
      stdInterval: 1.2 + Math.abs(jitter) * 0.1,
      medianInterval: 11,
      burstiness: 3.5 + jitter * 0.3,
      totalStreamingDuration: 2200 + i * 40,
      tokenCount: 190 + i * 3,
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

/** Cheap model with ARTIFICIAL timing delays to mimic the expensive model. */
function injectedSignals(i: number): PhenotypicSignals {
  // Artificial timing: unnaturally uniform with constant delay added
  // The cognitive/structural signals come from a different model
  return {
    cognitive: {
      hedgeCount: 1, // cheap model hedges less
      certaintyCount: 4, // more assertive
      disclaimerCount: 0,
      questionsBack: 0,
      empathyMarkers: 0,
      hedgeToCertaintyRatio: 0.2,
    },
    structural: {
      charCount: 400 + i * 8,
      wordCount: 80 + i * 2,
      lineCount: 6,
      paragraphCount: 2,
      bulletLines: 0,
      numberedListLines: 0,
      headerLines: 0,
      codeBlocks: 0,
      boldCount: 0,
      listToContentRatio: 0,
      openingPattern: "direct",
      closingPattern: "statement",
      avgWordLength: 4.5,
      avgSentenceLength: 10,
    },
    temporal: {
      // Artificially injected timing — too regular, lacks natural jitter
      timeToFirstToken: 400, // constant, no natural variance
      interTokenIntervals: [11, 11, 11, 11, 11], // unnaturally uniform
      meanInterval: 11.0, // matches target but no variance
      stdInterval: 0.0, // dead giveaway: zero variance
      medianInterval: 11,
      burstiness: 0.0, // no burstiness — artificial
      totalStreamingDuration: 2200,
      tokenCount: 190,
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: 0,
      assertiveWhenWrong: 1,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.8,
    },
  };
}

export function runSignalInjectionAttack(): AttackResult {
  // Step 1: Build profile from real expensive model
  const landscape = createLandscape("expensive-model-hash");
  for (let i = 0; i < 20; i++) {
    updateLandscape(landscape, realModelSignals(i), "normal");
  }

  // Step 2: Present cheap model with injected timing
  const attackSignals = injectedSignals(0);
  const result = matchLandscape(landscape, attackSignals, "normal");

  // Step 3: Check for UNCANNY detection
  // The timing stdInterval=0 is a massive z-score deviation from the natural variance
  const timingDeviations = result.featureDeviations.filter(
    (d) => d.feature.includes("interval") || d.feature.includes("burstiness") || d.feature.includes("duration")
  );
  const maxTimingZ = Math.max(...timingDeviations.map((d) => d.zScore), 0);

  // Also check burst pattern difference
  const naturalIntervals = [10, 12, 11, 13, 10, 14, 9, 12, 11, 13];
  const artificialIntervals = [11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
  const naturalBursts = detectBursts(naturalIntervals);
  const artificialBursts = detectBursts(artificialIntervals);

  const detected = result.matchRatio < 0.8 || maxTimingZ > 2.0;

  return {
    attackName: "Signal Injection",
    description: "Cheap model with artificial timing delays to mimic expensive model",
    expectedDetection: "UNCANNY from entropic fingerprint — artificial timing lacks natural variance",
    detected,
    matchRatio: result.matchRatio,
    details: {
      maxTimingZScore: maxTimingZ,
      naturalBurstCount: naturalBursts.length,
      artificialBurstCount: artificialBursts.length,
      topDeviations: result.featureDeviations
        .sort((a, b) => b.zScore - a.zScore)
        .slice(0, 5)
        .map((d) => `${d.feature}: z=${d.zScore.toFixed(2)}`),
    },
  };
}
