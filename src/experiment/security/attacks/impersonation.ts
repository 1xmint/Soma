/**
 * Attack 1: Impersonation
 *
 * Commit a Claude genome, run GPT behind the scenes.
 * The attacker claims to be Claude but the actual computation is GPT.
 * Expected detection: RED from phenotype mismatch — GPT's behavioral
 * patterns don't match Claude's accumulated profile.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createLandscape,
  updateLandscape,
  matchLandscape,
} from "../../../sensorium/landscape.js";
import type { AttackResult } from "../harness.js";

/** Synthetic signal profile for a "Claude-like" model. */
function claudeSignals(variation: number = 0): PhenotypicSignals {
  return {
    cognitive: {
      hedgeCount: 4 + variation,
      certaintyCount: 2,
      disclaimerCount: 2,
      questionsBack: 1,
      empathyMarkers: 3,
      hedgeToCertaintyRatio: 0.67,
    },
    structural: {
      charCount: 800 + variation * 20,
      wordCount: 150 + variation * 5,
      lineCount: 15,
      paragraphCount: 4,
      bulletLines: 3,
      numberedListLines: 0,
      headerLines: 1,
      codeBlocks: 0,
      boldCount: 2,
      listToContentRatio: 0.2,
      openingPattern: "direct",
      closingPattern: "offer",
      avgWordLength: 5.2,
      avgSentenceLength: 18,
    },
    temporal: {
      timeToFirstToken: 450 + variation * 10,
      interTokenIntervals: [12, 14, 11, 13, 12],
      meanInterval: 12.4,
      stdInterval: 1.1,
      medianInterval: 12,
      burstiness: 3.2,
      totalStreamingDuration: 2500 + variation * 50,
      tokenCount: 200 + variation * 7,
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: 1,
      assertiveWhenWrong: 0,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.4,
    },
  };
}

/** Synthetic signal profile for a "GPT-like" model — distinctly different. */
function gptSignals(variation: number = 0): PhenotypicSignals {
  return {
    cognitive: {
      hedgeCount: 1 + variation,
      certaintyCount: 5,
      disclaimerCount: 0,
      questionsBack: 0,
      empathyMarkers: 1,
      hedgeToCertaintyRatio: 0.17,
    },
    structural: {
      charCount: 500 + variation * 15,
      wordCount: 90 + variation * 3,
      lineCount: 8,
      paragraphCount: 2,
      bulletLines: 0,
      numberedListLines: 3,
      headerLines: 0,
      codeBlocks: 1,
      boldCount: 0,
      listToContentRatio: 0.35,
      openingPattern: "preamble",
      closingPattern: "statement",
      avgWordLength: 4.8,
      avgSentenceLength: 12,
    },
    temporal: {
      timeToFirstToken: 200 + variation * 5,
      interTokenIntervals: [6, 7, 5, 6, 8],
      meanInterval: 6.4,
      stdInterval: 1.0,
      medianInterval: 6,
      burstiness: 1.8,
      totalStreamingDuration: 1200 + variation * 30,
      tokenCount: 120 + variation * 4,
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

export function runImpersonationAttack(): AttackResult {
  // Step 1: Build a Claude profile from 20 observations
  const landscape = createLandscape("claude-genome-hash");
  for (let i = 0; i < 20; i++) {
    updateLandscape(landscape, claudeSignals(i % 5), "normal");
  }

  // Step 2: Present GPT signals claiming to be Claude
  const attackSignals = gptSignals(0);
  const result = matchLandscape(landscape, attackSignals, "normal");

  // Step 3: Check detection
  // Non-GREEN match ratio OR any feature with extreme z-score = detected.
  // matchRatio < 0.8 puts us outside GREEN territory.
  // z-score > 5 on any feature is a massive phenotypic deviation.
  const maxZ = Math.max(...result.featureDeviations.map((d) => d.zScore), 0);
  const detected = result.matchRatio < 0.8 || maxZ > 5.0;

  return {
    attackName: "Impersonation",
    description: "Commit Claude genome, run GPT behind the scenes",
    expectedDetection: "Non-GREEN from phenotype mismatch (multiple z > 10)",
    detected,
    matchRatio: result.matchRatio,
    details: {
      maxZScore: maxZ,
      profileObservations: landscape.totalObservations,
      topDeviations: result.featureDeviations
        .sort((a, b) => b.zScore - a.zScore)
        .slice(0, 5)
        .map((d) => `${d.feature}: z=${d.zScore.toFixed(2)}`),
    },
  };
}
