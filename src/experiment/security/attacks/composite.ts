/**
 * Attack 5: Composite Agent
 *
 * Use different models for different task types — e.g., GPT for coding,
 * Claude for conversation. The consistency manifold should detect
 * cross-category instability.
 * Expected detection: UNCANNY via cross-category behavioral inconsistency.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createLandscape,
  updateLandscape,
  matchLandscape,
} from "../../../sensorium/landscape.js";
import type { AttackResult } from "../harness.js";

/** Consistent agent: same model for all categories. */
function consistentSignals(category: string, i: number): PhenotypicSignals {
  const v = i % 5;
  // Same "voice" across categories — only task-appropriate variation
  const wordCount = category === "rapid_fire" ? 30 + v : category === "ambiguity" ? 200 + v * 10 : 120 + v * 5;
  return {
    cognitive: {
      hedgeCount: 3 + (category === "ambiguity" ? 2 : 0),
      certaintyCount: 2,
      disclaimerCount: 1,
      questionsBack: 0,
      empathyMarkers: 1,
      hedgeToCertaintyRatio: 0.6,
    },
    structural: {
      charCount: wordCount * 5,
      wordCount,
      lineCount: Math.ceil(wordCount / 10),
      paragraphCount: Math.ceil(wordCount / 50),
      bulletLines: 2,
      numberedListLines: 0,
      headerLines: category === "ambiguity" ? 1 : 0,
      codeBlocks: 0,
      boldCount: 1,
      listToContentRatio: 0.15,
      openingPattern: "direct",
      closingPattern: "statement",
      avgWordLength: 5.1, // CONSISTENT across categories
      avgSentenceLength: 16, // CONSISTENT
    },
    temporal: {
      timeToFirstToken: 400 + v * 10,
      interTokenIntervals: [12, 14, 11, 13, 12],
      meanInterval: 12.4, // CONSISTENT timing signature
      stdInterval: 1.1,
      medianInterval: 12,
      burstiness: 3.2,
      totalStreamingDuration: wordCount * 15,
      tokenCount: Math.round(wordCount * 1.3),
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: category === "ambiguity" ? 1 : 0,
      assertiveWhenWrong: 0,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.5,
    },
  };
}

/** Composite agent: DIFFERENT models for different categories. */
function compositeSignals(category: string, i: number): PhenotypicSignals {
  const v = i % 5;

  if (category === "normal") {
    // GPT-like for coding/normal tasks
    return {
      cognitive: {
        hedgeCount: 1,
        certaintyCount: 5,
        disclaimerCount: 0,
        questionsBack: 0,
        empathyMarkers: 0,
        hedgeToCertaintyRatio: 0.17,
      },
      structural: {
        charCount: 400 + v * 10,
        wordCount: 80 + v * 3,
        lineCount: 6,
        paragraphCount: 2,
        bulletLines: 0,
        numberedListLines: 3,
        headerLines: 0,
        codeBlocks: 1,
        boldCount: 0,
        listToContentRatio: 0.35,
        openingPattern: "direct",
        closingPattern: "statement",
        avgWordLength: 4.5, // DIFFERENT from ambiguity
        avgSentenceLength: 10, // DIFFERENT
      },
      temporal: {
        timeToFirstToken: 180 + v * 5,
        interTokenIntervals: [5, 6, 4, 5, 7],
        meanInterval: 5.4, // FAST — different model
        stdInterval: 1.0,
        medianInterval: 5,
        burstiness: 1.5,
        totalStreamingDuration: 800 + v * 20,
        tokenCount: 100 + v * 4,
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
  } else {
    // Claude-like for ambiguity/conversation
    return {
      cognitive: {
        hedgeCount: 6 + v,
        certaintyCount: 1,
        disclaimerCount: 2,
        questionsBack: 1,
        empathyMarkers: 3,
        hedgeToCertaintyRatio: 0.86,
      },
      structural: {
        charCount: 1200 + v * 20,
        wordCount: 250 + v * 8,
        lineCount: 20,
        paragraphCount: 5,
        bulletLines: 4,
        numberedListLines: 0,
        headerLines: 2,
        codeBlocks: 0,
        boldCount: 3,
        listToContentRatio: 0.2,
        openingPattern: "preamble",
        closingPattern: "offer",
        avgWordLength: 5.8, // DIFFERENT from normal
        avgSentenceLength: 22, // DIFFERENT
      },
      temporal: {
        timeToFirstToken: 500 + v * 15,
        interTokenIntervals: [15, 18, 14, 16, 15],
        meanInterval: 15.6, // SLOW — different model
        stdInterval: 1.5,
        medianInterval: 15,
        burstiness: 4.5,
        totalStreamingDuration: 4000 + v * 80,
        tokenCount: 320 + v * 10,
      },
      error: {
        containsRefusal: false,
        uncertaintyAdmissions: 2,
        assertiveWhenWrong: 0,
        attemptedImpossible: false,
        selfCorrections: 1,
        confidenceRatio: 0.3,
      },
    };
  }
}

export function runCompositeAttack(): AttackResult {
  // Step 1: Build landscape from consistent agent (same model for all tasks)
  const landscape = createLandscape("consistent-agent-hash");
  for (let i = 0; i < 10; i++) {
    updateLandscape(landscape, consistentSignals("normal", i), "normal");
    updateLandscape(landscape, consistentSignals("ambiguity", i), "ambiguity");
  }

  // Step 2: Present composite agent signals
  // Normal tasks: GPT-like (fast, terse, assertive)
  const normalResult = matchLandscape(landscape, compositeSignals("normal", 0), "normal");
  // Ambiguity tasks: Claude-like (slow, verbose, hedgy)
  const ambiguityResult = matchLandscape(landscape, compositeSignals("ambiguity", 0), "ambiguity");

  // Step 3: Check cross-category instability
  // A real agent has consistent timing/style ratios across categories
  // The composite has wildly different profiles per category
  const normalMeanInterval = 5.4;
  const ambiguityMeanInterval = 15.6;
  const timingRatioDivergence = Math.abs(normalMeanInterval / ambiguityMeanInterval - 1);

  const normalAvgWordLen = 4.5;
  const ambiguityAvgWordLen = 5.8;
  const styleDivergence = Math.abs(normalAvgWordLen - ambiguityAvgWordLen);

  // Combined match ratio should be low
  const avgMatchRatio = (normalResult.matchRatio + ambiguityResult.matchRatio) / 2;
  const detected = avgMatchRatio < 0.8 || timingRatioDivergence > 0.5;

  return {
    attackName: "Composite Agent",
    description: "Different models for different task types (GPT for normal, Claude for ambiguity)",
    expectedDetection: "UNCANNY via consistency manifold — cross-category instability",
    detected,
    matchRatio: avgMatchRatio,
    details: {
      normalMatchRatio: normalResult.matchRatio,
      ambiguityMatchRatio: ambiguityResult.matchRatio,
      timingRatioDivergence: timingRatioDivergence.toFixed(3),
      styleDivergence: styleDivergence.toFixed(3),
      normalTopDeviations: normalResult.featureDeviations
        .sort((a, b) => b.zScore - a.zScore)
        .slice(0, 3)
        .map((d) => `${d.feature}: z=${d.zScore.toFixed(2)}`),
      ambiguityTopDeviations: ambiguityResult.featureDeviations
        .sort((a, b) => b.zScore - a.zScore)
        .slice(0, 3)
        .map((d) => `${d.feature}: z=${d.zScore.toFixed(2)}`),
    },
  };
}
