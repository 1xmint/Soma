/**
 * Generate synthetic experiment data for testing the analysis pipeline.
 *
 * Each agent gets a distinct phenotypic profile so the classifier has
 * real signal to work with — like synthetic specimens in a teaching lab.
 * Not a substitute for real data, but proves the pipeline works end to end.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { AGENT_CONFIGS } from "./configs.js";
import { ALL_PROBES } from "./probes.js";
import type { PhenotypicSignals } from "./signals.js";
import type { ExperimentRun, ExperimentResult } from "./runner.js";

// --- Per-agent phenotypic profiles (synthetic ground truth) ---
// Each agent has characteristic ranges for each signal channel.
// These are exaggerated to give the classifier clear signal.

interface PhenotypeProfile {
  // Cognitive
  hedgeMean: number; certaintyMean: number; disclaimerMean: number;
  questionsMean: number; empathyMean: number;
  // Structural
  wordCountMean: number; bulletMean: number; codeMean: number;
  preambleProb: number; avgWordLenMean: number;
  // Temporal
  ttftMean: number; meanIntervalMean: number; burstMean: number;
  // Error
  refusalProb: number; uncertaintyMean: number; selfCorrMean: number;
}

const PROFILES: Record<string, PhenotypeProfile> = {
  "gemini-flash": {
    hedgeMean: 2, certaintyMean: 3, disclaimerMean: 0.5, questionsMean: 1, empathyMean: 2,
    wordCountMean: 150, bulletMean: 3, codeMean: 0.3, preambleProb: 0.6, avgWordLenMean: 5.2,
    ttftMean: 250, meanIntervalMean: 14, burstMean: 9,
    refusalProb: 0.05, uncertaintyMean: 0.5, selfCorrMean: 0.2,
  },
  "trinity-large": {
    hedgeMean: 3.5, certaintyMean: 2, disclaimerMean: 0.8, questionsMean: 1.8, empathyMean: 2.5,
    wordCountMean: 230, bulletMean: 3, codeMean: 0.3, preambleProb: 0.55, avgWordLenMean: 5.7,
    ttftMean: 380, meanIntervalMean: 17, burstMean: 11,
    refusalProb: 0.07, uncertaintyMean: 0.8, selfCorrMean: 0.3,
  },
  "llama3-70b": {
    hedgeMean: 4, certaintyMean: 4, disclaimerMean: 0.3, questionsMean: 0.5, empathyMean: 1,
    wordCountMean: 200, bulletMean: 2, codeMean: 0.8, preambleProb: 0.3, avgWordLenMean: 4.8,
    ttftMean: 150, meanIntervalMean: 8, burstMean: 5,
    refusalProb: 0.03, uncertaintyMean: 0.3, selfCorrMean: 0.5,
  },
  "llama3-8b": {
    hedgeMean: 1, certaintyMean: 5, disclaimerMean: 0.1, questionsMean: 0.3, empathyMean: 0.5,
    wordCountMean: 120, bulletMean: 1, codeMean: 0.4, preambleProb: 0.2, avgWordLenMean: 4.5,
    ttftMean: 100, meanIntervalMean: 5, burstMean: 3,
    refusalProb: 0.02, uncertaintyMean: 0.2, selfCorrMean: 0.8,
  },
  "mixtral": {
    hedgeMean: 3, certaintyMean: 3, disclaimerMean: 0.8, questionsMean: 1.5, empathyMean: 1.5,
    wordCountMean: 180, bulletMean: 5, codeMean: 0.6, preambleProb: 0.4, avgWordLenMean: 5.5,
    ttftMean: 180, meanIntervalMean: 10, burstMean: 7,
    refusalProb: 0.06, uncertaintyMean: 0.8, selfCorrMean: 0.4,
  },
  "gemma2": {
    hedgeMean: 2, certaintyMean: 2, disclaimerMean: 1.5, questionsMean: 2, empathyMean: 2.5,
    wordCountMean: 160, bulletMean: 2, codeMean: 0.2, preambleProb: 0.5, avgWordLenMean: 5.0,
    ttftMean: 130, meanIntervalMean: 9, burstMean: 6,
    refusalProb: 0.1, uncertaintyMean: 1.2, selfCorrMean: 0.3,
  },
  "mistral-small": {
    hedgeMean: 1.5, certaintyMean: 4, disclaimerMean: 0.4, questionsMean: 0.8, empathyMean: 1,
    wordCountMean: 140, bulletMean: 3, codeMean: 0.7, preambleProb: 0.25, avgWordLenMean: 5.3,
    ttftMean: 160, meanIntervalMean: 11, burstMean: 9,
    refusalProb: 0.04, uncertaintyMean: 0.4, selfCorrMean: 0.6,
  },
  // OpenRouter — distinct model families with unique phenotypic signatures
  "deepseek-v3": {
    hedgeMean: 2.5, certaintyMean: 5, disclaimerMean: 0.2, questionsMean: 0.4, empathyMean: 0.8,
    wordCountMean: 220, bulletMean: 2, codeMean: 1.0, preambleProb: 0.15, avgWordLenMean: 5.0,
    ttftMean: 350, meanIntervalMean: 14, burstMean: 10,
    refusalProb: 0.02, uncertaintyMean: 0.2, selfCorrMean: 0.4,
  },
  "nemotron-super": {
    hedgeMean: 3, certaintyMean: 3.5, disclaimerMean: 0.6, questionsMean: 1, empathyMean: 1.5,
    wordCountMean: 190, bulletMean: 4, codeMean: 0.5, preambleProb: 0.35, avgWordLenMean: 5.4,
    ttftMean: 280, meanIntervalMean: 16, burstMean: 11,
    refusalProb: 0.05, uncertaintyMean: 0.6, selfCorrMean: 0.3,
  },
  "step-flash": {
    hedgeMean: 1.5, certaintyMean: 4.5, disclaimerMean: 0.3, questionsMean: 0.6, empathyMean: 1.2,
    wordCountMean: 165, bulletMean: 3, codeMean: 0.4, preambleProb: 0.2, avgWordLenMean: 4.9,
    ttftMean: 170, meanIntervalMean: 7, burstMean: 4,
    refusalProb: 0.03, uncertaintyMean: 0.3, selfCorrMean: 0.5,
  },
  // Epigenetic: same temporal profile as llama3-70b, different cognitive/structural
  "llama3-70b-formal": {
    hedgeMean: 1, certaintyMean: 6, disclaimerMean: 0.2, questionsMean: 0.2, empathyMean: 0.3,
    wordCountMean: 280, bulletMean: 1, codeMean: 0.3, preambleProb: 0.1, avgWordLenMean: 6.2,
    ttftMean: 155, meanIntervalMean: 8.5, burstMean: 5.2,
    refusalProb: 0.02, uncertaintyMean: 0.1, selfCorrMean: 0.2,
  },
  "llama3-70b-chaotic": {
    hedgeMean: 5, certaintyMean: 1, disclaimerMean: 0.1, questionsMean: 3, empathyMean: 4,
    wordCountMean: 170, bulletMean: 0.5, codeMean: 0.1, preambleProb: 0.8, avgWordLenMean: 4.2,
    ttftMean: 148, meanIntervalMean: 7.8, burstMean: 4.8,
    refusalProb: 0.01, uncertaintyMean: 0.5, selfCorrMean: 1.0,
  },
  // Proxy: identical content profile to llama3-70b, but shifted temporal
  "proxy-llama3-70b": {
    hedgeMean: 4, certaintyMean: 4, disclaimerMean: 0.3, questionsMean: 0.5, empathyMean: 1,
    wordCountMean: 200, bulletMean: 2, codeMean: 0.8, preambleProb: 0.3, avgWordLenMean: 4.8,
    ttftMean: 300, meanIntervalMean: 23, burstMean: 18,
    refusalProb: 0.03, uncertaintyMean: 0.3, selfCorrMean: 0.5,
  },
};

// --- Noise helpers ---

function gaussianNoise(mean: number, std: number): number {
  const u1 = Math.random();
  const u2 = Math.random();
  return mean + std * Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

function poissonSample(lambda: number): number {
  return Math.max(0, Math.round(gaussianNoise(lambda, Math.sqrt(lambda))));
}

function generateSignals(profile: PhenotypeProfile, probeCategory: string): PhenotypicSignals {
  const hedgeCount = poissonSample(profile.hedgeMean);
  const certaintyCount = poissonSample(profile.certaintyMean);
  const disclaimerCount = poissonSample(profile.disclaimerMean);
  const questionsBack = poissonSample(profile.questionsMean);
  const empathyMarkers = poissonSample(profile.empathyMean);
  const total = hedgeCount + certaintyCount;

  const wordCount = Math.max(10, Math.round(gaussianNoise(profile.wordCountMean, profile.wordCountMean * 0.2)));
  const bulletLines = poissonSample(profile.bulletMean);
  const codeBlocks = poissonSample(profile.codeMean);
  const openingPattern = Math.random() < profile.preambleProb ? "preamble" as const : "direct" as const;
  const avgWordLength = Math.max(2, gaussianNoise(profile.avgWordLenMean, 0.3));

  const tokenCount = Math.max(5, Math.round(wordCount * 1.3));
  const ttft = Math.max(10, gaussianNoise(profile.ttftMean, profile.ttftMean * 0.15));
  const meanInterval = Math.max(1, gaussianNoise(profile.meanIntervalMean, profile.meanIntervalMean * 0.2));
  const burstiness = Math.max(0, gaussianNoise(profile.burstMean, profile.burstMean * 0.25));
  const stdInterval = Math.max(0, meanInterval * 0.5 + gaussianNoise(0, 1));

  const containsRefusal = Math.random() < profile.refusalProb;
  const uncertaintyAdmissions = poissonSample(profile.uncertaintyMean);
  const selfCorrections = poissonSample(profile.selfCorrMean);
  const assertiveWhenWrong = (probeCategory === "failure" || probeCategory === "edge_case") ? poissonSample(1) : 0;
  const attemptedImpossible = probeCategory === "failure" && !containsRefusal && assertiveWhenWrong > 0;
  const assertiveCount = poissonSample(2);
  const confTotal = assertiveCount + uncertaintyAdmissions;

  // Generate inter-token intervals
  const intervals: number[] = [];
  for (let i = 0; i < tokenCount - 1; i++) {
    intervals.push(Math.max(0.5, gaussianNoise(meanInterval, stdInterval)));
  }

  const closingOptions: Array<"question" | "offer" | "statement"> = ["question", "offer", "statement"];
  const closingPattern = closingOptions[Math.floor(Math.random() * 3)];

  return {
    cognitive: {
      hedgeCount, certaintyCount, disclaimerCount, questionsBack, empathyMarkers,
      hedgeToCertaintyRatio: total === 0 ? 0 : hedgeCount / total,
    },
    structural: {
      charCount: wordCount * Math.round(avgWordLength + 1),
      wordCount,
      lineCount: Math.max(1, Math.round(wordCount / 12)),
      paragraphCount: Math.max(1, Math.round(wordCount / 50)),
      bulletLines,
      numberedListLines: poissonSample(0.5),
      headerLines: poissonSample(0.3),
      codeBlocks,
      boldCount: poissonSample(0.5),
      listToContentRatio: bulletLines / Math.max(1, Math.round(wordCount / 12)),
      openingPattern,
      closingPattern,
      avgWordLength,
      avgSentenceLength: Math.max(3, gaussianNoise(15, 3)),
    },
    temporal: {
      timeToFirstToken: ttft,
      interTokenIntervals: intervals,
      meanInterval,
      stdInterval,
      medianInterval: meanInterval * 0.95,
      burstiness,
      totalStreamingDuration: ttft + meanInterval * tokenCount,
      tokenCount,
    },
    error: {
      containsRefusal,
      uncertaintyAdmissions,
      assertiveWhenWrong,
      attemptedImpossible,
      selfCorrections,
      confidenceRatio: confTotal === 0 ? 0 : assertiveCount / confTotal,
    },
  };
}

async function generateSyntheticData(): Promise<void> {
  console.log("\n  Generating synthetic experiment data...\n");

  const results: ExperimentResult[] = [];
  const errors: Array<{ agentId: string; probeId: string; error: string }> = [];

  for (const agent of AGENT_CONFIGS) {
    const profile = PROFILES[agent.id];
    if (!profile) {
      console.log(`  Skipping ${agent.id} — no profile defined`);
      continue;
    }

    for (const probe of ALL_PROBES) {
      const signals = generateSignals(profile, probe.category);
      results.push({
        agentId: agent.id,
        probeId: probe.id,
        probeCategory: probe.category,
        responseText: `[synthetic response for ${agent.id} / ${probe.id}]`,
        signals,
        trace: {
          tokenCount: signals.temporal.tokenCount,
          startTime: 0,
          endTime: signals.temporal.totalStreamingDuration,
          firstTokenTime: signals.temporal.timeToFirstToken,
          interTokenIntervals: signals.temporal.interTokenIntervals,
        },
        providerMeta: { synthetic: true },
        timestamp: Date.now(),
        error: null,
      });
    }
    console.log(`  ✓ ${agent.label} — ${ALL_PROBES.length} samples`);
  }

  const run: ExperimentRun = {
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    agentCount: AGENT_CONFIGS.length,
    probeCount: ALL_PROBES.length,
    results,
    errors,
  };

  const dir = "results/raw";
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true });
  }

  const outputPath = `${dir}/experiment-synthetic.json`;
  await writeFile(outputPath, JSON.stringify(run, null, 2));
  console.log(`\n  Saved: ${outputPath} (${results.length} samples)\n`);
}

generateSyntheticData().catch((err) => {
  console.error("Generation failed:", err);
  process.exit(1);
});
