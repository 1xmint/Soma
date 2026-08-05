#!/usr/bin/env node

import { watch } from "node:fs";
import { join, resolve } from "node:path";
import { initializeHeart, persistHeartbeats } from "./heart-setup.js";
import { readObservation, listObservations } from "./observation-reader.js";
import { evaluate, type EvaluationResult } from "./evaluator.js";

async function main() {
  console.log("Vera Day 0 — Energy-Based Evaluation Framework\n");

  const { heart, keyPair } = await initializeHeart();
  console.log(`Heart initialized: ${heart.did}`);
  console.log(`Heartbeat chain length: ${heart.heartbeats.length}\n`);

  const command = process.argv[2];

  if (command === "evaluate") {
    const target = process.argv[3];
    if (!target) {
      console.error("Usage: vera evaluate <observation-file-or-directory>");
      process.exit(1);
    }

    const path = resolve(target);
    if (path.endsWith(".json")) {
      const result = await evaluateFile(heart, keyPair, path);
      printResult(result);
    } else {
      const files = await listObservations(path);
      if (files.length === 0) {
        console.log("No observation files found.");
        return;
      }
      for (const file of files) {
        console.log(`\nEvaluating: ${file}`);
        const result = await evaluateFile(heart, keyPair, file);
        printResult(result);
      }
    }

    await persistHeartbeats(heart);
    return;
  }

  if (command === "watch") {
    const dir = process.argv[3] || findCortexObservations();
    if (!dir) {
      console.error("Usage: vera watch <cortex-observations-dir>");
      console.error("Or run from a directory containing .cortex/observations/");
      process.exit(1);
    }

    console.log(`Watching for new observations in: ${dir}\n`);
    const evaluated = new Set<string>();

    // Evaluate existing files first
    const existing = await listObservations(dir);
    for (const file of existing) {
      console.log(`Evaluating existing: ${file}`);
      const result = await evaluateFile(heart, keyPair, file);
      printResult(result);
      evaluated.add(file);
    }

    // Watch for new files
    const watcher = watch(dir, async (eventType, filename) => {
      if (!filename || !filename.endsWith(".json")) return;
      const fullPath = join(dir, filename);
      if (evaluated.has(fullPath)) return;
      evaluated.add(fullPath);

      // Small delay to ensure file is fully written
      await new Promise(r => setTimeout(r, 500));

      try {
        console.log(`\nNew observation detected: ${filename}`);
        const result = await evaluateFile(heart, keyPair, fullPath);
        printResult(result);
        await persistHeartbeats(heart);
      } catch (err) {
        console.error(`Error evaluating ${filename}:`, err);
      }
    });

    console.log("Press Ctrl+C to stop watching.\n");
    process.on("SIGINT", () => {
      watcher.close();
      persistHeartbeats(heart).then(() => process.exit(0));
    });

    // Keep process alive
    await new Promise(() => {});
    return;
  }

  console.log("Usage:");
  console.log("  vera evaluate <file.json>     Evaluate a single observation");
  console.log("  vera evaluate <directory>      Evaluate all observations in directory");
  console.log("  vera watch <directory>         Watch for new observations and evaluate");
  console.log();
  console.log("Example:");
  console.log("  vera evaluate .cortex/observations/");
  console.log("  vera watch .cortex/observations/");
}

async function evaluateFile(
  heart: import("soma-heart").HeartRuntime,
  keyPair: import("soma-heart/crypto-provider").SignKeyPair,
  path: string,
): Promise<EvaluationResult> {
  const observation = await readObservation(path);
  return evaluate(heart, keyPair, observation);
}

function printResult(result: EvaluationResult) {
  console.log(`\n  === Evaluation: ${result.evaluationId} ===`);
  console.log(`  Cortex: ${result.cortexDid}`);
  console.log(`  Vera:   ${result.veraDid}`);
  console.log(`  Chain verified: ${result.chainVerified}`);
  console.log(`  Layer 0 (quality):    ${(result.layer0.score * 100).toFixed(1)}%`);
  console.log(`  Layer 1 (energy):     ${result.layer1.mode} (${result.layer1.observationsCollected}/${result.layer1.observationsNeeded} obs)`);
  if (result.layer1.energyScore !== null) {
    console.log(`    Energy score: ${result.layer1.energyScore.toFixed(4)}`);
  }
  console.log(`  Layer 2 (structural): ${(result.layer2.score * 100).toFixed(1)}%`);
  console.log(`    Entropy: ${result.layer2.aggregateEntropy.toFixed(2)}, Complexity: ${result.layer2.aggregateComplexity.toFixed(0)}`);
  console.log(`  Overall: ${(result.overallScore * 100).toFixed(1)}% (confidence: ${(result.confidence * 100).toFixed(0)}%)`);
  if (result.anomalyFlags.length > 0) {
    console.log(`  ANOMALY FLAGS: ${result.anomalyFlags.join(", ")}`);
  }
  console.log();
}

function findCortexObservations(): string | null {
  const candidates = [
    join(process.cwd(), ".cortex", "observations"),
    join(process.cwd(), "..", "Cortex", ".cortex", "observations"),
  ];
  // Return first candidate that exists as a string — the caller handles missing dirs
  return candidates[0];
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
