/**
 * HMAC-SHA256 Overhead Benchmark
 *
 * Measures per-token HMAC computation time across varying token lengths,
 * then compares the added variance to natural inter-token variance from
 * our experiment data. Reports whether HMAC variance is under 5% of
 * natural variance.
 *
 * Run: pnpm run benchmark:hmac
 */

import "dotenv/config";
import { readFile, readdir } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { getCryptoProvider } from "../core/crypto-provider.js";
import { deriveHmacKey, computeTokenHmac } from "../heart/seed.js";
import type { ExperimentRun } from "./runner.js";

const log = (msg: string) => { process.stdout.write(msg + "\n"); };
const crypto = getCryptoProvider();

// ─── HMAC Benchmark ─────────────────────────────────────────────────────────

interface BenchResult {
  tokenLength: number;
  iterations: number;
  totalMs: number;
  meanUs: number;     // microseconds
  stdUs: number;
  minUs: number;
  maxUs: number;
  varianceUs2: number; // variance in microseconds^2
}

function benchmarkHmac(tokenLength: number, iterations: number): BenchResult {
  const sessionKey = crypto.random.randomBytes(32);
  const hmacKey = deriveHmacKey(sessionKey);
  const token = "A".repeat(tokenLength);

  // Warmup
  for (let i = 0; i < 100; i++) {
    computeTokenHmac(hmacKey, token, i, 0);
  }

  // Benchmark
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    computeTokenHmac(hmacKey, token, i, 0);
    const end = performance.now();
    times.push((end - start) * 1000); // convert ms to microseconds
  }

  const totalMs = times.reduce((a, b) => a + b, 0) / 1000;
  const meanUs = times.reduce((a, b) => a + b, 0) / times.length;
  const varianceUs2 = times.reduce((a, b) => a + (b - meanUs) ** 2, 0) / times.length;
  const stdUs = Math.sqrt(varianceUs2);
  const minUs = Math.min(...times);
  const maxUs = Math.max(...times);

  return { tokenLength, iterations, totalMs, meanUs, stdUs, minUs, maxUs, varianceUs2 };
}

// ─── Natural Variance from Experiment Data ──────────────────────────────────

async function loadNaturalVariance(): Promise<{ meanIntervalMs: number; varianceMs2: number; stdMs: number } | null> {
  const dir = "results/raw";
  try {
    const files = (await readdir(dir)).filter(f => /^experiment-2026-03-26.*\.json$/.test(f)).sort();
    if (files.length === 0) return null;

    const allIntervals: number[] = [];
    for (const file of files) {
      const run = JSON.parse(await readFile(`${dir}/${file}`, "utf-8")) as ExperimentRun;
      for (const r of run.results) {
        if (r.error || !r.trace.interTokenIntervals) continue;
        for (const interval of r.trace.interTokenIntervals) {
          if (interval > 0 && interval < 10000) { // filter outliers
            allIntervals.push(interval);
          }
        }
      }
    }

    if (allIntervals.length === 0) return null;

    const mean = allIntervals.reduce((a, b) => a + b, 0) / allIntervals.length;
    const variance = allIntervals.reduce((a, b) => a + (b - mean) ** 2, 0) / allIntervals.length;
    return { meanIntervalMs: mean, varianceMs2: variance, stdMs: Math.sqrt(variance) };
  } catch {
    return null;
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  log("\n╔══════════════════════════════════════════════════════════╗");
  log("║        HMAC-SHA256 PER-TOKEN OVERHEAD BENCHMARK        ║");
  log("╚══════════════════════════════════════════════════════════╝\n");

  const ITERATIONS = 10_000;
  const TOKEN_LENGTHS = [1, 10, 100, 500];

  log(`  Iterations per test: ${ITERATIONS.toLocaleString()}`);
  log(`  Token lengths: ${TOKEN_LENGTHS.join(", ")} chars\n`);

  // Run benchmarks
  const results: BenchResult[] = [];
  for (const len of TOKEN_LENGTHS) {
    log(`  Benchmarking ${len}-char tokens...`);
    const r = benchmarkHmac(len, ITERATIONS);
    results.push(r);
    log(`    Mean: ${r.meanUs.toFixed(2)}us  Std: ${r.stdUs.toFixed(2)}us  Min: ${r.minUs.toFixed(2)}us  Max: ${r.maxUs.toFixed(2)}us`);
  }

  // Summary table
  log("\n  ┌──────────┬──────────┬──────────┬──────────┬──────────┐");
  log("  │ Token Len│ Mean(us) │ Std(us)  │ Min(us)  │ Max(us)  │");
  log("  ├──────────┼──────────┼──────────┼──────────┼──────────┤");
  for (const r of results) {
    log(`  │ ${String(r.tokenLength).padStart(8)} │ ${r.meanUs.toFixed(2).padStart(8)} │ ${r.stdUs.toFixed(2).padStart(8)} │ ${r.minUs.toFixed(2).padStart(8)} │ ${r.maxUs.toFixed(2).padStart(8)} │`);
  }
  log("  └──────────┴──────────┴──────────┴──────────┴──────────┘");

  // Compare to natural inter-token variance
  log("\n── Comparison to Natural Inter-Token Variance ──\n");

  const natural = await loadNaturalVariance();
  if (natural) {
    log(`  Natural inter-token intervals (from experiment data):`);
    log(`    Mean: ${natural.meanIntervalMs.toFixed(2)}ms`);
    log(`    Std:  ${natural.stdMs.toFixed(2)}ms`);
    log(`    Variance: ${natural.varianceMs2.toFixed(2)}ms^2`);

    // Convert HMAC variance from us^2 to ms^2
    log(`\n  HMAC overhead vs natural variance:`);
    log("  ┌──────────┬────────────┬────────────┬───────────┬────────┐");
    log("  │ Token Len│ HMAC Var   │ Natural Var│ Ratio     │ < 5% ? │");
    log("  │          │ (ms^2)     │ (ms^2)     │           │        │");
    log("  ├──────────┼────────────┼────────────┼───────────┼────────┤");

    let allUnder5 = true;
    for (const r of results) {
      const hmacVarMs2 = r.varianceUs2 / 1_000_000; // us^2 -> ms^2
      const ratio = hmacVarMs2 / natural.varianceMs2;
      const pct = (ratio * 100).toFixed(3);
      const under5 = ratio < 0.05;
      if (!under5) allUnder5 = false;
      log(`  │ ${String(r.tokenLength).padStart(8)} │ ${hmacVarMs2.toFixed(6).padStart(10)} │ ${natural.varianceMs2.toFixed(2).padStart(10)} │ ${pct.padStart(8)}% │ ${under5 ? "  YES  " : "  NO   "} │`);
    }
    log("  └──────────┴────────────┴────────────┴───────────┴────────┘");

    log(`\n  Verdict: HMAC variance is ${allUnder5 ? "UNDER" : "OVER"} 5% of natural inter-token variance for all token lengths.`);
    if (allUnder5) {
      log("  Per-token HMAC authentication does NOT distort the temporal fingerprint.");
    } else {
      log("  WARNING: HMAC overhead may affect temporal fingerprint accuracy.");
    }
  } else {
    log("  No experiment data found. Run the experiment first to compare.");
    log("  HMAC computation alone (no comparison):");
    for (const r of results) {
      log(`    ${r.tokenLength}-char: ${r.meanUs.toFixed(2)}us mean, ${r.stdUs.toFixed(2)}us std`);
    }
  }

  log("");
  process.exit(0);
}

main().catch(err => { console.error("Benchmark failed:", err); process.exit(1); });
