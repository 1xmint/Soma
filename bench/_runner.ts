/**
 * Minimal microbenchmark runner.
 *
 * No framework dependency. Uses process.hrtime.bigint() for nanosecond
 * resolution, warms up the code path, then times N iterations and reports
 * median + p95 + mean in microseconds. Median is the headline number —
 * means can get dragged by GC pauses, medians don't.
 *
 * Each bench function gets a pre-prepared context (so setup cost isn't
 * counted) and returns nothing (we don't care about the result, only the
 * time). A single `run()` executes the bench and appends a row to the
 * output table.
 *
 * Calibration: fast functions (< 1µs each) are hard to time in isolation
 * because clock resolution bleeds in. For those, we batch — run `inner`
 * iterations per timed sample, then divide. The runner picks `inner`
 * automatically based on an initial probe.
 */

export interface BenchCase<T = void> {
  /** Human label. */
  name: string;
  /** Called once before timing to produce a context. */
  setup: () => T;
  /** Called inner×samples times. Body should do EXACTLY the work to measure. */
  body: (ctx: T) => void;
}

export interface BenchResult {
  name: string;
  samples: number;
  innerPerSample: number;
  medianNs: number;
  p95Ns: number;
  meanNs: number;
  opsPerSec: number;
}

const DEFAULT_WARMUP_SAMPLES = 100;
const DEFAULT_SAMPLES = 1000;
const TARGET_SAMPLE_NS = 50_000; // Aim for ~50µs per sample window.

function hrnow(): bigint {
  return process.hrtime.bigint();
}

/** Calibrate `inner` so a single sample takes ~TARGET_SAMPLE_NS. */
function calibrate<T>(bench: BenchCase<T>, ctx: T): number {
  let inner = 1;
  for (let attempt = 0; attempt < 20; attempt++) {
    const start = hrnow();
    for (let i = 0; i < inner; i++) bench.body(ctx);
    const elapsed = Number(hrnow() - start);
    if (elapsed >= TARGET_SAMPLE_NS) return inner;
    // Double until we land in the target window.
    const ratio = TARGET_SAMPLE_NS / Math.max(elapsed, 1);
    inner = Math.max(inner + 1, Math.ceil(inner * ratio));
    if (inner > 1_000_000) return inner; // Safety cap.
  }
  return inner;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx];
}

export function runBench<T>(
  bench: BenchCase<T>,
  opts: { samples?: number; warmup?: number } = {},
): BenchResult {
  const ctx = bench.setup();
  const warmup = opts.warmup ?? DEFAULT_WARMUP_SAMPLES;
  const samples = opts.samples ?? DEFAULT_SAMPLES;

  // Warm up (also primes JIT).
  for (let i = 0; i < warmup; i++) bench.body(ctx);

  const inner = calibrate(bench, ctx);

  const durations: number[] = new Array(samples);
  for (let s = 0; s < samples; s++) {
    const start = hrnow();
    for (let i = 0; i < inner; i++) bench.body(ctx);
    durations[s] = Number(hrnow() - start) / inner;
  }

  durations.sort((a, b) => a - b);
  const median = percentile(durations, 0.5);
  const p95 = percentile(durations, 0.95);
  const mean = durations.reduce((a, b) => a + b, 0) / durations.length;
  const opsPerSec = median > 0 ? 1_000_000_000 / median : 0;

  return {
    name: bench.name,
    samples,
    innerPerSample: inner,
    medianNs: median,
    p95Ns: p95,
    meanNs: mean,
    opsPerSec,
  };
}

// ─── Reporting ──────────────────────────────────────────────────────────────

export function fmtNs(ns: number): string {
  if (ns < 1_000) return `${ns.toFixed(1)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(2)} µs`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
}

export function fmtOps(ops: number): string {
  if (ops >= 1_000_000) return `${(ops / 1_000_000).toFixed(2)}M/s`;
  if (ops >= 1_000) return `${(ops / 1_000).toFixed(1)}K/s`;
  return `${ops.toFixed(0)}/s`;
}

export function printResults(title: string, results: BenchResult[]): void {
  console.log(`\n${title}`);
  console.log("─".repeat(title.length));
  const nameWidth = Math.max(
    12,
    ...results.map((r) => r.name.length),
  );
  const header =
    "name".padEnd(nameWidth) +
    "  " +
    "median".padStart(10) +
    "  " +
    "p95".padStart(10) +
    "  " +
    "mean".padStart(10) +
    "  " +
    "ops".padStart(10);
  console.log(header);
  console.log("─".repeat(header.length));
  for (const r of results) {
    const row =
      r.name.padEnd(nameWidth) +
      "  " +
      fmtNs(r.medianNs).padStart(10) +
      "  " +
      fmtNs(r.p95Ns).padStart(10) +
      "  " +
      fmtNs(r.meanNs).padStart(10) +
      "  " +
      fmtOps(r.opsPerSec).padStart(10);
    console.log(row);
  }
}
