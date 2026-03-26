/**
 * Enhanced Token Stream Capture — the raw voice of an agent.
 *
 * Treats the token stream as the primary identity signal. Captures
 * per-token data, logprob distributions, chunk boundaries, and burst
 * patterns. The streaming topology — how tokens arrive in time — is a
 * physical artifact of inference hardware that cannot be faked without
 * literally running the same model on the same infrastructure.
 */

import type { StreamingTrace } from "../experiment/signals.js";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Logprob data for a single token — the computational DNA. */
export interface TokenLogprob {
  token: string;
  logprob: number;
  topAlternatives: Array<{ token: string; logprob: number }>;
}

/** A burst — a sequence of tokens arriving in rapid succession. */
export interface BurstPattern {
  startIndex: number;
  endIndex: number;
  duration: number;
  tokenCount: number;
}

/**
 * Enhanced token stream capture — the full phenotypic recording.
 *
 * Extends StreamingTrace with logprobs, chunk boundaries, burst patterns,
 * and heart metadata. This is the primary input to the sensorium.
 */
export interface TokenStreamCapture {
  // --- Per-token data (the raw voice) ---
  tokens: string[];
  timestamps: number[];
  interTokenIntervals: number[];

  // --- Logprob data (the computational DNA, where API supports it) ---
  logprobs: TokenLogprob[] | null;

  // --- Chunk boundaries (physical artifacts of inference) ---
  chunkBoundaries: number[];
  chunkSizes: number[];

  // --- Burst pattern (the rhythm) ---
  burstPattern: BurstPattern[];

  // --- Heart metadata ---
  seedApplied: string;
  heartbeatCount: number;
  birthCertificateCount: number;

  // --- Timing ---
  startTime: number;
  firstTokenTime: number | null;
  endTime: number;
}

// ─── Conversion ─────────────────────────────────────────────────────────────

/**
 * Convert a basic StreamingTrace to a TokenStreamCapture.
 * Fills in derived fields (intervals, bursts, chunks) from the raw data.
 */
export function fromStreamingTrace(
  trace: StreamingTrace,
  logprobs?: TokenLogprob[] | null,
  chunkBoundaries?: number[],
  heartMeta?: { seedApplied?: string; heartbeatCount?: number; birthCertificateCount?: number }
): TokenStreamCapture {
  const intervals = computeIntervals(trace.tokenTimestamps);
  const chunks = chunkBoundaries ?? inferChunkBoundaries(trace.tokens, trace.tokenTimestamps);
  const chunkSizes = computeChunkSizes(chunks, trace.tokens.length);

  return {
    tokens: trace.tokens,
    timestamps: trace.tokenTimestamps,
    interTokenIntervals: intervals,
    logprobs: logprobs ?? null,
    chunkBoundaries: chunks,
    chunkSizes,
    burstPattern: detectBursts(intervals),
    seedApplied: heartMeta?.seedApplied ?? "",
    heartbeatCount: heartMeta?.heartbeatCount ?? 0,
    birthCertificateCount: heartMeta?.birthCertificateCount ?? 0,
    startTime: trace.startTime,
    firstTokenTime: trace.firstTokenTime,
    endTime: trace.endTime,
  };
}

/**
 * Convert a TokenStreamCapture back to a StreamingTrace (for backward compat).
 */
export function toStreamingTrace(capture: TokenStreamCapture): StreamingTrace {
  return {
    tokens: capture.tokens,
    tokenTimestamps: capture.timestamps,
    startTime: capture.startTime,
    firstTokenTime: capture.firstTokenTime,
    endTime: capture.endTime,
  };
}

// ─── Interval Computation ───────────────────────────────────────────────────

/** Compute inter-token intervals from timestamps. */
export function computeIntervals(timestamps: number[]): number[] {
  const intervals: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }
  return intervals;
}

// ─── Chunk Boundary Detection ───────────────────────────────────────────────

/**
 * Infer chunk boundaries from token timestamps.
 *
 * When multiple tokens arrive with near-zero inter-token interval (< 0.5ms),
 * they likely came in the same network chunk. Each boundary is the index
 * where a new chunk starts.
 */
export function inferChunkBoundaries(
  tokens: string[],
  timestamps: number[],
  sameChunkThreshold: number = 0.5
): number[] {
  if (tokens.length === 0) return [];

  const boundaries: number[] = [0]; // first token always starts a chunk
  for (let i = 1; i < timestamps.length; i++) {
    const gap = timestamps[i] - timestamps[i - 1];
    if (gap > sameChunkThreshold) {
      boundaries.push(i);
    }
  }
  return boundaries;
}

/** Compute chunk sizes from boundaries. */
export function computeChunkSizes(boundaries: number[], totalTokens: number): number[] {
  if (boundaries.length === 0) return [];

  const sizes: number[] = [];
  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i];
    const end = i + 1 < boundaries.length ? boundaries[i + 1] : totalTokens;
    sizes.push(end - start);
  }
  return sizes;
}

// ─── Burst Detection ────────────────────────────────────────────────────────

/**
 * Detect burst patterns in the token stream.
 *
 * A "burst" is a sequence of tokens where each inter-token interval is
 * below `mean_interval * 0.5`. A "pause" is a gap above this threshold.
 * Different models produce different burst patterns due to their KV cache,
 * batching, and attention mechanisms.
 */
export function detectBursts(
  intervals: number[],
  burstThresholdMultiplier: number = 0.5
): BurstPattern[] {
  if (intervals.length === 0) return [];

  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const threshold = mean * burstThresholdMultiplier;

  // If mean is near-zero, every interval is a burst — degenerate case
  if (mean < 0.001) return [];

  const bursts: BurstPattern[] = [];
  let burstStart: number | null = null;

  for (let i = 0; i < intervals.length; i++) {
    if (intervals[i] <= threshold) {
      if (burstStart === null) {
        burstStart = i;
      }
    } else {
      if (burstStart !== null) {
        // End of burst — token indices are interval index to interval index + 1
        const endIndex = i; // last token in burst
        const duration = intervals
          .slice(burstStart, i)
          .reduce((a, b) => a + b, 0);
        bursts.push({
          startIndex: burstStart,
          endIndex,
          duration,
          tokenCount: endIndex - burstStart + 1,
        });
        burstStart = null;
      }
    }
  }

  // Close trailing burst
  if (burstStart !== null) {
    const endIndex = intervals.length;
    const duration = intervals
      .slice(burstStart)
      .reduce((a, b) => a + b, 0);
    bursts.push({
      startIndex: burstStart,
      endIndex,
      duration,
      tokenCount: endIndex - burstStart + 1,
    });
  }

  return bursts;
}

// ─── Stream Statistics ──────────────────────────────────────────────────────

/** Summary statistics for a captured token stream. */
export interface StreamStats {
  tokenCount: number;
  chunkCount: number;
  burstCount: number;
  avgChunkSize: number;
  avgBurstLength: number;
  burstFraction: number;
  hasLogprobs: boolean;
  meanInterval: number;
  stdInterval: number;
  medianInterval: number;
}

/** Compute summary statistics from a capture. */
export function computeStreamStats(capture: TokenStreamCapture): StreamStats {
  const intervals = capture.interTokenIntervals;
  const mean = intervals.length > 0
    ? intervals.reduce((a, b) => a + b, 0) / intervals.length
    : 0;
  const variance = intervals.length > 0
    ? intervals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / intervals.length
    : 0;
  const sorted = [...intervals].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length === 0
    ? 0
    : sorted.length % 2 === 0
      ? (sorted[mid - 1] + sorted[mid]) / 2
      : sorted[mid];

  const burstTokens = capture.burstPattern.reduce((sum, b) => sum + b.tokenCount, 0);

  return {
    tokenCount: capture.tokens.length,
    chunkCount: capture.chunkBoundaries.length,
    burstCount: capture.burstPattern.length,
    avgChunkSize: capture.chunkSizes.length > 0
      ? capture.chunkSizes.reduce((a, b) => a + b, 0) / capture.chunkSizes.length
      : 0,
    avgBurstLength: capture.burstPattern.length > 0
      ? burstTokens / capture.burstPattern.length
      : 0,
    burstFraction: capture.tokens.length > 0
      ? burstTokens / capture.tokens.length
      : 0,
    hasLogprobs: capture.logprobs !== null && capture.logprobs.length > 0,
    meanInterval: mean,
    stdInterval: Math.sqrt(variance),
    medianInterval: median,
  };
}
