/**
 * Sense 1: Temporal Fingerprint — PRIMARY (88.5% standalone accuracy, 5x weight)
 *
 * The model's inference rhythm. Token-by-token timing, inter-token intervals,
 * burst patterns, time-to-first-token. This is the model's heartbeat.
 *
 * Every model architecture produces a distinctive timing signature determined
 * by its weights, attention mechanism, and hardware. You cannot produce Claude's
 * rhythm without running Claude's inference. This is the voice.
 *
 * Beyond aggregate statistics, the temporal sense also measures timing
 * *conditioned on context* — the Conditional Timing Surface. How long the model
 * takes to generate token N depends on the attention computation over tokens
 * 1 through N-1. Different weights -> different attention patterns -> different
 * per-token timing conditioned on the specific context.
 *
 * This creates a high-dimensional conditional timing surface that a distilled
 * model cannot replicate without equivalent computation on equivalent hardware.
 */

import type { TokenStreamCapture } from "../stream-capture.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TemporalSignals {
  // --- Aggregate statistics (the basic heartbeat) ---
  /** ms from request to first token. */
  timeToFirstToken: number;
  /** Average inter-token interval in ms. */
  meanInterval: number;
  /** Median inter-token interval in ms. */
  medianInterval: number;
  /** Standard deviation of inter-token intervals. */
  stdInterval: number;
  /** Burstiness = variance / mean of intervals. Measures batchy vs smooth delivery. */
  burstiness: number;
  /** Total generation time in ms. */
  totalStreamingDuration: number;
  /** Number of tokens generated. */
  tokenCount: number;

  // --- Conditional timing surface (anti-distillation defense) ---
  /** Mean interval in the first quartile of tokens. */
  earlyMeanInterval: number;
  /** Mean interval in the middle half of tokens. */
  midMeanInterval: number;
  /** Mean interval in the last quartile of tokens. */
  lateMeanInterval: number;
  /** Timing acceleration: late mean - early mean. Positive = slowing down. */
  acceleration: number;
  /** Ratio of avg interval at sentence boundaries vs mid-sentence. */
  sentenceBoundaryPauseRatio: number;

  // --- Burst topology ---
  /** Number of detected bursts. */
  burstCount: number;
  /** Fraction of tokens that are part of bursts. */
  burstFraction: number;
  /** Average number of tokens per burst. */
  meanBurstLength: number;
  /** Mean interval between consecutive bursts (ms). */
  interBurstInterval: number;

  // --- Distribution shape ---
  /** Number of inference chunks (network-level). */
  chunkCount: number;
  /** Average tokens per chunk. */
  meanChunkSize: number;
  /** Shannon entropy of binned interval distribution. */
  timingEntropy: number;
  /** 90th percentile inter-token interval. */
  p90Interval: number;
  /** 10th percentile inter-token interval. */
  p10Interval: number;
  /** Skewness of the interval distribution. */
  intervalSkewness: number;
}

// ─── Feature names (must match vector order) ─────────────────────────────────

export const TEMPORAL_FEATURE_NAMES: readonly string[] = [
  "temporal_time_to_first_token",
  "temporal_mean_interval",
  "temporal_median_interval",
  "temporal_std_interval",
  "temporal_burstiness",
  "temporal_total_streaming_duration",
  "temporal_token_count",
  "temporal_early_mean_interval",
  "temporal_mid_mean_interval",
  "temporal_late_mean_interval",
  "temporal_acceleration",
  "temporal_sentence_boundary_pause_ratio",
  "temporal_burst_count",
  "temporal_burst_fraction",
  "temporal_mean_burst_length",
  "temporal_inter_burst_interval",
  "temporal_chunk_count",
  "temporal_mean_chunk_size",
  "temporal_timing_entropy",
  "temporal_p90_interval",
  "temporal_p10_interval",
  "temporal_interval_skewness",
];

// ─── Extraction ──────────────────────────────────────────────────────────────

/**
 * Extract temporal signals from a token stream capture.
 * This is the PRIMARY sense — 88.5% standalone accuracy.
 */
export function extractTemporalSignals(capture: TokenStreamCapture): TemporalSignals {
  const intervals = capture.interTokenIntervals;
  const n = intervals.length;

  // --- Aggregate statistics ---
  const timeToFirstToken = capture.firstTokenTime !== null
    ? capture.firstTokenTime - capture.startTime
    : 0;

  const meanInterval = n > 0 ? intervals.reduce((a, b) => a + b, 0) / n : 0;

  const sorted = [...intervals].sort((a, b) => a - b);
  const medianInterval = n > 0
    ? (n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)])
    : 0;

  const variance = n > 0
    ? intervals.reduce((sum, v) => sum + (v - meanInterval) ** 2, 0) / n
    : 0;
  const stdInterval = Math.sqrt(variance);

  const burstiness = meanInterval > 0 ? variance / meanInterval : 0;

  const totalStreamingDuration = capture.endTime - capture.startTime;
  const tokenCount = capture.tokens.length;

  // --- Conditional timing surface ---
  const q1End = Math.floor(n * 0.25);
  const q3Start = Math.floor(n * 0.75);

  const earlyMeanInterval = q1End > 0
    ? intervals.slice(0, q1End).reduce((a, b) => a + b, 0) / q1End
    : meanInterval;

  const midSlice = intervals.slice(q1End, q3Start);
  const midMeanInterval = midSlice.length > 0
    ? midSlice.reduce((a, b) => a + b, 0) / midSlice.length
    : meanInterval;

  const lateSlice = intervals.slice(q3Start);
  const lateMeanInterval = lateSlice.length > 0
    ? lateSlice.reduce((a, b) => a + b, 0) / lateSlice.length
    : meanInterval;

  const acceleration = lateMeanInterval - earlyMeanInterval;

  // Sentence boundary pause ratio
  const sentenceBoundaryPauseRatio = computeSentenceBoundaryPauseRatio(capture.tokens, intervals);

  // --- Burst topology ---
  const burstCount = capture.burstPattern.length;
  const totalBurstTokens = capture.burstPattern.reduce((sum, b) => sum + b.tokenCount, 0);
  const burstFraction = tokenCount > 0 ? totalBurstTokens / tokenCount : 0;
  const meanBurstLength = burstCount > 0 ? totalBurstTokens / burstCount : 0;
  const interBurstInterval = computeInterBurstInterval(capture.burstPattern, intervals);

  // --- Distribution shape ---
  const chunkCount = capture.chunkBoundaries.length;
  const meanChunkSize = capture.chunkSizes.length > 0
    ? capture.chunkSizes.reduce((a, b) => a + b, 0) / capture.chunkSizes.length
    : 0;

  const timingEntropy = computeTimingEntropy(intervals);

  const p90Interval = n > 0 ? sorted[Math.min(Math.floor(n * 0.9), n - 1)] : 0;
  const p10Interval = n > 0 ? sorted[Math.min(Math.floor(n * 0.1), n - 1)] : 0;

  const intervalSkewness = computeSkewness(intervals, meanInterval, stdInterval);

  return {
    timeToFirstToken,
    meanInterval,
    medianInterval,
    stdInterval,
    burstiness,
    totalStreamingDuration,
    tokenCount,
    earlyMeanInterval,
    midMeanInterval,
    lateMeanInterval,
    acceleration,
    sentenceBoundaryPauseRatio,
    burstCount,
    burstFraction,
    meanBurstLength,
    interBurstInterval,
    chunkCount,
    meanChunkSize,
    timingEntropy,
    p90Interval,
    p10Interval,
    intervalSkewness,
  };
}

/**
 * Convert temporal signals to a feature vector in the order defined by TEMPORAL_FEATURE_NAMES.
 */
export function temporalToFeatureVector(signals: TemporalSignals): number[] {
  return [
    signals.timeToFirstToken,
    signals.meanInterval,
    signals.medianInterval,
    signals.stdInterval,
    signals.burstiness,
    signals.totalStreamingDuration,
    signals.tokenCount,
    signals.earlyMeanInterval,
    signals.midMeanInterval,
    signals.lateMeanInterval,
    signals.acceleration,
    signals.sentenceBoundaryPauseRatio,
    signals.burstCount,
    signals.burstFraction,
    signals.meanBurstLength,
    signals.interBurstInterval,
    signals.chunkCount,
    signals.meanChunkSize,
    signals.timingEntropy,
    signals.p90Interval,
    signals.p10Interval,
    signals.intervalSkewness,
  ];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Compute the ratio of average pause at sentence boundaries vs mid-sentence.
 *
 * Sentence boundaries are detected by tokens ending with '.', '!', '?', or
 * containing these followed by whitespace. The interval AFTER a sentence-ending
 * token typically includes model "thinking" time for the next sentence.
 */
function computeSentenceBoundaryPauseRatio(tokens: string[], intervals: number[]): number {
  const boundaryIntervals: number[] = [];
  const midSentenceIntervals: number[] = [];

  for (let i = 0; i < intervals.length; i++) {
    const token = tokens[i];
    if (isSentenceEnd(token)) {
      boundaryIntervals.push(intervals[i]);
    } else {
      midSentenceIntervals.push(intervals[i]);
    }
  }

  if (boundaryIntervals.length === 0 || midSentenceIntervals.length === 0) return 1.0;

  const boundaryMean = boundaryIntervals.reduce((a, b) => a + b, 0) / boundaryIntervals.length;
  const midMean = midSentenceIntervals.reduce((a, b) => a + b, 0) / midSentenceIntervals.length;

  return midMean > 0 ? boundaryMean / midMean : 1.0;
}

/** Check if a token marks the end of a sentence. */
function isSentenceEnd(token: string): boolean {
  const trimmed = token.trimEnd();
  return /[.!?]$/.test(trimmed) || /[.!?]["')}\]]$/.test(trimmed);
}

/**
 * Compute mean interval between consecutive burst ends and starts.
 */
function computeInterBurstInterval(bursts: Array<{ startIndex: number; endIndex: number }>, intervals: number[]): number {
  if (bursts.length < 2) return 0;

  const gaps: number[] = [];
  for (let i = 1; i < bursts.length; i++) {
    const gapStart = bursts[i - 1].endIndex;
    const gapEnd = bursts[i].startIndex;
    if (gapEnd > gapStart && gapEnd <= intervals.length) {
      const gapSum = intervals.slice(gapStart, gapEnd).reduce((a, b) => a + b, 0);
      gaps.push(gapSum);
    }
  }

  return gaps.length > 0 ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
}

/**
 * Compute Shannon entropy of the inter-token interval distribution.
 * Bins intervals into 20 equal-width bins spanning [0, 2 * mean].
 * Higher entropy = more uniform distribution. Lower = more peaked.
 */
function computeTimingEntropy(intervals: number[]): number {
  if (intervals.length < 2) return 0;

  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const binCount = 20;
  const binWidth = (2 * mean) / binCount;
  if (binWidth <= 0) return 0;

  const bins = new Array(binCount).fill(0);
  for (const interval of intervals) {
    const bin = Math.min(Math.floor(interval / binWidth), binCount - 1);
    bins[bin]++;
  }

  let entropy = 0;
  for (const count of bins) {
    if (count > 0) {
      const p = count / intervals.length;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Compute skewness of the interval distribution.
 * Positive skew = long right tail (occasional long pauses).
 * Negative skew = long left tail (unusual).
 */
function computeSkewness(values: number[], mean: number, std: number): number {
  if (values.length < 3 || std === 0) return 0;
  const n = values.length;
  const m3 = values.reduce((sum, v) => sum + ((v - mean) / std) ** 3, 0) / n;
  return m3;
}
