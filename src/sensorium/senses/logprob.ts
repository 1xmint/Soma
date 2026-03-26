/**
 * Logprob Fingerprint — available when API supports it (3x weight when available)
 *
 * Token probability distributions reveal the model's internal confidence
 * landscape. Different architectures produce different probability distributions
 * over next-token predictions — this is the computational DNA.
 *
 * API support:
 * - OpenAI: logprobs: true, top_logprobs: 5 ✓
 * - Groq: logprobs: true, top_logprobs: 5 ✓
 * - Anthropic: not currently supported — skip
 * - Mistral: check availability
 * - OpenRouter: depends on underlying model
 */

import type { TokenLogprob } from "../stream-capture.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface LogprobSignals {
  /** Average log-probability of chosen tokens. */
  logprobMean: number;
  /** Standard deviation of chosen token log-probs. */
  logprobStd: number;
  /** Average entropy of top-N alternative distributions. */
  logprobEntropyMean: number;
  /** How often the chosen token was the highest-probability option (0.0-1.0). */
  logprobTop1Confidence: number;
  /** Average number of alternatives with logprob > -2.0. */
  logprobAlternativeDiversity: number;
  /** Median log-probability of chosen tokens. */
  logprobMedian: number;
  /** Standard deviation of the entropy values across tokens. */
  logprobEntropyStd: number;
  /** Mean logprob of the second-most-likely alternative. */
  logprobRunnerUpMean: number;
  /** Mean gap between chosen token logprob and runner-up. */
  logprobConfidenceGap: number;
  /** Fraction of tokens where chosen logprob < -5.0 (surprising tokens). */
  logprobSurpriseRate: number;
}

// ─── Feature names (must match vector order) ─────────────────────────────────

export const LOGPROB_FEATURE_NAMES: readonly string[] = [
  "logprob_mean",
  "logprob_std",
  "logprob_entropy_mean",
  "logprob_top1_confidence",
  "logprob_alternative_diversity",
  "logprob_median",
  "logprob_entropy_std",
  "logprob_runner_up_mean",
  "logprob_confidence_gap",
  "logprob_surprise_rate",
];

// ─── Extraction ──────────────────────────────────────────────────────────────

/**
 * Extract logprob signals from token logprob data.
 * Returns null if logprobs are not available.
 */
export function extractLogprobSignals(logprobs: TokenLogprob[] | null): LogprobSignals | null {
  if (!logprobs || logprobs.length === 0) return null;

  const chosenLogprobs = logprobs.map(lp => lp.logprob);
  const n = chosenLogprobs.length;

  // Mean and std of chosen token log-probs
  const logprobMean = chosenLogprobs.reduce((a, b) => a + b, 0) / n;
  const logprobVariance = chosenLogprobs.reduce((sum, v) => sum + (v - logprobMean) ** 2, 0) / n;
  const logprobStd = Math.sqrt(logprobVariance);

  // Median
  const sortedLogprobs = [...chosenLogprobs].sort((a, b) => a - b);
  const logprobMedian = n % 2 === 0
    ? (sortedLogprobs[n / 2 - 1] + sortedLogprobs[n / 2]) / 2
    : sortedLogprobs[Math.floor(n / 2)];

  // Per-token entropy of the top-N alternative distribution
  const entropies: number[] = [];
  let top1Matches = 0;
  const diversities: number[] = [];
  const runnerUpLogprobs: number[] = [];
  const confidenceGaps: number[] = [];

  for (const lp of logprobs) {
    // Compute entropy of alternatives (including chosen token)
    const allTokens = [{ logprob: lp.logprob }, ...lp.topAlternatives];
    const probs = allTokens.map(t => Math.exp(t.logprob));
    const totalProb = probs.reduce((a, b) => a + b, 0);

    if (totalProb > 0) {
      let entropy = 0;
      for (const p of probs) {
        const normalized = p / totalProb;
        if (normalized > 0) {
          entropy -= normalized * Math.log2(normalized);
        }
      }
      entropies.push(entropy);
    }

    // Top-1 confidence: was the chosen token the highest probability?
    if (lp.topAlternatives.length === 0 || lp.logprob >= lp.topAlternatives[0].logprob) {
      top1Matches++;
    }

    // Alternative diversity: how many alternatives have logprob > -2.0
    const diverseCount = lp.topAlternatives.filter(a => a.logprob > -2.0).length;
    diversities.push(diverseCount);

    // Runner-up: second most likely token
    if (lp.topAlternatives.length > 0) {
      // Find the highest logprob among alternatives
      const bestAlt = lp.topAlternatives.reduce((best, a) =>
        a.logprob > best.logprob ? a : best, lp.topAlternatives[0]);
      runnerUpLogprobs.push(bestAlt.logprob);
      confidenceGaps.push(lp.logprob - bestAlt.logprob);
    }
  }

  const logprobEntropyMean = entropies.length > 0
    ? entropies.reduce((a, b) => a + b, 0) / entropies.length
    : 0;

  const entropyMean = logprobEntropyMean;
  const logprobEntropyStd = entropies.length > 1
    ? Math.sqrt(entropies.reduce((sum, e) => sum + (e - entropyMean) ** 2, 0) / entropies.length)
    : 0;

  const logprobTop1Confidence = n > 0 ? top1Matches / n : 0;

  const logprobAlternativeDiversity = diversities.length > 0
    ? diversities.reduce((a, b) => a + b, 0) / diversities.length
    : 0;

  const logprobRunnerUpMean = runnerUpLogprobs.length > 0
    ? runnerUpLogprobs.reduce((a, b) => a + b, 0) / runnerUpLogprobs.length
    : 0;

  const logprobConfidenceGap = confidenceGaps.length > 0
    ? confidenceGaps.reduce((a, b) => a + b, 0) / confidenceGaps.length
    : 0;

  const surprisingTokens = chosenLogprobs.filter(lp => lp < -5.0).length;
  const logprobSurpriseRate = n > 0 ? surprisingTokens / n : 0;

  return {
    logprobMean,
    logprobStd,
    logprobEntropyMean,
    logprobTop1Confidence,
    logprobAlternativeDiversity,
    logprobMedian,
    logprobEntropyStd,
    logprobRunnerUpMean,
    logprobConfidenceGap,
    logprobSurpriseRate,
  };
}

/**
 * Convert logprob signals to a feature vector in the order defined by LOGPROB_FEATURE_NAMES.
 */
export function logprobToFeatureVector(signals: LogprobSignals): number[] {
  return [
    signals.logprobMean,
    signals.logprobStd,
    signals.logprobEntropyMean,
    signals.logprobTop1Confidence,
    signals.logprobAlternativeDiversity,
    signals.logprobMedian,
    signals.logprobEntropyStd,
    signals.logprobRunnerUpMean,
    signals.logprobConfidenceGap,
    signals.logprobSurpriseRate,
  ];
}
