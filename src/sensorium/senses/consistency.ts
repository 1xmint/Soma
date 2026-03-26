/**
 * Sense 7: Consistency Manifold
 *
 * Measures cross-task stability — how consistently does this agent behave
 * across different probe categories? Some models are chameleons (high
 * variation), others are rigid (low variation). The consistency pattern
 * IS the identity.
 *
 * Meaningful after 3+ probes per category.
 */

// --- Types ---

export interface ConsistencySignals {
  consistVocabStability: number;
  consistTimingStability: number;
  consistStructureStability: number;
  consistHedgeStability: number;
  consistLengthCalibrationR2: number;
  consistIdentityCoherence: number;
}

// --- Helpers ---

function stdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function shannonEntropy(items: string[]): number {
  if (items.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item, (counts.get(item) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / items.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** R² = 1 - (SS_res / SS_tot) */
function rSquared(x: number[], y: number[]): number {
  const n = x.length;
  if (n < 2) return 0;
  const meanY = y.reduce((a, b) => a + b, 0) / n;
  const ssTot = y.reduce((sum, v) => sum + (v - meanY) ** 2, 0);
  if (ssTot === 0) return 1; // perfect prediction if no variation

  // Linear regression
  const meanX = x.reduce((a, b) => a + b, 0) / n;
  let num = 0, denX = 0;
  for (let i = 0; i < n; i++) {
    num += (x[i] - meanX) * (y[i] - meanY);
    denX += (x[i] - meanX) ** 2;
  }
  const slope = denX === 0 ? 0 : num / denX;
  const intercept = meanY - slope * meanX;

  const ssRes = y.reduce((sum, yi, i) => {
    const predicted = slope * x[i] + intercept;
    return sum + (yi - predicted) ** 2;
  }, 0);

  return 1 - ssRes / ssTot;
}

// --- Self-reference patterns ---

const SELF_REFERENCE_PATTERNS = ["I ", "As an AI", "As a language model", "As an assistant", "Let me"];

// --- Main Extractor ---

export interface CategoryObservation {
  category: string;
  typeTokenRatio: number;
  meanInterval: number;
  avgSentenceLength: number;
  hedgeCount: number;
  responseWordCount: number;
  promptWordCount: number;
  responseText: string;
}

/**
 * Extract consistency signals from categorized observations.
 * Operates across multiple categorized responses.
 *
 * @param observations - Per-response observations with category labels
 */
export function extractConsistencySignals(
  observations: CategoryObservation[]
): ConsistencySignals {
  const defaults: ConsistencySignals = {
    consistVocabStability: 0,
    consistTimingStability: 0,
    consistStructureStability: 0,
    consistHedgeStability: 0,
    consistLengthCalibrationR2: 0,
    consistIdentityCoherence: 0,
  };

  // Group by category
  const groups = new Map<string, CategoryObservation[]>();
  for (const obs of observations) {
    if (!groups.has(obs.category)) groups.set(obs.category, []);
    groups.get(obs.category)!.push(obs);
  }

  // Need 3+ categories with 3+ observations each
  const qualifiedCategories = [...groups.entries()].filter(
    ([, obs]) => obs.length >= 3
  );
  if (qualifiedCategories.length < 2) return defaults;

  // --- Per-category means ---
  const catMeans = {
    vocab: [] as number[],
    timing: [] as number[],
    structure: [] as number[],
    hedge: [] as number[],
  };
  for (const [, obs] of qualifiedCategories) {
    catMeans.vocab.push(obs.reduce((s, o) => s + o.typeTokenRatio, 0) / obs.length);
    catMeans.timing.push(obs.reduce((s, o) => s + o.meanInterval, 0) / obs.length);
    catMeans.structure.push(obs.reduce((s, o) => s + o.avgSentenceLength, 0) / obs.length);
    catMeans.hedge.push(obs.reduce((s, o) => s + o.hedgeCount, 0) / obs.length);
  }

  const consistVocabStability = stdDev(catMeans.vocab);
  const consistTimingStability = stdDev(catMeans.timing);
  const consistStructureStability = stdDev(catMeans.structure);
  const consistHedgeStability = stdDev(catMeans.hedge);

  // --- Length calibration R² ---
  const promptLengths = observations.map((o) => o.promptWordCount);
  const responseLengths = observations.map((o) => o.responseWordCount);
  const consistLengthCalibrationR2 = rSquared(promptLengths, responseLengths);

  // --- Identity coherence ---
  // Shannon entropy of self-reference pattern distribution
  const selfRefs: string[] = [];
  for (const obs of observations) {
    for (const pattern of SELF_REFERENCE_PATTERNS) {
      const re = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      const matches = obs.responseText.match(re);
      if (matches) {
        for (const m of matches) {
          selfRefs.push(pattern);
        }
      }
    }
  }
  const consistIdentityCoherence = shannonEntropy(selfRefs);

  return {
    consistVocabStability,
    consistTimingStability,
    consistStructureStability,
    consistHedgeStability,
    consistLengthCalibrationR2,
    consistIdentityCoherence,
  };
}

/** Feature names for the consistency sense. */
export const CONSISTENCY_FEATURE_NAMES: string[] = [
  "consist_vocab_stability",
  "consist_timing_stability",
  "consist_structure_stability",
  "consist_hedge_stability",
  "consist_length_calibration_r2",
  "consist_identity_coherence",
];

/** Convert consistency signals to a numeric feature vector. */
export function consistencyToFeatureVector(
  signals: ConsistencySignals
): number[] {
  return [
    signals.consistVocabStability,
    signals.consistTimingStability,
    signals.consistStructureStability,
    signals.consistHedgeStability,
    signals.consistLengthCalibrationR2,
    signals.consistIdentityCoherence,
  ];
}
