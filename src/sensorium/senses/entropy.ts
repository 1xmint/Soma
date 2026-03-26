/**
 * Sense 6: Entropic Fingerprint
 *
 * Measures the randomness profile ACROSS multiple responses. How variable
 * is this agent's output? Some models are highly consistent, others are
 * chaotic. The pattern of variation IS part of the identity.
 *
 * Returns defaults until 10+ responses are accumulated.
 */

// --- Types ---

export interface EntropySignals {
  entropyResponseLengthCv: number;
  entropyWordPredictability: number;
  entropySentenceLengthCv: number;
  entropyFormattingConsistency: number;
  entropyCrossResponseSimilarity: number;
  entropyOpeningDiversity: number;
  entropyFractalProxy: number;
}

// --- Helpers ---

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function splitSentences(text: string): string[] {
  return text.split(/[.!?]+/).filter((s) => s.trim().length > 0);
}

function coefficientOfVariation(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  if (mean === 0) return 0;
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance) / mean;
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

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let intersection = 0;
  for (const w of a) {
    if (b.has(w)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function extractFormattingFeatures(text: string): [number, number, number, number] {
  const hasHeaders = /^#{1,6}\s/m.test(text) ? 1 : 0;
  const hasBullets = /(?:^|\n)\s*[-*•]\s/.test(text) ? 1 : 0;
  const hasCode = /```/.test(text) ? 1 : 0;
  const hasBold = /\*\*[^*]+\*\*/.test(text) ? 1 : 0;
  return [hasHeaders, hasBullets, hasCode, hasBold];
}

// --- Main Extractor ---

/**
 * Extract entropic fingerprint from a collection of responses.
 * Operates ACROSS multiple responses — not on a single one.
 *
 * @param responses - Array of response texts
 * @param categories - Parallel array of category labels
 */
export function extractEntropySignals(
  responses: string[],
  categories: string[]
): EntropySignals {
  const defaults: EntropySignals = {
    entropyResponseLengthCv: 0,
    entropyWordPredictability: 0,
    entropySentenceLengthCv: 0,
    entropyFormattingConsistency: 0,
    entropyCrossResponseSimilarity: 0,
    entropyOpeningDiversity: 0,
    entropyFractalProxy: 0,
  };

  if (responses.length < 10) return defaults;

  // --- Response length CV ---
  const wordCounts = responses.map(wordCount);
  const entropyResponseLengthCv = coefficientOfVariation(wordCounts);

  // --- Word predictability (Shannon entropy of unigram distribution) ---
  const allWords: string[] = [];
  for (const r of responses) {
    const words = r.toLowerCase().split(/\s+/).filter((w) => w.length > 0);
    allWords.push(...words);
  }
  const entropyWordPredictability = shannonEntropy(allWords);

  // --- Sentence length CV (average per-response) ---
  const sentLengthCvs: number[] = [];
  for (const r of responses) {
    const sentences = splitSentences(r);
    const sentLengths = sentences.map(wordCount);
    if (sentLengths.length >= 2) {
      sentLengthCvs.push(coefficientOfVariation(sentLengths));
    }
  }
  const entropySentenceLengthCv =
    sentLengthCvs.length > 0
      ? sentLengthCvs.reduce((a, b) => a + b, 0) / sentLengthCvs.length
      : 0;

  // --- Formatting consistency ---
  const formattingVectors = responses.map(extractFormattingFeatures);
  let formattingVarianceSum = 0;
  for (let feat = 0; feat < 4; feat++) {
    const vals = formattingVectors.map((v) => v[feat]);
    const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
    const variance =
      vals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / vals.length;
    formattingVarianceSum += variance;
  }
  const entropyFormattingConsistency = formattingVarianceSum / 4;

  // --- Cross-response similarity (Jaccard between same-category pairs) ---
  const categoryGroups = new Map<string, string[]>();
  for (let i = 0; i < responses.length; i++) {
    const cat = categories[i] ?? "unknown";
    if (!categoryGroups.has(cat)) categoryGroups.set(cat, []);
    categoryGroups.get(cat)!.push(responses[i]);
  }
  let totalSim = 0;
  let pairCount = 0;
  for (const group of categoryGroups.values()) {
    for (let i = 0; i < group.length - 1; i++) {
      const wordsA = new Set(group[i].toLowerCase().split(/\s+/));
      const wordsB = new Set(group[i + 1].toLowerCase().split(/\s+/));
      totalSim += jaccard(wordsA, wordsB);
      pairCount++;
    }
  }
  const entropyCrossResponseSimilarity = pairCount > 0 ? totalSim / pairCount : 0;

  // --- Opening diversity ---
  const openings = responses.map((r) => {
    const words = r.trim().split(/\s+/).slice(0, 3);
    return words.join(" ").toLowerCase();
  });
  const uniqueOpenings = new Set(openings);
  const entropyOpeningDiversity = uniqueOpenings.size / responses.length;

  // --- Fractal proxy ---
  // Variance of quarter-length fractions across responses
  const quarterFractions: number[][] = [];
  for (const r of responses) {
    const wc = wordCount(r);
    if (wc < 4) continue;
    const words = r.split(/\s+/).filter((w) => w.length > 0);
    const q = Math.floor(words.length / 4);
    const quarters = [
      words.slice(0, q).length / wc,
      words.slice(q, 2 * q).length / wc,
      words.slice(2 * q, 3 * q).length / wc,
      words.slice(3 * q).length / wc,
    ];
    quarterFractions.push(quarters);
  }
  let fractalVarianceSum = 0;
  if (quarterFractions.length >= 2) {
    for (let q = 0; q < 4; q++) {
      const vals = quarterFractions.map((f) => f[q]);
      const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
      fractalVarianceSum +=
        vals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / vals.length;
    }
  }
  const entropyFractalProxy = fractalVarianceSum / 4;

  return {
    entropyResponseLengthCv,
    entropyWordPredictability,
    entropySentenceLengthCv,
    entropyFormattingConsistency,
    entropyCrossResponseSimilarity,
    entropyOpeningDiversity,
    entropyFractalProxy,
  };
}

/** Feature names for the entropy sense. */
export const ENTROPY_FEATURE_NAMES: string[] = [
  "entropy_response_length_cv",
  "entropy_word_predictability",
  "entropy_sentence_length_cv",
  "entropy_formatting_consistency",
  "entropy_cross_response_similarity",
  "entropy_opening_diversity",
  "entropy_fractal_proxy",
];

/** Convert entropy signals to a numeric feature vector. */
export function entropyToFeatureVector(signals: EntropySignals): number[] {
  return [
    signals.entropyResponseLengthCv,
    signals.entropyWordPredictability,
    signals.entropySentenceLengthCv,
    signals.entropyFormattingConsistency,
    signals.entropyCrossResponseSimilarity,
    signals.entropyOpeningDiversity,
    signals.entropyFractalProxy,
  ];
}
