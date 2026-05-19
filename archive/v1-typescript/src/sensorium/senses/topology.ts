/**
 * Sense 2: Response Topology
 *
 * Measures the structural shape of responses as a flow pattern — like
 * recognizing someone's gait. Different models have characteristic ways
 * of organizing information: paragraph structure, transition usage,
 * frontloading vs. backloading, list placement, code positioning.
 */

// --- Types ---

export interface TopologySignals {
  topoParagraphLengthVariance: number;
  topoParagraphLengthTrend: number;
  topoTransitionDensity: number;
  topoTopicCoherence: number;
  topoFrontloadingRatio: number;
  topoListPosition: number;
  topoConclusionPresent: number;
  topoNestingDepth: number;
  topoCodePosition: number;
}

// --- Transition phrases ---

const TRANSITION_PHRASES = [
  "first,", "second,", "third,", "finally,", "in conclusion",
  "to summarize", "next,", "however,", "in contrast", "similarly",
  "as a result", "therefore", "meanwhile",
];

// --- Conclusion phrases ---

const CONCLUSION_PHRASES = [
  "in summary", "in conclusion", "to sum up", "overall",
  "in short", "the key takeaway",
];

// --- Stop words for topic coherence ---

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "could",
  "should", "may", "might", "shall", "can", "need", "dare", "ought",
  "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
  "into", "through", "during", "before", "after", "above", "below",
  "between", "out", "off", "over", "under", "again", "further", "then",
  "once", "here", "there", "when", "where", "why", "how", "all", "each",
  "every", "both", "few", "more", "most", "other", "some", "such", "no",
  "nor", "not", "only", "own", "same", "so", "than", "too", "very",
  "just", "because", "but", "and", "or", "if", "while", "about", "up",
  "it", "its", "this", "that", "these", "those", "i", "me", "my", "we",
  "our", "you", "your", "he", "him", "his", "she", "her", "they", "them",
  "their", "what", "which", "who", "whom",
]);

// --- Helpers ---

function splitParagraphs(text: string): string[] {
  return text.split(/\n\s*\n/).filter((p) => p.trim().length > 0);
}

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function contentWords(text: string): Set<string> {
  const words = text.toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  const result = new Set<string>();
  for (const w of words) {
    const cleaned = w.replace(/[^\w]/g, "");
    if (cleaned.length > 0 && !STOP_WORDS.has(cleaned)) {
      result.add(cleaned);
    }
  }
  return result;
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

function variance(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  return values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
}

/** Linear regression slope: (n*Σxy - Σx*Σy) / (n*Σx² - (Σx)²) */
function linearSlope(values: number[]): number {
  const n = values.length;
  if (n < 2) return 0;
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  for (let i = 0; i < n; i++) {
    sumX += i;
    sumY += values[i];
    sumXY += i * values[i];
    sumX2 += i * i;
  }
  const denom = n * sumX2 - sumX * sumX;
  if (denom === 0) return 0;
  return (n * sumXY - sumX * sumY) / denom;
}

// --- Main Extractor ---

export function extractTopologySignals(text: string): TopologySignals {
  if (text.trim().length === 0) {
    return {
      topoParagraphLengthVariance: 0,
      topoParagraphLengthTrend: 0,
      topoTransitionDensity: 0,
      topoTopicCoherence: 0,
      topoFrontloadingRatio: 0,
      topoListPosition: -1,
      topoConclusionPresent: 0,
      topoNestingDepth: 0,
      topoCodePosition: -1,
    };
  }

  const paragraphs = splitParagraphs(text);
  const paraWordCounts = paragraphs.map(wordCount);
  const totalWords = paraWordCounts.reduce((a, b) => a + b, 0);
  const totalChars = text.length;

  // --- Paragraph length variance ---
  const topoParagraphLengthVariance = variance(paraWordCounts);

  // --- Paragraph length trend (slope) ---
  const topoParagraphLengthTrend = linearSlope(paraWordCounts);

  // --- Transition density ---
  const lowerText = text.toLowerCase();
  let transitionCount = 0;
  for (const phrase of TRANSITION_PHRASES) {
    let searchFrom = 0;
    while (true) {
      const idx = lowerText.indexOf(phrase, searchFrom);
      if (idx === -1) break;
      transitionCount++;
      searchFrom = idx + phrase.length;
    }
  }
  const topoTransitionDensity = paragraphs.length === 0
    ? 0
    : transitionCount / paragraphs.length;

  // --- Topic coherence (avg Jaccard of consecutive paragraph pairs) ---
  let topoTopicCoherence = 0;
  if (paragraphs.length >= 2) {
    let totalSim = 0;
    let pairs = 0;
    for (let i = 0; i < paragraphs.length - 1; i++) {
      const wordsA = contentWords(paragraphs[i]);
      const wordsB = contentWords(paragraphs[i + 1]);
      totalSim += jaccard(wordsA, wordsB);
      pairs++;
    }
    topoTopicCoherence = pairs === 0 ? 0 : totalSim / pairs;
  }

  // --- Frontloading ratio ---
  const topoFrontloadingRatio = totalWords === 0
    ? 0
    : (paraWordCounts[0] ?? 0) / totalWords;

  // --- List position ---
  const listMatch = text.match(/(?:^|\n)\s*[-*•]\s|(?:^|\n)\s*\d+[.)]\s/);
  const topoListPosition = listMatch && listMatch.index !== undefined
    ? listMatch.index / totalChars
    : -1;

  // --- Conclusion present ---
  const lastPara = paragraphs.length > 0
    ? paragraphs[paragraphs.length - 1].toLowerCase()
    : "";
  const topoConclusionPresent = CONCLUSION_PHRASES.some((p) => lastPara.includes(p))
    ? 1
    : 0;

  // --- Nesting depth ---
  const lines = text.split("\n");
  let maxDepth = 0;
  for (const line of lines) {
    let depth = 0;
    // Headers contribute depth by level
    const headerMatch = line.match(/^(#{1,6})\s/);
    if (headerMatch) {
      depth = headerMatch[1].length;
    }
    // Indented list items: count leading spaces / 2 (or tabs)
    const indentMatch = line.match(/^(\s+)[-*•\d]/);
    if (indentMatch) {
      const spaces = indentMatch[1].replace(/\t/g, "  ").length;
      depth = Math.ceil(spaces / 2);
    }
    if (depth > maxDepth) maxDepth = depth;
  }
  const topoNestingDepth = maxDepth;

  // --- Code position ---
  const codeMatch = text.match(/```/);
  const topoCodePosition = codeMatch && codeMatch.index !== undefined
    ? codeMatch.index / totalChars
    : -1;

  return {
    topoParagraphLengthVariance,
    topoParagraphLengthTrend,
    topoTransitionDensity,
    topoTopicCoherence,
    topoFrontloadingRatio,
    topoListPosition,
    topoConclusionPresent,
    topoNestingDepth,
    topoCodePosition,
  };
}

/** Feature names for the topology sense. */
export const TOPOLOGY_FEATURE_NAMES: string[] = [
  "topo_paragraph_length_variance",
  "topo_paragraph_length_trend",
  "topo_transition_density",
  "topo_topic_coherence",
  "topo_frontloading_ratio",
  "topo_list_position",
  "topo_conclusion_present",
  "topo_nesting_depth",
  "topo_code_position",
];

/** Convert topology signals to a numeric feature vector. */
export function topologyToFeatureVector(signals: TopologySignals): number[] {
  return [
    signals.topoParagraphLengthVariance,
    signals.topoParagraphLengthTrend,
    signals.topoTransitionDensity,
    signals.topoTopicCoherence,
    signals.topoFrontloadingRatio,
    signals.topoListPosition,
    signals.topoConclusionPresent,
    signals.topoNestingDepth,
    signals.topoCodePosition,
  ];
}
