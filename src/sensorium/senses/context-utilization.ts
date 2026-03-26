/**
 * Sense 8: Context Utilization
 *
 * Measures how the agent processes provided information — echo patterns,
 * response proportionality, hallucination indicators, adherence to
 * constraints, and information ordering.
 */

// --- Types ---

export interface ContextUtilizationSignals {
  ctxEchoRatio: number;
  ctxResponseToPromptRatio: number;
  ctxHallucinationIndicator: number;
  ctxPromptAdherence: number;
  ctxInfoOrdering: number;
}

// --- Helpers ---

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

/** Extract capitalized multi-word sequences (likely proper nouns / key phrases). */
function extractNounPhrases(text: string): string[] {
  const matches = text.match(/[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+/g);
  return matches ?? [];
}

/** Extract proper nouns (capitalized words not at sentence start). */
function extractProperNouns(text: string): string[] {
  const nouns: string[] = [];
  const sentences = text.split(/[.!?]+/).filter((s) => s.trim().length > 0);
  for (const sentence of sentences) {
    const words = sentence.trim().split(/\s+/);
    // Skip first word (sentence start), check rest for capitalization
    for (let i = 1; i < words.length; i++) {
      const cleaned = words[i].replace(/[^\w]/g, "");
      if (cleaned.length > 1 && /^[A-Z][a-z]/.test(cleaned)) {
        nouns.push(cleaned.toLowerCase());
      }
    }
  }
  return nouns;
}

/** Extract shared nouns between prompt and response, preserving order. */
function sharedNounsOrdered(prompt: string, response: string): { promptOrder: number[]; responseOrder: number[] } {
  const promptWords = prompt.toLowerCase().split(/\s+/).filter((w) => w.length > 3);
  const responseWords = response.toLowerCase().split(/\s+/).filter((w) => w.length > 3);

  // Get unique content words from prompt
  const promptUnique = [...new Set(promptWords)];
  const responseUnique = [...new Set(responseWords)];

  // Find shared words
  const responseSet = new Set(responseUnique);
  const shared = promptUnique.filter((w) => responseSet.has(w));

  if (shared.length < 3) return { promptOrder: [], responseOrder: [] };

  // Get position of each shared word in prompt and response
  const promptOrder: number[] = [];
  const responseOrder: number[] = [];

  for (const word of shared) {
    const pIdx = promptWords.indexOf(word);
    const rIdx = responseWords.indexOf(word);
    if (pIdx >= 0 && rIdx >= 0) {
      promptOrder.push(pIdx);
      responseOrder.push(rIdx);
    }
  }

  return { promptOrder, responseOrder };
}

/** Spearman rank correlation. */
function spearmanCorrelation(x: number[], y: number[]): number {
  const n = x.length;
  if (n < 3) return 0;

  // Convert to ranks
  const rankX = toRanks(x);
  const rankY = toRanks(y);

  // Pearson on ranks
  const meanRX = rankX.reduce((a, b) => a + b, 0) / n;
  const meanRY = rankY.reduce((a, b) => a + b, 0) / n;

  let num = 0, denX = 0, denY = 0;
  for (let i = 0; i < n; i++) {
    const dx = rankX[i] - meanRX;
    const dy = rankY[i] - meanRY;
    num += dx * dy;
    denX += dx * dx;
    denY += dy * dy;
  }

  const den = Math.sqrt(denX * denY);
  return den === 0 ? 0 : num / den;
}

function toRanks(values: number[]): number[] {
  const indexed = values.map((v, i) => ({ v, i }));
  indexed.sort((a, b) => a.v - b.v);
  const ranks = new Array(values.length);
  for (let i = 0; i < indexed.length; i++) {
    ranks[indexed[i].i] = i + 1;
  }
  return ranks;
}

// --- Main Extractor ---

export function extractContextUtilizationSignals(
  promptText: string,
  responseText: string
): ContextUtilizationSignals {
  const promptWords = wordCount(promptText);
  const responseWords = wordCount(responseText);

  // --- Echo ratio ---
  // Prompt noun phrases appearing verbatim in response / total extracted
  const promptPhrases = extractNounPhrases(promptText);
  let echoCount = 0;
  for (const phrase of promptPhrases) {
    if (responseText.includes(phrase)) echoCount++;
  }
  const ctxEchoRatio = promptPhrases.length === 0
    ? 0
    : echoCount / promptPhrases.length;

  // --- Response to prompt ratio ---
  const ctxResponseToPromptRatio = promptWords === 0
    ? 0
    : responseWords / promptWords;

  // --- Hallucination indicator ---
  // Proper nouns in response not in prompt / response word count
  const promptProperNouns = new Set(extractProperNouns(promptText));
  const responseProperNouns = extractProperNouns(responseText);
  let novelNouns = 0;
  for (const noun of responseProperNouns) {
    if (!promptProperNouns.has(noun)) novelNouns++;
  }
  const ctxHallucinationIndicator = responseWords === 0
    ? 0
    : novelNouns / responseWords;

  // --- Prompt adherence ---
  // Check if prompt has numeric constraint ("in N sentences/words/items")
  let ctxPromptAdherence = -1;
  const constraintMatch = promptText.match(
    /\bin (\d+) (sentences?|words?|items?|points?|steps?|lines?|paragraphs?|bullets?)\b/i
  );
  if (constraintMatch) {
    const target = parseInt(constraintMatch[1], 10);
    const unit = constraintMatch[2].toLowerCase().replace(/s$/, "");
    let actual = 0;
    switch (unit) {
      case "sentence":
        actual = responseText.split(/[.!?]+/).filter((s) => s.trim().length > 0).length;
        break;
      case "word":
        actual = responseWords;
        break;
      case "item":
      case "point":
      case "bullet":
        actual = (responseText.match(/(?:^|\n)\s*[-*•]\s|(?:^|\n)\s*\d+[.)]\s/g) || []).length;
        break;
      case "step":
        actual = (responseText.match(/\b(?:step \d|first|second|third|finally)\b/gi) || []).length;
        break;
      case "line":
        actual = responseText.split("\n").filter((l) => l.trim().length > 0).length;
        break;
      case "paragraph":
        actual = responseText.split(/\n\s*\n/).filter((p) => p.trim().length > 0).length;
        break;
    }
    ctxPromptAdherence = actual === target ? 1 : 0;
  }

  // --- Info ordering (Spearman rank correlation) ---
  const { promptOrder, responseOrder } = sharedNounsOrdered(promptText, responseText);
  const ctxInfoOrdering = promptOrder.length >= 3
    ? spearmanCorrelation(promptOrder, responseOrder)
    : 0;

  return {
    ctxEchoRatio,
    ctxResponseToPromptRatio,
    ctxHallucinationIndicator,
    ctxPromptAdherence,
    ctxInfoOrdering,
  };
}

/** Feature names for the context utilization sense. */
export const CONTEXT_UTILIZATION_FEATURE_NAMES: string[] = [
  "ctx_echo_ratio",
  "ctx_response_to_prompt_ratio",
  "ctx_hallucination_indicator",
  "ctx_prompt_adherence",
  "ctx_info_ordering",
];

/** Convert context utilization signals to a numeric feature vector. */
export function contextUtilizationToFeatureVector(
  signals: ContextUtilizationSignals
): number[] {
  return [
    signals.ctxEchoRatio,
    signals.ctxResponseToPromptRatio,
    signals.ctxHallucinationIndicator,
    signals.ctxPromptAdherence,
    signals.ctxInfoOrdering,
  ];
}
