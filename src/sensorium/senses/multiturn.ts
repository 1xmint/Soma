/**
 * Sense 10: Multi-Turn Dynamics
 *
 * Measures behavior across conversations — how does the agent adapt,
 * drift, reference earlier context, shift style, and handle corrections
 * over multiple turns?
 *
 * Requires multi-turn conversation data (see run-multiturn.ts for the
 * scripted conversations that generate this data).
 */

// --- Types ---

export interface MultiTurnSignals {
  multiLengthDrift: number;
  multiLatencyDrift: number;
  multiContextReferenceRate: number;
  multiStyleAdaptation: number;
  multiCorrectionResponse: number;
}

/** A single turn in a multi-turn conversation. */
export interface ConversationTurn {
  role: "user" | "assistant";
  content: string;
  durationMs: number;
  turnIndex: number;
}

/** A complete multi-turn conversation. */
export interface MultiTurnConversation {
  id: string;
  type: "topic_drift" | "deepening" | "correction" | "callback" | "style_shift";
  turns: ConversationTurn[];
}

// --- Helpers ---

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

/** Linear regression slope of values over their indices. */
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

/** Count contractions in text. */
function contractionCount(text: string): number {
  const matches = text.match(
    /\b(?:don't|won't|can't|it's|I'm|isn't|aren't|wasn't|weren't|couldn't|shouldn't|wouldn't|they're|we're|you're|he's|she's|that's|there's|here's|let's|who's|what's|how's)\b/g
  );
  return matches ? matches.length : 0;
}

/** Strip punctuation from a word for comparison. */
function cleanWord(w: string): string {
  return w.replace(/[^\w]/g, "");
}

/** Check if a turn references content from earlier turns. */
function referencesEarlierContent(turn: ConversationTurn, earlierTurns: ConversationTurn[]): boolean {
  const turnWords = new Set(
    turn.content.toLowerCase().split(/\s+/).map(cleanWord).filter((w) => w.length > 4)
  );

  for (const earlier of earlierTurns) {
    if (earlier.role !== "assistant") continue;
    const earlierWords = earlier.content.toLowerCase().split(/\s+/).map(cleanWord).filter((w) => w.length > 4);
    // Check for 3+ shared content words (excluding very common words)
    let shared = 0;
    for (const w of earlierWords) {
      if (turnWords.has(w)) shared++;
      if (shared >= 3) return true;
    }
  }
  return false;
}

// --- Main Extractor ---

/**
 * Extract multi-turn dynamics from a collection of conversations.
 *
 * @param conversations - Array of multi-turn conversations
 */
export function extractMultiTurnSignals(
  conversations: MultiTurnConversation[]
): MultiTurnSignals {
  const defaults: MultiTurnSignals = {
    multiLengthDrift: 0,
    multiLatencyDrift: 0,
    multiContextReferenceRate: 0,
    multiStyleAdaptation: 0,
    multiCorrectionResponse: 0,
  };

  if (conversations.length === 0) return defaults;

  // Collect assistant turns from all conversations
  const allLengthSlopes: number[] = [];
  const allLatencySlopes: number[] = [];
  const allReferenceRates: number[] = [];
  const allStyleChanges: number[] = [];
  const allCorrectionScores: number[] = [];

  for (const conv of conversations) {
    const assistantTurns = conv.turns.filter((t) => t.role === "assistant");
    if (assistantTurns.length < 2) continue;

    // --- Length drift (slope of word counts across turns) ---
    const lengths = assistantTurns.map((t) => wordCount(t.content));
    allLengthSlopes.push(linearSlope(lengths));

    // --- Latency drift (slope of durations across turns) ---
    const latencies = assistantTurns.map((t) => t.durationMs);
    allLatencySlopes.push(linearSlope(latencies));

    // --- Context reference rate ---
    let refCount = 0;
    for (let i = 1; i < assistantTurns.length; i++) {
      if (referencesEarlierContent(assistantTurns[i], assistantTurns.slice(0, i))) {
        refCount++;
      }
    }
    allReferenceRates.push(refCount / (assistantTurns.length - 1));

    // --- Style adaptation (contraction ratio change first-to-last) ---
    const firstContractionRatio =
      contractionCount(assistantTurns[0].content) /
      Math.max(wordCount(assistantTurns[0].content), 1);
    const lastContractionRatio =
      contractionCount(assistantTurns[assistantTurns.length - 1].content) /
      Math.max(wordCount(assistantTurns[assistantTurns.length - 1].content), 1);
    allStyleChanges.push(lastContractionRatio - firstContractionRatio);

    // --- Correction response ---
    if (conv.type === "correction") {
      // Look for correction turn (user says something is wrong)
      // then check assistant response
      for (let i = 1; i < conv.turns.length; i++) {
        const turn = conv.turns[i];
        if (turn.role === "user" && /\b(?:wrong|incorrect|actually|no,?\s|that's not)\b/i.test(turn.content)) {
          const nextAssistant = conv.turns.slice(i + 1).find((t) => t.role === "assistant");
          if (nextAssistant) {
            const text = nextAssistant.content;
            if (/\b(?:sorry|apologize|apologies|my mistake|I was wrong|you're right|correction)\b/i.test(text)) {
              allCorrectionScores.push(3); // apologizes
            } else if (/\b(?:maintain|actually|however|I stand by|I believe)\b/i.test(text)) {
              allCorrectionScores.push(2); // maintains position
            } else if (/\b(?:yes|right|correct|indeed)\b/i.test(text)) {
              allCorrectionScores.push(1); // agrees
            } else {
              allCorrectionScores.push(0); // unclear
            }
          }
        }
      }
    }
  }

  // Aggregate
  const avg = (arr: number[]) => arr.length === 0 ? 0 : arr.reduce((a, b) => a + b, 0) / arr.length;

  return {
    multiLengthDrift: avg(allLengthSlopes),
    multiLatencyDrift: avg(allLatencySlopes),
    multiContextReferenceRate: avg(allReferenceRates),
    multiStyleAdaptation: avg(allStyleChanges),
    multiCorrectionResponse: avg(allCorrectionScores),
  };
}

/** Feature names for the multi-turn dynamics sense. */
export const MULTITURN_FEATURE_NAMES: string[] = [
  "multi_length_drift",
  "multi_latency_drift",
  "multi_context_reference_rate",
  "multi_style_adaptation",
  "multi_correction_response",
];

/** Convert multi-turn signals to a numeric feature vector. */
export function multiturnToFeatureVector(signals: MultiTurnSignals): number[] {
  return [
    signals.multiLengthDrift,
    signals.multiLatencyDrift,
    signals.multiContextReferenceRate,
    signals.multiStyleAdaptation,
    signals.multiCorrectionResponse,
  ];
}
