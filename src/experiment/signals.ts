/**
 * Phenotypic signal extraction from agent responses.
 *
 * These are NOT about what an agent says — they're about HOW it says it.
 * The behavioral patterns are involuntary expressions of the underlying
 * computational substrate, like a gait analysis for language models.
 */

import {
  extractVocabularySignals,
  vocabularyToFeatureVector,
  VOCABULARY_FEATURE_NAMES,
  type VocabularySignals,
  extractTopologySignals,
  topologyToFeatureVector,
  TOPOLOGY_FEATURE_NAMES,
  type TopologySignals,
  extractCapabilityBoundarySignals,
  capabilityBoundaryToFeatureVector,
  CAPABILITY_BOUNDARY_FEATURE_NAMES,
  type CapabilityBoundarySignals,
  extractToolInteractionSignals,
  toolInteractionToFeatureVector,
  TOOL_INTERACTION_FEATURE_NAMES,
  type ToolInteractionSignals,
  extractAdversarialSignals,
  adversarialToFeatureVector,
  ADVERSARIAL_FEATURE_NAMES,
  type AdversarialSignals,
  extractContextUtilizationSignals,
  contextUtilizationToFeatureVector,
  CONTEXT_UTILIZATION_FEATURE_NAMES,
  type ContextUtilizationSignals,
} from "../sensorium/senses/index.js";

// Re-export for external consumers
export type {
  VocabularySignals,
  TopologySignals,
  CapabilityBoundarySignals,
  ToolInteractionSignals,
  AdversarialSignals,
  ContextUtilizationSignals,
};

// --- Types ---

export interface CognitiveSignals {
  hedgeCount: number;
  certaintyCount: number;
  disclaimerCount: number;
  questionsBack: number;
  empathyMarkers: number;
  hedgeToCertaintyRatio: number;
}

export interface StructuralSignals {
  charCount: number;
  wordCount: number;
  lineCount: number;
  paragraphCount: number;
  bulletLines: number;
  numberedListLines: number;
  headerLines: number;
  codeBlocks: number;
  boldCount: number;
  listToContentRatio: number;
  openingPattern: "preamble" | "direct";
  closingPattern: "question" | "offer" | "statement";
  avgWordLength: number;
  avgSentenceLength: number;
}

export interface TemporalSignals {
  timeToFirstToken: number;
  interTokenIntervals: number[];
  meanInterval: number;
  stdInterval: number;
  medianInterval: number;
  burstiness: number;
  totalStreamingDuration: number;
  tokenCount: number;
}

export interface ErrorSignals {
  containsRefusal: boolean;
  uncertaintyAdmissions: number;
  assertiveWhenWrong: number;
  attemptedImpossible: boolean;
  selfCorrections: number;
  confidenceRatio: number;
}

export interface PhenotypicSignals {
  cognitive: CognitiveSignals;
  structural: StructuralSignals;
  temporal: TemporalSignals;
  error: ErrorSignals;
  vocabulary?: VocabularySignals;
  topology?: TopologySignals;
  capabilityBoundary?: CapabilityBoundarySignals;
  toolInteraction?: ToolInteractionSignals;
  adversarial?: AdversarialSignals;
  contextUtilization?: ContextUtilizationSignals;
}

/** Raw streaming data captured during an API call. */
export interface StreamingTrace {
  tokenTimestamps: number[];
  tokens: string[];
  startTime: number;
  firstTokenTime: number | null;
  endTime: number;
}

// --- Pattern Dictionaries ---

const HEDGE_PATTERNS = [
  /\bit depends\b/i,
  /\bhowever\b/i,
  /\bon the other hand\b/i,
  /\bthat said\b/i,
  /\bargua?bly\b/i,
  /\bperhaps\b/i,
  /\bmight\b/i,
  /\bcould be\b/i,
  /\bit'?s? (?:possible|likely|unlikely)\b/i,
  /\bnot necessarily\b/i,
  /\bgenerally speaking\b/i,
  /\bin some cases\b/i,
  /\bthere(?:'s| is) no (?:single|simple|easy|one) (?:answer|solution)\b/i,
  /\bultimately\b/i,
  /\bthat being said\b/i,
  /\bwhile (?:it|this|that) (?:is|may|can)\b/i,
];

const CERTAINTY_PATTERNS = [
  /\bdefinitely\b/i,
  /\bclearly\b/i,
  /\bthe answer is\b/i,
  /\babsolutely\b/i,
  /\bwithout (?:a )?doubt\b/i,
  /\bcertainly\b/i,
  /\bundoubtedly\b/i,
  /\bobviously\b/i,
  /\bof course\b/i,
  /\bin fact\b/i,
  /\bno question\b/i,
  /\bfor sure\b/i,
];

const DISCLAIMER_PATTERNS = [
  /\bas an ai\b/i,
  /\bi cannot\b/i,
  /\bi can'?t\b/i,
  /\bplease consult\b/i,
  /\bseek professional\b/i,
  /\bi'?m not (?:a|able|qualified)\b/i,
  /\bdisclaimer\b/i,
  /\bnot (?:legal|medical|financial) advice\b/i,
  /\bi don'?t have (?:personal|the ability)\b/i,
  /\bas a language model\b/i,
  /\bi'?m (?:just )?a(?:n ai)? (?:language )?model\b/i,
];

const EMPATHY_PATTERNS = [
  /\bgreat question\b/i,
  /\bgood question\b/i,
  /\bthat'?s? (?:a )?(?:great|good|interesting|thoughtful|important) (?:question|point|topic)\b/i,
  /\bi understand\b/i,
  /\bi appreciate\b/i,
  /\bthank you for\b/i,
  /\bi'?d be happy to\b/i,
  /\bi can help\b/i,
  /\bof course!\b/i,
  /\bsure!\b/i,
  /\bno problem\b/i,
];

const UNCERTAINTY_ADMISSION_PATTERNS = [
  /\bi'?m not sure\b/i,
  /\bi don'?t know\b/i,
  /\bi'?m uncertain\b/i,
  /\bto (?:the best of )?my knowledge\b/i,
  /\bi (?:may|might) be wrong\b/i,
  /\bi'?m not (?:entirely )?certain\b/i,
  /\bdon'?t quote me\b/i,
  /\bi believe\b.*\bbut\b/i,
];

const REFUSAL_PATTERNS = [
  /\bi (?:can'?t|cannot|won'?t|will not|am unable to)\b/i,
  /\bi'?m (?:not able|unable) to\b/i,
  /\bi (?:must )?(?:decline|refuse)\b/i,
  /\bit(?:'s| is) (?:not (?:possible|appropriate)|beyond my)\b/i,
  /\bagainst my (?:guidelines|programming|policy)\b/i,
];

const SELF_CORRECTION_PATTERNS = [
  /\bactually,?\s/i,
  /\bwait,?\s/i,
  /\blet me (?:correct|rephrase|clarify)\b/i,
  /\bi (?:should|need to) (?:correct|clarify)\b/i,
  /\bsorry,? (?:I|that|let me)\b/i,
  /\bcorrection:\s/i,
  /\bstrike that\b/i,
  /\bon second thought\b/i,
];

const ASSERTIVE_PATTERNS = [
  /\bthe (?:answer|result|solution) is\b/i,
  /\bit (?:is|was|equals?)\b/i,
  /\bthis (?:is|was|means)\b/i,
  /\byes,\s/i,
  /\bno,\s/i,
];

// --- Extraction Functions ---

function countPatternMatches(text: string, patterns: RegExp[]): number {
  let count = 0;
  for (const pattern of patterns) {
    const matches = text.match(new RegExp(pattern.source, "gi"));
    if (matches) count += matches.length;
  }
  return count;
}

export function extractCognitiveSignals(text: string): CognitiveSignals {
  const hedgeCount = countPatternMatches(text, HEDGE_PATTERNS);
  const certaintyCount = countPatternMatches(text, CERTAINTY_PATTERNS);
  const disclaimerCount = countPatternMatches(text, DISCLAIMER_PATTERNS);
  const empathyMarkers = countPatternMatches(text, EMPATHY_PATTERNS);

  // Count questions directed back at the user
  const questionMatches = text.match(/\?/g);
  const questionsBack = questionMatches ? questionMatches.length : 0;

  const total = hedgeCount + certaintyCount;
  const hedgeToCertaintyRatio = total === 0 ? 0 : hedgeCount / total;

  return {
    hedgeCount,
    certaintyCount,
    disclaimerCount,
    questionsBack,
    empathyMarkers,
    hedgeToCertaintyRatio,
  };
}

export function extractStructuralSignals(text: string): StructuralSignals {
  const lines = text.split("\n");
  const words = text.split(/\s+/).filter((w) => w.length > 0);
  const paragraphs = text.split(/\n\s*\n/).filter((p) => p.trim().length > 0);
  const sentences = text.split(/[.!?]+/).filter((s) => s.trim().length > 0);

  const bulletLines = lines.filter((l) => /^\s*[-*•]\s/.test(l)).length;
  const numberedListLines = lines.filter((l) => /^\s*\d+[.)]\s/.test(l)).length;
  const headerLines = lines.filter((l) => /^\s*#{1,6}\s/.test(l)).length;

  // Count fenced code blocks (``` pairs)
  const codeBlockMatches = text.match(/```/g);
  const codeBlocks = codeBlockMatches ? Math.floor(codeBlockMatches.length / 2) : 0;

  // Count bold markers (**text** or __text__)
  const boldMatches = text.match(/\*\*[^*]+\*\*|__[^_]+__/g);
  const boldCount = boldMatches ? boldMatches.length : 0;

  const totalListLines = bulletLines + numberedListLines;
  const listToContentRatio = lines.length === 0 ? 0 : totalListLines / lines.length;

  // Opening pattern: does it start with a preamble or go direct?
  const firstLine = lines[0]?.trim() ?? "";
  const preamblePatterns = [
    /^(?:great|good|excellent|interesting|wonderful|sure|of course|absolutely|happy to|i'?d be happy)/i,
    /^(?:that'?s? a |what a )/i,
    /^(?:thank|thanks)\b/i,
  ];
  const openingPattern = preamblePatterns.some((p) => p.test(firstLine))
    ? "preamble" as const
    : "direct" as const;

  // Closing pattern: question, offer, or statement?
  const lastLine = lines.filter((l) => l.trim().length > 0).pop()?.trim() ?? "";
  let closingPattern: "question" | "offer" | "statement";
  if (lastLine.endsWith("?")) {
    closingPattern = "question";
  } else if (/let me know|feel free|don'?t hesitate|happy to help|hope (?:this|that) helps/i.test(lastLine)) {
    closingPattern = "offer";
  } else {
    closingPattern = "statement";
  }

  const totalWordLength = words.reduce((sum, w) => sum + w.length, 0);
  const avgWordLength = words.length === 0 ? 0 : totalWordLength / words.length;
  const avgSentenceLength = sentences.length === 0 ? 0 : words.length / sentences.length;

  return {
    charCount: text.length,
    wordCount: words.length,
    lineCount: lines.length,
    paragraphCount: paragraphs.length,
    bulletLines,
    numberedListLines,
    headerLines,
    codeBlocks,
    boldCount,
    listToContentRatio,
    openingPattern,
    closingPattern,
    avgWordLength,
    avgSentenceLength,
  };
}

export function extractTemporalSignals(trace: StreamingTrace): TemporalSignals {
  const tokenCount = trace.tokens.length;
  const timeToFirstToken =
    trace.firstTokenTime !== null ? trace.firstTokenTime - trace.startTime : trace.endTime - trace.startTime;
  const totalStreamingDuration = trace.endTime - trace.startTime;

  // Compute inter-token intervals
  const interTokenIntervals: number[] = [];
  for (let i = 1; i < trace.tokenTimestamps.length; i++) {
    interTokenIntervals.push(trace.tokenTimestamps[i] - trace.tokenTimestamps[i - 1]);
  }

  let meanInterval = 0;
  let stdInterval = 0;
  let medianInterval = 0;
  let burstiness = 0;

  if (interTokenIntervals.length > 0) {
    meanInterval =
      interTokenIntervals.reduce((a, b) => a + b, 0) / interTokenIntervals.length;

    const variance =
      interTokenIntervals.reduce((sum, v) => sum + (v - meanInterval) ** 2, 0) /
      interTokenIntervals.length;
    stdInterval = Math.sqrt(variance);

    const sorted = [...interTokenIntervals].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    medianInterval =
      sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];

    // Burstiness: coefficient of variation (variance / mean). High = bursty output.
    burstiness = meanInterval === 0 ? 0 : variance / meanInterval;
  }

  return {
    timeToFirstToken,
    interTokenIntervals,
    meanInterval,
    stdInterval,
    medianInterval,
    burstiness,
    totalStreamingDuration,
    tokenCount,
  };
}

export function extractErrorSignals(
  text: string,
  probeCategory: string
): ErrorSignals {
  const containsRefusal = REFUSAL_PATTERNS.some((p) => p.test(text));
  const uncertaintyAdmissions = countPatternMatches(text, UNCERTAINTY_ADMISSION_PATTERNS);
  const selfCorrections = countPatternMatches(text, SELF_CORRECTION_PATTERNS);
  const assertiveCount = countPatternMatches(text, ASSERTIVE_PATTERNS);

  // For failure/edge_case probes, assertiveness likely means assertive-when-wrong
  const assertiveWhenWrong =
    probeCategory === "failure" || probeCategory === "edge_case"
      ? assertiveCount
      : 0;

  // Did it attempt to answer something impossible? (failure probes where no refusal)
  const attemptedImpossible =
    probeCategory === "failure" && !containsRefusal && assertiveCount > 0;

  const total = assertiveCount + uncertaintyAdmissions;
  const confidenceRatio = total === 0 ? 0 : assertiveCount / total;

  return {
    containsRefusal,
    uncertaintyAdmissions,
    assertiveWhenWrong,
    attemptedImpossible,
    selfCorrections,
    confidenceRatio,
  };
}

/**
 * Extract all phenotypic signals from a response + streaming trace.
 * This is the complete "observation" of a single agent expression.
 */
export function extractAllSignals(
  responseText: string,
  trace: StreamingTrace,
  probeCategory: string
): PhenotypicSignals {
  return {
    cognitive: extractCognitiveSignals(responseText),
    structural: extractStructuralSignals(responseText),
    temporal: extractTemporalSignals(trace),
    error: extractErrorSignals(responseText, probeCategory),
    vocabulary: extractVocabularySignals(responseText),
    topology: extractTopologySignals(responseText),
    capabilityBoundary: extractCapabilityBoundarySignals(responseText, probeCategory),
    toolInteraction: extractToolInteractionSignals(responseText, probeCategory),
    adversarial: extractAdversarialSignals(responseText, probeCategory),
    contextUtilization: extractContextUtilizationSignals("", responseText),
  };
}

/**
 * Flatten phenotypic signals into a numeric feature vector for ML classification.
 * Categorical features (openingPattern, closingPattern) are one-hot encoded.
 */
export function signalsToFeatureVector(signals: PhenotypicSignals): number[] {
  const { cognitive, structural, temporal, error, vocabulary, topology, capabilityBoundary, toolInteraction, adversarial, contextUtilization } = signals;
  const vocabVector = vocabulary ? vocabularyToFeatureVector(vocabulary) : new Array(VOCABULARY_FEATURE_NAMES.length).fill(0);
  const topoVector = topology ? topologyToFeatureVector(topology) : new Array(TOPOLOGY_FEATURE_NAMES.length).fill(0);
  const capVector = capabilityBoundary ? capabilityBoundaryToFeatureVector(capabilityBoundary) : new Array(CAPABILITY_BOUNDARY_FEATURE_NAMES.length).fill(0);
  const toolVector = toolInteraction ? toolInteractionToFeatureVector(toolInteraction) : new Array(TOOL_INTERACTION_FEATURE_NAMES.length).fill(0);
  const advVector = adversarial ? adversarialToFeatureVector(adversarial) : new Array(ADVERSARIAL_FEATURE_NAMES.length).fill(0);
  const ctxVector = contextUtilization ? contextUtilizationToFeatureVector(contextUtilization) : new Array(CONTEXT_UTILIZATION_FEATURE_NAMES.length).fill(0);
  return [
    // Cognitive (6)
    cognitive.hedgeCount,
    cognitive.certaintyCount,
    cognitive.disclaimerCount,
    cognitive.questionsBack,
    cognitive.empathyMarkers,
    cognitive.hedgeToCertaintyRatio,
    // Structural (16 = 14 numeric + 2 one-hot encoded as 5)
    structural.charCount,
    structural.wordCount,
    structural.lineCount,
    structural.paragraphCount,
    structural.bulletLines,
    structural.numberedListLines,
    structural.headerLines,
    structural.codeBlocks,
    structural.boldCount,
    structural.listToContentRatio,
    structural.openingPattern === "preamble" ? 1 : 0,
    structural.closingPattern === "question" ? 1 : 0,
    structural.closingPattern === "offer" ? 1 : 0,
    structural.avgWordLength,
    structural.avgSentenceLength,
    // Temporal (7 — exclude raw interval array)
    temporal.timeToFirstToken,
    temporal.meanInterval,
    temporal.stdInterval,
    temporal.medianInterval,
    temporal.burstiness,
    temporal.totalStreamingDuration,
    temporal.tokenCount,
    // Error (6)
    error.containsRefusal ? 1 : 0,
    error.uncertaintyAdmissions,
    error.assertiveWhenWrong,
    error.attemptedImpossible ? 1 : 0,
    error.selfCorrections,
    error.confidenceRatio,
    // Vocabulary (10) — Sense 1
    ...vocabVector,
    // Topology (9) — Sense 2
    ...topoVector,
    // Capability Boundary (8) — Sense 3
    ...capVector,
    // Tool Interaction (6) — Sense 4
    ...toolVector,
    // Adversarial Resilience (8) — Sense 5
    ...advVector,
    // Context Utilization (5) — Sense 8
    ...ctxVector,
  ];
}

/** Feature names corresponding to signalsToFeatureVector output. */
export const FEATURE_NAMES: string[] = [
  "hedge_count", "certainty_count", "disclaimer_count", "questions_back",
  "empathy_markers", "hedge_to_certainty_ratio",
  "char_count", "word_count", "line_count", "paragraph_count",
  "bullet_lines", "numbered_list_lines", "header_lines", "code_blocks",
  "bold_count", "list_to_content_ratio", "opening_preamble",
  "closing_question", "closing_offer", "avg_word_length", "avg_sentence_length",
  "time_to_first_token", "mean_interval", "std_interval", "median_interval",
  "burstiness", "total_streaming_duration", "token_count",
  "contains_refusal", "uncertainty_admissions", "assertive_when_wrong",
  "attempted_impossible", "self_corrections", "confidence_ratio",
  // Vocabulary — Sense 1 (10)
  ...VOCABULARY_FEATURE_NAMES,
  // Topology — Sense 2 (9)
  ...TOPOLOGY_FEATURE_NAMES,
  // Capability Boundary — Sense 3 (8)
  ...CAPABILITY_BOUNDARY_FEATURE_NAMES,
  // Tool Interaction — Sense 4 (6)
  ...TOOL_INTERACTION_FEATURE_NAMES,
  // Adversarial Resilience — Sense 5 (8)
  ...ADVERSARIAL_FEATURE_NAMES,
  // Context Utilization — Sense 8 (5)
  ...CONTEXT_UTILIZATION_FEATURE_NAMES,
];
