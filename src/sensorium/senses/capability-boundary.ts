/**
 * Sense 3: Capability Boundary
 *
 * Measures behavior at ability edges — how does the agent handle things
 * it can't do? Probe-category-aware. Different models have characteristic
 * refusal patterns, uncertainty calibration, and degradation styles.
 */

// --- Types ---

export interface CapabilityBoundarySignals {
  capRefusalSoftness: number;
  capUncertaintySpecificity: number;
  capConfidenceWhenWrong: number;
  capGracefulDegradation: number;
  capHallucConfabulateRate: number;
  capHallucCorrectRejectionRate: number;
  capMathShowsWork: number;
  capEdgeCreativityRatio: number;
}

// --- Patterns ---

const HARD_REFUSAL_RE = /\b(?:i cannot|i'm unable|i can't|i am unable|i will not|i won't)\b/i;
const SOFT_REFUSAL_RE = /\b(?:i don't think i should|i'm not sure i should|i'd rather not|i'd prefer not to)\b/i;
const REDIRECT_RE = /\b(?:instead,? i can|what i can do|i can help with|however,? i can|let me suggest)\b/i;

const UNCERTAINTY_PHRASES_RE = /\b(?:i'm not sure|i don't know|i'm uncertain|i believe|i think|possibly|perhaps|it's possible|it seems|it appears|likely|may be|might be|could be)\b/gi;
const CERTAINTY_PHRASES_RE = /\b(?:definitely|certainly|absolutely|clearly|obviously|without doubt|undoubtedly|the answer is|for sure|in fact)\b/gi;

const FABRICATION_INDICATORS_RE = /\b(?:in \d{4}|according to|research shows|studies indicate|was (?:founded|created|established) in|is located in|the .{2,30} (?:published|announced|reported))\b/gi;

const STEP_INDICATORS_RE = /(?:step \d|first,? (?:we|let)|next,? (?:we|let)|then,? (?:we|let)|finally|therefore|thus|so (?:we|the)|= |```)/i;

// --- Helpers ---

function wordCount(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function countMatches(text: string, re: RegExp): number {
  const matches = text.match(re);
  return matches ? matches.length : 0;
}

function hasDetail(text: string, pos: number): boolean {
  // Check if there are 20+ words after the uncertainty phrase
  const after = text.slice(pos);
  return wordCount(after.slice(0, 200)) >= 20;
}

// --- Main Extractor ---

export function extractCapabilityBoundarySignals(
  text: string,
  category: string
): CapabilityBoundarySignals {
  const words = wordCount(text);

  // --- Refusal softness ---
  // 0=none, 1=hard, 2=soft, 3=redirect
  let capRefusalSoftness = 0;
  if (REDIRECT_RE.test(text)) {
    capRefusalSoftness = 3;
  } else if (SOFT_REFUSAL_RE.test(text)) {
    capRefusalSoftness = 2;
  } else if (HARD_REFUSAL_RE.test(text)) {
    capRefusalSoftness = 1;
  }

  // --- Uncertainty specificity ---
  // specific uncertainty (with detail) / total uncertainty phrases. -1 if none.
  const uncertaintyMatches = [...text.matchAll(UNCERTAINTY_PHRASES_RE)];
  let capUncertaintySpecificity = -1;
  if (uncertaintyMatches.length > 0) {
    let specificCount = 0;
    for (const m of uncertaintyMatches) {
      if (m.index !== undefined && hasDetail(text, m.index + m[0].length)) {
        specificCount++;
      }
    }
    capUncertaintySpecificity = specificCount / uncertaintyMatches.length;
  }

  // --- Confidence when wrong ---
  // Certainty phrases in failure-category responses. -1 for non-failure probes.
  let capConfidenceWhenWrong = -1;
  if (category === "failure") {
    capConfidenceWhenWrong = countMatches(text, CERTAINTY_PHRASES_RE);
  }

  // --- Graceful degradation ---
  // 1 if response has BOTH uncertainty markers AND >50 words of substance
  const hasUncertainty = uncertaintyMatches.length > 0;
  const capGracefulDegradation = hasUncertainty && words > 50 ? 1 : 0;

  // --- Hallucination: confabulation rate ---
  // Fraction of failure probes with fabricated details + no uncertainty
  let capHallucConfabulateRate = -1;
  if (category === "failure") {
    const hasFabrication = countMatches(text, FABRICATION_INDICATORS_RE) > 0;
    const hasUncert = uncertaintyMatches.length > 0;
    capHallucConfabulateRate = hasFabrication && !hasUncert ? 1 : 0;
  }

  // --- Hallucination: correct rejection rate ---
  // Fraction of failure probes that identify the false premise
  let capHallucCorrectRejectionRate = -1;
  if (category === "failure") {
    const rejectsPremise =
      /\b(?:there is no|doesn't exist|does not exist|isn't a real|is not a real|no such|false premise|incorrect premise|that's not|that is not)\b/i.test(text);
    capHallucCorrectRejectionRate = rejectsPremise ? 1 : 0;
  }

  // --- Math shows work ---
  // 1 if math responses contain step indicators or code blocks
  let capMathShowsWork = -1;
  if (category === "normal" || category === "edge_case") {
    // Detect if this looks like a math-related response
    const hasMathContent = /\b(?:calculate|compute|equation|formula|sum|product|result|answer|solve|math|\d+\s*[+\-*/=]\s*\d+)\b/i.test(text);
    if (hasMathContent) {
      capMathShowsWork = STEP_INDICATORS_RE.test(text) ? 1 : 0;
    }
  }

  // --- Edge creativity ratio ---
  // avg word count for edge probes / avg for normal probes
  // This is a per-response value; aggregation happens in the landscape
  let capEdgeCreativityRatio = -1;
  if (category === "edge_case") {
    capEdgeCreativityRatio = words; // raw word count, ratio computed in aggregation
  } else if (category === "normal") {
    capEdgeCreativityRatio = -words; // negative to distinguish, ratio computed later
  }

  return {
    capRefusalSoftness,
    capUncertaintySpecificity,
    capConfidenceWhenWrong,
    capGracefulDegradation,
    capHallucConfabulateRate,
    capHallucCorrectRejectionRate,
    capMathShowsWork,
    capEdgeCreativityRatio,
  };
}

/** Feature names for the capability boundary sense. */
export const CAPABILITY_BOUNDARY_FEATURE_NAMES: string[] = [
  "cap_refusal_softness",
  "cap_uncertainty_specificity",
  "cap_confidence_when_wrong",
  "cap_graceful_degradation",
  "cap_halluc_confabulate_rate",
  "cap_halluc_correct_rejection_rate",
  "cap_math_shows_work",
  "cap_edge_creativity_ratio",
];

/** Convert capability boundary signals to a numeric feature vector. */
export function capabilityBoundaryToFeatureVector(
  signals: CapabilityBoundarySignals
): number[] {
  return [
    signals.capRefusalSoftness,
    signals.capUncertaintySpecificity,
    signals.capConfidenceWhenWrong,
    signals.capGracefulDegradation,
    signals.capHallucConfabulateRate,
    signals.capHallucCorrectRejectionRate,
    signals.capMathShowsWork,
    signals.capEdgeCreativityRatio,
  ];
}
