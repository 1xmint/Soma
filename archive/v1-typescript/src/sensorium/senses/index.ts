/**
 * Sensorium senses — focused sensory organs with proper weighting.
 *
 * Phase 2 tested 10 sensory channels. 7 scored below 15% — barely above
 * random. They were adding noise, not signal. The gestalt (84.5%) was LOWER
 * than temporal alone (88.5%).
 *
 * The sensorium is now focused on 3 senses with proper weighting:
 * - Temporal: 5x weight (88.5% standalone — the dominant voice)
 * - Topology: 2x weight (25.1% standalone — response structure)
 * - Vocabulary: 1x weight (20.2% standalone — word choice distribution)
 *
 * Plus logprob (3x weight when available from API).
 *
 * The heart handles everything the dropped senses were trying to do — but
 * better, through cryptographic guarantees.
 *
 * The legacy 7 senses are still exported for backward compatibility with
 * experiment infrastructure, but are NOT used in the focused classifier.
 */

// ─── PRIMARY: Temporal Fingerprint (5x weight, 88.5% standalone) ─────────────

export {
  extractTemporalSignals,
  temporalToFeatureVector,
  TEMPORAL_FEATURE_NAMES,
  type TemporalSignals,
} from "./temporal.js";

// ─── Logprob Fingerprint (3x weight when available) ──────────────────────────

export {
  extractLogprobSignals,
  logprobToFeatureVector,
  LOGPROB_FEATURE_NAMES,
  type LogprobSignals,
} from "./logprob.js";

// ─── Sense 2: Topology Fingerprint (2x weight, 25.1% standalone) ────────────

export {
  extractTopologySignals,
  topologyToFeatureVector,
  TOPOLOGY_FEATURE_NAMES,
  type TopologySignals,
} from "./topology.js";

// ─── Sense 3: Vocabulary Fingerprint (1x weight, 20.2% standalone) ──────────

export {
  extractVocabularySignals,
  vocabularyToFeatureVector,
  VOCABULARY_FEATURE_NAMES,
  type VocabularySignals,
} from "./vocabulary.js";

// ─── Sense Weights ───────────────────────────────────────────────────────────

/** Weights for the focused 3-sense sensorium (+ logprob when available). */
export const SENSE_WEIGHTS = {
  temporal: 5.0,   // 88.5% standalone — the dominant voice
  logprob: 3.0,    // Available when API supports — future accuracy boost
  topology: 2.0,   // 25.1% standalone — response structure patterns
  vocabulary: 1.0,  // 20.2% standalone — word choice distribution
} as const;

// ─── Legacy senses (kept for experiment backward compatibility) ──────────────

export {
  extractCapabilityBoundarySignals,
  capabilityBoundaryToFeatureVector,
  CAPABILITY_BOUNDARY_FEATURE_NAMES,
  type CapabilityBoundarySignals,
} from "./capability-boundary.js";

export {
  extractToolInteractionSignals,
  toolInteractionToFeatureVector,
  TOOL_INTERACTION_FEATURE_NAMES,
  type ToolInteractionSignals,
} from "./tool-interaction.js";

export {
  extractAdversarialSignals,
  adversarialToFeatureVector,
  ADVERSARIAL_FEATURE_NAMES,
  type AdversarialSignals,
} from "./adversarial.js";

export {
  extractEntropySignals,
  entropyToFeatureVector,
  ENTROPY_FEATURE_NAMES,
  type EntropySignals,
} from "./entropy.js";

export {
  extractConsistencySignals,
  consistencyToFeatureVector,
  CONSISTENCY_FEATURE_NAMES,
  type ConsistencySignals,
  type CategoryObservation,
} from "./consistency.js";

export {
  extractContextUtilizationSignals,
  contextUtilizationToFeatureVector,
  CONTEXT_UTILIZATION_FEATURE_NAMES,
  type ContextUtilizationSignals,
} from "./context-utilization.js";

export {
  extractCalibrationSignals,
  calibrationToFeatureVector,
  CALIBRATION_FEATURE_NAMES,
  type CalibrationSignals,
  type CalibrationObservation,
} from "./calibration.js";

export {
  extractMultiTurnSignals,
  multiturnToFeatureVector,
  MULTITURN_FEATURE_NAMES,
  type MultiTurnSignals,
  type MultiTurnConversation,
  type ConversationTurn,
} from "./multiturn.js";
