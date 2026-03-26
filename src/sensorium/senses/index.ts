/**
 * Sensorium senses — individual sensory organs that extract phenotypic signals.
 *
 * Each sense is an independent extractor that captures a different dimension
 * of agent behavior. Together they form the gestalt that makes identity
 * verification reliable.
 */

export {
  extractVocabularySignals,
  vocabularyToFeatureVector,
  VOCABULARY_FEATURE_NAMES,
  type VocabularySignals,
} from "./vocabulary.js";

export {
  extractTopologySignals,
  topologyToFeatureVector,
  TOPOLOGY_FEATURE_NAMES,
  type TopologySignals,
} from "./topology.js";

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
