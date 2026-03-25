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
