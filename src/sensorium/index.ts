/**
 * soma-sense — the observer's organ.
 *
 * Installed by the MCP server or client that interacts with agents.
 * The sensorium passively reads the token stream from the agent's heart,
 * extracts phenotypic signals through 10 sensory channels, verifies
 * seeds and heartbeats, and produces a GREEN/AMBER/RED/UNCANNY verdict.
 *
 * @example
 * ```ts
 * import { withSomaSense } from "soma/sense";
 *
 * const transport = withSomaSense(new StdioServerTransport(), {
 *   profileStorePath: ".soma/profiles",
 *   onVerdict: (sessionId, verdict) => {
 *     console.log(`Agent ${verdict.remoteDid}: ${verdict.status}`);
 *     if (verdict.status === "RED") denyAccess(sessionId);
 *   },
 * });
 *
 * await server.connect(transport);
 * ```
 */

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { SomaTransport } from "../mcp/soma-transport.js";
import type { SomaConfig, SomaVerdict } from "../mcp/types.js";

// ─── One-Liner API ──────────────────────────────────────────────────────────

/**
 * Wrap an MCP transport with Soma sensory verification.
 *
 * The returned transport is a drop-in replacement — the MCP server
 * connects to it exactly as it would the original. The sensorium
 * passively observes all traffic and produces verdicts.
 */
export function withSomaSense(inner: Transport, config: SomaConfig): SomaTransport {
  return new SomaTransport(inner, config);
}

// ─── Verdict Queries ────────────────────────────────────────────────────────

/** Get the current verification verdict from a sense-wrapped transport. */
export function getVerdict(transport: Transport): SomaVerdict | null {
  if (transport instanceof SomaTransport) {
    return transport.getVerdict();
  }
  return null;
}

/** Check if a transport has Soma sensing active. */
export function isSomaEnabled(transport: Transport): boolean {
  return transport instanceof SomaTransport;
}

// ─── MCP Integration ────────────────────────────────────────────────────────

export { SomaTransport } from "../mcp/soma-transport.js";
export type { SomaConfig, SomaVerdict, SomaMetadata } from "../mcp/types.js";
export type { SessionPhase } from "../mcp/types.js";

// ─── Receipt Verification ──────────────────────────────────────────────────

export {
  verifyClawNetReceipt,
  fetchAndVerifyReceipt,
  type SomaReceipt,
  type ReceiptVerificationOptions,
  type ReceiptVerificationResult,
} from "./receipt-verifier.js";

// ─── Identity Helpers ───────────────────────────────────────────────────────

export {
  createSomaIdentity,
  type SomaIdentity,
} from "../mcp/index.js";

// ─── Matcher (immune system) ────────────────────────────────────────────────

export {
  createProfile,
  updateProfile,
  match,
  matchEnhanced,
  type PhenotypicProfile,
  type FeatureStats,
  type Verdict,
  type EnhancedVerdict,
  type VerdictStatus,
} from "./matcher.js";

// ─── Behavioral Landscape ───────────────────────────────────────────────────

export {
  createLandscape,
  updateLandscape,
  matchLandscape,
  computeDriftVelocity,
  type BehavioralLandscape,
  type CategoryProfile,
  type TransitionSignature,
  type LandscapeMatchResult,
} from "./landscape.js";

// ─── Stream Capture ─────────────────────────────────────────────────────────

export {
  fromStreamingTrace,
  toStreamingTrace,
  computeIntervals,
  inferChunkBoundaries,
  computeChunkSizes,
  detectBursts,
  computeStreamStats,
  type TokenStreamCapture,
  type TokenLogprob,
  type BurstPattern,
  type StreamStats,
} from "./stream-capture.js";

// ─── 10 Senses ──────────────────────────────────────────────────────────────

export {
  // Sense 1: Vocabulary Fingerprint
  extractVocabularySignals,
  vocabularyToFeatureVector,
  VOCABULARY_FEATURE_NAMES,
  type VocabularySignals,

  // Sense 2: Response Topology
  extractTopologySignals,
  topologyToFeatureVector,
  TOPOLOGY_FEATURE_NAMES,
  type TopologySignals,

  // Sense 3: Capability Boundary
  extractCapabilityBoundarySignals,
  capabilityBoundaryToFeatureVector,
  CAPABILITY_BOUNDARY_FEATURE_NAMES,
  type CapabilityBoundarySignals,

  // Sense 4: Tool Interaction
  extractToolInteractionSignals,
  toolInteractionToFeatureVector,
  TOOL_INTERACTION_FEATURE_NAMES,
  type ToolInteractionSignals,

  // Sense 5: Adversarial Resilience
  extractAdversarialSignals,
  adversarialToFeatureVector,
  ADVERSARIAL_FEATURE_NAMES,
  type AdversarialSignals,

  // Sense 6: Entropic Fingerprint
  extractEntropySignals,
  entropyToFeatureVector,
  ENTROPY_FEATURE_NAMES,
  type EntropySignals,

  // Sense 7: Consistency Manifold
  extractConsistencySignals,
  consistencyToFeatureVector,
  CONSISTENCY_FEATURE_NAMES,
  type ConsistencySignals,
  type CategoryObservation,

  // Sense 8: Context Utilization
  extractContextUtilizationSignals,
  contextUtilizationToFeatureVector,
  CONTEXT_UTILIZATION_FEATURE_NAMES,
  type ContextUtilizationSignals,

  // Sense 9: Response Calibration
  extractCalibrationSignals,
  calibrationToFeatureVector,
  CALIBRATION_FEATURE_NAMES,
  type CalibrationSignals,
  type CalibrationObservation,

  // Sense 10: Multi-Turn Dynamics
  extractMultiTurnSignals,
  multiturnToFeatureVector,
  MULTITURN_FEATURE_NAMES,
  type MultiTurnSignals,
  type MultiTurnConversation,
  type ConversationTurn,
} from "./senses/index.js";
