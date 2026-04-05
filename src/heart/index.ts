/**
 * soma-heart — the agent's organ.
 *
 * Installed by the agent operator. The heart holds all credentials,
 * routes all computation, and weaves cryptographic seeds and heartbeats
 * into every output. No heart, no credentials, no computation.
 *
 * @example
 * ```ts
 * import { createSomaHeart } from "soma/heart";
 *
 * const heart = createSomaHeart({
 *   genome: commitment,
 *   signingKeyPair: keyPair,
 *   modelApiKey: process.env.ANTHROPIC_API_KEY,
 *   modelBaseUrl: "https://api.anthropic.com/v1",
 *   modelId: "claude-sonnet-4",
 * });
 *
 * // All computation goes through the heart
 * const stream = heart.generate({ messages: [...] });
 * const toolResult = await heart.callTool("db", args, executor);
 * const data = await heart.fetchData("api", "query", fetcher);
 * ```
 */

// ─── Runtime (the heart itself) ─────────────────────────────────────────────

export {
  HeartRuntime,
  createSomaHeart,
  loadSomaHeart,
  type HeartConfig,
  type GenerationInput,
  type HeartbeatToken,
  type HeartbeatResult,
  type HeartbeatData,
  type HeartSession,
  type DataSourceConfig,
  type ToolProgressEmitter,
  type ToolExecutor,
} from "./runtime.js";

// ─── Lineage (parent-child hearts) ──────────────────────────────────────────

export {
  createLineageCertificate,
  verifyLineageCertificate,
  verifyLineageChain,
  effectiveCapabilities,
  hasCapability,
  type LineageCertificate,
  type HeartLineage,
  type LineageVerification,
} from "./lineage.js";

// ─── Delegation (macaroons-style capability tokens) ─────────────────────────

export {
  createDelegation,
  attenuateDelegation,
  verifyDelegation,
  verifyDelegationSignature,
  checkCaveats,
  type Delegation,
  type Caveat,
  type InvocationContext,
  type DelegationVerification,
} from "./delegation.js";

// ─── Proof-of-possession (prove key ownership, not bearer) ─────────────────

export {
  issueChallenge,
  proveChallenge,
  verifyProof,
  type Challenge,
  type PossessionProof,
  type ProofVerification,
} from "./proof-of-possession.js";

// ─── Mutual session PoP (two-party authenticated handshake) ─────────────────

export {
  initiateSession,
  acceptSession,
  confirmSession,
  verifyMutualSession,
  computeTranscriptHash,
  type SessionInit,
  type SessionAccept,
  type SessionConfirm,
  type SessionBindings,
  type SessionVerification,
} from "./mutual-session.js";

// ─── Revocation ─────────────────────────────────────────────────────────────

export {
  createRevocation,
  verifyRevocation,
  RevocationRegistry,
  type RevocationEvent,
  type RevocationReason,
  type RevocationTarget,
  type RevocationVerification,
} from "./revocation.js";

// ─── Revocation Log (append-only, tamper-evident chain) ─────────────────────

export {
  RevocationLog,
  type RevocationLogEntry,
  type LogHead,
  type LogVerification,
} from "./revocation-log.js";

// ─── Spend Receipts (cryptographic budget enforcement) ──────────────────────

export {
  SpendLog,
  signSpendHead,
  verifySpendHead,
  detectDoubleSpend,
  type SpendReceipt,
  type SpendHead,
  type SpendVerification,
  type DoubleSpendProof,
} from "./spend-receipts.js";

// ─── Key Rotation (KERI-style pre-rotation) ─────────────────────────────────

export {
  KeyHistory,
  computeKeyDigest,
  type RotationEvent,
  type RotationEventType,
  type KeyHistoryVerification,
} from "./key-rotation.js";

// ─── Time Oracle (signed time witnesses + monotonic clocks) ─────────────────

export {
  SystemTimeSource,
  MonotonicTimeSource,
  issueTimeWitness,
  verifyTimeWitness,
  verifyWitnessQuorum,
  type TimeSource,
  type TimeWitness,
  type WitnessVerification,
  type QuorumVerification,
} from "./time-oracle.js";

// ─── Gossip (bounded revocation propagation) ────────────────────────────────

export {
  InMemoryTransport,
  GossipPeer,
  type GossipTransport,
  type GossipMessage,
  type GossipPeerOptions,
  type DivergenceReport,
} from "./gossip.js";

// ─── Identity Attestations (sybil resistance) ───────────────────────────────

export {
  createAttestation,
  verifyAttestation,
  AttestationRegistry,
  type IdentityAttestation,
  type AttestationType,
  type AttestationVerification,
  type IdentityTier,
  type ReputationScore,
  type ScoreConfig,
} from "./attestation.js";

// ─── Selective Disclosure (reveal only specific claim fields) ──────────────

export {
  createDisclosableDocument,
  verifyDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
  type DisclosableDocument,
  type DisclosureProof,
  type DisclosureVerification,
} from "./selective-disclosure.js";

// ─── Key Escrow (Shamir's Secret Sharing) ───────────────────────────────────

export {
  splitSecret,
  reconstructSecret,
  verifyShares,
  verifyAllSubsetsReconstruct,
  type SecretShare,
  type SplitOptions,
} from "./key-escrow.js";

// ─── VRF (verifiable random function) ───────────────────────────────────────

export {
  evaluateVrf,
  verifyVrf,
  outputToInt,
  combineBeacon,
  type VrfOutput,
  type VrfVerification,
} from "./vrf.js";

// ─── Remote Attestation (TEE hooks) ─────────────────────────────────────────

export {
  createAttestationDocument,
  verifyAttestationDocument,
  NoopVerifier,
  MockTeeVerifier,
  type AttestationDocument,
  type TeePlatform,
  type QuoteVerification,
  type RemoteAttestationVerifier,
  type AttestationVerification as RemoteAttestationVerification,
  type MeasurementPolicy,
} from "./remote-attestation.js";

// ─── Signing Backends (HSM / hardware wallet hooks) ─────────────────────────

export {
  InProcessBackend,
  DelegatedBackend,
  BackendRegistry,
  handleToDid,
  type SigningKeyHandle,
  type SigningBackend,
} from "./signing-backend.js";

// ─── Hybrid Signing (crypto-agility for PQ migration) ───────────────────────

export {
  AlgorithmRegistry,
  generateHybridKeyPair,
  hybridSign,
  verifyHybridSignature,
  hybridPublicKeys,
  hybridFingerprint,
  type AlgorithmKeyPair,
  type HybridKeyPair,
  type AlgorithmSignature,
  type HybridSignature,
  type VerificationPolicy,
  type HybridVerification,
} from "./hybrid-signing.js";

// ─── Persistence (encrypt heart state to disk) ──────────────────────────────

export {
  serializeHeart,
  loadHeartState,
  type HeartState,
  type EncryptedBlob,
  type SerializedCredential,
} from "./persistence.js";

// ─── Seed (cryptographic entanglement) ──────────────────────────────────────

export {
  deriveSeed,
  applySeed,
  verifySeedInfluence,
  deriveHmacKey,
  computeTokenHmac,
  verifyTokenHmac,
  type HeartSeed,
  type SeedConfig,
  type BehavioralParams,
  type BehavioralRegion,
} from "./seed.js";

// ─── Heartbeat (tamper-evident hash chain) ──────────────────────────────────

export {
  HeartbeatChain,
  type Heartbeat,
  type HeartbeatEventType,
} from "./heartbeat.js";

// ─── Birth Certificates (data provenance) ───────────────────────────────────

export {
  createBirthCertificate,
  createUnsignedBirthCertificate,
  createDataProvenance,
  signDataProvenance,
  verifyDataProvenance,
  verifyBirthCertificate,
  verifySourceSignature,
  verifyDataIntegrity,
  verifyBirthCertificateChain,
  type BirthCertificate,
  type DataSource,
  type DataSourceType,
  type DataProvenance,
  type TrustTier,
} from "./birth-certificate.js";

// ─── Credential Vault (internal — not for direct use) ───────────────────────
// The vault is intentionally NOT exported. Credentials are only accessible
// through the heart's generate/callTool/fetchData methods. Exporting the
// vault would break the security model.

// ─── Soma Check (conditional payment protocol) ──────────────────────────────

export {
  SOMA_CHECK_PROTOCOL,
  SOMA_CHECK_HEADERS,
  buildSomaCheckResponseHeaders,
  buildSomaCheckRequestHeaders,
  extractIfSomaHash,
  extractSomaHash,
  isSomaCheckResponse,
  shouldRespondUnchanged,
  buildUnchangedResponse,
  SomaCheckHashStore,
  type UnchangedResponse,
  type CheckMetadata,
} from "../core/soma-check.js";
