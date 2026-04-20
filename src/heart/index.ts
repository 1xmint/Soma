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
} from './runtime.js';

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
} from './lineage.js';

// ─── Fork Ceremony (offline lineage provisioning) ───────────────────────────

export {
  forkCeremony,
  type ForkCeremonyOptions,
  type ForkCeremonyResult,
} from './fork-ceremony.js';

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
  type CustomCaveatEvaluator,
} from './delegation.js';

// ─── Delegation Chain (SOMA-CAPABILITIES-SPEC steps 6-7) ────────────────────

export {
  verifyDelegationChain,
  type ChainVerificationResult,
  type ChainVerificationSuccess,
  type ChainVerificationFailure,
  type ChainVerificationOptions,
} from './delegation-chain.js';

// ─── Human Delegation (session-scoped human→agent consent) ─────────────────

export {
  createHumanDelegation,
  verifyHumanDelegation,
  computeChallengeHash,
  type HumanDelegation,
  type HumanAttestation,
  type AttestationVerifier,
  type CeremonyTier,
  type HumanDelegationVerification,
} from './human-delegation.js';

export {
  createCeremonyPolicy,
  DEFAULT_CEREMONY_POLICY,
  type ActionClass,
  type PolicyMap,
  type PolicyOverrides,
  type PolicyDecision,
  type CeremonyPolicy,
} from './ceremony-policy.js';

export {
  HumanSessionRegistry,
  type HumanSession,
  type SessionStatus,
  type InvokeRequest,
  type InvokeResult,
} from './human-session.js';

// ─── Proof-of-possession (prove key ownership, not bearer) ─────────────────

export {
  issueChallenge,
  proveChallenge,
  verifyProof,
  type Challenge,
  type PossessionProof,
  type ProofVerification,
} from './proof-of-possession.js';

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
} from './mutual-session.js';

// ─── Revocation ─────────────────────────────────────────────────────────────

export {
  createRevocation,
  verifyRevocation,
  RevocationRegistry,
  type RevocationEvent,
  type RevocationReason,
  type RevocationTarget,
  type RevocationVerification,
} from './revocation.js';

// ─── Revocation Log (append-only, tamper-evident chain) ─────────────────────

export {
  RevocationLog,
  type RevocationLogEntry,
  type LogHead,
  type LogVerification,
} from './revocation-log.js';

// ─── Reception Receipts (accountability primitive for capability verification) ─

export {
  signReceipt,
  verifyReceipt,
  receiptCanonical,
  EVIDENCE_SUMMARY_MAX,
  type ReceiptPayload,
  type SignedReceipt,
  type ReceiptOutcome,
} from './reception-receipt.js';

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
} from './spend-receipts.js';

// ─── Credential Rotation (generic controller — user-facing rotation API) ───
//
// `CredentialRotationController` encodes the twelve invariants from the
// credential-rotation architecture spec and is the only user-facing rotation
// API. `KeyHistory` in `./key-rotation.js` is retained as an internal KERI
// log primitive consumed by the future ed25519-identity backend, and is
// intentionally NOT re-exported here (sealed per §14 D5 revision).

export {
  CredentialRotationController,
  Ed25519IdentityBackend,
  MockCredentialBackend,
  DEFAULT_POLICY,
  DEFAULT_TTL_POLICY,
  POLICY_FLOORS,
  computeManifestCommitment,
  verifyRotationChain,
  BackendNotAllowlisted,
  ChallengePeriodActive,
  CredentialExpired,
  DuplicateBackend,
  InvariantViolation,
  NotYetEffective,
  PreRotationMismatch,
  RateLimitExceeded,
  StagedRotationConflict,
  SuiteDowngradeRejected,
  VerifyBeforeRevokeFailed,
  SNAPSHOT_VERSION,
  type AlgorithmSuite,
  type Clock,
  type ControllerOptions,
  type ControllerPolicy,
  type ControllerSnapshot,
  type Credential,
  type CredentialBackend,
  type CredentialClass,
  type CredentialManifest,
  type HistoricalCredentialLookupHit,
  type HistoricalCredentialLookupKey,
  type HistoricalCredentialLookupMiss,
  type HistoricalCredentialLookupResult,
  type RotationEvent,
  type RotationEventStatus,
  type TtlPolicy,
} from './credential-rotation/index.js';

// ─── Historical Key Lookup (rotation-aware key validity for verifiers) ──────

export {
  checkKeyEffective,
  type HistoricalKeyLookup,
  type HistoricalKeyLookupHit,
  type HistoricalKeyLookupMiss,
  type HistoricalKeyLookupResult,
} from './historical-key-lookup.js';

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
} from './time-oracle.js';

// ─── Gossip (bounded revocation propagation) ────────────────────────────────

export {
  InMemoryTransport,
  GossipPeer,
  type GossipTransport,
  type GossipMessage,
  type GossipPeerOptions,
  type DivergenceReport,
} from './gossip.js';

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
} from './attestation.js';

// ─── Selective Disclosure (reveal only specific claim fields) ──────────────

export {
  createDisclosableDocument,
  verifyDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
  type DisclosableDocument,
  type DisclosureProof,
  type DisclosureVerification,
} from './selective-disclosure.js';

// ─── Key Escrow (Shamir's Secret Sharing) ───────────────────────────────────

export {
  splitSecret,
  reconstructSecret,
  verifyShares,
  verifyAllSubsetsReconstruct,
  type SecretShare,
  type SplitOptions,
} from './key-escrow.js';

// ─── VRF (verifiable random function) ───────────────────────────────────────

export {
  evaluateVrf,
  verifyVrf,
  outputToInt,
  combineBeacon,
  type VrfOutput,
  type VrfVerification,
} from './vrf.js';

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
} from './remote-attestation.js';

// ─── Signing Backends (HSM / hardware wallet hooks) ─────────────────────────

export {
  InProcessBackend,
  DelegatedBackend,
  BackendRegistry,
  handleToDid,
  type SigningKeyHandle,
  type SigningBackend,
} from './signing-backend.js';

// ─── Threshold Signing (M-of-N Ed25519 via share reconstruction) ───────────

export {
  generateThresholdKeyPair,
  shareExistingKey,
  thresholdSign,
  verifyThresholdSignature,
  SigningCeremony,
  type ThresholdKeyPair,
  type ThresholdSignature,
  type GenerateThresholdKeyOpts,
  type ShareExistingKeyOpts,
} from './threshold-signing.js';

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
} from './hybrid-signing.js';

// ─── Persistence (encrypt heart state to disk) ──────────────────────────────

export {
  serializeHeart,
  loadHeartState,
  type HeartState,
  type EncryptedBlob,
  type SerializedCredential,
} from './persistence.js';

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
} from './seed.js';

// ─── Heartbeat (tamper-evident hash chain) ──────────────────────────────────

export { HeartbeatChain, type Heartbeat, type HeartbeatEventType } from './heartbeat.js';

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
} from './birth-certificate.js';

export type { PackageProvenance } from '../supply-chain/update-certificate.js';

// ─── Credential Vault (internal — not for direct use) ───────────────────────
// The vault is intentionally NOT exported. Credentials are only accessible
// through the heart's generate/callTool/fetchData methods. Exporting the
// vault would break the security model.

// ─── Factor Registry (auth factors bound to DIDs, soma-capabilities/1.1) ────

export {
  FactorRegistry,
  WELL_KNOWN_FACTOR_TYPES,
  type FactorType,
  type RegisteredFactor,
} from './factor-registry.js';

// ─── Step-Up (live human approval for high-risk delegations) ───────────────

export {
  StepUpService,
  FactorVerifierRegistry,
  verifyChallengeSignature,
  verifyStepUpAttestation,
  computeActionDigest,
  type StepUpChallenge,
  type StepUpAttestation,
  type FactorAssertion,
  type FactorAssertionVerifier,
  type FactorVerificationResult,
  type StepUpVerification,
} from './stepup.js';

// ─── Step-Up Oracles (pluggable delivery channels) ─────────────────────────

export {
  BaseStepUpOracle,
  CliPromptOracle,
  OracleChain,
  type StepUpOracle,
  type DeliveryResult,
  type AssertionCallback,
} from './stepup-oracle.js';

// ─── Tier Ladder (deployment-configurable factor → tier policy) ────────────

export {
  checkPredicate,
  evaluateLadder,
  evaluateLadderDetailed,
  DEFAULT_LADDER,
  PARANOID_LADDER,
  type TierPredicate,
  type TierRule,
  type TierLadder,
  type TierEvalInput,
} from './tier-ladder.js';

// ─── Soma Check (conditional payment protocol) ──────────────────────────────

export {
  SOMA_CHECK_PROTOCOL,
  SOMA_CHECK_HEADERS,
  SOMA_CHECK_MIN_HASH_LENGTH,
  buildSomaCheckResponseHeaders,
  buildSomaCheckRequestHeaders,
  extractIfSomaHash,
  extractSomaHash,
  isSomaCheckResponse,
  shouldRespondUnchanged,
  buildUnchangedResponse,
  verifyDataHashConsistency,
  SomaCheckHashStore,
  type UnchangedResponse,
  type CheckMetadata,
} from '../core/soma-check.js';
