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
