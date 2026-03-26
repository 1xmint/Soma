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
  type HeartConfig,
  type GenerationInput,
  type HeartbeatToken,
  type HeartbeatResult,
  type HeartbeatData,
  type HeartSession,
  type DataSourceConfig,
} from "./runtime.js";

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
