/**
 * The Heart Runtime — the execution pathway through which all agent
 * computation flows.
 *
 * The agent's API keys, tool credentials, and data connections all live
 * inside the heart. No heart, no credentials, no computation. The agent
 * literally cannot function without it.
 *
 * Every computation that passes through the heart gets:
 * 1. A cryptographic seed woven into the input
 * 2. A heartbeat logged in the hash chain
 * 3. A birth certificate for any new data
 *
 * The output is inseparable from the heart that produced it.
 */

import OpenAI from "openai";
import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from "../core/crypto-provider.js";
import {
  commitGenome,
  createGenome,
  type GenomeCommitment,
  sha256,
} from "../core/genome.js";
import {
  type Channel,
  generateEphemeralKeyPair,
  createHandshakePayload,
  establishChannel,
  type HandshakePayload,
  type BoxKeyPair,
} from "../core/channel.js";
import { CredentialVault } from "./credential-vault.js";
import { HeartbeatChain, type Heartbeat } from "./heartbeat.js";
import { deriveSeed, applySeed, deriveHmacKey, computeTokenHmac, type HeartSeed, type BehavioralParams } from "./seed.js";
import {
  createBirthCertificate,
  type BirthCertificate,
} from "./birth-certificate.js";
import {
  createLineageCertificate,
  effectiveCapabilities,
  hasCapability,
  type HeartLineage,
  type LineageCertificate,
} from "./lineage.js";
import {
  createDelegation,
  type Caveat,
  type Delegation,
} from "./delegation.js";
import {
  createRevocation,
  RevocationRegistry,
  type RevocationEvent,
  type RevocationReason,
} from "./revocation.js";
import {
  loadHeartState,
  serializeHeart,
  signKeyPairFromJson,
  signKeyPairToJson,
  type HeartState,
} from "./persistence.js";
import {
  HumanSessionRegistry,
  type HumanSession,
  type InvokeRequest,
  type InvokeResult,
} from "./human-session.js";
import type {
  AttestationVerifier,
  HumanDelegation,
} from "./human-delegation.js";
import type { CeremonyPolicy } from "./ceremony-policy.js";
import type { DidMethodRegistry } from "../core/did-method.js";
import {
  issueProductSession,
  issueAdapterBridgeSession,
  elevateProductSession,
  decayProductSession,
  deriveProductTokenKey,
  mintProductSessionToken,
  validateProductSessionToken,
  matchTokenToSession,
  DEFAULT_PRODUCT_SESSION_TTL_MS,
  type ProductSession,
  type DeviceBinding,
  type DeviceTrustLevel,
  type IssueProductSessionResult,
  type StepUpElevationResult,
  type ValidateTokenResult,
  type MatchTokenResult,
  type ProductSessionTokenClaims,
} from "./product-session.js";
import {
  verifyLoginVerificationSignature,
  type LoginVerification,
  type LoginCeremonyEvidence,
  type LoginDeviceTrust,
} from "./login-challenge.js";
import {
  ProductAccountBindingStore,
  type ProductAccountBinding,
} from "./product-account-binding.js";
import { ProductSessionStore } from "./product-session-store.js";
import type { CeremonyTier } from "./human-delegation.js";

// ─── Evidence → DeviceBinding derivation ───────────────────────────────────

const LOGIN_TRUST_TO_DEVICE_TRUST: Record<LoginDeviceTrust, DeviceTrustLevel> = {
  'hardware-attested': 'hardware-attested',
  'platform': 'platform',
  'software': 'software',
};

const DEVICE_TRUST_RANK: Record<DeviceTrustLevel, number> = {
  'hardware-attested': 3,
  'platform': 2,
  'software': 1,
  'adapter': 0,
};

function deriveDeviceBindingFromEvidence(
  evidence: LoginCeremonyEvidence,
): DeviceBinding | null {
  if (evidence.provenFactors.length === 0) return null;
  const strongest = evidence.provenFactors.reduce((best, f) => {
    const bestRank = DEVICE_TRUST_RANK[LOGIN_TRUST_TO_DEVICE_TRUST[best.deviceTrust]];
    const fRank = DEVICE_TRUST_RANK[LOGIN_TRUST_TO_DEVICE_TRUST[f.deviceTrust]];
    return fRank > bestRank ? f : best;
  });
  return {
    factorId: strongest.factorId,
    factorType: strongest.factorType,
    deviceTrustLevel: LOGIN_TRUST_TO_DEVICE_TRUST[strongest.deviceTrust],
  };
}

// ─── Adapter Migration Result ──────────────────────────────────────────────

export type AdapterMigrationResult =
  | AdapterMigrationSuccess
  | AdapterMigrationFailure;

export interface AdapterMigrationSuccess {
  ok: true;
  newSession: ProductSession;
  revokedSessionId: string;
  binding: ProductAccountBinding;
}

export interface AdapterMigrationFailure {
  ok: false;
  reason: string;
}

// --- Types ---

/**
 * Default maximum age of a session, in ms. Sessions older than this are
 * purged from the sessions Map and treated as not-found on any read.
 *
 * Without a cap, the sessions Map grows unbounded — every createSession call
 * allocates a HeartbeatChain + ephemeral keypair that persist until destroy().
 * A long-lived heart handling many short sessions would leak memory and
 * accumulate revoked-but-not-cleaned session keys. One hour is long enough
 * for ordinary streaming interactions and short enough to bound growth.
 */
export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;

export interface DataSourceConfig {
  name: string;
  url: string;
  headers?: Record<string, string>;
}

/**
 * Configuration for human session support. When provided on HeartConfig,
 * the runtime creates an internal HumanSessionRegistry and exposes
 * `createHumanSession` / `invokeHumanSession` / `revokeHumanSession`.
 *
 * Hearts that only serve agent-to-agent sessions can omit this — calling
 * any human session method on a heart without this config throws clearly.
 */
export interface HumanSessionConfig {
  /** Pluggable attestation verifier — Soma stays authenticator-agnostic. */
  attestationVerifier: AttestationVerifier;
  /** Optional ceremony policy override (defaults to DEFAULT_CEREMONY_POLICY). */
  ceremonyPolicy?: CeremonyPolicy;
  /** Optional DID method registry for multi-method humanDid resolution. */
  didRegistry?: DidMethodRegistry;
}

export interface HeartConfig {
  genome: GenomeCommitment;
  signingKeyPair: SignKeyPair;

  // Model credentials — only accessible through the heart
  modelApiKey: string;
  modelBaseUrl: string;
  modelId: string;

  // Tool credentials — only accessible through the heart
  toolCredentials?: Record<string, string>;

  // Data source configurations — only accessible through the heart
  dataSources?: DataSourceConfig[];

  // Profile storage path
  profileStorePath?: string;

  /**
   * Lineage chain — if present, this heart was forked from a parent.
   * effectiveCapabilities(lineage) gates what this heart can do.
   */
  lineage?: HeartLineage;

  /** Pre-existing revocation events this heart should honor. */
  revocations?: RevocationEvent[];

  /**
   * Pre-encrypted credentials to restore into the vault (persistence).
   * Used by loadSomaHeart() — callers should NOT set this directly.
   * @internal
   */
  restoreCredentials?: Array<{
    name: string;
    nonceB64: string;
    ciphertextB64: string;
  }>;

  /**
   * Prior heartbeat chain to continue from (persistence).
   * Used by loadSomaHeart() — callers should NOT set this directly.
   * @internal
   */
  restoreHeartbeats?: Heartbeat[];

  /** Crypto provider — swap algorithms without changing the protocol. */
  cryptoProvider?: CryptoProvider;

  /**
   * Maximum age of a session in milliseconds. Defaults to
   * `DEFAULT_SESSION_TTL_MS` (1 hour). Sessions older than this are purged
   * and treated as not-found on any read — caps unbounded Map growth.
   */
  sessionTtlMs?: number;

  /**
   * Human session support. When set, enables `createHumanSession` and
   * related methods. Omit for agent-only hearts.
   */
  humanSessionConfig?: HumanSessionConfig;
}

export interface GenerationInput {
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  temperature?: number;
  maxTokens?: number;
}

/** A token emitted by the heart during generation — interleaved with heartbeats. */
export interface HeartbeatToken {
  type: "token" | "heartbeat";
  /** The token text (when type === "token"). */
  token?: string;
  /** The heartbeat (when type === "heartbeat"). */
  heartbeat?: Heartbeat;
  /** Timestamp of emission. */
  timestamp: number;
  /** HMAC-SHA256(hmacKey, token || sequence || interaction_counter). Present when type === "token" and session has a key. */
  hmac?: string;
  /** Monotonic per-interaction token counter. Present when type === "token" and session has a key. */
  sequence?: number;
}

/** Result of a tool call routed through the heart. */
export interface HeartbeatResult {
  result: unknown;
  heartbeats: Heartbeat[];
  birthCertificate: BirthCertificate;
}

/**
 * Progress emitter handed to tool executors. Each call records a
 * `tool_progress` heartbeat, giving observers sub-beat visibility into
 * the work a tool is doing — the blacksmith's strikes between input
 * and output.
 */
export type ToolProgressEmitter = (stage: string, detail?: string) => void;

/** Function signature for a tool executor. */
export type ToolExecutor = (
  credential: string,
  args: Record<string, unknown>,
  emit: ToolProgressEmitter,
) => Promise<unknown>;

/** Result of a data fetch routed through the heart. */
export interface HeartbeatData {
  content: string;
  heartbeats: Heartbeat[];
  birthCertificate: BirthCertificate;
}

/** A session between two hearted parties. */
export interface HeartSession {
  sessionId: string;
  remoteDid: string;
  remoteGenome: GenomeCommitment;
  channel: Channel | null;
  sessionKey: Uint8Array | null;
  ephemeralKeyPair: BoxKeyPair;
  heartbeatChain: HeartbeatChain;
  interactionCounter: number;
  createdAt: number;
}

// --- The Heart ---

export class HeartRuntime {
  private readonly vault: CredentialVault;
  private readonly heartbeatChain: HeartbeatChain;
  private readonly genome: GenomeCommitment;
  private readonly signingKeyPair: SignKeyPair;
  private readonly modelId: string;
  private readonly modelBaseUrl: string;
  private readonly dataSources: Map<string, DataSourceConfig>;
  private readonly sessions: Map<string, HeartSession> = new Map();
  private readonly sessionTtlMs: number;
  private readonly provider: CryptoProvider;
  private readonly _lineage?: HeartLineage;
  private readonly _effectiveCaps: string[] | null;
  private readonly revocations: RevocationRegistry;
  private readonly humanSessionRegistry: HumanSessionRegistry | null;
  private readonly _productSessionStore: ProductSessionStore;
  private alive: boolean = true;

  constructor(config: HeartConfig) {
    this.provider = config.cryptoProvider ?? getCryptoProvider();
    this.genome = config.genome;
    this.signingKeyPair = config.signingKeyPair;
    this.modelId = config.modelId;
    this.modelBaseUrl = config.modelBaseUrl;
    this.sessionTtlMs = config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    if (this.sessionTtlMs <= 0) {
      throw new Error("sessionTtlMs must be > 0");
    }
    this.heartbeatChain = config.restoreHeartbeats
      ? HeartbeatChain.restore(config.restoreHeartbeats, this.provider)
      : new HeartbeatChain(this.provider);
    this._lineage = config.lineage;
    this._effectiveCaps = config.lineage
      ? effectiveCapabilities(config.lineage)
      : null;
    this.revocations = new RevocationRegistry({ provider: this.provider });

    // Register lineage authorities so regular import() accepts lineage
    // revocations from the parent — the parent DID is the legitimate
    // authority for each lineage certificate it signed.
    // Also register the immediate parent as authority for this heart's
    // own DID, so heart-level revocations (targetKind: 'heart') are
    // accepted via the regular import() path.
    if (config.lineage) {
      for (const cert of config.lineage.chain) {
        this.revocations.registerAuthority(cert.id, cert.parentDid);
      }
      // The last cert in the chain is the immediate parent → child link.
      // Register the parent as authority for this heart's DID so the
      // parent can revoke the child heart directly.
      const immediateCert = config.lineage.chain[config.lineage.chain.length - 1];
      this.revocations.registerAuthority(this.did, immediateCert.parentDid);
    }

    if (config.revocations) {
      if (config.restoreCredentials) {
        // Restore path (loadSomaHeart): revocations were already authority-
        // checked before serialization. Use importTrusted to skip authority
        // re-verification since not all authorities can be reconstructed
        // (e.g. delegation issuers from prior runtime).
        this.revocations.importTrusted(config.revocations);
      } else {
        // Direct construction path: require authority verification.
        // Lineage authorities were registered above; delegation/heart
        // revocations must come from a known authority.
        this.revocations.import(config.revocations);
      }
    }

    // Human session support — opt-in via humanSessionConfig
    this.humanSessionRegistry = config.humanSessionConfig
      ? new HumanSessionRegistry({
          attestationVerifier: config.humanSessionConfig.attestationVerifier,
          policy: config.humanSessionConfig.ceremonyPolicy,
          provider: this.provider,
          didRegistry: config.humanSessionConfig.didRegistry,
        })
      : null;

    // Product session store — always available (lightweight Map)
    this._productSessionStore = new ProductSessionStore();

    // Store all credentials in the vault — encrypted at rest
    this.vault = new CredentialVault(config.signingKeyPair.secretKey, this.provider);
    if (config.restoreCredentials) {
      this.vault.importEncrypted(config.restoreCredentials);
    } else {
      this.vault.store("model_api_key", config.modelApiKey);
    }

    // Store tool credentials (skipped when restoring — already in vault)
    if (config.toolCredentials && !config.restoreCredentials) {
      for (const [name, value] of Object.entries(config.toolCredentials)) {
        this.vault.store(`tool:${name}`, value);
      }
    }

    // Store data source configs
    this.dataSources = new Map();
    if (config.dataSources) {
      for (const ds of config.dataSources) {
        this.dataSources.set(ds.name, ds);
        // On restore, credentials are already in the vault; don't overwrite.
        if (ds.headers && !config.restoreCredentials) {
          for (const [key, value] of Object.entries(ds.headers)) {
            if (isAuthHeader(key)) {
              this.vault.store(`datasource:${ds.name}:${key}`, value);
            }
          }
        }
      }
    }
  }

  /** The heart's DID identity. */
  get did(): string {
    return this.genome.did;
  }

  /** The heart's genome commitment. */
  get genomeCommitment(): GenomeCommitment {
    return this.genome;
  }

  /** Whether the heart is still alive. */
  get isAlive(): boolean {
    return this.alive;
  }

  /** Get the global heartbeat chain (read-only). */
  get heartbeats(): HeartbeatChain {
    return this.heartbeatChain;
  }

  /** The crypto provider this heart uses. */
  get cryptoProvider(): CryptoProvider {
    return this.provider;
  }

  /**
   * Compute the content hash used in birth certificates — exposed so providers
   * can hash their own cached content with the same scheme the heart uses.
   * This is the hash that flows through Soma Check's `X-Soma-Hash` header.
   */
  hashContent(content: string): string {
    return sha256(content, this.provider);
  }

  /** The lineage chain this heart carries (if it was forked from a parent). */
  get lineage(): HeartLineage | undefined {
    return this._lineage;
  }

  /**
   * Capabilities granted to this heart by its lineage.
   * `null` = no restrictions (root heart).
   */
  get capabilities(): string[] | null {
    return this._effectiveCaps;
  }

  /**
   * Check whether this heart is allowed to exercise a given capability
   * under its lineage. Root hearts (no lineage) return true for everything.
   */
  can(capability: string): boolean {
    if (this._effectiveCaps === null) return true;
    return hasCapability(this._effectiveCaps, capability);
  }

  // ─── Agent Observability (the blacksmith's sub-strikes) ─────────────────

  /**
   * Record an internal reasoning step. Agents should call this between
   * query-received and tool-call to make chain-of-thought visible in the
   * heartbeat chain — hashed, so the content stays private.
   */
  recordReasoning(summary: string, sessionId?: string): Heartbeat {
    this.ensureAlive();
    const chain = this.chainFor(sessionId);
    return chain.record(
      "reasoning_step",
      JSON.stringify({ summaryHash: sha256(summary, this.provider) }),
    );
  }

  /**
   * Record a retry — any operation that was re-attempted. Makes the
   * blacksmith's missed strikes visible.
   */
  recordRetry(
    operation: string,
    reason: string,
    attempt: number,
    sessionId?: string,
  ): Heartbeat {
    this.ensureAlive();
    const chain = this.chainFor(sessionId);
    return chain.record(
      "retry",
      JSON.stringify({ operation, reason, attempt }),
    );
  }

  /**
   * Record a RAG lookup — what was retrieved to augment context. The
   * observer sees that retrieval happened and how many items were used,
   * without the retrieved content being exposed.
   */
  recordRagLookup(
    queryHash: string,
    resultCount: number,
    sessionId?: string,
  ): Heartbeat {
    this.ensureAlive();
    const chain = this.chainFor(sessionId);
    return chain.record(
      "rag_lookup",
      JSON.stringify({ queryHash, resultCount }),
    );
  }

  /**
   * Record that work was dispatched to a child or delegatee.
   * Makes multi-agent handoffs visible in the heartbeat chain.
   */
  recordSubtaskDispatch(
    subjectDid: string,
    taskHash: string,
    sessionId?: string,
  ): Heartbeat {
    this.ensureAlive();
    const chain = this.chainFor(sessionId);
    return chain.record(
      "subtask_dispatch",
      JSON.stringify({ subjectDid, taskHash }),
    );
  }

  /**
   * Record that a child or delegatee returned a result for previously
   * dispatched work.
   */
  recordSubtaskReturn(
    subjectDid: string,
    resultHash: string,
    sessionId?: string,
  ): Heartbeat {
    this.ensureAlive();
    const chain = this.chainFor(sessionId);
    return chain.record(
      "subtask_return",
      JSON.stringify({ subjectDid, resultHash }),
    );
  }

  /** Pick the chain for a given session (global if none). */
  private chainFor(sessionId?: string): HeartbeatChain {
    if (!sessionId) return this.heartbeatChain;
    return this.activeSession(sessionId)?.heartbeatChain ?? this.heartbeatChain;
  }

  // ─── Fork — spawn a child heart with signed lineage ─────────────────────

  /**
   * Fork a child heart: generate a fresh keypair, build the child's genome,
   * sign a lineage certificate binding the child to this heart, and return
   * the materials needed to construct the child HeartRuntime.
   *
   * The caller provisions the child's credentials (model API key, tool
   * credentials). This separation is intentional — a parent may fork many
   * children, each with different credentials.
   */
  fork(opts: {
    systemPrompt: string;
    toolManifest: string;
    modelProvider?: string;
    modelId?: string;
    modelVersion?: string;
    runtimeId?: string;
    capabilities?: string[];
    ttl?: number;
    budgetCredits?: number;
  }): {
    childKeyPair: SignKeyPair;
    childGenome: GenomeCommitment;
    lineageCertificate: LineageCertificate;
    childLineage: HeartLineage;
  } {
    this.ensureAlive();
    this.ensureLineageValid();

    // Enforce: a forked child cannot have capabilities the parent lacks.
    if (opts.capabilities && this._effectiveCaps !== null) {
      for (const cap of opts.capabilities) {
        if (!hasCapability(this._effectiveCaps, cap)) {
          throw new Error(
            `Cannot fork with capability "${cap}" — not granted to this heart`,
          );
        }
      }
    }

    // Generate child's keypair and genome
    const childKeyPair = this.provider.signing.generateKeyPair();
    const childGenomeDoc = createGenome(
      {
        modelProvider: opts.modelProvider ?? this.genome.genome.modelProvider,
        modelId: opts.modelId ?? this.modelId,
        modelVersion: opts.modelVersion ?? this.genome.genome.modelVersion,
        systemPrompt: opts.systemPrompt,
        toolManifest: opts.toolManifest,
        runtimeId: opts.runtimeId ?? this.genome.genome.runtimeId,
        parentHash: this.genome.hash,
        version: 1,
      },
      this.provider,
    );
    const childGenome = commitGenome(childGenomeDoc, childKeyPair, this.provider);

    // Parent signs the lineage cert binding child identity
    const lineageCert = createLineageCertificate({
      parent: this.genome,
      parentSigningKey: this.signingKeyPair.secretKey,
      child: childGenome,
      capabilities: opts.capabilities ?? [],
      ttl: opts.ttl,
      budgetCredits: opts.budgetCredits,
      provider: this.provider,
    });

    // Compose the child's lineage chain: this heart's chain + new cert
    const parentChain = this._lineage?.chain ?? [];
    const rootDid = this._lineage?.rootDid ?? this.did;
    const childLineage: HeartLineage = {
      did: childGenome.did,
      rootDid,
      chain: [...parentChain, lineageCert],
    };

    // Record the fork in the heartbeat chain
    this.heartbeatChain.record(
      "fork_created",
      JSON.stringify({
        childDid: childGenome.did,
        lineageCertId: lineageCert.id,
        capabilities: opts.capabilities ?? [],
      }),
    );

    return { childKeyPair, childGenome, lineageCertificate: lineageCert, childLineage };
  }

  // ─── Delegate — grant attenuated capabilities to another party ──────────

  /**
   * Create a delegation — grant a subject DID the right to exercise some
   * capabilities under caveats. The subject does NOT need to be a forked
   * child; delegation is a separate primitive.
   */
  delegate(opts: {
    subjectDid: string;
    capabilities: string[];
    caveats?: Caveat[];
    parentId?: string | null;
  }): Delegation {
    this.ensureAlive();
    this.ensureLineageValid();

    // Enforce: can't delegate what we don't have.
    if (this._effectiveCaps !== null) {
      for (const cap of opts.capabilities) {
        if (!hasCapability(this._effectiveCaps, cap)) {
          throw new Error(
            `Cannot delegate "${cap}" — not granted to this heart`,
          );
        }
      }
    }

    const delegation = createDelegation({
      issuerDid: this.did,
      issuerPublicKey: this.genome.publicKey,
      issuerSigningKey: this.signingKeyPair.secretKey,
      subjectDid: opts.subjectDid,
      capabilities: opts.capabilities,
      caveats: opts.caveats,
      parentId: opts.parentId ?? null,
      provider: this.provider,
    });

    // Record the legitimate issuer for this target so that any later
    // revocation must come from us — closes the "fresh-key forged
    // revocation" hole (see revocation.ts authority check).
    this.revocations.registerAuthority(delegation.id, this.did);

    this.heartbeatChain.record(
      "delegation_issued",
      JSON.stringify({
        delegationId: delegation.id,
        subjectDid: delegation.subjectDid,
        capabilities: delegation.capabilities,
        caveatCount: delegation.caveats.length,
      }),
    );

    return delegation;
  }

  // ─── Revoke — permanently kill a credential this heart issued ──────────

  /**
   * Sign a revocation event for a credential this heart previously issued.
   * The event is added to this heart's registry AND returned so the caller
   * can broadcast it to other parties.
   */
  revoke(opts: {
    targetId: string;
    targetKind: "lineage" | "delegation" | "heart";
    reason?: RevocationReason;
    detail?: string;
  }): RevocationEvent {
    this.ensureAlive();

    const event = createRevocation({
      targetId: opts.targetId,
      targetKind: opts.targetKind,
      issuerDid: this.did,
      issuerPublicKey: this.genome.publicKey,
      issuerSigningKey: this.signingKeyPair.secretKey,
      reason: opts.reason,
      detail: opts.detail,
      provider: this.provider,
    });

    // Self-revocation: the heart is the authority over its own issuances.
    this.revocations.add(event, this.did);

    this.heartbeatChain.record(
      "delegation_revoked",
      JSON.stringify({
        revocationId: event.id,
        targetId: event.targetId,
        targetKind: event.targetKind,
        reason: event.reason,
      }),
    );

    return event;
  }

  /** Check whether a credential ID is revoked in this heart's registry. */
  isRevoked(targetId: string): boolean {
    return this.revocations.isRevoked(targetId);
  }

  /** Import revocation events from an external source (e.g. a feed). */
  addRevocations(events: RevocationEvent[]): number {
    return this.revocations.import(events);
  }

  /** Export this heart's revocation registry contents. */
  exportRevocations(): RevocationEvent[] {
    return this.revocations.export();
  }

  // ─── Persistence — encrypt heart state to disk and rehydrate ───────────

  /**
   * Serialize this heart's state to an encrypted blob.
   * Sessions are NOT serialized — they are ephemeral by design.
   *
   * Uses scrypt (memory-hard) by default. Override tuning via `scrypt`.
   */
  serialize(
    password: string,
    opts?: { scrypt?: { N?: number; r?: number; p?: number } },
  ): string {
    this.ensureAlive();
    const state: HeartState = {
      version: 1,
      genome: this.genome,
      signingKey: signKeyPairToJson(this.signingKeyPair, this.provider),
      modelId: this.modelId,
      modelBaseUrl: this.modelBaseUrl,
      dataSources: Array.from(this.dataSources.values()),
      credentials: this.vault.exportEncrypted(),
      heartbeats: [...this.heartbeatChain.getChain()],
      revocations: this.revocations.export(),
      lineageChain: this._lineage?.chain,
      lineageRootDid: this._lineage?.rootDid,
      savedAt: Date.now(),
    };
    return serializeHeart(state, password, {
      provider: this.provider,
      scrypt: opts?.scrypt,
    });
  }

  // --- Session Management ---

  /**
   * Create a session with a remote party.
   * Generates an ephemeral key pair for the handshake.
   */
  createSession(remoteDid: string, remoteGenome: GenomeCommitment): HeartSession {
    this.ensureAlive();

    // Opportunistic cleanup: purge any sessions that have outlived the TTL.
    // This keeps the Map bounded even when no reader touches the stale entries.
    this.purgeExpiredSessions();

    const ephemeralKeyPair = generateEphemeralKeyPair(this.provider);
    const sessionId = sha256(`${this.did}|${remoteDid}|${Date.now()}|${Math.random()}`, this.provider);

    const session: HeartSession = {
      sessionId,
      remoteDid,
      remoteGenome: remoteGenome,
      channel: null,
      sessionKey: null,
      ephemeralKeyPair,
      heartbeatChain: new HeartbeatChain(this.provider),
      interactionCounter: 0,
      createdAt: Date.now(),
    };

    // Record session start
    session.heartbeatChain.record(
      "session_start",
      JSON.stringify({
        sessionId,
        remoteDid,
        remoteGenomeHash: remoteGenome.hash,
      })
    );

    this.sessions.set(sessionId, session);
    return session;
  }

  /** Get the handshake payload for a session. */
  getHandshakePayload(sessionId: string): HandshakePayload {
    this.ensureAlive();
    const session = this.activeSession(sessionId);
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    return createHandshakePayload(this.genome, session.ephemeralKeyPair, this.provider);
  }

  /**
   * Complete a session handshake with the remote party's handshake payload.
   * Establishes the encrypted channel and extracts the session key for seeding.
   */
  completeHandshake(sessionId: string, remoteHandshake: HandshakePayload): void {
    this.ensureAlive();
    const session = this.activeSession(sessionId);
    if (!session) throw new Error(`Session not found: ${sessionId}`);

    const localHandshake = createHandshakePayload(this.genome, session.ephemeralKeyPair, this.provider);
    const channel = establishChannel(
      { handshake: localHandshake, ephemeralKeyPair: session.ephemeralKeyPair },
      remoteHandshake,
      this.provider
    );

    session.channel = channel;
    session.sessionKey = channel.sessionKey;
  }

  /**
   * Get a session by ID. Returns undefined if the session has expired
   * past `sessionTtlMs` — expired sessions are purged on access so the
   * caller sees them as not-found.
   */
  getSession(sessionId: string): HeartSession | undefined {
    return this.activeSession(sessionId);
  }

  /**
   * Internal session accessor. Purges the session if expired and returns
   * undefined in that case, otherwise returns the live session. All internal
   * session reads go through this so no code path observes a stale session.
   */
  private activeSession(sessionId: string): HeartSession | undefined {
    const session = this.sessions.get(sessionId);
    if (!session) return undefined;
    if (this.isSessionExpired(session)) {
      this.sessions.delete(sessionId);
      return undefined;
    }
    return session;
  }

  /** True if the session has outlived `sessionTtlMs`. */
  private isSessionExpired(session: HeartSession): boolean {
    return Date.now() - session.createdAt > this.sessionTtlMs;
  }

  /**
   * Purge every expired session from the Map. Called opportunistically
   * from createSession so repeated creation can't leak memory even when
   * no reader ever touches the stale sessions.
   */
  private purgeExpiredSessions(): number {
    let purged = 0;
    for (const [id, session] of this.sessions) {
      if (this.isSessionExpired(session)) {
        this.sessions.delete(id);
        purged++;
      }
    }
    return purged;
  }

  // ─── Human Session Management (Soma-native consent path) ───────────────

  /**
   * Open a human session from a signed HumanDelegation.
   *
   * This is the runtime bridge (PR-B.5) that takes a verified-or-verifiable
   * HumanDelegation and opens a runtime-managed session. The delegation is
   * verified end-to-end by the internal HumanSessionRegistry (signature,
   * DID binding, attestation, time window, challenge hash). On success a
   * `consent_granted` heartbeat is recorded; on failure a
   * `consent_rejected` heartbeat captures the reason.
   *
   * Requires `humanSessionConfig` in HeartConfig — throws if the heart
   * was not configured for human sessions.
   *
   * Idempotent by `delegation.sessionId`: re-opening an already-active
   * session returns the existing handle without double-counting the
   * envelope.
   *
   * @param delegation  The signed HumanDelegation payload.
   * @param now         Timestamp for verification (defaults to Date.now()).
   * @returns           InvokeResult — ok + session handle, or failure reason.
   */
  createHumanSession(delegation: HumanDelegation, now?: number): InvokeResult {
    this.ensureAlive();
    this.ensureHumanSessionSupport();

    const ts = now ?? Date.now();
    const result = this.humanSessionRegistry!.open(delegation, ts);

    if (result.ok) {
      this.heartbeatChain.record(
        "consent_granted",
        JSON.stringify({
          sessionId: delegation.sessionId,
          humanDid: delegation.humanDid,
          agentEphemeralDid: delegation.agentEphemeralDid,
          tier: result.session.tier,
          expiresAt: delegation.expiresAt,
        }),
      );
    } else {
      this.heartbeatChain.record(
        "consent_rejected",
        JSON.stringify({
          sessionId: delegation.sessionId,
          humanDid: delegation.humanDid,
          reason: result.reason,
        }),
      );
    }

    return result;
  }

  /**
   * Get a human session by ID. Returns undefined if not found or not
   * active.
   */
  getHumanSession(sessionId: string): HumanSession | undefined {
    this.ensureAlive();
    return this.humanSessionRegistry?.get(sessionId);
  }

  /**
   * Attempt an in-session action against a human session. Walks envelope
   * caveats + ceremony policy, drains budget/invocations on success, and
   * records a heartbeat for the outcome.
   */
  invokeHumanSession(sessionId: string, req: InvokeRequest): InvokeResult {
    this.ensureAlive();
    this.ensureHumanSessionSupport();

    const result = this.humanSessionRegistry!.invoke(sessionId, req);

    this.heartbeatChain.record(
      result.ok ? "human_session_invoke" : "human_session_invoke_denied",
      JSON.stringify({
        sessionId,
        actionClass: req.actionClass,
        ok: result.ok,
        ...(!result.ok && { reason: (result as { reason: string }).reason }),
        status: result.session.status,
      }),
    );

    return result;
  }

  /**
   * Revoke a human session. Returns true if the session existed and was
   * revoked, false if it was not found.
   */
  revokeHumanSession(sessionId: string): boolean {
    this.ensureAlive();
    this.ensureHumanSessionSupport();

    const revoked = this.humanSessionRegistry!.revoke(sessionId);
    if (revoked) {
      this.heartbeatChain.record(
        "human_session_revoked",
        JSON.stringify({ sessionId }),
      );
    }
    return revoked;
  }

  /**
   * Prune terminated / expired human sessions. Returns the number
   * of sessions removed. Call from a periodic sweep.
   */
  pruneHumanSessions(now?: number): number {
    this.ensureAlive();
    if (!this.humanSessionRegistry) return 0;
    return this.humanSessionRegistry.prune(now ?? Date.now());
  }

  // ─── Product Session Issuance (Mode A — Soma-direct) ────────────────────

  /**
   * Issue a Mode A (soma-direct) ProductSession from a runtime-managed
   * HumanSession.
   *
   * This is the runtime convenience method that:
   *   1. Looks up the HumanSession by `humanSessionId`
   *   2. Delegates to the pure `issueProductSession` factory
   *   3. Records a heartbeat (`product_session_issued` or
   *      `product_session_denied`)
   *
   * Requires `humanSessionConfig` in HeartConfig.
   *
   * @param humanSessionId  The Soma-layer session ID (from createHumanSession).
   * @param accountId       Product account ID (e.g. HeyVera account).
   * @param opts            Optional device binding, TTL, session ID overrides.
   */
  issueProductSession(
    humanSessionId: string,
    accountId: string,
    opts?: {
      deviceBinding?: DeviceBinding | null;
      sessionTtlMs?: number;
      sessionId?: string;
      now?: number;
    },
  ): IssueProductSessionResult {
    this.ensureAlive();
    this.ensureHumanSessionSupport();

    const now = opts?.now ?? Date.now();
    const humanSession = this.humanSessionRegistry!.get(humanSessionId);

    if (!humanSession) {
      const reason = `human session not found: ${humanSessionId}`;
      this.heartbeatChain.record(
        "product_session_denied",
        JSON.stringify({ humanSessionId, accountId, reason }),
      );
      return { ok: false, reason };
    }

    const result = issueProductSession({
      accountId,
      humanSession,
      deviceBinding: opts?.deviceBinding,
      sessionTtlMs: opts?.sessionTtlMs,
      sessionId: opts?.sessionId,
      now,
    });

    if (result.ok) {
      this._productSessionStore.put(result.session);
      this.heartbeatChain.record(
        "product_session_issued",
        JSON.stringify({
          productSessionId: result.session.sessionId,
          humanSessionId,
          accountId,
          somaIdentityBinding: result.session.somaIdentityBinding,
          authOrigin: result.session.authOrigin,
          tier: result.session.currentAuthorityTier,
          expiresAt: result.session.expiresAt,
        }),
      );
    } else {
      this.heartbeatChain.record(
        "product_session_denied",
        JSON.stringify({
          humanSessionId,
          accountId,
          reason: result.reason,
        }),
      );
    }

    return result;
  }

  // ─── Product Session Issuance (Mode B — Adapter-bridge) ─────────────────

  /**
   * Issue a Mode B (adapter-bridge) ProductSession.
   *
   * This path does NOT require `humanSessionConfig` — adapter-bridge
   * sessions bypass HumanDelegation entirely. The adapter's auth
   * assertion is verified externally by the product server; this method
   * takes the verified result and produces a tagged, capped
   * ProductSession.
   *
   * Authority is capped at L1 (Decision 7). The `authOrigin` is always
   * `'adapter-bridge'`. If the product account has a Soma identity
   * binding, it is carried honestly; if not, `somaIdentityBinding` is
   * null.
   *
   * Records an `adapter_session_issued` heartbeat.
   *
   * @param accountId            Product account ID.
   * @param opts                 Soma binding, requested tier, TTL, session ID.
   */
  issueAdapterBridgeSession(
    accountId: string,
    opts?: {
      somaIdentityBinding?: string | null;
      requestedTier?: CeremonyTier;
      sessionTtlMs?: number;
      sessionId?: string;
      now?: number;
    },
  ): IssueProductSessionResult {
    this.ensureAlive();

    const result = issueAdapterBridgeSession({
      accountId,
      somaIdentityBinding: opts?.somaIdentityBinding,
      requestedTier: opts?.requestedTier,
      sessionTtlMs: opts?.sessionTtlMs,
      sessionId: opts?.sessionId,
      now: opts?.now,
    });

    if (result.ok) {
      this._productSessionStore.put(result.session);
      this.heartbeatChain.record(
        "adapter_session_issued",
        JSON.stringify({
          productSessionId: result.session.sessionId,
          accountId,
          authOrigin: result.session.authOrigin,
          tier: result.session.currentAuthorityTier,
          hasSomaBinding: result.session.somaIdentityBinding !== null,
          expiresAt: result.session.expiresAt,
        }),
      );
    }

    return result;
  }

  // ─── Product Session from Login Verification (Mode A shortcut) ──────────

  /**
   * Issue a Mode A (soma-direct) ProductSession from a signed
   * LoginVerification.
   *
   * This is the browser login convenience path. After the product server
   * verifies a login through `LoginChallengeService.verifyLogin`, it
   * passes the resulting `LoginVerification` here to get a ProductSession
   * without going through the HumanDelegation → HumanSession indirection.
   *
   * The method verifies the LoginVerification's signature against this
   * heart's public key, then constructs a soma-direct ProductSession.
   *
   * Does NOT require `humanSessionConfig` — this is a standalone login
   * path independent of agent-to-human delegation.
   *
   * Records `product_session_issued` heartbeat on success,
   * `product_session_denied` on failure.
   *
   * @param verification  Signed LoginVerification from LoginChallengeService.
   * @param accountId     Product account ID (e.g. HeyVera account).
   * @param opts          Optional TTL, session ID overrides.
   */
  issueProductSessionFromLogin(
    verification: LoginVerification,
    accountId: string,
    opts?: {
      sessionTtlMs?: number;
      sessionId?: string;
      now?: number;
    },
  ): IssueProductSessionResult {
    this.ensureAlive();
    const now = opts?.now ?? Date.now();

    // ── Verify the LoginVerification signature ────────────────────────
    const sigCheck = verifyLoginVerificationSignature(verification, {
      trustedHeartPublicKeys: [this.genome.publicKey],
      maxAgeMs: 300_000, // 5 minutes
      now,
      provider: this.provider,
    });

    if (!sigCheck.valid) {
      const reason = `login verification rejected: ${sigCheck.reason}`;
      this.heartbeatChain.record(
        "product_session_denied",
        JSON.stringify({ accountId, reason }),
      );
      return { ok: false, reason };
    }

    // ── Derive device binding from ceremony evidence ─────────────────
    const deviceBinding = deriveDeviceBindingFromEvidence(verification.evidence);

    // ── Construct soma-direct ProductSession ──────────────────────────
    const sessionTtl = opts?.sessionTtlMs ?? DEFAULT_PRODUCT_SESSION_TTL_MS;
    const sessionId = opts?.sessionId ?? crypto.randomUUID();

    const session: ProductSession = {
      sessionId,
      accountId,
      somaIdentityBinding: verification.subjectDid,
      baseAuthorityTier: verification.tierAchieved,
      currentAuthorityTier: verification.tierAchieved,
      authOrigin: 'soma-direct',
      deviceBinding,
      issuedAt: now,
      expiresAt: now + sessionTtl,
      lastStepUpAt: null,
      stepUpWindowExpiresAt: null,
      revocationState: 'active',
    };

    this._productSessionStore.put(session);
    this.heartbeatChain.record(
      "product_session_issued",
      JSON.stringify({
        productSessionId: session.sessionId,
        accountId,
        somaIdentityBinding: session.somaIdentityBinding,
        authOrigin: session.authOrigin,
        tier: session.currentAuthorityTier,
        deviceTrust: deviceBinding?.deviceTrustLevel ?? null,
        loginChallengeId: verification.challengeId,
        expiresAt: session.expiresAt,
      }),
    );

    return { ok: true, session };
  }

  // ─── Adapter-to-Direct Migration Ceremony ──────────────────────────────

  /**
   * Migrate an adapter-bridge session to soma-direct by binding the
   * account to a Soma identity and issuing a new ProductSession.
   *
   * This is the canonical adapter sunset path (Decision 7). The flow:
   *   1. Verify the adapter session is valid and active
   *   2. Verify the LoginVerification signature
   *   3. Create or validate the ProductAccountBinding
   *   4. Issue a NEW soma-direct ProductSession with evidence-derived tier/device
   *   5. Revoke the old adapter session
   *   6. Record the transition in the heartbeat chain
   *
   * The old adapter session's authOrigin is never mutated. Provenance
   * is preserved: old session = adapter-bridge (revoked), new session =
   * soma-direct (active).
   *
   * Records `adapter_migration_completed` heartbeat on success,
   * `adapter_migration_denied` on failure.
   */
  migrateAdapterToSomaDirect(
    input: {
      /** The active adapter-bridge ProductSession to migrate from. */
      adapterSession: ProductSession;
      /** Signed LoginVerification proving the user's Soma identity. */
      verification: LoginVerification;
      /** Product account binding store — caller-owned, durable. */
      bindingStore: ProductAccountBindingStore;
    },
    opts?: {
      sessionTtlMs?: number;
      sessionId?: string;
      now?: number;
    },
  ): AdapterMigrationResult {
    this.ensureAlive();
    const now = opts?.now ?? Date.now();
    const { adapterSession, verification, bindingStore } = input;
    const accountId = adapterSession.accountId;

    // ── Validate adapter session is active and adapter-bridged ────────
    if (adapterSession.authOrigin !== 'adapter-bridge') {
      return this.denyMigration(accountId, 'session is not adapter-bridge');
    }
    if (adapterSession.revocationState !== 'active') {
      return this.denyMigration(accountId, 'adapter session is revoked');
    }
    if (now >= adapterSession.expiresAt) {
      return this.denyMigration(accountId, 'adapter session has expired');
    }

    // ── Verify the LoginVerification signature ───────────────────────
    const sigCheck = verifyLoginVerificationSignature(verification, {
      trustedHeartPublicKeys: [this.genome.publicKey],
      maxAgeMs: 300_000,
      now,
      provider: this.provider,
    });
    if (!sigCheck.valid) {
      return this.denyMigration(
        accountId,
        `login verification rejected: ${sigCheck.reason}`,
      );
    }

    // ── Binding authorization ────────────────────────────────────────
    const existingBinding = bindingStore.getActive(accountId);
    if (existingBinding) {
      // Account already bound — verify it's bound to the same identity
      if (existingBinding.somaIdentityDid !== verification.subjectDid) {
        return this.denyMigration(
          accountId,
          `account already bound to ${existingBinding.somaIdentityDid}, cannot rebind to ${verification.subjectDid}`,
        );
      }
      // Same identity — binding already correct, proceed to session issuance
    } else {
      // No binding yet — create one
      bindingStore.bind({
        accountId,
        somaIdentityDid: verification.subjectDid,
        bindingType: 'primary',
      }, now);
    }

    // ── Derive device binding from ceremony evidence ─────────────────
    const deviceBinding = deriveDeviceBindingFromEvidence(verification.evidence);

    // ── Issue new soma-direct ProductSession ─────────────────────────
    const sessionTtl = opts?.sessionTtlMs ?? DEFAULT_PRODUCT_SESSION_TTL_MS;
    const sessionId = opts?.sessionId ?? crypto.randomUUID();

    const newSession: ProductSession = {
      sessionId,
      accountId,
      somaIdentityBinding: verification.subjectDid,
      baseAuthorityTier: verification.tierAchieved,
      currentAuthorityTier: verification.tierAchieved,
      authOrigin: 'soma-direct',
      deviceBinding,
      issuedAt: now,
      expiresAt: now + sessionTtl,
      lastStepUpAt: null,
      stepUpWindowExpiresAt: null,
      revocationState: 'active',
    };

    this._productSessionStore.put(newSession);

    // ── Revoke the old adapter session ───────────────────────────────
    this._productSessionStore.revoke(adapterSession.sessionId);

    // ── Heartbeat trail ─────────────────────────────────────────────
    this.heartbeatChain.record(
      "adapter_migration_completed",
      JSON.stringify({
        accountId,
        oldSessionId: adapterSession.sessionId,
        oldAuthOrigin: adapterSession.authOrigin,
        newSessionId: newSession.sessionId,
        newAuthOrigin: newSession.authOrigin,
        somaIdentityBinding: newSession.somaIdentityBinding,
        tier: newSession.currentAuthorityTier,
        deviceTrust: deviceBinding?.deviceTrustLevel ?? null,
        loginChallengeId: verification.challengeId,
        migratedAt: now,
      }),
    );

    return {
      ok: true,
      newSession,
      revokedSessionId: adapterSession.sessionId,
      binding: bindingStore.getActive(accountId)!,
    };
  }

  private denyMigration(accountId: string, reason: string): AdapterMigrationFailure {
    this.heartbeatChain.record(
      "adapter_migration_denied",
      JSON.stringify({ accountId, reason }),
    );
    return { ok: false, reason };
  }

  // ─── Product Session Step-Up (Decision 8) ───────────────────────────────

  /**
   * Elevate a ProductSession's authority tier through a verified step-up
   * ceremony.
   *
   * This is the runtime convenience method that wraps the pure
   * `elevateProductSession` factory with heartbeat recording. The caller
   * is responsible for verifying the step-up attestation (via
   * `StepUpService.submitAttestation`) BEFORE calling this.
   *
   * Does NOT require `humanSessionConfig` — step-up operates on
   * ProductSessions regardless of their auth origin.
   *
   * Records `product_session_elevated` on success,
   * `product_session_elevation_denied` on failure.
   *
   * @param session       The ProductSession to elevate.
   * @param tierAchieved  Numeric tier from StepUpAttestation (0-3).
   * @param opts          Optional device binding, window duration, timestamp.
   */
  elevateProductSession(
    session: ProductSession,
    tierAchieved: number,
    opts?: {
      deviceBinding?: DeviceBinding | null;
      windowMs?: number;
      now?: number;
    },
  ): StepUpElevationResult {
    this.ensureAlive();

    const result = elevateProductSession({
      session,
      tierAchieved,
      deviceBinding: opts?.deviceBinding,
      windowMs: opts?.windowMs,
      now: opts?.now,
    });

    if (result.ok) {
      this._productSessionStore.update(result.session);
      this.heartbeatChain.record(
        "product_session_elevated",
        JSON.stringify({
          productSessionId: result.session.sessionId,
          fromTier: session.currentAuthorityTier,
          toTier: result.session.currentAuthorityTier,
          authOrigin: result.session.authOrigin,
          windowExpiresAt: result.session.stepUpWindowExpiresAt,
        }),
      );
    } else {
      this.heartbeatChain.record(
        "product_session_elevation_denied",
        JSON.stringify({
          productSessionId: session.sessionId,
          tierAchieved,
          currentTier: session.currentAuthorityTier,
          reason: result.reason,
        }),
      );
    }

    return result;
  }

  // ─── Product Session Tokens (opaque transport references) ──────────────

  /** Cached token key — derived once from the signing key via HKDF. */
  private _productTokenKey: Uint8Array | null = null;

  /** Get or derive the product session token HMAC key. */
  private getProductTokenKey(): Uint8Array {
    if (!this._productTokenKey) {
      this._productTokenKey = deriveProductTokenKey(
        this.signingKeyPair.secretKey,
        this.provider,
      );
    }
    return this._productTokenKey;
  }

  /**
   * Mint an opaque transport token for a ProductSession.
   *
   * The token is a transport carrier — not the session truth. It embeds
   * only sessionId, accountId, mint time, and session expiry, bound by
   * an HMAC derived from this heart's signing key.
   *
   * Records a `product_session_token_minted` heartbeat.
   *
   * @param session  The ProductSession to mint a token for.
   * @param opts     Optional: override mint timestamp.
   */
  mintProductSessionToken(
    session: ProductSession,
    opts?: { now?: number },
  ): string {
    this.ensureAlive();

    const token = mintProductSessionToken(session, this.getProductTokenKey(), {
      now: opts?.now,
      provider: this.provider,
    });

    this.heartbeatChain.record(
      "product_session_token_minted",
      JSON.stringify({
        productSessionId: session.sessionId,
        accountId: session.accountId,
        authOrigin: session.authOrigin,
        expiresAt: session.expiresAt,
      }),
    );

    return token;
  }

  /**
   * Validate an opaque product session token (structure + MAC + expiry).
   *
   * This is the first gate — checks the token itself without needing
   * the session store. On success, returns the embedded claims so the
   * caller can look up the ProductSession by `claims.sid`.
   *
   * Does NOT record a heartbeat on success (read path). Records
   * `product_session_token_rejected` on failure.
   *
   * @param token  The opaque token string.
   * @param opts   Optional: override current time.
   */
  validateProductSessionToken(
    token: string,
    opts?: { now?: number },
  ): ValidateTokenResult {
    this.ensureAlive();

    const result = validateProductSessionToken(token, this.getProductTokenKey(), {
      now: opts?.now,
      provider: this.provider,
    });

    if (!result.ok) {
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({ reason: result.reason }),
      );
    }

    return result;
  }

  /**
   * Validate a token AND match it against a live ProductSession in one
   * call. Convenience for the common server-side flow:
   *   receive token → validate → match to session → proceed or reject.
   *
   * Records `product_session_token_rejected` if either gate fails.
   *
   * @param token    The opaque token string.
   * @param session  The live ProductSession from the session store.
   * @param opts     Optional: override current time.
   */
  validateAndMatchProductSessionToken(
    token: string,
    session: ProductSession,
    opts?: { now?: number },
  ): MatchTokenResult {
    this.ensureAlive();
    const now = opts?.now ?? Date.now();

    // Gate 1: structure + MAC + expiry
    const vr = validateProductSessionToken(token, this.getProductTokenKey(), {
      now,
      provider: this.provider,
    });

    if (!vr.ok) {
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({ reason: vr.reason }),
      );
      return { ok: false, reason: vr.reason };
    }

    // Gate 2: cross-check claims against live session
    const mr = matchTokenToSession(vr.claims, session, { now });

    if (!mr.ok) {
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({
          productSessionId: session.sessionId,
          reason: mr.reason,
        }),
      );
    }

    return mr;
  }

  // ─── Product Session Store ─────────────────────────────────────────────

  /** The product session store backing this heart. */
  get productSessionStore(): ProductSessionStore {
    return this._productSessionStore;
  }

  /**
   * Resolve an opaque product session token to a live ProductSession
   * in one call: validate MAC/expiry → look up in store → match.
   *
   * This is the primary server-side entry point for token-bearing
   * requests. Returns the validated, active ProductSession on success
   * or a rejection reason on failure.
   *
   * Applies step-up decay automatically before returning — the caller
   * always gets the current-authority-tier truth.
   *
   * Records `product_session_token_rejected` heartbeat on any failure.
   *
   * @param token  The opaque token string from the client.
   * @param opts   Optional: override current time.
   */
  resolveProductSessionToken(
    token: string,
    opts?: { now?: number },
  ): MatchTokenResult {
    this.ensureAlive();
    const now = opts?.now ?? Date.now();

    // Gate 1: structure + MAC + expiry
    const vr = validateProductSessionToken(token, this.getProductTokenKey(), {
      now,
      provider: this.provider,
    });

    if (!vr.ok) {
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({ reason: vr.reason }),
      );
      return { ok: false, reason: vr.reason };
    }

    // Gate 2: store lookup
    const stored = this._productSessionStore.get(vr.claims.sid);
    if (!stored) {
      const reason = `session not found: ${vr.claims.sid}`;
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({ reason }),
      );
      return { ok: false, reason };
    }

    // Apply step-up decay before matching — authority may have expired
    const decayed = decayProductSession(stored, now);
    if (decayed !== stored) {
      // Decay happened — update store with decayed state
      this._productSessionStore.update(decayed);
    }

    // Gate 3: match claims against live session
    const mr = matchTokenToSession(vr.claims, decayed, { now });

    if (!mr.ok) {
      this.heartbeatChain.record(
        "product_session_token_rejected",
        JSON.stringify({
          productSessionId: decayed.sessionId,
          reason: mr.reason,
        }),
      );
    }

    return mr;
  }

  /** Throw if human session support was not configured. */
  private ensureHumanSessionSupport(): void {
    if (!this.humanSessionRegistry) {
      throw new Error(
        "Heart was not configured for human sessions — provide humanSessionConfig in HeartConfig",
      );
    }
  }

  // --- The ONLY Way to Generate ---

  async *generate(
    input: GenerationInput,
    sessionId?: string
  ): AsyncGenerator<HeartbeatToken> {
    this.ensureAlive();
    this.ensureLineageValid();

    const session = sessionId ? this.activeSession(sessionId) : undefined;
    const chain = session?.heartbeatChain ?? this.heartbeatChain;

    // Step 1: Record query received
    const queryData = JSON.stringify(
      input.messages.map((m) => ({ role: m.role, contentHash: sha256(m.content, this.provider) }))
    );
    const queryBeat = chain.record("query_received", queryData);
    yield { type: "heartbeat", heartbeat: queryBeat, timestamp: Date.now() };

    // Step 2: Derive and apply seed (only if we have a session key)
    let seed: HeartSeed | undefined;
    if (session?.sessionKey) {
      const queryHash = sha256(JSON.stringify(input.messages), this.provider);
      seed = deriveSeed(
        { sessionKey: session.sessionKey, interactionCounter: session.interactionCounter },
        queryHash,
        this.provider
      );
      session.interactionCounter++;

      const seedBeat = chain.record(
        "seed_generated",
        JSON.stringify({
          nonce: seed.nonce.slice(0, 16),
          behavioralParams: seed.behavioralParams,
        })
      );
      yield { type: "heartbeat", heartbeat: seedBeat, timestamp: Date.now() };
    }

    // Step 3: Prepare messages with seed applied
    const messages = [...input.messages];
    if (seed) {
      if (messages.length > 0 && messages[0].role === "system") {
        messages[0] = {
          ...messages[0],
          content: applySeed(messages[0].content, seed),
        };
      } else {
        messages.unshift({
          role: "system",
          content: applySeed("You are a helpful assistant.", seed),
        });
      }
    }

    // Step 4: Call the model through the vault
    const apiKey = this.vault.retrieve("model_api_key");
    const client = new OpenAI({ baseURL: this.modelBaseUrl, apiKey });

    const callStartBeat = chain.record(
      "model_call_start",
      JSON.stringify({ model: this.modelId, messageCount: messages.length })
    );
    yield { type: "heartbeat", heartbeat: callStartBeat, timestamp: Date.now() };

    // Step 5: Stream tokens with per-token HMAC authentication
    const stream = await client.chat.completions.create({
      model: this.modelId,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      stream: true,
      temperature: input.temperature,
      max_tokens: input.maxTokens,
    });

    // Derive HMAC key from session key (if available) for token authentication
    const hmacKey = session?.sessionKey
      ? deriveHmacKey(session.sessionKey, this.provider)
      : undefined;
    const interactionCounter = seed?.interactionCounter ?? 0;

    let tokenCount = 0;
    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        // Capture timestamp BEFORE HMAC computation to avoid distorting
        // inter-token intervals used by the temporal fingerprint.
        const ts = Date.now();
        const seq = tokenCount;
        tokenCount++;

        if (hmacKey) {
          const hmac = computeTokenHmac(hmacKey, content, seq, interactionCounter, this.provider);
          yield { type: "token", token: content, timestamp: ts, hmac, sequence: seq };
        } else {
          yield { type: "token", token: content, timestamp: ts };
        }
      }
    }

    // Step 6: Record model call end
    const callEndBeat = chain.record(
      "model_call_end",
      JSON.stringify({ model: this.modelId, tokenCount })
    );
    yield { type: "heartbeat", heartbeat: callEndBeat, timestamp: Date.now() };

    // Step 7: Record response sent
    const responseBeat = chain.record("response_sent", JSON.stringify({ tokenCount }));
    yield { type: "heartbeat", heartbeat: responseBeat, timestamp: Date.now() };
  }

  // --- The ONLY Way to Call Tools ---

  async callTool(
    name: string,
    args: Record<string, unknown>,
    toolExecutor: ToolExecutor | ((credential: string, args: Record<string, unknown>) => Promise<unknown>),
    sessionId?: string
  ): Promise<HeartbeatResult> {
    this.ensureAlive();
    this.ensureLineageValid();

    // Lineage-based capability enforcement
    if (!this.can(`tool:${name}`)) {
      throw new Error(
        `Heart lacks capability "tool:${name}" — not granted by lineage`,
      );
    }

    const chain = sessionId
      ? (this.activeSession(sessionId)?.heartbeatChain ?? this.heartbeatChain)
      : this.heartbeatChain;
    const heartbeats: Heartbeat[] = [];

    // Record tool call
    const callBeat = chain.record(
      "tool_call",
      JSON.stringify({ name, argsHash: sha256(JSON.stringify(args), this.provider) })
    );
    heartbeats.push(callBeat);

    // Get tool credential from vault
    const credentialKey = `tool:${name}`;
    const credential = this.vault.has(credentialKey)
      ? this.vault.retrieve(credentialKey)
      : "";

    // Progress emitter — tool executors can call this to record sub-beats
    // between input and output, giving observers visibility into the work.
    const emit: ToolProgressEmitter = (stage: string, detail?: string) => {
      const beat = chain.record(
        "tool_progress",
        JSON.stringify({
          tool: name,
          stage,
          detailHash: detail ? sha256(detail, this.provider) : undefined,
        }),
      );
      heartbeats.push(beat);
    };

    // Execute tool — pass emitter so the executor can log sub-beats
    const result = await (toolExecutor as ToolExecutor)(credential, args, emit);

    // Record tool result
    const resultBeat = chain.record(
      "tool_result",
      JSON.stringify({ name, resultHash: sha256(JSON.stringify(result), this.provider) })
    );
    heartbeats.push(resultBeat);

    // Create birth certificate for tool output
    const birthCert = createBirthCertificate(
      JSON.stringify(result),
      { type: "api", identifier: name, heartVerified: true },
      this.did,
      sessionId ?? "local",
      this.signingKeyPair,
      [],
      this.provider
    );

    const certBeat = chain.record("birth_certificate", birthCert.dataHash);
    heartbeats.push(certBeat);

    return { result, heartbeats, birthCertificate: birthCert };
  }

  // --- The ONLY Way to Fetch Data ---

  async fetchData(
    sourceName: string,
    query: string,
    fetcher?: (url: string, headers: Record<string, string>, query: string) => Promise<string>,
    sessionId?: string
  ): Promise<HeartbeatData> {
    this.ensureAlive();
    this.ensureLineageValid();

    // Lineage-based capability enforcement
    if (!this.can(`data:${sourceName}`)) {
      throw new Error(
        `Heart lacks capability "data:${sourceName}" — not granted by lineage`,
      );
    }

    const chain = sessionId
      ? (this.activeSession(sessionId)?.heartbeatChain ?? this.heartbeatChain)
      : this.heartbeatChain;
    const heartbeats: Heartbeat[] = [];

    const source = this.dataSources.get(sourceName);
    if (!source) throw new Error(`Unknown data source: ${sourceName}`);

    // Record data fetch
    const fetchBeat = chain.record(
      "data_fetch",
      JSON.stringify({ source: sourceName, queryHash: sha256(query, this.provider) })
    );
    heartbeats.push(fetchBeat);

    // Reconstruct headers from vault
    const headers: Record<string, string> = {};
    if (source.headers) {
      for (const [key, value] of Object.entries(source.headers)) {
        if (isAuthHeader(key)) {
          headers[key] = this.vault.retrieve(`datasource:${sourceName}:${key}`);
        } else {
          headers[key] = value;
        }
      }
    }

    // Fetch data
    const content = fetcher
      ? await fetcher(source.url, headers, query)
      : await defaultFetcher(source.url, headers, query);

    // Record data received
    const receiveBeat = chain.record(
      "data_received",
      JSON.stringify({ source: sourceName, contentHash: sha256(content, this.provider) })
    );
    heartbeats.push(receiveBeat);

    // Create birth certificate
    const birthCert = createBirthCertificate(
      content,
      { type: "api", identifier: source.url, heartVerified: false },
      this.did,
      sessionId ?? "local",
      this.signingKeyPair,
      [],
      this.provider
    );

    const certBeat = chain.record("birth_certificate", birthCert.dataHash);
    heartbeats.push(certBeat);

    return { content, heartbeats, birthCertificate: birthCert };
  }

  // --- Lifecycle ---

  /** Stop the heart. All credentials are wiped. The agent can no longer compute. */
  destroy(): void {
    this.vault.destroy();
    this.sessions.clear();
    this.alive = false;
  }

  private ensureAlive(): void {
    if (!this.alive) {
      throw new Error("Heart has been destroyed — agent cannot compute");
    }
  }

  /**
   * Check that this heart's authority is still valid:
   *   1. No certificate in the lineage chain has been revoked.
   *   2. The heart itself has not been revoked (targetKind: 'heart').
   *
   * Called on every hot-path operation (generate, callTool, fetchData,
   * fork, delegate) so revocations are enforced promptly.
   */
  private ensureLineageValid(): void {
    // Heart-level revocation check — a parent can revoke a child heart
    // directly via targetKind: 'heart', targetId: childDid.
    if (this.revocations.isRevoked(this.did)) {
      this.alive = false;
      throw new Error(
        `Heart ${this.did} has been revoked — no longer authorized`,
      );
    }

    if (!this._lineage) return;
    for (const cert of this._lineage.chain) {
      if (this.revocations.isRevoked(cert.id)) {
        this.alive = false;
        throw new Error(
          `Lineage certificate ${cert.id} has been revoked — heart is no longer authorized`,
        );
      }
    }
  }
}

// --- Helpers ---

/** Check if a header key looks like an auth/credential header. */
function isAuthHeader(key: string): boolean {
  const lower = key.toLowerCase();
  return lower.includes("auth") || lower.includes("key") || lower.includes("token");
}

/** Default data fetcher — simple HTTP GET with query as URL parameter. */
async function defaultFetcher(
  url: string,
  headers: Record<string, string>,
  query: string
): Promise<string> {
  const fetchUrl = new URL(url);
  fetchUrl.searchParams.set("q", query);
  const response = await fetch(fetchUrl.toString(), { headers });
  if (!response.ok) {
    throw new Error(`Data fetch failed: ${response.status} ${response.statusText}`);
  }
  return response.text();
}

// --- Factory ---

/** Create a heart runtime — the one-liner that gives an agent its heartbeat. */
export function createSomaHeart(config: HeartConfig): HeartRuntime {
  return new HeartRuntime(config);
}

/**
 * Rehydrate a heart from an encrypted blob + password.
 * The vault's credentials are already encrypted with a key derived from the
 * signing secret key, so they are restored directly without re-entry.
 *
 * Sessions are not restored — they were ephemeral by design.
 */
export function loadSomaHeart(
  blob: string,
  password: string,
  opts?: { cryptoProvider?: CryptoProvider },
): HeartRuntime {
  const provider = opts?.cryptoProvider ?? getCryptoProvider();
  const state = loadHeartState(blob, password, { provider });
  const keyPair = signKeyPairFromJson(state.signingKey, provider);

  // Reconstruct the lineage if present
  const lineage: HeartLineage | undefined =
    state.lineageChain && state.lineageRootDid
      ? {
          did: state.genome.did,
          rootDid: state.lineageRootDid,
          chain: state.lineageChain,
        }
      : undefined;

  return new HeartRuntime({
    genome: state.genome,
    signingKeyPair: keyPair,
    modelApiKey: "", // unused — restoreCredentials populates the vault
    modelBaseUrl: state.modelBaseUrl,
    modelId: state.modelId,
    dataSources: state.dataSources,
    lineage,
    revocations: state.revocations,
    restoreCredentials: state.credentials,
    restoreHeartbeats: state.heartbeats,
    cryptoProvider: provider,
  });
}
