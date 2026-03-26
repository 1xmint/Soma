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
import { deriveSeed, applySeed, deriveHmacKey, computeTokenHmac, type HeartSeed } from "./seed.js";
import {
  createBirthCertificate,
  type BirthCertificate,
} from "./birth-certificate.js";

// --- Types ---

export interface DataSourceConfig {
  name: string;
  url: string;
  headers?: Record<string, string>;
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

  /** Crypto provider — swap algorithms without changing the protocol. */
  cryptoProvider?: CryptoProvider;
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
  private readonly provider: CryptoProvider;
  private alive: boolean = true;

  constructor(config: HeartConfig) {
    this.provider = config.cryptoProvider ?? getCryptoProvider();
    this.genome = config.genome;
    this.signingKeyPair = config.signingKeyPair;
    this.modelId = config.modelId;
    this.modelBaseUrl = config.modelBaseUrl;
    this.heartbeatChain = new HeartbeatChain(this.provider);

    // Store all credentials in the vault — encrypted at rest
    this.vault = new CredentialVault(config.signingKeyPair.secretKey, this.provider);
    this.vault.store("model_api_key", config.modelApiKey);

    // Store tool credentials
    if (config.toolCredentials) {
      for (const [name, value] of Object.entries(config.toolCredentials)) {
        this.vault.store(`tool:${name}`, value);
      }
    }

    // Store data source configs
    this.dataSources = new Map();
    if (config.dataSources) {
      for (const ds of config.dataSources) {
        this.dataSources.set(ds.name, ds);
        if (ds.headers) {
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

  // --- Session Management ---

  /**
   * Create a session with a remote party.
   * Generates an ephemeral key pair for the handshake.
   */
  createSession(remoteDid: string, remoteGenome: GenomeCommitment): HeartSession {
    this.ensureAlive();

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
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    return createHandshakePayload(this.genome, session.ephemeralKeyPair, this.provider);
  }

  /**
   * Complete a session handshake with the remote party's handshake payload.
   * Establishes the encrypted channel and extracts the session key for seeding.
   */
  completeHandshake(sessionId: string, remoteHandshake: HandshakePayload): void {
    this.ensureAlive();
    const session = this.sessions.get(sessionId);
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

  /** Get a session by ID. */
  getSession(sessionId: string): HeartSession | undefined {
    return this.sessions.get(sessionId);
  }

  // --- The ONLY Way to Generate ---

  async *generate(
    input: GenerationInput,
    sessionId?: string
  ): AsyncGenerator<HeartbeatToken> {
    this.ensureAlive();

    const session = sessionId ? this.sessions.get(sessionId) : undefined;
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
          modificationId: seed.modificationId,
          nonce: seed.nonce.slice(0, 16),
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
        const seq = tokenCount;
        tokenCount++;

        if (hmacKey) {
          const hmac = computeTokenHmac(hmacKey, content, seq, interactionCounter, this.provider);
          yield { type: "token", token: content, timestamp: Date.now(), hmac, sequence: seq };
        } else {
          yield { type: "token", token: content, timestamp: Date.now() };
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
    toolExecutor: (credential: string, args: Record<string, unknown>) => Promise<unknown>,
    sessionId?: string
  ): Promise<HeartbeatResult> {
    this.ensureAlive();

    const chain = sessionId
      ? (this.sessions.get(sessionId)?.heartbeatChain ?? this.heartbeatChain)
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

    // Execute tool
    const result = await toolExecutor(credential, args);

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

    const chain = sessionId
      ? (this.sessions.get(sessionId)?.heartbeatChain ?? this.heartbeatChain)
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
