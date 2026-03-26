/**
 * Per-connection session lifecycle for Soma MCP middleware.
 *
 * Manages the state machine for a single MCP connection:
 * PENDING → HANDSHAKE → ACTIVE (or DEGRADED/REJECTED)
 *
 * Phase 2: When a heart is present, observations route through the
 * behavioral landscape for category-aware matching and drift detection.
 * The transport handles communication. The heart handles computation.
 */

import { getCryptoProvider } from "../core/crypto-provider.js";
import type { BoxKeyPair } from "../core/crypto-provider.js";
import {
  establishChannel,
  generateEphemeralKeyPair,
  createHandshakePayload,
  type Channel,
} from "../core/channel.js";
import type { GenomeCommitment } from "../core/genome.js";
import {
  createProfile,
  updateProfile,
  match,
  matchEnhanced,
  type PhenotypicProfile,
  type EnhancedVerdict,
} from "../sensorium/matcher.js";
import {
  createLandscape,
  updateLandscape,
  type BehavioralLandscape,
  type LandscapeMatchResult,
} from "../sensorium/landscape.js";
import type { PhenotypicSignals } from "../experiment/signals.js";
import { SignalTap } from "./signal-tap.js";
import { ProfileStore } from "./profile-store.js";
import type {
  SomaConfig,
  SomaVerdict,
  SomaSessionState,
  SessionPhase,
  SomaMetadata,
} from "./types.js";
import type { EncryptedMessage } from "../core/channel.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { HeartRuntime } from "../heart/runtime.js";

/** A JSON-RPC message wrapped in Soma encryption. */
export interface SomaEncryptedEnvelope {
  _somaEncrypted: true;
  payload: EncryptedMessage;
}

export class SomaSession {
  readonly sessionId: string;
  private phase: SessionPhase = "PENDING";
  private remoteDid: string | null = null;
  private remoteGenomeCommitment: GenomeCommitment | null = null;
  private channel: Channel | null = null;
  private profile: PhenotypicProfile | null = null;
  private landscape: BehavioralLandscape | null = null;
  private recentLandscapeResults: LandscapeMatchResult[] = [];
  private lastCategory: string | null = null;
  private currentVerdict: SomaVerdict | null = null;
  private readonly signalTap = new SignalTap();
  private readonly ephemeralKeyPair: BoxKeyPair;
  private readonly heart: HeartRuntime | null;
  private pendingRequestTimes: Map<string | number, number> = new Map();

  constructor(
    private readonly config: SomaConfig,
    private readonly profileStore: ProfileStore
  ) {
    const provider = getCryptoProvider();
    const idBytes = provider.random.randomBytes(16);
    this.sessionId = Array.from(idBytes).map(b => b.toString(16).padStart(2, "0")).join("");
    this.ephemeralKeyPair = generateEphemeralKeyPair();
    this.heart = config.heart ?? null;
  }

  /** Get this server's Soma metadata for the initialize response. */
  getLocalMetadata(): SomaMetadata {
    const handshake = createHandshakePayload(
      this.config.genome,
      this.ephemeralKeyPair
    );
    return {
      genomeCommitment: this.config.genome,
      ephemeralPublicKey: handshake.ephemeralPublicKey,
    };
  }

  /** Process an incoming message from the client. */
  async onIncomingMessage(message: JSONRPCMessage): Promise<void> {
    // Track request timing for latency measurement
    if ("method" in message && "id" in message && message.id !== undefined) {
      this.pendingRequestTimes.set(message.id, performance.now());
    }

    // Handle initialize — extract genome commitment if present
    if ("method" in message && message.method === "initialize") {
      this.phase = "HANDSHAKE";
      const params = (message as Record<string, unknown>).params as Record<string, unknown> | undefined;
      const clientInfo = params?.clientInfo as Record<string, unknown> | undefined;
      const somaData = clientInfo?._soma as SomaMetadata | undefined;

      if (somaData?.genomeCommitment && somaData?.ephemeralPublicKey) {
        try {
          await this.completeHandshake(somaData);
          this.phase = "ACTIVE";
        } catch {
          this.phase = "REJECTED";
        }
      } else {
        // Client didn't present Soma metadata — degraded mode
        this.phase = "DEGRADED";
      }
    }
  }

  /** Process an outgoing message (response to client). Extract signals. */
  async onOutgoingMessage(message: JSONRPCMessage): Promise<void> {
    if (this.phase !== "ACTIVE" && this.phase !== "DEGRADED") return;

    // Compute timing from the matching request
    let timing = { requestTime: performance.now() - 100, responseTime: performance.now() };
    if ("id" in message && message.id !== undefined) {
      const requestTime = this.pendingRequestTimes.get(message.id);
      if (requestTime !== undefined) {
        timing = { requestTime, responseTime: performance.now() };
        this.pendingRequestTimes.delete(message.id);
      }
    }

    const signals = this.signalTap.tap(message, timing);
    if (!signals) return;

    // Infer category for landscape routing
    const category = this.inferCategory(message);

    // Route through landscape if available, else flat profile
    if (this.landscape) {
      updateLandscape(this.landscape, signals, category, this.lastCategory ?? undefined);
      this.lastCategory = category;

      const verdict = matchEnhanced(
        this.landscape,
        signals,
        category,
        this.recentLandscapeResults,
        this.config.minObservations ?? 5,
        {
          heartSeedVerified: this.heart !== null,
          birthCertificateChain: this.heart !== null,
        }
      );

      // Track recent results for drift detection
      this.recentLandscapeResults.push({
        matchRatio: verdict.matchRatio,
        featureDeviations: verdict.featureDeviations,
        usedCategoryProfile: verdict.usedCategoryProfile,
        landscapeDepth: verdict.landscapeDepth,
        maturity: verdict.profileMaturity,
        totalObservations: verdict.observationCount,
      });
      if (this.recentLandscapeResults.length > 20) {
        this.recentLandscapeResults.shift();
      }

      this.emitVerdict(verdict);
    } else if (this.profile) {
      // Fallback: flat profile matching (Phase 1 behavior)
      updateProfile(this.profile, signals);
      const verdict = match(
        this.profile,
        signals,
        this.config.minObservations ?? 5
      );
      this.emitVerdict(verdict);
    }

    // Persist periodically
    const obsCount = this.landscape?.totalObservations
      ?? Object.values(this.profile?.features ?? {})[0]?.count
      ?? 0;
    if (obsCount > 0 && obsCount % 10 === 0 && this.profile) {
      await this.profileStore.save(this.profile);
    }
  }

  /** Establish the encrypted channel from the client's Soma metadata. */
  private async completeHandshake(remote: SomaMetadata): Promise<void> {
    const localHandshake = createHandshakePayload(
      this.config.genome,
      this.ephemeralKeyPair
    );

    this.channel = establishChannel(
      { handshake: localHandshake, ephemeralKeyPair: this.ephemeralKeyPair },
      {
        did: remote.genomeCommitment.did,
        genomeCommitment: remote.genomeCommitment,
        ephemeralPublicKey: remote.ephemeralPublicKey,
      }
    );

    this.remoteDid = remote.genomeCommitment.did;
    this.remoteGenomeCommitment = remote.genomeCommitment;

    // Load or create phenotypic profile for this genome
    const hash = remote.genomeCommitment.hash;
    this.profile = await this.profileStore.load(hash);

    // Create behavioral landscape for enhanced matching
    this.landscape = createLandscape(hash);
  }

  /** Infer a probe category from the MCP message. */
  private inferCategory(message: JSONRPCMessage): string {
    if ("error" in message) return "failure";
    if ("method" in message) {
      const method = message.method;
      if (method === "tools/call") return "normal";
      if (method === "prompts/get") return "normal";
      if (method === "resources/read") return "normal";
    }
    return "normal";
  }

  /** Emit a verdict from either flat or enhanced matching. */
  private emitVerdict(verdict: { status: string; confidence: number; observationCount: number }): void {
    const newVerdict: SomaVerdict = {
      status: verdict.status as SomaVerdict["status"],
      confidence: verdict.confidence,
      observationCount: verdict.observationCount,
      remoteGenomeHash: this.remoteGenomeCommitment
        ? this.profile?.genomeHash ?? null
        : null,
      remoteDid: this.remoteDid,
      timestamp: Date.now(),
    };
    this.currentVerdict = newVerdict;
    this.config.onVerdict?.(this.sessionId, newVerdict);
  }

  /** Get the current state snapshot. */
  getState(): SomaSessionState {
    return {
      sessionId: this.sessionId,
      phase: this.phase,
      remoteDid: this.remoteDid,
      remoteGenomeCommitment: this.remoteGenomeCommitment,
      channel: this.channel,
      profile: this.profile,
      observations: [],
      currentVerdict: this.currentVerdict,
      createdAt: 0,
    };
  }

  getVerdict(): SomaVerdict | null {
    return this.currentVerdict;
  }

  getPhase(): SessionPhase {
    return this.phase;
  }

  /** Get the behavioral landscape (null if no handshake yet). */
  getLandscape(): BehavioralLandscape | null {
    return this.landscape;
  }

  // --- Encryption ---

  /** Whether this session has an active encrypted channel. */
  hasEncryptedChannel(): boolean {
    return this.channel !== null && this.phase === "ACTIVE";
  }

  encryptMessage(message: JSONRPCMessage): SomaEncryptedEnvelope {
    if (!this.channel) throw new Error("No encrypted channel established");
    const plaintext = JSON.stringify(message);
    const encrypted = this.channel.encrypt(plaintext);
    return { _somaEncrypted: true, payload: encrypted };
  }

  decryptMessage(envelope: SomaEncryptedEnvelope): JSONRPCMessage {
    if (!this.channel) throw new Error("No encrypted channel established");
    const plaintext = this.channel.decrypt(envelope.payload);
    return JSON.parse(plaintext) as JSONRPCMessage;
  }

  static isEncryptedEnvelope(message: unknown): message is SomaEncryptedEnvelope {
    return (
      typeof message === "object" &&
      message !== null &&
      "_somaEncrypted" in message &&
      (message as Record<string, unknown>)._somaEncrypted === true
    );
  }

  /** Flush profile to disk on session close. */
  async close(): Promise<void> {
    if (this.profile) {
      await this.profileStore.save(this.profile);
    }
  }
}
