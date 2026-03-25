/**
 * Per-connection session lifecycle for Soma MCP middleware.
 *
 * Manages the state machine for a single MCP connection:
 * PENDING → HANDSHAKE → ACTIVE (or DEGRADED/REJECTED)
 *
 * Like a developing immune system: starts naive (PENDING),
 * calibrates during the handshake, then actively monitors.
 */

import { randomBytes } from "node:crypto";
import {
  establishChannel,
  generateEphemeralKeyPair,
  createHandshakePayload,
  type Channel,
} from "../core/channel.js";
import type { GenomeCommitment } from "../core/genome.js";
import {
  updateProfile,
  match,
  type PhenotypicProfile,
} from "../sensorium/matcher.js";
import type { PhenotypicSignals } from "../experiment/signals.js";
import { SignalTap } from "./signal-tap.js";
import { ProfileStore } from "./profile-store.js";
import type {
  SomaConfig,
  SomaVerdict,
  SomaSessionState,
  SessionPhase,
  SomaMetadata,
  SOMA_METADATA_KEY,
} from "./types.js";
import type { EncryptedMessage } from "../core/channel.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type nacl from "tweetnacl";

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
  private currentVerdict: SomaVerdict | null = null;
  private readonly signalTap = new SignalTap();
  private readonly ephemeralKeyPair: nacl.BoxKeyPair;
  private pendingRequestTimes: Map<string | number, number> = new Map();

  constructor(
    private readonly config: SomaConfig,
    private readonly profileStore: ProfileStore
  ) {
    this.sessionId = randomBytes(16).toString("hex");
    this.ephemeralKeyPair = generateEphemeralKeyPair();
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

    // Update profile if we have a genome to verify against
    if (this.profile) {
      updateProfile(this.profile, signals);
      const verdict = match(
        this.profile,
        signals,
        this.config.minObservations ?? 5
      );

      const newVerdict: SomaVerdict = {
        status: verdict.status,
        confidence: verdict.confidence,
        observationCount: verdict.observationCount,
        remoteGenomeHash: this.remoteGenomeCommitment
          ? this.profile.genomeHash
          : null,
        remoteDid: this.remoteDid,
        timestamp: Date.now(),
      };

      this.currentVerdict = newVerdict;
      this.config.onVerdict?.(this.sessionId, newVerdict);

      // Periodically persist the profile
      if (verdict.observationCount % 10 === 0) {
        await this.profileStore.save(this.profile);
      }
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

  // --- Encryption ---

  /** Whether this session has an active encrypted channel. */
  hasEncryptedChannel(): boolean {
    return this.channel !== null && this.phase === "ACTIVE";
  }

  /**
   * Encrypt an outgoing JSON-RPC message for the wire.
   * The sensorium has already observed the plaintext — this only
   * affects what travels over the transport.
   */
  encryptMessage(message: JSONRPCMessage): SomaEncryptedEnvelope {
    if (!this.channel) throw new Error("No encrypted channel established");
    const plaintext = JSON.stringify(message);
    const encrypted = this.channel.encrypt(plaintext);
    return { _somaEncrypted: true, payload: encrypted };
  }

  /**
   * Decrypt an incoming message from the wire.
   * Returns the plaintext JSON-RPC message for the sensorium to observe
   * and the MCP server to process.
   */
  decryptMessage(envelope: SomaEncryptedEnvelope): JSONRPCMessage {
    if (!this.channel) throw new Error("No encrypted channel established");
    const plaintext = this.channel.decrypt(envelope.payload);
    return JSON.parse(plaintext) as JSONRPCMessage;
  }

  /** Check if a raw message is a Soma encrypted envelope. */
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
