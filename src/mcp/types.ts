/**
 * Shared types for the Soma MCP middleware layer.
 */

import type { GenomeCommitment } from "../core/genome.js";
import type { Channel } from "../core/channel.js";
import type { PhenotypicSignals } from "../experiment/signals.js";
import type { VerdictStatus, Verdict, PhenotypicProfile } from "../sensorium/matcher.js";
import type { SignKeyPair } from "../core/crypto-provider.js";

// --- Configuration ---

export interface SomaConfig {
  /** This server's genome commitment — its identity declaration. */
  genome: GenomeCommitment;
  /** Signing key pair for this server. */
  signingKeyPair: SignKeyPair;
  /** Where to persist phenotypic profiles. Default: .soma/profiles */
  profileStorePath?: string;
  /** Minimum observations before issuing a real verdict (immune learning phase). Default: 5 */
  minObservations?: number;
  /** Called whenever a session's verdict changes. */
  onVerdict?: (sessionId: string, verdict: SomaVerdict) => void;
}

// --- Verdict ---

export interface SomaVerdict {
  status: VerdictStatus;
  confidence: number;
  observationCount: number;
  remoteGenomeHash: string | null;
  remoteDid: string | null;
  timestamp: number;
}

// --- Session ---

export type SessionPhase = "PENDING" | "HANDSHAKE" | "ACTIVE" | "DEGRADED" | "REJECTED";

export interface SomaSessionState {
  sessionId: string;
  phase: SessionPhase;
  remoteDid: string | null;
  remoteGenomeCommitment: GenomeCommitment | null;
  channel: Channel | null;
  profile: PhenotypicProfile | null;
  observations: PhenotypicSignals[];
  currentVerdict: SomaVerdict | null;
  createdAt: number;
}

// --- Genome exchange via MCP metadata ---

/**
 * The _soma metadata block embedded in MCP initialize clientInfo/serverInfo.
 * Soma never adds new JSON-RPC methods — it piggybacks on extensible fields.
 */
export interface SomaMetadata {
  /** Genome commitment — the agent's identity declaration. */
  genomeCommitment: GenomeCommitment;
  /** Ephemeral X25519 public key for session channel (base64). */
  ephemeralPublicKey: string;
}

/** Key used in clientInfo/serverInfo for Soma metadata. */
export const SOMA_METADATA_KEY = "_soma";
