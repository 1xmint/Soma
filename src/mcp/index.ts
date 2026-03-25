/**
 * Soma MCP Middleware — public API.
 *
 * Install with one line:
 *
 *   const transport = withSoma(new StdioServerTransport(), somaConfig);
 *   await server.connect(transport);
 *
 * That's it. The sensorium is now observing. Like adding a sense of smell
 * to your server — passive, local, involuntary for the connecting agent.
 */

import nacl from "tweetnacl";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { SomaTransport } from "./soma-transport.js";
import {
  createGenome,
  commitGenome,
  type GenomeCommitment,
} from "../core/genome.js";
import type { SomaConfig, SomaVerdict } from "./types.js";

// --- One-Liner API ---

/**
 * Wrap an MCP transport with Soma phenotypic verification.
 *
 * The returned transport is a drop-in replacement — the MCP server
 * connects to it exactly as it would the original. Soma observes
 * passively inside the channel.
 *
 * @example
 * ```ts
 * import { withSoma, createSomaIdentity } from "soma/mcp";
 *
 * const identity = createSomaIdentity({
 *   modelProvider: "anthropic",
 *   modelId: "claude-sonnet-4-20250514",
 *   modelVersion: "2025-05-14",
 *   systemPrompt: "You are a helpful assistant.",
 *   toolManifest: JSON.stringify(myTools),
 *   runtimeId: `node-${process.version}-${process.platform}-${process.arch}`,
 * });
 *
 * const transport = withSoma(new StdioServerTransport(), {
 *   genome: identity.commitment,
 *   signingKeyPair: identity.keyPair,
 * });
 *
 * await server.connect(transport);
 * ```
 */
export function withSoma(inner: Transport, config: SomaConfig): SomaTransport {
  return new SomaTransport(inner, config);
}

// --- Identity Helpers ---

export interface SomaIdentity {
  keyPair: nacl.SignKeyPair;
  commitment: GenomeCommitment;
}

/**
 * Generate a complete Soma identity — key pair + genome commitment.
 * Convenience for servers that don't already have one.
 */
export function createSomaIdentity(genomeConfig: {
  modelProvider: string;
  modelId: string;
  modelVersion: string;
  systemPrompt: string;
  toolManifest: string;
  runtimeId: string;
}): SomaIdentity {
  const keyPair = nacl.sign.keyPair();
  const genome = createGenome(genomeConfig);
  const commitment = commitGenome(genome, keyPair);
  return { keyPair, commitment };
}

// --- Verdict Queries ---

/**
 * Get the current verification verdict from a Soma-wrapped transport.
 * Returns null if the transport is not a SomaTransport or no verdict yet.
 */
export function getVerdict(transport: Transport): SomaVerdict | null {
  if (transport instanceof SomaTransport) {
    return transport.getVerdict();
  }
  return null;
}

/**
 * Check if a transport has Soma active.
 */
export function isSomaEnabled(transport: Transport): boolean {
  return transport instanceof SomaTransport;
}

// --- Re-exports ---

export { SomaTransport } from "./soma-transport.js";
export type { SomaConfig, SomaVerdict, SomaMetadata } from "./types.js";
export type { VerdictStatus, Verdict } from "../sensorium/matcher.js";
