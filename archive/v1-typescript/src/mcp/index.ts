/**
 * Soma MCP Middleware — public API.
 *
 * Phase 1 (observation only):
 *   const transport = withSoma(new StdioServerTransport(), somaConfig);
 *   await server.connect(transport);
 *
 * Phase 2 (heart-integrated):
 *   const heart = createSomaHeart({ genome, signingKeyPair, modelApiKey, ... });
 *   const transport = withSoma(new StdioServerTransport(), { ...somaConfig, heart });
 *   await server.connect(transport);
 *
 * The transport handles communication. The heart handles computation.
 * Different organs, one system.
 */

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { SomaTransport } from "./soma-transport.js";
import {
  getCryptoProvider,
  type SignKeyPair,
} from "../core/crypto-provider.js";
import {
  createGenome,
  commitGenome,
  type GenomeCommitment,
} from "../core/genome.js";
import type { SomaConfig, SomaVerdict } from "./types.js";
import type { HeartRuntime } from "../heart/runtime.js";

// --- One-Liner API ---

/**
 * Wrap an MCP transport with Soma identity verification.
 *
 * The returned transport is a drop-in replacement — the MCP server
 * connects to it exactly as it would the original.
 *
 * When a heart is provided via config, computation routes through it:
 * - Observations go through the behavioral landscape (not flat profile)
 * - Enhanced verdicts include drift velocity and category awareness
 * - The heart is accessible via transport.getHeart() for MCP tools
 *
 * @example Phase 1 (observation only):
 * ```ts
 * const transport = withSoma(new StdioServerTransport(), {
 *   genome: identity.commitment,
 *   signingKeyPair: identity.keyPair,
 * });
 * ```
 *
 * @example Phase 2 (heart-integrated):
 * ```ts
 * const heart = createSomaHeart({
 *   genome: identity.commitment,
 *   signingKeyPair: identity.keyPair,
 *   modelApiKey: process.env.API_KEY,
 *   modelBaseUrl: "https://api.anthropic.com/v1",
 *   modelId: "claude-sonnet-4-20250514",
 * });
 * const transport = withSoma(new StdioServerTransport(), {
 *   genome: identity.commitment,
 *   signingKeyPair: identity.keyPair,
 *   heart,
 * });
 * // MCP tools now use the heart:
 * // const analysis = await transport.getHeart().generate({ messages });
 * ```
 */
export function withSoma(inner: Transport, config: SomaConfig): SomaTransport {
  return new SomaTransport(inner, config);
}

// --- Identity Helpers ---

export interface SomaIdentity {
  keyPair: SignKeyPair;
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
  const keyPair = getCryptoProvider().signing.generateKeyPair();
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
 * Get the heart runtime from a Soma-wrapped transport.
 * Returns null if no heart configured or transport is not Soma.
 */
export function getHeart(transport: Transport): HeartRuntime | null {
  if (transport instanceof SomaTransport) {
    return transport.getHeart();
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
export { createSomaHeart, HeartRuntime } from "../heart/runtime.js";
export type { HeartConfig } from "../heart/runtime.js";
export type { SomaConfig, SomaVerdict, SomaMetadata } from "./types.js";
export type { VerdictStatus, Verdict, EnhancedVerdict } from "../sensorium/matcher.js";
