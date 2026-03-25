/**
 * The Soma Transport — an invisible wrapper around any MCP transport.
 *
 * Sits between the MCP server and the underlying transport (stdio, HTTP),
 * passively observing all JSON-RPC messages flowing through. Like a sense
 * organ attached to a nerve — it reads signals without altering them.
 *
 * Soma never speaks (Rule 2). This transport never adds, removes, or
 * modifies application messages. It only reads. The one exception: it
 * embeds Soma metadata in the initialize response's serverInfo, which
 * is an extensible field that non-Soma clients simply ignore.
 */

import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { SomaSession } from "./soma-session.js";
import { ProfileStore } from "./profile-store.js";
import { SOMA_METADATA_KEY, type SomaConfig, type SomaVerdict } from "./types.js";

export class SomaTransport implements Transport {
  private readonly inner: Transport;
  private readonly session: SomaSession;
  private readonly profileStore: ProfileStore;

  sessionId?: string;

  constructor(inner: Transport, config: SomaConfig) {
    this.inner = inner;
    this.profileStore = new ProfileStore(config.profileStorePath);
    this.session = new SomaSession(config, this.profileStore);
  }

  async start(): Promise<void> {
    await this.profileStore.init();

    // Intercept inbound messages from the inner transport
    this.inner.onmessage = (message: JSONRPCMessage, extra?: unknown) => {
      // Observe the incoming message (non-blocking)
      this.session.onIncomingMessage(message).catch(() => {});
      // Forward to the MCP server's handler
      this.onmessage?.(message, extra as undefined);
    };

    this.inner.onclose = () => {
      this.session.close().catch(() => {});
      this.onclose?.();
    };

    this.inner.onerror = (error: Error) => {
      this.onerror?.(error);
    };

    await this.inner.start();
    this.sessionId = this.inner.sessionId;
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    // Inject Soma metadata into the initialize response
    const enriched = this.maybeInjectMetadata(message);

    // Observe outgoing message for phenotypic signal extraction
    this.session.onOutgoingMessage(enriched).catch(() => {});

    // Send through the inner transport — unmodified application data
    await this.inner.send(enriched, options);
  }

  async close(): Promise<void> {
    await this.session.close();
    await this.inner.close();
  }

  // --- Callbacks (set by the MCP Server) ---

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: unknown) => void;

  setProtocolVersion?: (version: string) => void;

  // --- Soma API ---

  /** Get the current verification verdict for the connected client. */
  getVerdict(): SomaVerdict | null {
    return this.session.getVerdict();
  }

  /** Get the session's Soma-specific ID. */
  getSomaSessionId(): string {
    return this.session.sessionId;
  }

  /** Get the session phase (PENDING, ACTIVE, DEGRADED, etc). */
  getPhase(): string {
    return this.session.getPhase();
  }

  // --- Internal ---

  /**
   * Inject this server's Soma metadata into the initialize response.
   * The only place Soma "speaks" — and it does so via an extensible
   * metadata field that non-Soma clients simply ignore.
   */
  private maybeInjectMetadata(message: JSONRPCMessage): JSONRPCMessage {
    if (!("result" in message) || !message.result) return message;

    const result = message.result as Record<string, unknown>;
    // Detect initialize response by presence of serverInfo + capabilities
    if (!result.serverInfo || !result.capabilities) return message;

    const serverInfo = result.serverInfo as Record<string, unknown>;
    serverInfo[SOMA_METADATA_KEY] = this.session.getLocalMetadata();

    return message;
  }
}
