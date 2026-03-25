/**
 * Integration tests for Soma MCP middleware.
 * Tests the transport wrapper, session lifecycle, and signal extraction
 * without requiring a real MCP client/server.
 */

import { describe, it, expect, beforeEach } from "vitest";
import nacl from "tweetnacl";
import { SomaTransport } from "../../src/mcp/soma-transport.js";
import { createSomaIdentity, withSoma, getVerdict, isSomaEnabled } from "../../src/mcp/index.js";
import { commitGenome, createGenome, computeHash } from "../../src/core/genome.js";
import {
  generateEphemeralKeyPair,
  createHandshakePayload,
} from "../../src/core/channel.js";
import { SOMA_METADATA_KEY, type SomaMetadata } from "../../src/mcp/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { SignalTap, extractTextFromMessage } from "../../src/mcp/signal-tap.js";

// --- Mock Transport ---

class MockTransport implements Transport {
  started = false;
  closed = false;
  sent: JSONRPCMessage[] = [];
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  sessionId?: string;

  async start(): Promise<void> {
    this.started = true;
  }
  async send(message: JSONRPCMessage): Promise<void> {
    this.sent.push(message);
  }
  async close(): Promise<void> {
    this.closed = true;
    this.onclose?.();
  }

  /** Simulate receiving a message from a client. */
  simulateIncoming(message: JSONRPCMessage): void {
    this.onmessage?.(message);
  }
}

// --- Test helpers ---

function makeServerIdentity() {
  return createSomaIdentity({
    modelProvider: "test",
    modelId: "test-model",
    modelVersion: "1.0",
    systemPrompt: "Test prompt",
    toolManifest: "[]",
    runtimeId: "test-runtime",
  });
}

function makeClientIdentity() {
  const keyPair = nacl.sign.keyPair();
  const genome = createGenome({
    modelProvider: "client",
    modelId: "client-model",
    modelVersion: "1.0",
    systemPrompt: "Client prompt",
    toolManifest: "[]",
    runtimeId: "client-runtime",
  });
  return { keyPair, commitment: commitGenome(genome, keyPair) };
}

function makeInitializeRequest(somaMetadata?: SomaMetadata): JSONRPCMessage {
  const params: Record<string, unknown> = {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: {
      name: "test-client",
      version: "1.0",
      ...(somaMetadata ? { [SOMA_METADATA_KEY]: somaMetadata } : {}),
    },
  };
  return { jsonrpc: "2.0", id: 1, method: "initialize", params } as unknown as JSONRPCMessage;
}

function makeInitializeResponse(): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      serverInfo: { name: "test-server", version: "1.0" },
    },
  } as unknown as JSONRPCMessage;
}

function makeToolCallResponse(text: string): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: 2,
    result: {
      content: [{ type: "text", text }],
    },
  } as unknown as JSONRPCMessage;
}

// --- Tests ---

describe("withSoma", () => {
  it("returns a SomaTransport wrapping the inner transport", () => {
    const identity = makeServerIdentity();
    const inner = new MockTransport();
    const soma = withSoma(inner, {
      genome: identity.commitment,
      signingKeyPair: identity.keyPair,
    });
    expect(soma).toBeInstanceOf(SomaTransport);
  });

  it("isSomaEnabled returns true for SomaTransport", () => {
    const identity = makeServerIdentity();
    const inner = new MockTransport();
    const soma = withSoma(inner, {
      genome: identity.commitment,
      signingKeyPair: identity.keyPair,
    });
    expect(isSomaEnabled(soma)).toBe(true);
    expect(isSomaEnabled(inner)).toBe(false);
  });
});

describe("createSomaIdentity", () => {
  it("generates a valid key pair and genome commitment", () => {
    const identity = createSomaIdentity({
      modelProvider: "anthropic",
      modelId: "claude-sonnet-4",
      modelVersion: "2025-05-14",
      systemPrompt: "You are helpful.",
      toolManifest: "[]",
      runtimeId: "node-22",
    });
    expect(identity.keyPair.publicKey).toHaveLength(32);
    expect(identity.keyPair.secretKey).toHaveLength(64);
    expect(identity.commitment.hash).toBeTruthy();
    expect(identity.commitment.did).toMatch(/^did:key:/);
  });
});

describe("SomaTransport", () => {
  let inner: MockTransport;
  let soma: SomaTransport;
  let serverIdentity: ReturnType<typeof makeServerIdentity>;

  beforeEach(async () => {
    inner = new MockTransport();
    serverIdentity = makeServerIdentity();
    soma = new SomaTransport(inner, {
      genome: serverIdentity.commitment,
      signingKeyPair: serverIdentity.keyPair,
      profileStorePath: ".soma/test-profiles-" + Date.now(),
    });
  });

  it("delegates start to inner transport", async () => {
    await soma.start();
    expect(inner.started).toBe(true);
  });

  it("delegates close to inner transport", async () => {
    await soma.start();
    await soma.close();
    expect(inner.closed).toBe(true);
  });

  it("forwards incoming messages to onmessage handler", async () => {
    const received: JSONRPCMessage[] = [];
    await soma.start();
    soma.onmessage = (msg) => received.push(msg);
    inner.simulateIncoming(makeInitializeRequest());
    expect(received).toHaveLength(1);
  });

  it("injects Soma metadata into initialize response", async () => {
    await soma.start();
    soma.onmessage = () => {};
    inner.simulateIncoming(makeInitializeRequest());

    const response = makeInitializeResponse();
    await soma.send(response);

    const sent = inner.sent[0] as Record<string, unknown>;
    const result = sent.result as Record<string, unknown>;
    const serverInfo = result.serverInfo as Record<string, unknown>;
    expect(serverInfo[SOMA_METADATA_KEY]).toBeTruthy();
    const meta = serverInfo[SOMA_METADATA_KEY] as SomaMetadata;
    expect(meta.genomeCommitment.did).toMatch(/^did:key:/);
    expect(meta.ephemeralPublicKey).toBeTruthy();
  });

  it("enters DEGRADED phase when client has no Soma metadata", async () => {
    await soma.start();
    soma.onmessage = () => {};
    inner.simulateIncoming(makeInitializeRequest()); // no _soma metadata
    // Allow async processing
    await new Promise((r) => setTimeout(r, 10));
    expect(soma.getPhase()).toBe("DEGRADED");
  });

  it("enters ACTIVE phase when client presents valid Soma metadata", async () => {
    const client = makeClientIdentity();
    const ephemeral = generateEphemeralKeyPair();
    const clientMeta: SomaMetadata = {
      genomeCommitment: client.commitment,
      ephemeralPublicKey: Buffer.from(ephemeral.publicKey).toString("base64"),
    };

    await soma.start();
    soma.onmessage = () => {};
    inner.simulateIncoming(makeInitializeRequest(clientMeta));
    await new Promise((r) => setTimeout(r, 10));
    expect(soma.getPhase()).toBe("ACTIVE");
  });

  it("returns null verdict before any observations", () => {
    expect(soma.getVerdict()).toBeNull();
    expect(getVerdict(soma)).toBeNull();
  });
});

describe("SignalTap", () => {
  it("extracts text from tool call results", () => {
    const msg = makeToolCallResponse("Hello, world!");
    const text = extractTextFromMessage(msg);
    expect(text).toBe("Hello, world!");
  });

  it("extracts text from resource read results", () => {
    const msg = {
      jsonrpc: "2.0", id: 1,
      result: { contents: [{ uri: "test://x", text: "Resource content" }] },
    } as unknown as JSONRPCMessage;
    expect(extractTextFromMessage(msg)).toBe("Resource content");
  });

  it("returns null for messages without text content", () => {
    const msg = { jsonrpc: "2.0", id: 1, result: {} } as unknown as JSONRPCMessage;
    expect(extractTextFromMessage(msg)).toBeNull();
  });

  it("extracts phenotypic signals from a response with timing", () => {
    const tap = new SignalTap();
    const msg = makeToolCallResponse(
      "A hash function is a mathematical algorithm that takes input data of any size " +
      "and produces a fixed-size string of characters. It is designed to be a one-way " +
      "function, meaning it should be computationally infeasible to reverse."
    );
    const signals = tap.tap(msg, {
      requestTime: 1000,
      responseTime: 1500,
    });
    expect(signals).not.toBeNull();
    expect(signals!.cognitive.hedgeCount).toBeGreaterThanOrEqual(0);
    expect(signals!.structural.wordCount).toBeGreaterThan(0);
    expect(signals!.temporal.timeToFirstToken).toBe(500);
    expect(signals!.temporal.tokenCount).toBeGreaterThan(0);
  });
});
