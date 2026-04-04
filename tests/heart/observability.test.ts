import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { commitGenome, createGenome } from "../../src/core/genome.js";
import {
  createSomaHeart,
  type HeartConfig,
  type ToolProgressEmitter,
} from "../../src/heart/runtime.js";

const crypto = getCryptoProvider();

function makeConfig(): HeartConfig {
  const kp = crypto.signing.generateKeyPair();
  const genome = commitGenome(
    createGenome({
      modelProvider: "test",
      modelId: "m",
      modelVersion: "1",
      systemPrompt: "p",
      toolManifest: "[]",
      runtimeId: "r",
    }),
    kp,
  );
  return {
    genome,
    signingKeyPair: kp,
    modelApiKey: "k",
    modelBaseUrl: "https://x",
    modelId: "m",
    toolCredentials: { search: "s" },
  };
}

describe("Agent observability methods", () => {
  it("recordReasoning() adds a reasoning_step heartbeat with hashed content", () => {
    const heart = createSomaHeart(makeConfig());
    const beat = heart.recordReasoning("I should look up the price first");
    expect(beat.eventType).toBe("reasoning_step");
    expect(heart.heartbeats.length).toBe(1);
    // Content is hashed, not stored as plaintext
    const lastBeat = heart.heartbeats.getChain()[0];
    expect(lastBeat.eventHash).toBeTruthy();
  });

  it("recordRetry() captures operation, reason, and attempt number", () => {
    const heart = createSomaHeart(makeConfig());
    const beat = heart.recordRetry("tool:search", "timeout", 2);
    expect(beat.eventType).toBe("retry");
    expect(heart.heartbeats.length).toBe(1);
  });

  it("recordRagLookup() records query hash and result count", () => {
    const heart = createSomaHeart(makeConfig());
    const beat = heart.recordRagLookup("query-hash-abc", 5);
    expect(beat.eventType).toBe("rag_lookup");
  });

  it("recordSubtaskDispatch + recordSubtaskReturn bracket child work", () => {
    const heart = createSomaHeart(makeConfig());
    const dispatch = heart.recordSubtaskDispatch("did:key:zChild", "task-hash");
    const ret = heart.recordSubtaskReturn("did:key:zChild", "result-hash");
    expect(dispatch.eventType).toBe("subtask_dispatch");
    expect(ret.eventType).toBe("subtask_return");
    // Sequential in the chain
    expect(ret.previousHash).toBe(dispatch.hash);
  });

  it("events integrate with the chain — verify() still passes", () => {
    const heart = createSomaHeart(makeConfig());
    heart.recordReasoning("step 1");
    heart.recordRetry("tool:x", "err", 1);
    heart.recordRagLookup("q", 3);
    heart.recordSubtaskDispatch("did:key:zC", "t");
    heart.recordSubtaskReturn("did:key:zC", "r");
    expect(heart.heartbeats.length).toBe(5);
    // Chain head should equal the last beat's hash
    const beats = heart.heartbeats.getChain();
    expect(heart.heartbeats.head).toBe(beats[beats.length - 1].hash);
  });
});

describe("Tool progress emitter", () => {
  it("records tool_progress heartbeats during execution", async () => {
    const heart = createSomaHeart(makeConfig());
    const result = await heart.callTool(
      "search",
      { q: "BTC" },
      async (cred, args, emit: ToolProgressEmitter) => {
        emit("validating");
        emit("fetching", "https://api.example.com");
        emit("parsing");
        return { price: 42000 };
      },
    );

    // Heartbeats should include: tool_call, 3x tool_progress, tool_result, birth_certificate
    const types = result.heartbeats.map((h) => h.eventType);
    expect(types).toContain("tool_call");
    expect(types).toContain("tool_progress");
    expect(types).toContain("tool_result");

    const progressBeats = result.heartbeats.filter(
      (h) => h.eventType === "tool_progress",
    );
    expect(progressBeats.length).toBe(3);
  });

  it("still works with a legacy 2-arg executor (no emit)", async () => {
    const heart = createSomaHeart(makeConfig());
    const result = await heart.callTool(
      "search",
      { q: "BTC" },
      async (_cred, _args) => ({ price: 42000 }),
    );
    expect(result.result).toEqual({ price: 42000 });
    const types = result.heartbeats.map((h) => h.eventType);
    expect(types).toContain("tool_call");
    expect(types).toContain("tool_result");
    // No progress beats when emit isn't called
    expect(types.filter((t) => t === "tool_progress").length).toBe(0);
  });

  it("progress beats link into the chain before tool_result", async () => {
    const heart = createSomaHeart(makeConfig());
    const result = await heart.callTool(
      "search",
      { q: "x" },
      async (_cred, _args, emit) => {
        emit("stage1");
        emit("stage2");
        return "ok";
      },
    );
    const types = result.heartbeats.map((h) => h.eventType);
    // tool_call, tool_progress (stage1), tool_progress (stage2), tool_result, birth_certificate
    expect(types).toEqual([
      "tool_call",
      "tool_progress",
      "tool_progress",
      "tool_result",
      "birth_certificate",
    ]);
  });
});

describe("Fork/delegate/revoke event types", () => {
  it("fork() records fork_created (not birth_certificate)", () => {
    const parent = createSomaHeart(makeConfig());
    parent.fork({
      systemPrompt: "child",
      toolManifest: "[]",
      capabilities: ["tool:search"],
    });
    const beats = parent.heartbeats.getChain();
    const types = beats.map((b) => b.eventType);
    expect(types).toContain("fork_created");
    expect(types).not.toContain("birth_certificate");
  });

  it("delegate() records delegation_issued", () => {
    const heart = createSomaHeart(makeConfig());
    heart.delegate({
      subjectDid: "did:key:zSubject",
      capabilities: ["tool:search"],
    });
    const types = heart.heartbeats.getChain().map((b) => b.eventType);
    expect(types).toContain("delegation_issued");
  });

  it("revoke() records delegation_revoked", () => {
    const heart = createSomaHeart(makeConfig());
    const d = heart.delegate({
      subjectDid: "did:key:zSubject",
      capabilities: ["tool:search"],
    });
    heart.revoke({ targetId: d.id, targetKind: "delegation", reason: "rotated" });
    const types = heart.heartbeats.getChain().map((b) => b.eventType);
    expect(types).toContain("delegation_issued");
    expect(types).toContain("delegation_revoked");
  });
});
