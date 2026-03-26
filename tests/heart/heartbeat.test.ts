import { describe, it, expect } from "vitest";
import { HeartbeatChain, GENESIS_HASH } from "../../src/heart/heartbeat.js";

describe("HeartbeatChain", () => {
  it("starts with genesis hash and zero length", () => {
    const chain = new HeartbeatChain();
    expect(chain.head).toBe(GENESIS_HASH);
    expect(chain.length).toBe(0);
    expect(chain.getChain()).toEqual([]);
  });

  it("records a heartbeat and advances the chain", () => {
    const chain = new HeartbeatChain();
    const beat = chain.record("session_start", "test-session-data");

    expect(beat.sequence).toBe(0);
    expect(beat.previousHash).toBe(GENESIS_HASH);
    expect(beat.eventType).toBe("session_start");
    expect(beat.eventHash).toBeTruthy();
    expect(beat.hash).toBeTruthy();
    expect(beat.timestamp).toBeGreaterThan(0);

    expect(chain.length).toBe(1);
    expect(chain.head).toBe(beat.hash);
  });

  it("chains heartbeats — each references the previous hash", () => {
    const chain = new HeartbeatChain();
    const beat1 = chain.record("session_start", "data1");
    const beat2 = chain.record("query_received", "data2");
    const beat3 = chain.record("model_call_start", "data3");

    expect(beat1.previousHash).toBe(GENESIS_HASH);
    expect(beat2.previousHash).toBe(beat1.hash);
    expect(beat3.previousHash).toBe(beat2.hash);
    expect(chain.length).toBe(3);
    expect(chain.head).toBe(beat3.hash);
  });

  it("monotonically increasing sequence numbers", () => {
    const chain = new HeartbeatChain();
    for (let i = 0; i < 10; i++) {
      const beat = chain.record("response_sent", `data-${i}`);
      expect(beat.sequence).toBe(i);
    }
  });

  it("recent() returns the last N heartbeats", () => {
    const chain = new HeartbeatChain();
    for (let i = 0; i < 5; i++) {
      chain.record("response_sent", `data-${i}`);
    }
    const last3 = chain.recent(3);
    expect(last3.length).toBe(3);
    expect(last3[0].sequence).toBe(2);
    expect(last3[1].sequence).toBe(3);
    expect(last3[2].sequence).toBe(4);
  });

  it("recent() handles requesting more than available", () => {
    const chain = new HeartbeatChain();
    chain.record("session_start", "data");
    expect(chain.recent(5).length).toBe(1);
  });

  it("different event data produces different event hashes", () => {
    const chain1 = new HeartbeatChain();
    const chain2 = new HeartbeatChain();
    const beat1 = chain1.record("query_received", "query A");
    const beat2 = chain2.record("query_received", "query B");
    expect(beat1.eventHash).not.toBe(beat2.eventHash);
  });

  it("getChain() returns all heartbeats in order", () => {
    const chain = new HeartbeatChain();
    chain.record("session_start", "a");
    chain.record("query_received", "b");
    chain.record("model_call_start", "c");
    const all = chain.getChain();
    expect(all.length).toBe(3);
    expect(all[0].eventType).toBe("session_start");
    expect(all[1].eventType).toBe("query_received");
    expect(all[2].eventType).toBe("model_call_start");
  });

  describe("verify()", () => {
    it("verifies an empty chain", () => {
      expect(HeartbeatChain.verify([])).toBe(true);
    });

    it("verifies a valid chain", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");
      chain.record("query_received", "b");
      chain.record("seed_generated", "c");
      chain.record("model_call_start", "d");
      chain.record("model_call_end", "e");
      chain.record("response_sent", "f");

      expect(HeartbeatChain.verify([...chain.getChain()])).toBe(true);
    });

    it("detects tampered hash", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");
      chain.record("query_received", "b");

      const tampered = [...chain.getChain()];
      tampered[1] = { ...tampered[1], hash: "tampered-hash" };
      expect(HeartbeatChain.verify(tampered)).toBe(false);
    });

    it("detects broken chain linkage", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");
      chain.record("query_received", "b");

      const broken = [...chain.getChain()];
      broken[1] = { ...broken[1], previousHash: "wrong-previous" };
      expect(HeartbeatChain.verify(broken)).toBe(false);
    });

    it("detects wrong genesis", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");

      const bad = [...chain.getChain()];
      bad[0] = { ...bad[0], previousHash: "not-genesis" };
      expect(HeartbeatChain.verify(bad)).toBe(false);
    });

    it("detects tampered event data", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");

      const tampered = [...chain.getChain()];
      tampered[0] = { ...tampered[0], eventHash: "tampered-event-hash" };
      expect(HeartbeatChain.verify(tampered)).toBe(false);
    });

    it("detects out-of-order sequence", () => {
      const chain = new HeartbeatChain();
      chain.record("session_start", "a");
      chain.record("query_received", "b");

      const reordered = [...chain.getChain()];
      reordered[0] = { ...reordered[0], sequence: 5 };
      expect(HeartbeatChain.verify(reordered)).toBe(false);
    });
  });
});
