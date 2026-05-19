/**
 * Attack #8 — Heartbeat chain gap / reorder.
 *
 * Scenario:
 *   A heart records a session: heartbeats [H0, H1, H2, H3]. An auditor later
 *   reviews the chain to confirm nothing went missing or got reordered. Eve
 *   (a malicious operator) tries several tampering strategies:
 *     - Delete H2 entirely (gap between H1 and H3).
 *     - Swap H1 and H2 (out-of-order timestamps but preserved hashes).
 *     - Substitute H2 with a different event.
 *
 * Defense: `HeartbeatChain.verify` checks monotonic sequence, linked hashes,
 * and hash computation. Any gap, reorder, or substitution breaks the chain.
 *
 * Primitives composed:
 *   heartbeat · hash chain linkage
 */

import { describe, it, expect } from "vitest";
import { HeartbeatChain } from "../../src/heart/heartbeat.js";

describe("Attack #8: heartbeat chain gap / reorder", () => {
  function recordChain(events: { type: string; data: string }[]) {
    const chain = new HeartbeatChain();
    for (const e of events) {
      chain.record(e.type as "session_start", e.data);
    }
    return chain;
  }

  it("deleting a heartbeat in the middle breaks chain verification", () => {
    const chain = recordChain([
      { type: "session_start", data: "s0" },
      { type: "query_received", data: "q0" },
      { type: "model_call_start", data: "m0" },
      { type: "response_sent", data: "r0" },
    ]);
    expect(HeartbeatChain.verify([...chain.getChain()])).toBe(true);

    // Remove the second event.
    const gapped = [
      chain.getChain()[0],
      chain.getChain()[2],
      chain.getChain()[3],
    ];
    expect(HeartbeatChain.verify(gapped)).toBe(false);
  });

  it("swapping two adjacent heartbeats breaks sequence + linkage", () => {
    const chain = recordChain([
      { type: "session_start", data: "s0" },
      { type: "query_received", data: "q0" },
      { type: "model_call_start", data: "m0" },
      { type: "response_sent", data: "r0" },
    ]);
    const events = [...chain.getChain()];
    const swapped = [events[0], events[2], events[1], events[3]];
    expect(HeartbeatChain.verify(swapped)).toBe(false);
  });

  it("substituting an event's payload breaks its own hash", () => {
    const chain = recordChain([
      { type: "session_start", data: "honest-session" },
      { type: "model_call_start", data: "honest-call" },
    ]);
    const events = [...chain.getChain()];
    // Alter the eventHash to pretend a different event happened.
    const tampered = [
      events[0],
      { ...events[1], eventHash: "covering-up-something" },
    ];
    expect(HeartbeatChain.verify(tampered)).toBe(false);
  });

  it("renumbering sequence to hide a gap still fails chain linkage", () => {
    // Eve removes event #2 and renumbers #3 to pretend it was always #2.
    const chain = recordChain([
      { type: "session_start", data: "s0" },
      { type: "tool_call", data: "t0" },
      { type: "tool_result", data: "r0" },
      { type: "response_sent", data: "done" },
    ]);
    const events = [...chain.getChain()];
    const forged = [
      events[0],
      events[1],
      { ...events[3], sequence: 2 }, // renumber
    ];
    // Sequence is sequential (0,1,2) and hashes still point to events[1].hash
    // for the second entry, but events[3].previousHash pointed to events[2],
    // which we removed — linkage broken.
    expect(HeartbeatChain.verify(forged)).toBe(false);
  });

  it("an intact chain verifies and exposes the correct head", () => {
    const chain = recordChain([
      { type: "session_start", data: "s0" },
      { type: "query_received", data: "q0" },
      { type: "response_sent", data: "r0" },
    ]);
    expect(HeartbeatChain.verify([...chain.getChain()])).toBe(true);
    expect(chain.length).toBe(3);
    expect(chain.head).not.toBe(chain.genesisHash);
  });
});
