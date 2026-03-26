/**
 * The cryptographic heartbeat — a hash chain recording every computational step.
 *
 * The heartbeat is the sound of the heart pumping — visible to the receiving
 * party in real time. Each heartbeat links to the previous one, forming a
 * tamper-evident log. Breaking the chain invalidates everything after it.
 *
 * The heartbeat is not verification. It's transparency. It doesn't prove the
 * computation was honest. It makes the computation VISIBLE. If the creator
 * lies, the lie is permanently recorded with the creator's genome attached.
 */

import { sha256 } from "../core/genome.js";

/** Types of events that the heart records in its hash chain. */
export type HeartbeatEventType =
  | "session_start"
  | "query_received"
  | "seed_generated"
  | "model_call_start"
  | "model_call_end"
  | "tool_call"
  | "tool_result"
  | "data_fetch"
  | "data_received"
  | "response_sent"
  | "birth_certificate";

/** A single heartbeat — one link in the hash chain. */
export interface Heartbeat {
  sequence: number;
  previousHash: string;
  eventType: HeartbeatEventType;
  eventHash: string;
  timestamp: number;
  hash: string;
}

/** The genesis hash — the beginning of all heartbeat chains. */
const GENESIS_HASH = sha256("soma:genesis");

export { GENESIS_HASH };

/**
 * The heartbeat chain — a tamper-evident log of all computation.
 *
 * Like a cardiac rhythm visible in real time. Each heartbeat links to the
 * previous, forming an immutable chain. Breaking the chain invalidates
 * everything after it.
 */
export class HeartbeatChain {
  private chain: Heartbeat[] = [];
  private currentHash: string = GENESIS_HASH;
  private sequence: number = 0;

  /** Record a new heartbeat event. Returns the heartbeat for transmission. */
  record(eventType: HeartbeatEventType, eventData: string): Heartbeat {
    const heartbeat: Heartbeat = {
      sequence: this.sequence,
      previousHash: this.currentHash,
      eventType,
      eventHash: sha256(eventData),
      timestamp: Date.now(),
      hash: "", // computed below
    };

    heartbeat.hash = computeHeartbeatHash(heartbeat);

    this.currentHash = heartbeat.hash;
    this.sequence++;
    this.chain.push(heartbeat);

    return heartbeat;
  }

  /** Get the current chain head hash. */
  get head(): string {
    return this.currentHash;
  }

  /** Get the current sequence number. */
  get length(): number {
    return this.sequence;
  }

  /** Get the full chain (read-only). */
  getChain(): readonly Heartbeat[] {
    return this.chain;
  }

  /** Get the last N heartbeats. */
  recent(count: number): Heartbeat[] {
    return this.chain.slice(-count);
  }

  /**
   * Verify chain integrity — every link must hash correctly
   * and reference the previous hash.
   */
  static verify(chain: Heartbeat[]): boolean {
    if (chain.length === 0) return true;

    // First heartbeat must reference genesis
    if (chain[0].previousHash !== GENESIS_HASH) return false;

    for (let i = 0; i < chain.length; i++) {
      const beat = chain[i];

      // Verify hash computation
      const expectedHash = computeHeartbeatHash(beat);
      if (beat.hash !== expectedHash) return false;

      // Verify chain linkage (except first)
      if (i > 0 && beat.previousHash !== chain[i - 1].hash) return false;

      // Verify monotonic sequence
      if (beat.sequence !== i) return false;
    }

    return true;
  }
}

/** Compute the hash of a heartbeat from its fields. */
function computeHeartbeatHash(beat: Heartbeat): string {
  return sha256(
    `${beat.sequence}|${beat.previousHash}|${beat.eventType}|${beat.eventHash}|${beat.timestamp}`
  );
}
