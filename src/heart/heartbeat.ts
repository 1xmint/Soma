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

import {
  getCryptoProvider,
  type CryptoProvider,
} from "../core/crypto-provider.js";

/** Types of events that the heart records in its hash chain. */
export type HeartbeatEventType =
  // Core session + generation events
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
  | "birth_certificate"
  // Observability — agent internal state (the blacksmith's sub-strikes)
  | "reasoning_step"      // internal reasoning / chain-of-thought
  | "retry"               // operation was retried
  | "rag_lookup"          // context enriched via retrieval
  | "tool_progress"       // sub-beat emitted during tool execution
  // Multi-agent coordination
  | "fork_created"        // this heart forked a child
  | "subtask_dispatch"    // work handed off to a child/delegatee
  | "subtask_return"      // child/delegatee returned a result
  | "delegation_issued"   // this heart issued a delegation
  | "delegation_revoked"; // this heart revoked a delegation

/** A single heartbeat — one link in the hash chain. */
export interface Heartbeat {
  sequence: number;
  previousHash: string;
  eventType: HeartbeatEventType;
  eventHash: string;
  timestamp: number;
  hash: string;
}

/**
 * The heartbeat chain — a tamper-evident log of all computation.
 *
 * Like a cardiac rhythm visible in real time. Each heartbeat links to the
 * previous, forming an immutable chain. Breaking the chain invalidates
 * everything after it.
 */
export class HeartbeatChain {
  private chain: Heartbeat[] = [];
  private currentHash: string;
  private sequence: number = 0;
  private readonly provider: CryptoProvider;
  /** The genesis hash for this chain (depends on the hash algorithm). */
  readonly genesisHash: string;

  constructor(provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
    this.genesisHash = this.provider.hashing.hash("soma:genesis");
    this.currentHash = this.genesisHash;
  }

  /** Record a new heartbeat event. Returns the heartbeat for transmission. */
  record(eventType: HeartbeatEventType, eventData: string): Heartbeat {
    const hash = this.provider.hashing.hash;
    const heartbeat: Heartbeat = {
      sequence: this.sequence,
      previousHash: this.currentHash,
      eventType,
      eventHash: hash(eventData),
      timestamp: Date.now(),
      hash: "", // computed below
    };

    heartbeat.hash = computeHeartbeatHash(heartbeat, this.provider);

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
   * Restore a chain from previously-recorded heartbeats.
   * The caller is responsible for verifying integrity first via HeartbeatChain.verify().
   * Returns a fresh HeartbeatChain continuing from where the old one left off.
   */
  static restore(chain: Heartbeat[], provider?: CryptoProvider): HeartbeatChain {
    const hc = new HeartbeatChain(provider);
    if (chain.length === 0) return hc;
    hc.chain = [...chain];
    hc.sequence = chain.length;
    hc.currentHash = chain[chain.length - 1].hash;
    return hc;
  }

  /**
   * Verify chain integrity — every link must hash correctly
   * and reference the previous hash.
   */
  static verify(chain: Heartbeat[], provider?: CryptoProvider): boolean {
    const p = provider ?? getCryptoProvider();
    if (chain.length === 0) return true;

    // First heartbeat must reference genesis
    const genesisHash = p.hashing.hash("soma:genesis");
    if (chain[0].previousHash !== genesisHash) return false;

    for (let i = 0; i < chain.length; i++) {
      const beat = chain[i];

      // Verify hash computation
      const expectedHash = computeHeartbeatHash(beat, p);
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
function computeHeartbeatHash(beat: Heartbeat, provider: CryptoProvider): string {
  return provider.hashing.hash(
    `${beat.sequence}|${beat.previousHash}|${beat.eventType}|${beat.eventHash}|${beat.timestamp}`
  );
}
