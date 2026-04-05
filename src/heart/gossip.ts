/**
 * Gossip transport — bounded, accountable revocation propagation.
 *
 * `RevocationLog` is a local data structure. A heart running on node A
 * revokes a delegation; a verifier on node B may hold a stale log and
 * honour the now-dead credential. Audit limit #1: the race window between
 * revoke-here and observe-there.
 *
 * We can't eliminate the race — propagation always has latency — but we
 * CAN make it bounded and accountable:
 *
 *   1. Bounded: every peer tracks `lastSyncAt` (the last time it heard
 *      ANY message on the topic). Validation callers refuse to honour
 *      credentials when `now - lastSyncAt > maxStaleness`. A peer that
 *      can't reach the network becomes fail-closed in a bounded time.
 *
 *   2. Accountable: peers periodically publish signed `LogHead` commitments.
 *      Two conflicting heads from the same authority at the same sequence
 *      are a provable fork. This is CT's "gossip" mechanism.
 *
 * Transport is pluggable. The default `InMemoryTransport` is fine for tests
 * and small single-process deployments. Production can plug libp2p / NATS /
 * Redis pub/sub / HTTP SSE behind the same interface.
 *
 * Distribution model (from docs/design/revocation-gossip.md):
 *   - Every node subscribes to topic "soma/revocations/v1"
 *   - On local append: publish `revocation` + updated `head`
 *   - On interval: publish `head` (heartbeat)
 *   - On receiving `revocation`: try to append to local log
 *   - On receiving `head`: record per-authority, check divergence
 *   - Staleness enforcement is the caller's job via `isStale()`
 */

import type { CryptoProvider } from '../core/crypto-provider.js';
import { getCryptoProvider } from '../core/crypto-provider.js';
import {
  RevocationLog,
  type LogHead,
  type RevocationLogEntry,
} from './revocation-log.js';

// ─── Message types ──────────────────────────────────────────────────────────

export type GossipMessage =
  | { kind: 'revocation'; entry: RevocationLogEntry }
  | { kind: 'head'; head: LogHead };

// ─── Transport ──────────────────────────────────────────────────────────────

/** Abstract pub/sub transport. Pluggable — ships with InMemoryTransport. */
export interface GossipTransport {
  readonly kind: string;
  publish(message: GossipMessage): Promise<void>;
  subscribe(handler: (msg: GossipMessage) => void | Promise<void>): () => void;
}

/**
 * Synchronous in-memory broadcast bus. All subscribers on the same instance
 * receive all messages, skipping the publisher. Useful for tests and
 * single-process topologies.
 */
export class InMemoryTransport implements GossipTransport {
  readonly kind = 'in-memory';
  private readonly handlers = new Set<(msg: GossipMessage) => void | Promise<void>>();

  async publish(message: GossipMessage): Promise<void> {
    // Snapshot handlers so mutations during delivery don't surprise us
    const snapshot = Array.from(this.handlers);
    for (const h of snapshot) {
      try {
        await h(message);
      } catch {
        // swallow — one bad subscriber shouldn't block others
      }
    }
  }

  subscribe(handler: (msg: GossipMessage) => void | Promise<void>): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }
}

// ─── Divergence tracking ────────────────────────────────────────────────────

/** Evidence that the same authority signed two conflicting heads. */
export interface DivergenceReport {
  operatorDid: string;
  sequence: number;
  headA: LogHead;
  headB: LogHead;
}

// ─── Peer ───────────────────────────────────────────────────────────────────

export interface GossipPeerOptions {
  transport: GossipTransport;
  log: RevocationLog;
  operatorSigningKey: Uint8Array;
  operatorPublicKey: Uint8Array;
  /** DIDs of trusted relays; heads from other authorities are still tracked
   *  but this lets callers enforce "staleness relative to trusted set". */
  trustedAuthorities?: string[];
  /** Stub-replaceable clock for tests. */
  now?: () => number;
  provider?: CryptoProvider;
}

/**
 * A gossip peer. Listens on a transport, propagates local revocations,
 * publishes periodic heartbeat heads, and tracks divergence.
 */
export class GossipPeer {
  private readonly transport: GossipTransport;
  private readonly log: RevocationLog;
  private readonly operatorSigningKey: Uint8Array;
  private readonly operatorPublicKey: Uint8Array;
  private readonly trustedAuthorities: Set<string> | null;
  private readonly provider: CryptoProvider;
  private readonly now: () => number;
  private unsubscribe: (() => void) | null = null;

  private _lastSyncAt = 0;
  private readonly headsByAuthority = new Map<string, LogHead[]>();
  private divergence: DivergenceReport | null = null;

  constructor(opts: GossipPeerOptions) {
    this.transport = opts.transport;
    this.log = opts.log;
    this.operatorSigningKey = opts.operatorSigningKey;
    this.operatorPublicKey = opts.operatorPublicKey;
    this.trustedAuthorities =
      opts.trustedAuthorities && opts.trustedAuthorities.length > 0
        ? new Set(opts.trustedAuthorities)
        : null;
    this.provider = opts.provider ?? getCryptoProvider();
    this.now = opts.now ?? (() => Date.now());
  }

  /** Subscribe to the transport. Idempotent. */
  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.transport.subscribe((msg) => this.handleMessage(msg));
  }

  /** Unsubscribe from the transport. */
  stop(): void {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
  }

  // ─── Outbound ───────────────────────────────────────────────────────────

  /** Publish a revocation entry that was just locally appended. */
  async publishRevocation(entry: RevocationLogEntry): Promise<void> {
    await this.transport.publish({ kind: 'revocation', entry });
  }

  /** Publish the current head as a signed commitment. */
  async publishHead(): Promise<LogHead> {
    const head = this.log.signHead(
      this.operatorSigningKey,
      this.operatorPublicKey,
    );
    await this.transport.publish({ kind: 'head', head });
    return head;
  }

  // ─── Inbound ────────────────────────────────────────────────────────────

  private async handleMessage(msg: GossipMessage): Promise<void> {
    // Treat any message from the topic as proof that the network is live
    this._lastSyncAt = this.now();

    if (msg.kind === 'revocation') {
      this.ingestRevocation(msg.entry);
    } else if (msg.kind === 'head') {
      this.ingestHead(msg.head);
    }
  }

  private ingestRevocation(entry: RevocationLogEntry): void {
    // Try to append. If the revocation is already present or out-of-order,
    // silently skip — the sender may catch us up via a head + replay or the
    // caller may bootstrap from a relay out-of-band.
    try {
      // Only attempt if its expected sequence matches our next slot
      if (entry.sequence !== this.log.length) return;
      // Rebuild using append() which re-verifies signature + dedup
      this.log.append(entry.revocation);
    } catch {
      // signature bad / duplicate / reorder — just drop
    }
  }

  private ingestHead(head: LogHead): void {
    const check = RevocationLog.verifyHead(head, this.provider);
    if (!check.valid) return; // forged sig, ignore

    // Record per-authority, detect divergence at the same sequence
    const list = this.headsByAuthority.get(head.operatorDid) ?? [];
    for (const prior of list) {
      if (prior.sequence === head.sequence && prior.hash !== head.hash) {
        // Same authority, same sequence, different hash = provable fork
        this.divergence = {
          operatorDid: head.operatorDid,
          sequence: head.sequence,
          headA: prior,
          headB: head,
        };
        break;
      }
    }
    list.push(head);
    // Keep just a modest window per authority
    if (list.length > 64) list.shift();
    this.headsByAuthority.set(head.operatorDid, list);
  }

  // ─── State ──────────────────────────────────────────────────────────────

  /** Most recent time any message was observed. 0 if never. */
  get lastSyncAt(): number {
    return this._lastSyncAt;
  }

  /**
   * Is this peer's view stale? True if no message has been seen in the last
   * `maxStaleness` ms. Use as a fail-closed check in credential validation:
   * if stale, refuse to honour credentials that could have been revoked.
   */
  isStale(maxStalenessMs: number, now?: number): boolean {
    const t = now ?? this.now();
    if (this._lastSyncAt === 0) return true;
    return t - this._lastSyncAt > maxStalenessMs;
  }

  /** Divergence report if detected, else null. */
  getDivergenceReport(): DivergenceReport | null {
    return this.divergence;
  }

  /** Heads collected from a specific authority, most recent last. */
  getHeadsFromAuthority(operatorDid: string): readonly LogHead[] {
    return this.headsByAuthority.get(operatorDid) ?? [];
  }

  /** Is this authority in the trust set (or is trust set unconfigured)? */
  isAuthorityTrusted(operatorDid: string): boolean {
    if (this.trustedAuthorities === null) return true;
    return this.trustedAuthorities.has(operatorDid);
  }
}
