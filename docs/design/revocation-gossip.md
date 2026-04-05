# Revocation Gossip — design spec (audit limit #1)

**Status:** design. Implementation deferred.
**Closes:** audit limit #1 (revocation race — an attacker can use a stolen
credential between revocation and propagation).

## The problem

`RevocationRegistry` and `RevocationLog` are local data structures. A heart
running on node A revokes a delegation; a verifier on node B holds a stale
copy of the registry and honours the now-dead credential. The race window is
however long it takes the revocation to propagate.

No matter how fast the transport, a window of non-zero size will always exist.
The goal here is not to make the window zero. The goal is to:

1. **Make the window bounded and observable** — every verifier knows when it
   last synced and can refuse to honour credentials if its view is stale.
2. **Make propagation accountable** — an operator who claims "I didn't see
   the revocation" must produce a signed head committing to that view.
3. **Make censorship detectable** — if a relay drops revocations, honest
   participants can notice the divergence and route around it.

## Non-goals

- **Consensus.** This is not a blockchain. Two honest operators can
  temporarily disagree; the goal is to make disagreement detectable, not
  impossible.
- **Private revocations.** Revocations are public facts. Hiding them is a
  separate problem (see `spend-receipts.md` for metadata privacy thoughts).

## Architecture

### Transport: epidemic gossip over pub/sub

Each node runs a small gossip peer. When a heart calls `heart.revoke()`:

```
    heart.revoke()
         │
         ▼
    local RevocationLog.append()
         │
         ▼
    GossipPeer.publish(entry)
         │
         ▼
    peers ← topic "soma/revocations/v1"
```

Three message types on the topic:

| Message | Payload | Sent when |
|---|---|---|
| `revocation` | `RevocationLogEntry` | On local append |
| `head` | `LogHead` (signed) | On interval (e.g. every 30s) or on demand |
| `request` | `{ fromSequence: n }` | When catching up |

Peers MAY republish each message once (bounded epidemic) to cover peers they
think may have missed it. Messages carry a small TTL counter to limit
amplification.

### Subscription model

Two tiers of participant:

- **Relays** — always online, subscribe to the topic, persist all entries,
  serve `request` messages from catchup peers. Run by platform operators,
  governance entities, or commercial providers.
- **Edge verifiers** — short-lived, subscribe on startup, fast-forward from
  their last known head via a `request` to any relay.

A verifier chooses N relays (3–5 is reasonable) and treats their combined
view as the current truth. Divergence between relays is itself a signal.

### Staleness bound

Every verifier records `lastSyncAt` — the wall-clock time it last received
ANY message on the topic (even a heartbeat `head`). When validating a
credential, the verifier checks:

```ts
if (now - lastSyncAt > config.maxStaleness) {
  return { valid: false, reason: 'revocation view stale' };
}
```

This is the enforcement lever. A verifier that cannot reach the gossip
network refuses to honour credentials beyond a configurable horizon. The
default should be **60 seconds** for interactive work, longer for batch
systems where offline operation is expected and compensated with shorter
credential TTLs.

### Divergence detection

Relay R1 publishes signed head at sequence=100, hash=H1.
Relay R2 publishes signed head at sequence=100, hash=H2 ≠ H1.

At least one of them is presenting a forked log. A verifier sees both heads,
notes the conflict, requests the full range `[0..100]` from each, and
identifies the divergence point. The relay that presented the smaller set
(missing entries that the other has) is either censoring or lagging.

This is Certificate Transparency's "gossip" mechanism applied to revocations.
The detection is **after the fact** — it cannot prevent a single-relay
forker from temporarily deceiving a verifier. But the forker's signed head
becomes a permanent proof of misbehaviour.

## Protocol details (to flesh out in implementation)

### Peer identity

Each relay has a stable Ed25519 keypair. Edge verifiers remember the
`operatorDid`s of relays they trust.

### Anti-flood

- Rate limit per peer (N messages/second).
- Reject messages with stale `issuedAt` (older than T seconds).
- Bloom filter of recent entry hashes to suppress loops.

### Backpressure

Relays that fall behind MUST advertise so — they include `lastAppendedAt` in
their signed heads. A verifier that sees a head more than 5 minutes stale
drops the relay from its active set.

### Confidentiality

The topic is public. Revocations do not leak credential contents (the
`targetId` is opaque), but a watcher could correlate `targetId` back to an
issuer. Issuers concerned about this should randomise their
`targetId`s — they're already opaque strings.

## Implementation sketch

New module: `src/heart/gossip.ts`.

```ts
interface GossipConfig {
  transport: GossipTransport;  // pluggable: libp2p, redis pub/sub, websocket
  log: RevocationLog;          // local view
  trustedRelays: string[];     // operatorDids
  maxStaleness: number;        // ms
}

class GossipPeer {
  start(): Promise<void>
  stop(): Promise<void>
  publishRevocation(entry: RevocationLogEntry): void
  publishHead(): void
  get lastSyncAt(): number
  get divergenceDetected(): DivergenceReport | null
}
```

Transport is pluggable because Soma ships as a library — the consumer
decides whether to use libp2p, Redis pub/sub, NATS, or HTTP/SSE. A
reference `InMemoryTransport` is fine for tests and small deployments.

## Open questions

- **How do relays bootstrap?** Initial set shipped in config; later, relay
  discovery via a published directory signed by governance keys.
- **Should entries carry a proof of chronological order?** RFC 6962 Merkle
  tree consistency proofs would let a verifier check that a later head is
  a proper extension of an earlier one without replaying the whole log.
  Worth it once the log exceeds ~10k entries.
- **What's the story for air-gapped verifiers?** Export/import with a
  signed head and a time window; they trade latency for bandwidth.

## Relation to other limits

- **#2 (revocation log)** — already closed. This doc assumes that primitive.
- **#6 (key rotation)** — a relay's operator key may rotate; signed heads
  must reference `keyId` so old signatures remain verifiable after rotation.

## Success criteria (for the eventual implementation)

1. Simulated network of 10 relays + 100 edge verifiers reaches 99% consistency
   within 5 seconds for a revocation originating at any relay.
2. A malicious relay that drops one revocation is detected within 30 seconds
   by any verifier that queries it + at least one honest relay.
3. `lastSyncAt` staleness refusal is wired into `verifyDelegation()` and
   tested in the attack harness (scenario #10 "revocation race").
