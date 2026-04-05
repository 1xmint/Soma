import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import { createRevocation } from "../../src/heart/revocation.js";
import { RevocationLog, type LogHead } from "../../src/heart/revocation-log.js";
import {
  InMemoryTransport,
  GossipPeer,
  type GossipMessage,
} from "../../src/heart/gossip.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKeyB64: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function makeRev(targetId: string, issuer = makeIdentity()) {
  return createRevocation({
    targetId,
    targetKind: "delegation",
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKeyB64,
    issuerSigningKey: issuer.kp.secretKey,
    reason: "rotated",
  });
}

function buildPeer() {
  const operator = makeIdentity();
  const transport = new InMemoryTransport();
  const log = new RevocationLog();
  let clock = 1000;
  const peer = new GossipPeer({
    transport,
    log,
    operatorSigningKey: operator.kp.secretKey,
    operatorPublicKey: operator.kp.publicKey,
    now: () => clock,
  });
  return {
    peer,
    log,
    transport,
    operator,
    advance: (ms: number) => {
      clock += ms;
    },
    setClock: (t: number) => {
      clock = t;
    },
    clock: () => clock,
  };
}

describe("InMemoryTransport", () => {
  it("broadcasts to all subscribers", async () => {
    const t = new InMemoryTransport();
    const received1: GossipMessage[] = [];
    const received2: GossipMessage[] = [];
    t.subscribe((m) => void received1.push(m));
    t.subscribe((m) => void received2.push(m));

    const issuer = makeIdentity();
    const rev = makeRev("dg-1", issuer);
    const log = new RevocationLog();
    const entry = log.append(rev);
    await t.publish({ kind: "revocation", entry });

    expect(received1.length).toBe(1);
    expect(received2.length).toBe(1);
  });

  it("unsubscribe stops delivery", async () => {
    const t = new InMemoryTransport();
    const got: GossipMessage[] = [];
    const unsub = t.subscribe((m) => void got.push(m));

    const operator = makeIdentity();
    const log = new RevocationLog();
    const head = log.signHead(operator.kp.secretKey, operator.kp.publicKey);
    await t.publish({ kind: "head", head });
    expect(got.length).toBe(1);

    unsub();
    await t.publish({ kind: "head", head });
    expect(got.length).toBe(1); // no further delivery
  });

  it("continues delivering when one subscriber throws", async () => {
    const t = new InMemoryTransport();
    const got: GossipMessage[] = [];
    t.subscribe(() => {
      throw new Error("boom");
    });
    t.subscribe((m) => void got.push(m));

    const operator = makeIdentity();
    const log = new RevocationLog();
    const head = log.signHead(operator.kp.secretKey, operator.kp.publicKey);
    await t.publish({ kind: "head", head });
    expect(got.length).toBe(1);
  });
});

describe("GossipPeer — propagation", () => {
  it("two peers on the same transport sync a revocation", async () => {
    const transport = new InMemoryTransport();
    const opA = makeIdentity();
    const opB = makeIdentity();
    const logA = new RevocationLog();
    const logB = new RevocationLog();
    const peerA = new GossipPeer({
      transport,
      log: logA,
      operatorSigningKey: opA.kp.secretKey,
      operatorPublicKey: opA.kp.publicKey,
    });
    const peerB = new GossipPeer({
      transport,
      log: logB,
      operatorSigningKey: opB.kp.secretKey,
      operatorPublicKey: opB.kp.publicKey,
    });
    peerA.start();
    peerB.start();

    // A appends locally, publishes
    const entry = logA.append(makeRev("dg-1"));
    await peerA.publishRevocation(entry);

    expect(logB.length).toBe(1);
    expect(logB.isRevoked("dg-1")).toBe(true);
  });

  it("drops revocations arriving out of order", async () => {
    const transport = new InMemoryTransport();
    const opA = makeIdentity();
    const logA = new RevocationLog();
    const logB = new RevocationLog();
    const peerB = new GossipPeer({
      transport,
      log: logB,
      operatorSigningKey: opA.kp.secretKey,
      operatorPublicKey: opA.kp.publicKey,
    });
    peerB.start();

    // A appends two events but we publish out of order
    const e1 = logA.append(makeRev("dg-1"));
    const e2 = logA.append(makeRev("dg-2"));
    // Publish e2 first — B's log is empty, e2.sequence=1 ≠ 0, drop
    await transport.publish({ kind: "revocation", entry: e2 });
    expect(logB.length).toBe(0);
    // Then publish e1 — B's log expects sequence 0, accept
    await transport.publish({ kind: "revocation", entry: e1 });
    expect(logB.length).toBe(1);
    // Now e2 expected at sequence 1 — re-publish
    await transport.publish({ kind: "revocation", entry: e2 });
    expect(logB.length).toBe(2);
  });

  it("ignores revocations with bad signatures", async () => {
    const transport = new InMemoryTransport();
    const opA = makeIdentity();
    const logA = new RevocationLog();
    const logB = new RevocationLog();
    const peerB = new GossipPeer({
      transport,
      log: logB,
      operatorSigningKey: opA.kp.secretKey,
      operatorPublicKey: opA.kp.publicKey,
    });
    peerB.start();

    const entry = logA.append(makeRev("dg-1"));
    const tampered = {
      ...entry,
      revocation: {
        ...entry.revocation,
        signature: entry.revocation.signature.replace(
          /^./,
          (c) => (c === "A" ? "B" : "A"),
        ),
      },
    };
    await transport.publish({ kind: "revocation", entry: tampered });
    expect(logB.length).toBe(0);
  });
});

describe("GossipPeer — lastSyncAt + staleness", () => {
  it("lastSyncAt starts at 0 before any messages", () => {
    const { peer } = buildPeer();
    expect(peer.lastSyncAt).toBe(0);
  });

  it("lastSyncAt updates when a message arrives", async () => {
    const a = buildPeer();
    const b = buildPeer();
    // Wire peer b's transport so a can publish through its own transport
    // Actually they need the same transport. Rebuild:
    const transport = new InMemoryTransport();
    let clock = 5000;
    const op1 = makeIdentity();
    const op2 = makeIdentity();
    const peer1 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op1.kp.secretKey,
      operatorPublicKey: op1.kp.publicKey,
      now: () => clock,
    });
    const peer2 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op2.kp.secretKey,
      operatorPublicKey: op2.kp.publicKey,
      now: () => clock,
    });
    peer2.start();
    void a;
    void b;
    await peer1.publishHead();
    expect(peer2.lastSyncAt).toBe(5000);
    clock = 6000;
    await peer1.publishHead();
    expect(peer2.lastSyncAt).toBe(6000);
  });

  it("isStale returns true before any sync", () => {
    const { peer } = buildPeer();
    expect(peer.isStale(60_000)).toBe(true);
  });

  it("isStale true when no message within window", async () => {
    const transport = new InMemoryTransport();
    let clock = 1000;
    const op1 = makeIdentity();
    const op2 = makeIdentity();
    const peer1 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op1.kp.secretKey,
      operatorPublicKey: op1.kp.publicKey,
      now: () => clock,
    });
    const peer2 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op2.kp.secretKey,
      operatorPublicKey: op2.kp.publicKey,
      now: () => clock,
    });
    peer2.start();
    await peer1.publishHead();
    expect(peer2.isStale(1000)).toBe(false);
    clock += 2000;
    expect(peer2.isStale(1000)).toBe(true);
  });

  it("isStale false after message with room to spare", async () => {
    const transport = new InMemoryTransport();
    let clock = 1000;
    const op1 = makeIdentity();
    const op2 = makeIdentity();
    const peer1 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op1.kp.secretKey,
      operatorPublicKey: op1.kp.publicKey,
      now: () => clock,
    });
    const peer2 = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op2.kp.secretKey,
      operatorPublicKey: op2.kp.publicKey,
      now: () => clock,
    });
    peer2.start();
    await peer1.publishHead();
    clock += 100;
    expect(peer2.isStale(1000)).toBe(false);
  });
});

describe("GossipPeer — divergence detection", () => {
  it("detects fork: same authority signs two conflicting heads", async () => {
    const transport = new InMemoryTransport();
    const opFork = makeIdentity(); // the forking authority
    const opLocal = makeIdentity();
    const peer = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: opLocal.kp.secretKey,
      operatorPublicKey: opLocal.kp.publicKey,
    });
    peer.start();
    expect(peer.getDivergenceReport()).toBeNull();

    // Fabricate two log instances for the same authority, different content
    const logA = new RevocationLog();
    logA.append(makeRev("dg-A"));
    const headA: LogHead = logA.signHead(
      opFork.kp.secretKey,
      opFork.kp.publicKey,
    );
    const logB = new RevocationLog();
    logB.append(makeRev("dg-B"));
    const headB: LogHead = logB.signHead(
      opFork.kp.secretKey,
      opFork.kp.publicKey,
    );
    expect(headA.sequence).toBe(0);
    expect(headB.sequence).toBe(0);
    expect(headA.hash).not.toBe(headB.hash);

    await transport.publish({ kind: "head", head: headA });
    expect(peer.getDivergenceReport()).toBeNull();
    await transport.publish({ kind: "head", head: headB });
    const d = peer.getDivergenceReport();
    expect(d).not.toBeNull();
    expect(d?.operatorDid).toBe(opFork.did);
    expect(d?.sequence).toBe(0);
  });

  it("does not flag same-hash heads as divergence", async () => {
    const transport = new InMemoryTransport();
    const opRelay = makeIdentity();
    const opLocal = makeIdentity();
    const peer = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: opLocal.kp.secretKey,
      operatorPublicKey: opLocal.kp.publicKey,
    });
    peer.start();

    const log = new RevocationLog();
    log.append(makeRev("dg-X"));
    const head1 = log.signHead(opRelay.kp.secretKey, opRelay.kp.publicKey);
    // Wait a millisecond conceptually and sign again — timestamps differ but
    // sequence + hash are stable. We'll set signedAt differently by building
    // a second head; the hashes here WILL differ because signedAt differs.
    // So this test instead: publish the SAME head twice.
    await transport.publish({ kind: "head", head: head1 });
    await transport.publish({ kind: "head", head: head1 });
    expect(peer.getDivergenceReport()).toBeNull();
  });

  it("ignores heads with bad signatures", async () => {
    const transport = new InMemoryTransport();
    const opLocal = makeIdentity();
    const peer = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: opLocal.kp.secretKey,
      operatorPublicKey: opLocal.kp.publicKey,
    });
    peer.start();

    const opOther = makeIdentity();
    const log = new RevocationLog();
    const head = log.signHead(opOther.kp.secretKey, opOther.kp.publicKey);
    const tampered: LogHead = { ...head, hash: "Z".repeat(64) };
    await transport.publish({ kind: "head", head: tampered });
    expect(peer.getHeadsFromAuthority(opOther.did).length).toBe(0);
  });

  it("tracks heads per authority", async () => {
    const transport = new InMemoryTransport();
    const opLocal = makeIdentity();
    const peer = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: opLocal.kp.secretKey,
      operatorPublicKey: opLocal.kp.publicKey,
    });
    peer.start();

    const op1 = makeIdentity();
    const op2 = makeIdentity();
    const log1 = new RevocationLog();
    const log2 = new RevocationLog();
    const h1 = log1.signHead(op1.kp.secretKey, op1.kp.publicKey);
    const h2 = log2.signHead(op2.kp.secretKey, op2.kp.publicKey);
    await transport.publish({ kind: "head", head: h1 });
    await transport.publish({ kind: "head", head: h2 });

    expect(peer.getHeadsFromAuthority(op1.did).length).toBe(1);
    expect(peer.getHeadsFromAuthority(op2.did).length).toBe(1);
  });
});

describe("GossipPeer — trusted authorities", () => {
  it("isAuthorityTrusted returns true when no allowlist", () => {
    const { peer, operator } = buildPeer();
    expect(peer.isAuthorityTrusted(operator.did)).toBe(true);
    expect(peer.isAuthorityTrusted("did:key:z-anything")).toBe(true);
  });

  it("isAuthorityTrusted enforces allowlist", () => {
    const transport = new InMemoryTransport();
    const op = makeIdentity();
    const trusted = makeIdentity();
    const peer = new GossipPeer({
      transport,
      log: new RevocationLog(),
      operatorSigningKey: op.kp.secretKey,
      operatorPublicKey: op.kp.publicKey,
      trustedAuthorities: [trusted.did],
    });
    expect(peer.isAuthorityTrusted(trusted.did)).toBe(true);
    expect(peer.isAuthorityTrusted("did:key:z-rogue")).toBe(false);
  });
});

describe("GossipPeer — stop/start", () => {
  it("stop() unsubscribes from transport", async () => {
    const transport = new InMemoryTransport();
    const op = makeIdentity();
    const log = new RevocationLog();
    const peer = new GossipPeer({
      transport,
      log,
      operatorSigningKey: op.kp.secretKey,
      operatorPublicKey: op.kp.publicKey,
    });
    peer.start();

    const source = new RevocationLog();
    const entry = source.append(makeRev("dg-1"));
    await transport.publish({ kind: "revocation", entry });
    expect(log.length).toBe(1);

    peer.stop();
    const entry2 = source.append(makeRev("dg-2"));
    await transport.publish({ kind: "revocation", entry: entry2 });
    expect(log.length).toBe(1); // no delivery after stop
  });

  it("start() is idempotent", () => {
    const { peer } = buildPeer();
    peer.start();
    peer.start(); // should not throw or duplicate subscriptions
    peer.stop();
  });
});
