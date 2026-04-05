import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import { createRevocation } from "../../src/heart/revocation.js";
import type { RevocationEvent } from "../../src/heart/revocation.js";
import {
  RevocationLog,
  type RevocationLogEntry,
} from "../../src/heart/revocation-log.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function makeRevocation(targetId: string, issuer = makeIdentity()): RevocationEvent {
  return createRevocation({
    targetId,
    targetKind: "delegation",
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKey,
    issuerSigningKey: issuer.kp.secretKey,
    reason: "rotated",
  });
}

describe("RevocationLog — append + chain integrity", () => {
  it("appends revocations with monotonic sequence", () => {
    const log = new RevocationLog();
    const e1 = log.append(makeRevocation("dg-1"));
    const e2 = log.append(makeRevocation("dg-2"));
    const e3 = log.append(makeRevocation("dg-3"));

    expect(e1.sequence).toBe(0);
    expect(e2.sequence).toBe(1);
    expect(e3.sequence).toBe(2);
    expect(log.length).toBe(3);
  });

  it("chains entries via previousHash", () => {
    const log = new RevocationLog();
    const e1 = log.append(makeRevocation("dg-1"));
    const e2 = log.append(makeRevocation("dg-2"));

    expect(e1.previousHash).toBe(log.genesisHash);
    expect(e2.previousHash).toBe(e1.hash);
  });

  it("head advances on each append", () => {
    const log = new RevocationLog();
    expect(log.head).toBe(log.genesisHash);
    const e1 = log.append(makeRevocation("dg-1"));
    expect(log.head).toBe(e1.hash);
    const e2 = log.append(makeRevocation("dg-2"));
    expect(log.head).toBe(e2.hash);
  });

  it("verify() passes on an untouched log", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    log.append(makeRevocation("dg-2"));
    log.append(makeRevocation("dg-3"));
    expect(log.verify().valid).toBe(true);
  });

  it("isRevoked() reflects appended targets", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-X"));
    expect(log.isRevoked("dg-X")).toBe(true);
    expect(log.isRevoked("dg-Y")).toBe(false);
  });
});

describe("RevocationLog — tamper detection", () => {
  it("detects a dropped entry (chain breaks)", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    log.append(makeRevocation("dg-2"));
    log.append(makeRevocation("dg-3"));

    // Attacker drops entry 1 (index 1) from an exported log
    const entries = [...log.getEntries()];
    entries.splice(1, 1);

    const check = RevocationLog.verifyEntries(entries);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/sequence|previousHash/);
  });

  it("detects reordered entries", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    log.append(makeRevocation("dg-2"));
    log.append(makeRevocation("dg-3"));

    const entries = [...log.getEntries()];
    // Swap entries 0 and 2 (and nothing else — attacker doesn't recompute hashes)
    [entries[0], entries[2]] = [entries[2], entries[0]];

    const check = RevocationLog.verifyEntries(entries);
    expect(check.valid).toBe(false);
  });

  it("detects a tampered entry hash", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    log.append(makeRevocation("dg-2"));

    const entries: RevocationLogEntry[] = [...log.getEntries()].map((e, i) =>
      i === 1 ? { ...e, hash: "X".repeat(64) } : e,
    );
    const check = RevocationLog.verifyEntries(entries);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("hash mismatch");
  });

  it("rejects appending a revocation with a bad signature", () => {
    const log = new RevocationLog();
    // Use a same-length but bytes-wrong signature so we hit our own check,
    // not the provider's size pre-check.
    const orig = makeRevocation("dg-1");
    const flipped = orig.signature.replace(/^./, (c) => (c === "A" ? "B" : "A"));
    const bad = { ...orig, signature: flipped };
    expect(() => log.append(bad)).toThrow(/cannot append/);
  });

  it("rejects duplicate targetId in append", () => {
    const log = new RevocationLog();
    log.append(makeRevocation("dg-DUP"));
    expect(() => log.append(makeRevocation("dg-DUP"))).toThrow(/already revoked/);
  });
});

describe("RevocationLog — signed heads", () => {
  it("operator signs head, verifiers can verify it", () => {
    const operator = makeIdentity();
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    log.append(makeRevocation("dg-2"));

    const head = log.signHead(operator.kp.secretKey, operator.kp.publicKey);
    expect(head.sequence).toBe(1);
    expect(head.hash).toBe(log.head);
    expect(head.operatorDid).toBe(operator.did);

    const check = RevocationLog.verifyHead(head);
    expect(check.valid).toBe(true);
  });

  it("detects a forged head signature", () => {
    const operator = makeIdentity();
    const log = new RevocationLog();
    log.append(makeRevocation("dg-1"));
    const head = log.signHead(operator.kp.secretKey, operator.kp.publicKey);
    const tampered = { ...head, hash: "Z".repeat(64) };
    const check = RevocationLog.verifyHead(tampered);
    expect(check.valid).toBe(false);
  });

  it("empty log produces head at genesis (sequence=-1)", () => {
    const operator = makeIdentity();
    const log = new RevocationLog();
    const head = log.signHead(operator.kp.secretKey, operator.kp.publicKey);
    expect(head.sequence).toBe(-1);
    expect(head.hash).toBe(log.genesisHash);
    expect(RevocationLog.verifyHead(head).valid).toBe(true);
  });
});

describe("RevocationLog — import/export + reconciliation", () => {
  it("replaceWith() accepts a valid chain and rejects a tampered one", () => {
    const source = new RevocationLog();
    source.append(makeRevocation("dg-A"));
    source.append(makeRevocation("dg-B"));
    const exported = [...source.getEntries()];

    const dest = new RevocationLog();
    const ok = dest.replaceWith(exported);
    expect(ok.valid).toBe(true);
    expect(dest.length).toBe(2);
    expect(dest.head).toBe(source.head);

    // Now try importing a tampered version into a fresh log
    const dest2 = new RevocationLog();
    const tampered = exported.map((e, i) => (i === 0 ? { ...e, hash: "X" } : e));
    const bad = dest2.replaceWith(tampered);
    expect(bad.valid).toBe(false);
    // Destination log is untouched (still empty)
    expect(dest2.length).toBe(0);
  });

  it("two peers can detect divergence via signed heads", () => {
    // Peer A has [1, 2, 3]. Peer B has [1, 2] and signs head committing to seq=1.
    // Later B claims they have [1, 2, 3] with a head committing to seq=2.
    // Anyone holding B's earlier signed head can prove divergence (sequence=1 then claim=2 but same events).
    const operator = makeIdentity();
    const b = new RevocationLog();
    b.append(makeRevocation("dg-1"));
    b.append(makeRevocation("dg-2"));
    const earlyHead = b.signHead(operator.kp.secretKey, operator.kp.publicKey);
    expect(earlyHead.sequence).toBe(1);

    b.append(makeRevocation("dg-3"));
    const laterHead = b.signHead(operator.kp.secretKey, operator.kp.publicKey);
    expect(laterHead.sequence).toBe(2);

    // Both heads are individually valid — divergence detection is a policy
    // question (compare earlyHead against B's current entries)
    expect(RevocationLog.verifyHead(earlyHead).valid).toBe(true);
    expect(RevocationLog.verifyHead(laterHead).valid).toBe(true);
    expect(earlyHead.hash).not.toBe(laterHead.hash);
  });
});
