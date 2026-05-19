import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  SpendLog,
  signSpendHead,
  verifySpendHead,
  detectDoubleSpend,
  type SpendReceipt,
} from "../../src/heart/spend-receipts.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  return { kp, did };
}

function makeLog(delegationId = "dg-test") {
  const subject = makeIdentity();
  const log = new SpendLog({
    delegationId,
    subjectSigningKey: subject.kp.secretKey,
    subjectPublicKey: subject.kp.publicKey,
  });
  return { log, subject };
}

describe("SpendLog — append + chain integrity", () => {
  it("appends receipts with monotonic sequence and correct cumulative", () => {
    const { log } = makeLog();
    const r0 = log.append({ amount: 10, capability: "tool:db" });
    const r1 = log.append({ amount: 25, capability: "tool:db" });
    const r2 = log.append({ amount: 7, capability: "tool:api" });

    expect(r0.sequence).toBe(0);
    expect(r1.sequence).toBe(1);
    expect(r2.sequence).toBe(2);
    expect(r0.cumulative).toBe(10);
    expect(r1.cumulative).toBe(35);
    expect(r2.cumulative).toBe(42);
    expect(log.cumulative).toBe(42);
    expect(log.length).toBe(3);
  });

  it("chains entries via previousHash", () => {
    const { log } = makeLog();
    const r0 = log.append({ amount: 1, capability: "x" });
    const r1 = log.append({ amount: 1, capability: "x" });
    expect(r0.previousHash).toBe(log.genesisHash);
    expect(r1.previousHash).toBe(r0.hash);
  });

  it("head advances on each append", () => {
    const { log } = makeLog();
    expect(log.head).toBe(log.genesisHash);
    const r0 = log.append({ amount: 1, capability: "x" });
    expect(log.head).toBe(r0.hash);
    const r1 = log.append({ amount: 1, capability: "x" });
    expect(log.head).toBe(r1.hash);
  });

  it("genesis hash binds delegationId — different delegations produce different genesis", () => {
    const { log: a } = makeLog("dg-A");
    const { log: b } = makeLog("dg-B");
    expect(a.genesisHash).not.toBe(b.genesisHash);
  });

  it("verify() passes on untouched log", () => {
    const { log } = makeLog();
    log.append({ amount: 5, capability: "tool:x" });
    log.append({ amount: 15, capability: "tool:y" });
    expect(log.verify().valid).toBe(true);
  });

  it("rejects non-positive amounts", () => {
    const { log } = makeLog();
    expect(() => log.append({ amount: 0, capability: "x" })).toThrow(/positive/);
    expect(() => log.append({ amount: -5, capability: "x" })).toThrow(/positive/);
    expect(() => log.append({ amount: NaN, capability: "x" })).toThrow(/positive/);
  });

  it("wouldExceed correctly predicts budget exhaustion", () => {
    const { log } = makeLog();
    log.append({ amount: 800, capability: "x" });
    expect(log.wouldExceed(100, 1000)).toBe(false); // 800+100 ≤ 1000
    expect(log.wouldExceed(200, 1000)).toBe(false); // 800+200 = 1000 (boundary)
    expect(log.wouldExceed(201, 1000)).toBe(true);  // 800+201 > 1000
  });
});

describe("SpendLog — tamper detection", () => {
  it("detects an altered amount", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 10, capability: "x" });
    log.append({ amount: 20, capability: "x" });

    const entries: SpendReceipt[] = [...log.getEntries()].map((e, i) =>
      i === 1 ? { ...e, amount: 500 } : e,
    );
    const check = SpendLog.verifyChain(entries, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
  });

  it("detects a tampered cumulative", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 10, capability: "x" });
    log.append({ amount: 20, capability: "x" });

    const entries: SpendReceipt[] = [...log.getEntries()].map((e, i) =>
      i === 1 ? { ...e, cumulative: 5 } : e,
    );
    const check = SpendLog.verifyChain(entries, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("cumulative");
  });

  it("detects a dropped receipt (chain breaks)", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 1, capability: "x" });
    log.append({ amount: 1, capability: "x" });
    log.append({ amount: 1, capability: "x" });

    const entries = [...log.getEntries()];
    entries.splice(1, 1);
    const check = SpendLog.verifyChain(entries, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/sequence|previousHash/);
  });

  it("detects reordered receipts", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 1, capability: "x" });
    log.append({ amount: 2, capability: "x" });
    log.append({ amount: 3, capability: "x" });

    const entries = [...log.getEntries()];
    [entries[0], entries[2]] = [entries[2], entries[0]];
    const check = SpendLog.verifyChain(entries, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
  });

  it("detects a forged signature", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 1, capability: "x" });
    const entries = [...log.getEntries()];
    const bad = entries[0].subjectSignature.replace(
      /^./,
      (c) => (c === "A" ? "B" : "A"),
    );
    const tampered: SpendReceipt[] = [{ ...entries[0], subjectSignature: bad }];
    const check = SpendLog.verifyChain(tampered, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
  });

  it("detects subjectDid mismatch (chain from wrong holder)", () => {
    const { log } = makeLog();
    log.append({ amount: 1, capability: "x" });
    const wrongSubject = makeIdentity();
    const check = SpendLog.verifyChain([...log.getEntries()], {
      delegationId: log.delegationId,
      subjectDid: wrongSubject.did,
    });
    expect(check.valid).toBe(false);
  });

  it("detects delegationId mismatch (chain for wrong delegation)", () => {
    const { log, subject } = makeLog("dg-A");
    log.append({ amount: 1, capability: "x" });
    const check = SpendLog.verifyChain([...log.getEntries()], {
      delegationId: "dg-DIFFERENT",
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
  });

  it("detects swapped public key (real sig, wrong subject pubkey)", () => {
    const { log, subject } = makeLog();
    log.append({ amount: 1, capability: "x" });
    const other = makeIdentity();
    const entries = [...log.getEntries()];
    const tampered: SpendReceipt[] = [
      {
        ...entries[0],
        subjectPublicKey: crypto.encoding.encodeBase64(other.kp.publicKey),
      },
    ];
    const check = SpendLog.verifyChain(tampered, {
      delegationId: log.delegationId,
      subjectDid: subject.did,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain("subjectPublicKey");
  });
});

describe("SpendLog — import/export", () => {
  it("replaceWith() accepts a valid chain", () => {
    const { log: src, subject } = makeLog("dg-X");
    src.append({ amount: 5, capability: "x" });
    src.append({ amount: 7, capability: "y" });
    const exported = [...src.getEntries()];

    const dest = new SpendLog({
      delegationId: "dg-X",
      subjectSigningKey: subject.kp.secretKey,
      subjectPublicKey: subject.kp.publicKey,
    });
    const ok = dest.replaceWith(exported);
    expect(ok.valid).toBe(true);
    expect(dest.length).toBe(2);
    expect(dest.cumulative).toBe(12);
    expect(dest.head).toBe(src.head);
  });

  it("replaceWith() rejects a tampered chain and leaves log untouched", () => {
    const { log: src, subject } = makeLog("dg-X");
    src.append({ amount: 10, capability: "x" });
    const entries = [...src.getEntries()];
    const tampered: SpendReceipt[] = [{ ...entries[0], amount: 999 }];

    const dest = new SpendLog({
      delegationId: "dg-X",
      subjectSigningKey: subject.kp.secretKey,
      subjectPublicKey: subject.kp.publicKey,
    });
    const bad = dest.replaceWith(tampered);
    expect(bad.valid).toBe(false);
    expect(dest.length).toBe(0);
  });

  it("replaceWith() rejects chain for a different delegation", () => {
    const { log: src, subject } = makeLog("dg-A");
    src.append({ amount: 1, capability: "x" });
    const dest = new SpendLog({
      delegationId: "dg-B",
      subjectSigningKey: subject.kp.secretKey,
      subjectPublicKey: subject.kp.publicKey,
    });
    const result = dest.replaceWith([...src.getEntries()]);
    expect(result.valid).toBe(false);
  });
});

describe("signSpendHead + verifySpendHead", () => {
  it("issuer signs head, anyone verifies", () => {
    const { log } = makeLog("dg-H");
    log.append({ amount: 10, capability: "x" });
    log.append({ amount: 15, capability: "x" });

    const issuer = makeIdentity();
    const head = signSpendHead({
      delegationId: log.delegationId,
      sequence: log.length - 1,
      hash: log.head,
      cumulative: log.cumulative,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    expect(head.sequence).toBe(1);
    expect(head.cumulative).toBe(25);
    expect(head.issuerDid).toBe(issuer.did);
    expect(verifySpendHead(head).valid).toBe(true);
  });

  it("detects a forged head signature", () => {
    const { log } = makeLog();
    log.append({ amount: 1, capability: "x" });
    const issuer = makeIdentity();
    const head = signSpendHead({
      delegationId: log.delegationId,
      sequence: 0,
      hash: log.head,
      cumulative: 1,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    const tampered = { ...head, cumulative: 999 };
    expect(verifySpendHead(tampered).valid).toBe(false);
  });

  it("empty chain signs head at sequence=-1 and cumulative=0", () => {
    const { log } = makeLog("dg-empty");
    const issuer = makeIdentity();
    const head = signSpendHead({
      delegationId: log.delegationId,
      sequence: -1,
      hash: log.head,
      cumulative: 0,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    expect(head.sequence).toBe(-1);
    expect(head.hash).toBe(log.genesisHash);
    expect(verifySpendHead(head).valid).toBe(true);
  });
});

describe("detectDoubleSpend", () => {
  it("returns a proof when same issuer signs two conflicting heads", () => {
    const issuer = makeIdentity();
    const delegationId = "dg-FORK";

    // Two different chains for the same delegation+sequence
    const headA = signSpendHead({
      delegationId,
      sequence: 3,
      hash: "a".repeat(64),
      cumulative: 100,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    const headB = signSpendHead({
      delegationId,
      sequence: 3,
      hash: "b".repeat(64),
      cumulative: 150,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });

    const proof = detectDoubleSpend(headA, headB);
    expect(proof).not.toBeNull();
    expect(proof?.sequence).toBe(3);
    expect(proof?.delegationId).toBe(delegationId);
  });

  it("returns null when heads agree (same hash)", () => {
    const issuer = makeIdentity();
    const base = {
      delegationId: "dg-X",
      sequence: 1,
      hash: "c".repeat(64),
      cumulative: 10,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    };
    const a = signSpendHead(base);
    const b = signSpendHead(base);
    // Same sequence + same hash = no conflict
    expect(detectDoubleSpend(a, b)).toBeNull();
  });

  it("returns null when sequences differ (normal progression)", () => {
    const issuer = makeIdentity();
    const a = signSpendHead({
      delegationId: "dg-X",
      sequence: 1,
      hash: "a".repeat(64),
      cumulative: 10,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    const b = signSpendHead({
      delegationId: "dg-X",
      sequence: 2,
      hash: "b".repeat(64),
      cumulative: 20,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    expect(detectDoubleSpend(a, b)).toBeNull();
  });

  it("returns null when delegations differ", () => {
    const issuer = makeIdentity();
    const a = signSpendHead({
      delegationId: "dg-A",
      sequence: 1,
      hash: "a".repeat(64),
      cumulative: 10,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    const b = signSpendHead({
      delegationId: "dg-B",
      sequence: 1,
      hash: "b".repeat(64),
      cumulative: 10,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    expect(detectDoubleSpend(a, b)).toBeNull();
  });

  it("returns null when a head signature is bad", () => {
    const issuer = makeIdentity();
    const good = signSpendHead({
      delegationId: "dg-X",
      sequence: 1,
      hash: "a".repeat(64),
      cumulative: 10,
      issuerSigningKey: issuer.kp.secretKey,
      issuerPublicKey: issuer.kp.publicKey,
    });
    const bad = { ...good, hash: "b".repeat(64) }; // sig no longer matches
    expect(detectDoubleSpend(good, bad)).toBeNull();
  });
});
