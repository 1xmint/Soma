/**
 * Attack #15 — Spend log tampering via hash-chain mutation.
 *
 * Scenario:
 *   Bob holds a delegation with a 1000-credit budget. He spends receipts
 *   r0 (100), r1 (200), r2 (300) → cumulative 600. Eve acquires a copy of
 *   his log and tries to tamper to save credits for herself:
 *     - Zero out r0's amount (pretend nothing was spent).
 *     - Reduce amounts but leave the chain structure intact.
 *     - Swap r1 and r2 order (claim r2 spent first).
 *     - Re-append a "zero-sum" corrective receipt to fake cumulative rewind.
 *     - Splice in a receipt signed by a DIFFERENT subject.
 *
 * Defense: each receipt is subject-signed, hash-chained, and carries an
 * explicit `cumulative` that must match `prev.cumulative + amount`. Any
 * mutation breaks one of: signature, hash chain linkage, cumulative math,
 * or subjectPublicKey binding.
 *
 * Primitives composed:
 *   spend-receipts · hash chain · subject signature · cumulative math
 */

import { describe, it, expect } from "vitest";
import { SpendLog } from "../../src/heart/spend-receipts.js";
import { makeIdentity } from "./_harness.js";

function buildLog(
  subject: { signingKey: Uint8Array; publicKeyBytes: Uint8Array },
  delegationId: string,
  amounts: number[],
) {
  const log = new SpendLog({
    delegationId,
    subjectSigningKey: subject.signingKey,
    subjectPublicKey: subject.publicKeyBytes,
  });
  for (const a of amounts) {
    log.append({ amount: a, capability: "api:pay" });
  }
  return log;
}

describe("Attack #15: spend log tampering", () => {
  it("zeroing an amount breaks cumulative math", () => {
    const bob = makeIdentity();
    const log = buildLog(bob, "dg-zero-001", [100, 200, 300]);
    const entries = [...log.getEntries()];
    // Eve rewrites r0.amount to 0 (and ALSO cumulative to 0, then cascades).
    const tampered = [
      { ...entries[0], amount: 0, cumulative: 0 },
      { ...entries[1], cumulative: 200 },
      { ...entries[2], cumulative: 500 },
    ];
    const fresh = new SpendLog({
      delegationId: "dg-zero-001",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(tampered);
    expect(result.valid).toBe(false);
  });

  it("swapping receipt order breaks previousHash linkage", () => {
    const bob = makeIdentity();
    const log = buildLog(bob, "dg-swap-002", [100, 200]);
    const entries = [...log.getEntries()];
    // Swap r0 and r1.
    const swapped = [
      { ...entries[1], sequence: 0 },
      { ...entries[0], sequence: 1 },
    ];
    const fresh = new SpendLog({
      delegationId: "dg-swap-002",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(swapped);
    expect(result.valid).toBe(false);
  });

  it("splicing a receipt signed by a different subject fails", () => {
    const bob = makeIdentity();
    const eve = makeIdentity();
    const log = buildLog(bob, "dg-splice-003", [100]);
    const eveLog = buildLog(eve, "dg-splice-003", [50]);

    const mixedEntries = [
      log.getEntries()[0],
      eveLog.getEntries()[0], // wrong subject, even though same delegationId
    ];
    const fresh = new SpendLog({
      delegationId: "dg-splice-003",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(mixedEntries);
    expect(result.valid).toBe(false);
  });

  it("mutating a receipt's signature breaks signature verification", () => {
    const bob = makeIdentity();
    const log = buildLog(bob, "dg-sigtamper-004", [100, 200]);
    const entries = [...log.getEntries()];
    const tampered = [
      {
        ...entries[0],
        subjectSignature: Buffer.alloc(64, 0).toString("base64"),
      },
      entries[1],
    ];
    const fresh = new SpendLog({
      delegationId: "dg-sigtamper-004",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(tampered);
    expect(result.valid).toBe(false);
  });

  it("inserting a receipt from a different delegationId fails", () => {
    const bob = makeIdentity();
    const log1 = buildLog(bob, "dg-A-005", [100]);
    const log2 = buildLog(bob, "dg-B-005", [100]);

    // Eve glues log2's receipt into log1's chain.
    const mixed = [log1.getEntries()[0], log2.getEntries()[0]];
    const fresh = new SpendLog({
      delegationId: "dg-A-005",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(mixed);
    expect(result.valid).toBe(false);
  });

  it("a full untampered chain verifies round-trip through replaceWith", () => {
    const bob = makeIdentity();
    const log = buildLog(bob, "dg-roundtrip-006", [100, 200, 300]);
    const entries = [...log.getEntries()];
    expect(log.cumulative).toBe(600);
    const fresh = new SpendLog({
      delegationId: "dg-roundtrip-006",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith(entries);
    expect(result.valid).toBe(true);
    expect(fresh.cumulative).toBe(600);
  });

  it("imported chain from a different delegationId's genesis fails", () => {
    const bob = makeIdentity();
    const logA = buildLog(bob, "dg-GENESIS-A", [100, 200]);
    // Try to import A's entries into a B log (different delegationId →
    // different genesisHash → first receipt's previousHash won't match).
    const fresh = new SpendLog({
      delegationId: "dg-GENESIS-B",
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const result = fresh.replaceWith([...logA.getEntries()]);
    expect(result.valid).toBe(false);
  });
});
