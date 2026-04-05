/**
 * Attack #6 — Double-spend fork against a budget caveat.
 *
 * Scenario:
 *   Alice grants Bob a delegation with a 100-credit budget cap and an
 *   associated spend log. Bob accumulates receipts up to sequence=2 and
 *   shows Alice the head (which she signs). Then Bob forks his log:
 *   against verifier V1, he presents the chain [r0, r1, r2]. Against
 *   verifier V2, he presents an alternate chain [r0, r1', r2'] with
 *   different amounts but the same sequence. Each chain is internally
 *   consistent and signed by Bob, so each chain passes in isolation.
 *
 * Defense: the delegation issuer (Alice) signs the head at each point she
 * sees. Given two SignedHeads at the same sequence with divergent hashes,
 * `detectDoubleSpend` produces a proof. Alice can then revoke the
 * delegation, slash stake, or hand the proof to a court.
 *
 * Primitives composed:
 *   spend-receipts · SpendLog · signSpendHead · detectDoubleSpend
 */

import { describe, it, expect } from "vitest";
import {
  SpendLog,
  signSpendHead,
  detectDoubleSpend,
  verifySpendHead,
} from "../../src/heart/spend-receipts.js";
import { makeIdentity } from "./_harness.js";

describe("Attack #6: double-spend fork detection", () => {
  it("two signed heads at the same sequence with different hashes yield a proof", () => {
    const alice = makeIdentity(); // delegation issuer
    const bob = makeIdentity();   // delegation subject

    const delegationId = "dg-fork-test-001";

    // Bob maintains two divergent logs (e.g., one per verifier).
    const logV1 = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const logV2 = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });

    // V1 sees: 20, 30 → cumulative 50 at seq=1
    logV1.append({ amount: 20, capability: "api:pay" });
    logV1.append({ amount: 30, capability: "api:pay" });

    // V2 sees: 40, 10 → cumulative 50 at seq=1 BUT different receipts
    // (different amounts, nonces, hashes)
    logV2.append({ amount: 40, capability: "api:pay" });
    logV2.append({ amount: 10, capability: "api:pay" });

    // Alice signs the head of each chain as she sees it (in real life,
    // each verifier asks Alice to confirm: V1 sends its view, V2 sends its
    // view, Alice produces signed commitments for both).
    const headV1 = signSpendHead({
      delegationId,
      sequence: 1,
      hash: logV1.head,
      cumulative: logV1.cumulative,
      issuerSigningKey: alice.signingKey,
      issuerPublicKey: alice.publicKeyBytes,
    });
    const headV2 = signSpendHead({
      delegationId,
      sequence: 1,
      hash: logV2.head,
      cumulative: logV2.cumulative,
      issuerSigningKey: alice.signingKey,
      issuerPublicKey: alice.publicKeyBytes,
    });

    // Each head verifies independently.
    expect(verifySpendHead(headV1).valid).toBe(true);
    expect(verifySpendHead(headV2).valid).toBe(true);

    // Different hashes at the same sequence = fork.
    expect(headV1.hash).not.toBe(headV2.hash);

    // detectDoubleSpend produces the proof.
    const proof = detectDoubleSpend(headV1, headV2);
    expect(proof).not.toBeNull();
    expect(proof!.delegationId).toBe(delegationId);
    expect(proof!.sequence).toBe(1);
    expect(proof!.commitmentA.hash).not.toBe(proof!.commitmentB.hash);
  });

  it("detectDoubleSpend returns null when chains agree", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const delegationId = "dg-no-fork-002";

    const log = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    log.append({ amount: 10, capability: "api:pay" });
    log.append({ amount: 20, capability: "api:pay" });

    const snapshot = {
      delegationId,
      sequence: 1,
      hash: log.head,
      cumulative: log.cumulative,
    };
    const headA = signSpendHead({
      ...snapshot,
      issuerSigningKey: alice.signingKey,
      issuerPublicKey: alice.publicKeyBytes,
    });
    const headB = signSpendHead({
      ...snapshot,
      issuerSigningKey: alice.signingKey,
      issuerPublicKey: alice.publicKeyBytes,
    });
    // Same hash, same sequence — not a fork. (Different `signedAt` and nonce
    // within the head are allowed; detectDoubleSpend cares about divergence.)
    expect(detectDoubleSpend(headA, headB)).toBeNull();
  });

  it("fraudulent verifier cannot manufacture a fake fork with its own signature", () => {
    const alice = makeIdentity(); // real issuer
    const bob = makeIdentity();
    const eve = makeIdentity(); // attacker tries to frame bob

    const delegationId = "dg-frame-bob-003";

    const log = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    log.append({ amount: 10, capability: "api:pay" });
    log.append({ amount: 20, capability: "api:pay" });

    // Alice's legitimate head.
    const legit = signSpendHead({
      delegationId,
      sequence: 1,
      hash: log.head,
      cumulative: log.cumulative,
      issuerSigningKey: alice.signingKey,
      issuerPublicKey: alice.publicKeyBytes,
    });
    // Eve fabricates a second head SIGNED BY HERSELF, claiming it's Alice's
    // commitment to a divergent view.
    const forged = signSpendHead({
      delegationId,
      sequence: 1,
      hash: "forged-hash-eve-is-lying",
      cumulative: log.cumulative,
      issuerSigningKey: eve.signingKey,
      issuerPublicKey: eve.publicKeyBytes,
    });
    // detectDoubleSpend checks issuerDid parity — issuer DIDs differ → null.
    const proof = detectDoubleSpend(legit, forged);
    expect(proof).toBeNull();
  });

  it("an imported chain that mutates a receipt fails verification", () => {
    const bob = makeIdentity();
    const delegationId = "dg-tamper-receipt-004";

    const original = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    original.append({ amount: 10, capability: "api:pay" });
    original.append({ amount: 20, capability: "api:pay" });

    const entries = [...original.getEntries()];
    // Tamper: inflate the first amount (but keep the hash chain as-is).
    const tampered = [
      { ...entries[0], amount: 9999, cumulative: 9999 },
      entries[1],
    ];
    const fresh = new SpendLog({
      delegationId,
      subjectSigningKey: bob.signingKey,
      subjectPublicKey: bob.publicKeyBytes,
    });
    const importResult = fresh.replaceWith(tampered);
    expect(importResult.valid).toBe(false);
  });
});
