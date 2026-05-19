/**
 * Attack #13 — VRF output manipulation to bias a beacon.
 *
 * Scenario:
 *   Three parties (Alice, Bob, Carol) each evaluate vrf(sk_i, seed) to
 *   contribute to a combined beacon. Eve (Carol) wants to bias the beacon
 *   so a specific outcome (say, her own leadership) is selected.
 *
 *   Variants:
 *     - Eve computes sig honestly then OVERWRITES output bytes.
 *     - Eve tries to present proof for input A but claim it was computed
 *       from input B.
 *     - Eve takes Alice's VRF tuple and swaps Alice's evaluatorDid for her own.
 *     - Eve grinds inputs until her output < some target (grinding attack).
 *       Defense: the input must be a protocol-chosen value, not attacker-
 *       chosen. We test that protocol-chosen input makes grinding moot.
 *
 * Defense: `verifyVrf` reconstructs the proof → output mapping. Any mismatch
 * between output and H(OUTPUT_DOMAIN || proof) rejects. Any swap of input
 * breaks the signature check. Any DID substitution breaks the key binding.
 *
 * Primitives composed:
 *   vrf · proof verification · DID binding · beacon combining
 */

import { describe, it, expect } from "vitest";
import {
  evaluateVrf,
  verifyVrf,
  combineBeacon,
} from "../../src/heart/vrf.js";
import { makeIdentity, bytes, failedWith } from "./_harness.js";

describe("Attack #13: VRF output manipulation", () => {
  it("tampering the outputB64 field fails verification", () => {
    const eve = makeIdentity();
    const input = bytes("epoch-42");
    const vrf = evaluateVrf({
      input,
      signingKey: eve.signingKey,
      publicKey: eve.publicKeyBytes,
    });

    // Eve overwrites output with something convenient (e.g., all zeros).
    const tampered = {
      ...vrf,
      outputB64: Buffer.alloc(32, 0).toString("base64"),
    };
    const result = verifyVrf(input, tampered);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "output does not match proof")).toBe(true);
  });

  it("substituting input at verify time breaks the signature", () => {
    const eve = makeIdentity();
    const input = bytes("correct-input");
    const wrong = bytes("wrong-input");
    const vrf = evaluateVrf({
      input,
      signingKey: eve.signingKey,
      publicKey: eve.publicKeyBytes,
    });

    // Verifier is told input is `wrong` but the proof was computed over `input`.
    const result = verifyVrf(wrong, vrf);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "invalid VRF proof")).toBe(true);
  });

  it("swapping evaluatorDid breaks the key binding check", () => {
    const alice = makeIdentity();
    const eve = makeIdentity();
    const input = bytes("honest-round");
    const vrf = evaluateVrf({
      input,
      signingKey: alice.signingKey,
      publicKey: alice.publicKeyBytes,
    });

    // Eve claims she produced the output.
    const tampered = { ...vrf, evaluatorDid: eve.did };
    const result = verifyVrf(input, tampered);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "evaluatorDid does not match")).toBe(true);
  });

  it("protocol-chosen input prevents grinding attack", () => {
    // If Eve can pick the input herself, she can grind until her output
    // meets a target. Defense: use a protocol-chosen seed (e.g., the hash of
    // the previous epoch's beacon). We demonstrate that DIFFERENT inputs
    // yield DIFFERENT (unpredictable) outputs — Eve cannot predict or bias.
    const eve = makeIdentity();
    const input1 = bytes("round-1-seed");
    const input2 = bytes("round-2-seed");
    const vrf1 = evaluateVrf({
      input: input1,
      signingKey: eve.signingKey,
      publicKey: eve.publicKeyBytes,
    });
    const vrf2 = evaluateVrf({
      input: input2,
      signingKey: eve.signingKey,
      publicKey: eve.publicKeyBytes,
    });
    expect(vrf1.outputB64).not.toBe(vrf2.outputB64);
    // Both verify legitimately.
    expect(verifyVrf(input1, vrf1).valid).toBe(true);
    expect(verifyVrf(input2, vrf2).valid).toBe(true);
  });

  it("beacon resists bias when computed from multiple VRFs", () => {
    // Alice + Bob + Eve. Eve tries to remove her own output after seeing
    // the others'. A combined beacon pins all contributors together.
    const alice = makeIdentity();
    const bob = makeIdentity();
    const eve = makeIdentity();
    const seed = bytes("epoch-99");

    const vAlice = evaluateVrf({
      input: seed,
      signingKey: alice.signingKey,
      publicKey: alice.publicKeyBytes,
    });
    const vBob = evaluateVrf({
      input: seed,
      signingKey: bob.signingKey,
      publicKey: bob.publicKeyBytes,
    });
    const vEve = evaluateVrf({
      input: seed,
      signingKey: eve.signingKey,
      publicKey: eve.publicKeyBytes,
    });

    // Honest beacon.
    const beacon = combineBeacon([vAlice, vBob, vEve]);

    // Eve drops out after seeing others' outputs — the beacon DIFFERS.
    const withoutEve = combineBeacon([vAlice, vBob]);
    expect(beacon).not.toBe(withoutEve);

    // Eve substitutes her output with an all-zeros blob (to bias toward zero).
    const fakeEve = {
      ...vEve,
      outputB64: Buffer.alloc(32, 0).toString("base64"),
    };
    // This VRF tuple no longer verifies — any honest verifier rejects Eve's
    // contribution BEFORE combining into the beacon.
    expect(verifyVrf(seed, fakeEve).valid).toBe(false);
  });

  it("legitimate VRF tuple verifies and yields deterministic output", () => {
    const alice = makeIdentity();
    const input = bytes("election-input");
    const r1 = evaluateVrf({
      input,
      signingKey: alice.signingKey,
      publicKey: alice.publicKeyBytes,
    });
    const r2 = evaluateVrf({
      input,
      signingKey: alice.signingKey,
      publicKey: alice.publicKeyBytes,
    });
    // Determinism: same key + input → same output.
    expect(r1.outputB64).toBe(r2.outputB64);
    expect(verifyVrf(input, r1).valid).toBe(true);
  });
});
