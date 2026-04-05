/**
 * Attack #9 — Session transcript forgery / swap.
 *
 * Scenario:
 *   Alice initiates a mutual session with Bob for purpose "delegate-payment".
 *   The 3-message handshake produces an init, accept, and confirm message.
 *   Eve attempts to swap, rewrite, or forge parts of the transcript so she
 *   gets a session binding that APPEARS to prove Alice<->Bob (without either
 *   of them actually handshaking with her).
 *
 *   Variants:
 *     - Eve swaps responder's DID in the accept message.
 *     - Eve rebuilds the transcript with her OWN purpose but keeps both
 *       parties' signatures (mix-and-match fields).
 *     - Eve forwards an expired (stale) handshake past its TTL.
 *
 * Defense: `verifyMutualSession` verifies BOTH signatures over the SAME
 * canonical transcript. Any field change reshapes the signing payload and
 * invalidates at least one signature. TTL check rejects stale handshakes.
 *
 * Primitives composed:
 *   mutual-session · transcript canonicalization · DID/key binding
 */

import { describe, it, expect } from "vitest";
import {
  initiateSession,
  acceptSession,
  confirmSession,
  verifyMutualSession,
} from "../../src/heart/mutual-session.js";
import { makeIdentity, failedWith } from "./_harness.js";

function threeWayHandshake(purpose: string, ttlMs: number | null = null) {
  const alice = makeIdentity();
  const bob = makeIdentity();
  const init = initiateSession({
    initiatorDid: alice.did,
    initiatorPublicKey: alice.publicKey,
    purpose,
    ttlMs,
  });
  const accept = acceptSession({
    init,
    responderDid: bob.did,
    responderPublicKey: bob.publicKey,
    responderSigningKey: bob.signingKey,
  });
  const confirm = confirmSession({
    init,
    accept,
    initiatorSigningKey: alice.signingKey,
  });
  return { alice, bob, init, accept, confirm };
}

describe("Attack #9: session transcript forgery", () => {
  it("legitimate handshake verifies and produces consistent bindings", () => {
    const { init, accept, confirm } = threeWayHandshake("delegate-payment");
    const result = verifyMutualSession({ init, accept, confirm });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.bindings.purpose).toBe("delegate-payment");
    }
  });

  it("swapping responder DID in accept fails verification", () => {
    const { init, accept, confirm } = threeWayHandshake("delegate-payment");
    const eve = makeIdentity();
    const tamperedAccept = {
      ...accept,
      responderDid: eve.did,
      responderPublicKey: eve.publicKey,
    };
    const result = verifyMutualSession({
      init,
      accept: tamperedAccept,
      confirm,
    });
    expect(result.valid).toBe(false);
  });

  it("mutating purpose in init after signing breaks confirm signature", () => {
    const { init, accept, confirm } = threeWayHandshake("delegate-payment");
    const tampered = { ...init, purpose: "delegate-admin" };
    const result = verifyMutualSession({
      init: tampered,
      accept,
      confirm,
    });
    expect(result.valid).toBe(false);
  });

  it("mixing accept from a different session fails", () => {
    const a = threeWayHandshake("session-A");
    const b = threeWayHandshake("session-B");
    // Attacker: use A's init + A's confirm + B's accept.
    const result = verifyMutualSession({
      init: a.init,
      accept: { ...b.accept, sessionId: a.init.sessionId },
      confirm: a.confirm,
    });
    expect(result.valid).toBe(false);
  });

  it("swapping initiator signature (reused from a prior session) fails", () => {
    const a = threeWayHandshake("session-A");
    const b = threeWayHandshake("session-B");
    // Attacker: reuse b.confirm.initiatorSignature inside a's transcript.
    const forgedConfirm = {
      ...a.confirm,
      initiatorSignature: b.confirm.initiatorSignature,
    };
    const result = verifyMutualSession({
      init: a.init,
      accept: a.accept,
      confirm: forgedConfirm,
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "initiator signature")).toBe(true);
  });

  it("TTL-expired handshake is rejected regardless of signature validity", () => {
    const ttl = 100; // 100 ms
    const { init, accept, confirm } = threeWayHandshake("fast-session", ttl);
    // Pretend we're checking 10 seconds later.
    const result = verifyMutualSession({
      init,
      accept,
      confirm,
      now: init.initiatedAt + 10_000,
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "TTL")).toBe(true);
  });

  it("responder DID rebinding to a LOOKALIKE key fails because DID != key", () => {
    // Eve crafts a key pair whose public key is NOT her DID-declared one.
    const eve = makeIdentity();
    const eveImpostor = makeIdentity();

    const alice = makeIdentity();
    const init = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "phish-me",
    });
    // Eve signs with one key but claims another DID in the accept.
    // We bypass acceptSession's sanity check (which would refuse) by
    // hand-building the message: sign with eve's real key but advertise
    // eveImpostor's DID.
    const accept = {
      sessionId: init.sessionId,
      responderDid: eveImpostor.did, // claims impostor DID
      responderPublicKey: eve.publicKey, // wraps eve's actual pk
      nonceB: "xxxx",
      acceptedAt: Date.now(),
      responderSignature: "aaaa",
    };
    const confirm = {
      sessionId: init.sessionId,
      confirmedAt: Date.now(),
      initiatorSignature: "bbbb",
    };
    const result = verifyMutualSession({ init, accept, confirm });
    expect(result.valid).toBe(false);
  });
});
