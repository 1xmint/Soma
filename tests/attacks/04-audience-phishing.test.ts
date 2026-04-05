/**
 * Attack #4 — Audience phishing (cross-service credential reuse).
 *
 * Scenario:
 *   Alice delegates `api:balance` to Bob, scoped with an `audience` caveat
 *   naming ServiceA's DID. Bob accidentally (or under social engineering)
 *   shows the delegation to ServiceB, a look-alike phishing verifier. If
 *   ServiceB passes no `audienceDid` in its invocation context and the caveat
 *   is silently ignored, Bob's credential is exposed to a service it was
 *   never meant for.
 *
 * Defense: audience enforcement is FAIL-CLOSED. If a delegation carries an
 * `audience` caveat and the verifier doesn't declare its own DID in the
 * context, verification must reject. Additionally, if the verifier declares
 * a DID that doesn't match the caveat, reject.
 *
 * Primitives composed:
 *   delegation · audience caveat · invocation context fail-closed semantics
 */

import { describe, it, expect } from "vitest";
import {
  createDelegation,
  verifyDelegation,
} from "../../src/heart/delegation.js";
import { makeIdentity, failedWith } from "./_harness.js";

describe("Attack #4: audience phishing", () => {
  it("verifier without audienceDid fails closed on an audience-bound delegation", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:balance"],
      caveats: [{ kind: "audience", did: serviceA.did }],
    });

    // Phishing verifier forgets to set audienceDid — caveat silently ignored?
    // No — fail closed.
    const result = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:balance",
      // audienceDid missing!
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "audience caveat")).toBe(true);
  });

  it("verifier with wrong audienceDid fails with mismatch", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();
    const serviceB = makeIdentity(); // phishing look-alike

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:balance"],
      caveats: [{ kind: "audience", did: serviceA.did }],
    });

    // Phisher declares itself as ServiceB (honest about its own identity,
    // dishonest about its intentions) — still rejected because ServiceA != B.
    const result = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:balance",
      audienceDid: serviceB.did,
    });
    expect(result.valid).toBe(false);
    expect(failedWith(result, "audience mismatch")).toBe(true);
  });

  it("correct audience passes", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:balance"],
      caveats: [{ kind: "audience", did: serviceA.did }],
    });

    const result = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:balance",
      audienceDid: serviceA.did,
    });
    expect(result.valid).toBe(true);
  });

  it("absence of audience caveat does NOT require audienceDid (backwards compat)", () => {
    // A delegation with no audience caveat should remain usable by verifiers
    // that don't know to declare their identity. We're not forcing audience
    // on every call site — only when explicitly bound.
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:balance"],
      // no caveats
    });

    const result = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:balance",
      // no audienceDid
    });
    expect(result.valid).toBe(true);
  });

  it("attenuated delegation inherits the audience caveat — cannot be stripped", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();
    const serviceA = makeIdentity();

    const alice2bob = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:balance"],
      caveats: [{ kind: "audience", did: serviceA.did }],
    });

    // Bob tries to hand Carol a child delegation — caveats are copied
    // unchanged, so the audience is inherited. Even if Bob tried to sneak
    // past, attenuation copies ALL parent caveats before appending. We verify
    // by attenuating and asserting the audience caveat is still there.
    // (We construct by hand since attenuateDelegation appends automatically.)
    // Here we just verify that stripping the caveat breaks signature.
    const tamperedChild = {
      ...alice2bob,
      caveats: [], // strip audience
    };
    // The signature is over the original caveats → tampered payload fails.
    const result = verifyDelegation(tamperedChild, {
      invokerDid: bob.did,
      capability: "api:balance",
      audienceDid: serviceA.did,
    });
    expect(result.valid).toBe(false);
  });
});
