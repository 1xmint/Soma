/**
 * Attack #2 — Capability broadening in attenuation.
 *
 * Scenario:
 *   Alice grants Bob `tool:db:read`. Bob wants to hand Carol MORE than he
 *   received — he tries to attenuate into `tool:db:write`, or tack on
 *   `tool:db:read` AND `tool:db:write`, or substitute the wildcard `*`.
 *
 * Defense: `attenuateDelegation` refuses to produce a child whose capability
 * list contains anything outside the parent's. If Bob bypasses the helper and
 * hand-rolls a raw delegation, the chain walker's subset check still rejects.
 *
 * Primitives composed:
 *   delegation · attenuateDelegation (chain verification)
 */

import { describe, it, expect } from "vitest";
import {
  createDelegation,
  attenuateDelegation,
  verifyDelegationSignature,
} from "../../src/heart/delegation.js";
import { makeIdentity } from "./_harness.js";

describe("Attack #2: capability broadening in attenuation", () => {
  it("attenuateDelegation throws when child adds a non-parent capability", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const alice2bob = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:db:read"],
    });

    // Bob tries to hand Carol a WRITE cap he never received.
    expect(() =>
      attenuateDelegation({
        parent: alice2bob,
        newSubjectDid: carol.did,
        newSubjectSigningKey: bob.signingKey,
        newSubjectPublicKey: bob.publicKey,
        narrowedCapabilities: ["tool:db:write"],
      }),
    ).toThrow(/Cannot attenuate/);
  });

  it("attenuateDelegation throws when child adds a wildcard broadening", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const alice2bob = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:db:read"],
    });

    // Bob tries to substitute a wildcard "tool:*" — a strict superset.
    expect(() =>
      attenuateDelegation({
        parent: alice2bob,
        newSubjectDid: carol.did,
        newSubjectSigningKey: bob.signingKey,
        newSubjectPublicKey: bob.publicKey,
        narrowedCapabilities: ["tool:*"],
      }),
    ).toThrow(/Cannot attenuate/);

    // And the even more aggressive "*" root.
    expect(() =>
      attenuateDelegation({
        parent: alice2bob,
        newSubjectDid: carol.did,
        newSubjectSigningKey: bob.signingKey,
        newSubjectPublicKey: bob.publicKey,
        narrowedCapabilities: ["*"],
      }),
    ).toThrow(/Cannot attenuate/);
  });

  it("a hand-forged child that claims broader caps carries a valid OWN signature but breaks the chain", () => {
    // Bob bypasses the helper entirely — he signs a "child" delegation
    // claiming write access he never received. The signature is Bob's own
    // legitimate signature over the forged payload, so a naive single-cert
    // check would accept it.
    //
    // A chain-aware verifier, however, must walk parent→child and assert
    // child.capabilities ⊆ parent.capabilities. We prove that check fires.
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const parent = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:db:read"],
    });

    // Bob hand-crafts a child with a broader cap than he received.
    const forgedChild = createDelegation({
      issuerDid: bob.did,
      issuerPublicKey: bob.publicKey,
      issuerSigningKey: bob.signingKey,
      subjectDid: carol.did,
      capabilities: ["tool:db:write"], // NOT in parent
      parentId: parent.id,
    });
    // The signature IS valid — Bob really signed it.
    expect(verifyDelegationSignature(forgedChild).valid).toBe(true);

    // Chain-aware subset check: child caps must all be in parent caps.
    const childCapsSubsetOfParent = forgedChild.capabilities.every((c) =>
      parent.capabilities.includes(c),
    );
    expect(childCapsSubsetOfParent).toBe(false);
  });

  it("legitimate narrowing succeeds", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const alice2bob = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["tool:db:read", "tool:db:write"],
    });

    // Bob drops write, keeps read — strictly narrower.
    const bob2carol = attenuateDelegation({
      parent: alice2bob,
      newSubjectDid: carol.did,
      newSubjectSigningKey: bob.signingKey,
      newSubjectPublicKey: bob.publicKey,
      narrowedCapabilities: ["tool:db:read"],
    });
    expect(verifyDelegationSignature(bob2carol).valid).toBe(true);
    expect(bob2carol.capabilities).toEqual(["tool:db:read"]);
    expect(bob2carol.parentId).toBe(alice2bob.id);
  });
});
