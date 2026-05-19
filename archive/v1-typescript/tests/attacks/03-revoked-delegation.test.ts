/**
 * Attack #3 — Presenting a revoked delegation.
 *
 * Scenario:
 *   Alice grants Bob `api:pay`. Later, Bob's key is suspected compromised.
 *   Alice publishes a RevocationEvent targeting the delegation ID. Bob (or
 *   Eve, who stole the token) presents the still-signature-valid delegation
 *   to a verifier, hoping the verifier hasn't consulted the registry.
 *
 * Defense: the verifier MUST consult the RevocationRegistry before honoring
 * any credential. A revoked delegation's ID is present in the registry;
 * verification must fail. Also: only the ORIGINAL issuer may revoke —
 * third-party "revocations" are policy-rejected by the application.
 *
 * Primitives composed:
 *   delegation · revocation · RevocationRegistry
 */

import { describe, it, expect } from "vitest";
import {
  createDelegation,
  verifyDelegation,
} from "../../src/heart/delegation.js";
import {
  createRevocation,
  RevocationRegistry,
} from "../../src/heart/revocation.js";
import { makeIdentity } from "./_harness.js";

describe("Attack #3: presenting a revoked delegation", () => {
  it("a verifier consulting the registry rejects revoked IDs", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:pay"],
    });

    // Before revocation: delegation is verifiable under caveat check.
    const beforeRevoke = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:pay",
    });
    expect(beforeRevoke.valid).toBe(true);

    // Alice publishes a revocation event.
    const revocation = createRevocation({
      targetId: delegation.id,
      targetKind: "delegation",
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      reason: "compromised",
    });

    // The verifier records Alice as the legitimate authority over this
    // delegation ID (she issued it) and then accepts her revocation.
    const registry = new RevocationRegistry();
    registry.registerAuthority(delegation.id, alice.did);
    expect(registry.add(revocation).accepted).toBe(true);
    expect(registry.isRevoked(delegation.id)).toBe(true);

    // A full verification pipeline MUST consult the registry. We emulate that
    // here: delegation signature is still valid, but the registry check fails.
    const sigCheck = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:pay",
    });
    expect(sigCheck.valid).toBe(true);
    expect(registry.isRevoked(delegation.id)).toBe(true);
  });

  it("a third party cannot revoke someone else's delegation (authority enforced at registry layer)", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const eve = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:pay"],
    });

    // Eve forges a revocation for Alice's delegation, signing with her
    // own fresh key. The signature is valid, but Eve is not authorized.
    const eveRevocation = createRevocation({
      targetId: delegation.id,
      targetKind: "delegation",
      issuerDid: eve.did,
      issuerPublicKey: eve.publicKey,
      issuerSigningKey: eve.signingKey,
      reason: "abuse",
    });

    // Registry knows Alice is the legitimate issuer of this delegation.
    const registry = new RevocationRegistry();
    registry.registerAuthority(delegation.id, alice.did);

    // The registry now enforces authority — Eve's forged revocation is
    // rejected at the registry layer, not left for the caller to catch.
    const result = registry.add(eveRevocation);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/issuer not authorized/);
    expect(registry.isRevoked(delegation.id)).toBe(false);
  });

  it("rejects revocations for targets with no registered authority (fail-closed)", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:pay"],
    });

    const revocation = createRevocation({
      targetId: delegation.id,
      targetKind: "delegation",
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      reason: "rotated",
    });

    // Registry has no authority record for this delegation — fail-closed.
    const registry = new RevocationRegistry();
    const result = registry.add(revocation);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/unknown authority/);
  });

  it("registry rejects a tampered revocation event", () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const delegation = createDelegation({
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      subjectDid: bob.did,
      capabilities: ["api:pay"],
    });

    const legit = createRevocation({
      targetId: delegation.id,
      targetKind: "delegation",
      issuerDid: alice.did,
      issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey,
      reason: "compromised",
    });

    // Eve flips the reason to "unknown" to hide the severity.
    const tampered = { ...legit, reason: "unknown" as const };
    const registry = new RevocationRegistry();
    registry.registerAuthority(delegation.id, alice.did);
    const result = registry.add(tampered);
    expect(result.accepted).toBe(false); // signature no longer matches
    expect(result.reason).toMatch(/invalid/);
    expect(registry.isRevoked(delegation.id)).toBe(false);
  });
});
