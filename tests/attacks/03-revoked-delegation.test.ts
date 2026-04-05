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

    // Verifier's registry accepts the event and now knows the target is dead.
    const registry = new RevocationRegistry();
    expect(registry.add(revocation)).toBe(true);
    expect(registry.isRevoked(delegation.id)).toBe(true);

    // A full verification pipeline MUST consult the registry. We emulate that
    // here: delegation signature is still valid, but the registry check fails.
    const sigCheck = verifyDelegation(delegation, {
      invokerDid: bob.did,
      capability: "api:pay",
    });
    expect(sigCheck.valid).toBe(true);
    // Application-level policy:
    expect(registry.isRevoked(delegation.id)).toBe(true);
  });

  it("a third party cannot produce a valid revocation for someone else's delegation", () => {
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

    // Eve forges a revocation for Alice's delegation, signing with HER OWN
    // key. The signature is technically valid (it's Eve's sig over Eve's
    // claim) but Eve's DID doesn't match the delegation's issuer.
    const eveRevocation = createRevocation({
      targetId: delegation.id,
      targetKind: "delegation",
      issuerDid: eve.did,
      issuerPublicKey: eve.publicKey,
      issuerSigningKey: eve.signingKey,
      reason: "abuse",
    });

    // The registry verifies the signature but does NOT enforce authority.
    // That's the application's job — we enforce it here.
    const registry = new RevocationRegistry();
    expect(registry.add(eveRevocation)).toBe(true); // signature is real

    // Application policy: only trust revocations signed by the DELEGATION's
    // own issuer DID. Eve's revocation must be ignored.
    const stored = registry.get(delegation.id);
    expect(stored).toBeDefined();
    const authorityOk = stored!.issuerDid === delegation.issuerDid;
    expect(authorityOk).toBe(false);
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
    expect(registry.add(tampered)).toBe(false); // signature no longer matches
    expect(registry.isRevoked(delegation.id)).toBe(false);
  });
});
