/**
 * Attack #16 — Adversarial integration tests across Soma's attack surface.
 *
 * These are end-to-end scenarios that cross multiple primitives and
 * integration seams, written from the perspective of a consumer (e.g.
 * ClawNet/Pulse) trying to break the system. Each test names the attack
 * vector and the spec section it exercises.
 *
 * Targets the gaps and partial-coverage areas from the spec-to-implementation
 * audit (docs/audit/spec-implementation-gap-report-2026-04-19.md):
 *
 *   §1 Delegation chain-walk — cascade revocation via registry
 *   §2 Revocation not wired into verifyDelegation — caller must check
 *   §3 Birth certificate co-signing — both signatures required
 *   §4 Key-rotation + delegation — historical key validity
 *   §5 Spend-cap enforcement across delegation chain
 *   §6 Audience-caveat phishing
 *   §7 Capability broadening attempt
 */

import { describe, it, expect } from 'vitest';
import {
  createDelegation,
  attenuateDelegation,
  verifyDelegation,
  verifyDelegationSignature,
} from '../../src/heart/delegation.js';
import {
  createRevocation,
  RevocationRegistry,
} from '../../src/heart/revocation.js';
import {
  createBirthCertificate,
  verifyBirthCertificate,
  verifySourceSignature,
  signDataProvenance,
  createDataProvenance,
} from '../../src/heart/birth-certificate.js';
import { SpendLog } from '../../src/heart/spend-receipts.js';
import {
  CredentialRotationController,
  MockCredentialBackend,
  DEFAULT_POLICY,
  DEFAULT_TTL_POLICY,
} from '../../src/heart/credential-rotation/index.js';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import { makeIdentity, makeIdentities } from './_harness.js';

const crypto = getCryptoProvider();

// ═══════════════════════════════════════════════════════════════════════════
// §1 — Delegation chain-walk: cascade revocation via registry
// SOMA-DELEGATION-SPEC.md §Delegation Chain / §Revocation
// Gap: verifyDelegation only checks single delegation; chain-walk is
// the consumer's responsibility.
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.1: Delegation chain-walk with cascade revocation', () => {
  it('revoking a mid-chain delegation kills the leaf — consumer must walk', () => {
    const [alice, bob, carol] = makeIdentities(3);

    const ab = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:search', 'api:read'],
    });
    const bc = attenuateDelegation({
      parent: ab, newSubjectDid: carol.did,
      newSubjectSigningKey: bob.signingKey, newSubjectPublicKey: bob.publicKey,
      narrowedCapabilities: ['tool:search'],
    });

    // Before revocation: both links individually verify.
    expect(verifyDelegationSignature(ab).valid).toBe(true);
    expect(verifyDelegationSignature(bc).valid).toBe(true);
    expect(verifyDelegation(bc, { invokerDid: carol.did, capability: 'tool:search' }).valid).toBe(true);

    // Alice revokes the A→B link.
    const registry = new RevocationRegistry();
    registry.registerAuthority(ab.id, alice.did);
    registry.add(createRevocation({
      targetId: ab.id, targetKind: 'delegation',
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, reason: 'compromised',
    }));

    // The leaf sig still passes — verifyDelegation doesn't walk the chain.
    expect(verifyDelegation(bc, { invokerDid: carol.did, capability: 'tool:search' }).valid).toBe(true);

    // Consumer must check: is any parentId in the chain revoked?
    expect(registry.isRevoked(bc.parentId!)).toBe(true); // A→B is the parent of B→C
  });

  it('4-deep chain A→B→C→D: revoking B kills both C and D', () => {
    const [alice, bob, carol, dave] = makeIdentities(4);

    const ab = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['api:read', 'api:write'],
    });
    const bc = attenuateDelegation({
      parent: ab, newSubjectDid: carol.did,
      newSubjectSigningKey: bob.signingKey, newSubjectPublicKey: bob.publicKey,
      narrowedCapabilities: ['api:read', 'api:write'],
    });
    const cd = attenuateDelegation({
      parent: bc, newSubjectDid: dave.did,
      newSubjectSigningKey: carol.signingKey, newSubjectPublicKey: carol.publicKey,
      narrowedCapabilities: ['api:read'],
    });

    const registry = new RevocationRegistry();
    registry.registerAuthority(ab.id, alice.did);
    registry.add(createRevocation({
      targetId: ab.id, targetKind: 'delegation',
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, reason: 'rotated',
    }));

    // Dave's leaf still sig-verifies alone.
    expect(verifyDelegation(cd, { invokerDid: dave.did, capability: 'api:read' }).valid).toBe(true);

    // Consumer walks chain: cd → bc → ab (revoked). Chain is dead.
    const chain = [cd, bc, ab];
    expect(chain.some((d) => registry.isRevoked(d.id))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §2 — Revocation not wired into verifyDelegation
// SOMA-DELEGATION-SPEC.md §Revocation Interaction
// Consumer contract: verifyDelegation() && !registry.isRevoked(del.id)
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.2: Revocation-not-wired — correct consumer pattern', () => {
  it('verifyDelegation alone does NOT catch a revoked delegation', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['api:pay'],
    });

    const registry = new RevocationRegistry();
    registry.registerAuthority(del.id, alice.did);
    registry.add(createRevocation({
      targetId: del.id, targetKind: 'delegation',
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, reason: 'compromised',
    }));

    // verifyDelegation alone: still valid (doesn't consult registry).
    const sigCheck = verifyDelegation(del, { invokerDid: bob.did, capability: 'api:pay' });
    expect(sigCheck.valid).toBe(true);

    // Correct consumer pattern: sig check AND revocation check.
    const accepted = sigCheck.valid && !registry.isRevoked(del.id);
    expect(accepted).toBe(false); // correctly rejected
  });

  it('correct two-step pattern accepts a non-revoked delegation', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['api:pay'],
    });

    const registry = new RevocationRegistry();
    registry.registerAuthority(del.id, alice.did);

    const sigCheck = verifyDelegation(del, { invokerDid: bob.did, capability: 'api:pay' });
    const accepted = sigCheck.valid && !registry.isRevoked(del.id);
    expect(accepted).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §3 — Birth certificate co-signing: both signatures required
// SOMA-HEART-CERTIFICATE-SPEC.md §5 heart-to-heart profile
// Consumer must verify BOTH receiver and source signatures on dual-signed
// certs; a forgery with a valid receiver sig but garbage source sig fails.
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.3: Birth certificate — dual-signature requirement', () => {
  it('forgery with garbage source signature is caught by verifySourceSignature', () => {
    const source = makeIdentity();
    const receiver = makeIdentity();
    const data = 'heart-to-heart payload';

    // Legitimate cert: pin bornAt so provenance.timestamp matches cert.bornAt.
    const bornAt = Date.now();
    const provenance = { ...createDataProvenance(data, source.did, receiver.did), timestamp: bornAt };
    const realSourceSig = signDataProvenance(provenance, {
      publicKey: source.publicKeyBytes,
      secretKey: source.signingKey,
    });
    const realCert = createBirthCertificate(
      data,
      { type: 'agent', identifier: source.did, heartVerified: true },
      receiver.did, 'session-legit',
      { publicKey: receiver.publicKeyBytes, secretKey: receiver.signingKey },
      [], undefined, realSourceSig, bornAt,
    );
    expect(realCert.trustTier).toBe('dual-signed');
    expect(verifyBirthCertificate(realCert, receiver.publicKeyBytes)).toBe(true);
    expect(verifySourceSignature(realCert, source.publicKeyBytes)).toBe(true);

    // Forged cert: receiver sig valid, source sig is garbage (valid base64, wrong bytes).
    const garbageSig = crypto.encoding.encodeBase64(new Uint8Array(64).fill(0xab));
    const forgery = createBirthCertificate(
      data,
      { type: 'agent', identifier: source.did, heartVerified: true },
      receiver.did, 'session-forgery',
      { publicKey: receiver.publicKeyBytes, secretKey: receiver.signingKey },
      [], undefined, garbageSig,
    );
    expect(verifyBirthCertificate(forgery, receiver.publicKeyBytes)).toBe(true);  // receiver ok
    expect(verifySourceSignature(forgery, source.publicKeyBytes)).toBe(false);    // source forged

    // Consumer must check both.
    const bothValid =
      verifyBirthCertificate(forgery, receiver.publicKeyBytes) &&
      verifySourceSignature(forgery, source.publicKeyBytes);
    expect(bothValid).toBe(false);
  });

  it('single-signed cert downgrades trust tier when no source co-sig provided', () => {
    const source = makeIdentity();
    const receiver = makeIdentity();

    const cert = createBirthCertificate(
      'payload',
      { type: 'agent', identifier: source.did, heartVerified: true },
      receiver.did, 'session-no-cosig',
      { publicKey: receiver.publicKeyBytes, secretKey: receiver.signingKey },
      [], undefined, null,
    );
    expect(cert.trustTier).toBe('single-signed');
    expect(cert.sourceSignature).toBeNull();
    expect(verifyBirthCertificate(cert, receiver.publicKeyBytes)).toBe(true);
    expect(verifySourceSignature(cert, source.publicKeyBytes)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §4 — Key-rotation + delegation: historical key validity
// SOMA-DELEGATION-SPEC.md §Rotation Interaction
// The rotation controller's lookupHistoricalCredential correctly resolves
// effective windows; this exercises it from a consumer perspective.
// ═══════════════════════════════════════════════════════════════════════════

async function bootstrapRotationIdentity(identityId = 'heart-alice') {
  const backend = new MockCredentialBackend({ backendId: 'mock-ed25519' });
  const controller = new CredentialRotationController({
    policy: {
      ...DEFAULT_POLICY,
      backendAllowlist: ['mock-ed25519'],
      suiteAllowlist: ['ed25519'],
      ttl: DEFAULT_TTL_POLICY,
    },
  });
  controller.registerBackend(backend);
  const { event, credential } = await controller.incept({ identityId, backendId: 'mock-ed25519' });
  controller.anchorEvent(identityId, event.hash, 'anchor-root');
  controller.witnessEvent(identityId, event.hash);
  return { controller, credential, backend };
}

describe('Attack #16.4: Key-rotation + delegation — historical key validity', () => {
  it('V1 key is historically valid at delegation issuedAt after rotation to V2', async () => {
    const identityId = 'heart-alice';
    const { controller, credential: v1Cred } = await bootstrapRotationIdentity(identityId);

    const issuedAt = Date.now();
    const v1PubKeyBytes = v1Cred.publicKey;

    // Rotate to V2 using the same identityId.
    const { event: rotEvent, credential: v2Cred } = await controller.rotate(identityId);
    controller.anchorEvent(identityId, rotEvent.hash, 'anchor-v2');
    controller.witnessEvent(identityId, rotEvent.hash);

    // V1 should be historically valid at issuedAt (before rotation).
    const result = controller.lookupHistoricalCredential(identityId, {
      kind: 'publicKey', publicKey: v1PubKeyBytes,
    });
    expect(result.found).toBe(true);
    if (result.found) {
      const { effectiveFrom, effectiveUntil } = result;
      const wasEffective =
        (effectiveFrom === null || effectiveFrom <= issuedAt) &&
        (effectiveUntil === null || effectiveUntil > issuedAt);
      expect(wasEffective).toBe(true);
    }

    // V2 should NOT be historically valid at issuedAt (it didn't exist yet).
    const v2Result = controller.lookupHistoricalCredential(identityId, {
      kind: 'publicKey', publicKey: v2Cred.publicKey,
    });
    if (v2Result.found) {
      const { effectiveFrom } = v2Result;
      expect(effectiveFrom !== null && effectiveFrom > issuedAt).toBe(true);
    }
  });

  it('fabricated key has no rotation history — lookup returns not-found', async () => {
    const identityId = 'heart-bob';
    const { controller } = await bootstrapRotationIdentity(identityId);

    const fabricatedKey = crypto.signing.generateKeyPair().publicKey;
    const result = controller.lookupHistoricalCredential(identityId, {
      kind: 'publicKey', publicKey: fabricatedKey,
    });
    expect(result.found).toBe(false);
  });

  it('unknown identity returns not-found', async () => {
    const { controller } = await bootstrapRotationIdentity('heart-carol');
    const anyKey = crypto.signing.generateKeyPair().publicKey;
    const result = controller.lookupHistoricalCredential('heart-unknown', {
      kind: 'publicKey', publicKey: anyKey,
    });
    expect(result.found).toBe(false);
    if (!result.found) {
      expect(result.reason).toBe('unknown-identity');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §5 — Spend-cap enforcement across delegation chain
// SOMA-CAPABILITIES-SPEC.md §Caveat Types: budget
// Parent delegates with a cap of 100; child attenuates to 50.
// Child tries to spend 60 — the child's tighter cap is enforced.
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.5: Spend-cap enforcement across delegation chain', () => {
  it('child budget cap is enforced even when parent cap is higher', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    // Alice delegates to Bob with a budget of 100 credits.
    const abDel = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['api:call'],
      caveats: [{ kind: 'budget', credits: 100 }],
    });

    // Bob attenuates to Carol with a tighter cap of 50.
    const bcDel = attenuateDelegation({
      parent: abDel, newSubjectDid: carol.did,
      newSubjectSigningKey: bob.signingKey, newSubjectPublicKey: bob.publicKey,
      narrowedCapabilities: ['api:call'],
      additionalCaveats: [{ kind: 'budget', credits: 50 }],
    });

    // Carol tries to spend 60 credits in one shot — over her 50 cap.
    const tooExpensive = verifyDelegation(bcDel, {
      invokerDid: carol.did,
      capability: 'api:call',
      creditsSpent: 60,
      cumulativeCreditsSpent: 0,
    });
    expect(tooExpensive.valid).toBe(false);
    expect(tooExpensive.valid ? '' : tooExpensive.reason).toMatch(/budget/i);

    // Carol spends 30 credits — within her 50 cap.
    const affordable = verifyDelegation(bcDel, {
      invokerDid: carol.did,
      capability: 'api:call',
      creditsSpent: 30,
      cumulativeCreditsSpent: 0,
    });
    expect(affordable.valid).toBe(true);

    // Carol has already spent 40, tries to spend 20 more (total 60 > 50).
    const overCumulative = verifyDelegation(bcDel, {
      invokerDid: carol.did,
      capability: 'api:call',
      creditsSpent: 20,
      cumulativeCreditsSpent: 40,
    });
    expect(overCumulative.valid).toBe(false);
  });

  it('SpendLog tracks cumulative spend and detects when budget would be exceeded', () => {
    const alice = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: 'did:key:bob',
      capabilities: ['api:call'],
      caveats: [{ kind: 'budget', credits: 100 }],
    });

    const log = new SpendLog({
      delegationId: del.id,
      subjectSigningKey: alice.signingKey,
      subjectPublicKey: alice.publicKeyBytes,
    });

    log.append({ amount: 40, capability: 'api:call' });
    log.append({ amount: 30, capability: 'api:call' });
    // Cumulative: 70. Would 35 more exceed 100? Yes.
    expect(log.wouldExceed(35, 100)).toBe(true);
    // Would 25 more exceed 100? No.
    expect(log.wouldExceed(25, 100)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §6 — Audience-caveat phishing
// SOMA-CAPABILITIES-SPEC.md §Caveat Types: audience
// Delegation issued with audience=ServiceA; attacker tries to use it at
// ServiceB. Must fail closed. Missing audienceDid also fails closed.
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.6: Audience-caveat phishing', () => {
  it('delegation bound to ServiceA is rejected at ServiceB', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();
    const serviceB = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:query'],
      caveats: [{ kind: 'audience', did: serviceA.did }],
    });

    // Bob uses it at ServiceA — should pass.
    const atServiceA = verifyDelegation(del, {
      invokerDid: bob.did, capability: 'tool:query', audienceDid: serviceA.did,
    });
    expect(atServiceA.valid).toBe(true);

    // Attacker replays it at ServiceB — must fail.
    const atServiceB = verifyDelegation(del, {
      invokerDid: bob.did, capability: 'tool:query', audienceDid: serviceB.did,
    });
    expect(atServiceB.valid).toBe(false);
    expect(atServiceB.valid ? '' : atServiceB.reason).toMatch(/audience/i);
  });

  it('omitting audienceDid when audience caveat is present fails closed', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:query'],
      caveats: [{ kind: 'audience', did: serviceA.did }],
    });

    // Verifier forgets to pass audienceDid — must fail closed, not silently accept.
    const missing = verifyDelegation(del, {
      invokerDid: bob.did, capability: 'tool:query',
      // audienceDid intentionally omitted
    });
    expect(missing.valid).toBe(false);
    expect(missing.valid ? '' : missing.reason).toMatch(/fail-closed/i);
  });

  it('multi-caveat delegation: audience + expiry — wrong audience fails even if not expired', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const serviceA = makeIdentity();
    const serviceB = makeIdentity();
    const farFuture = Date.now() + 86_400_000;

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:query'],
      caveats: [
        { kind: 'audience', did: serviceA.did },
        { kind: 'expires-at', timestamp: farFuture },
      ],
    });

    // Not expired, but wrong audience — must still fail.
    const result = verifyDelegation(del, {
      invokerDid: bob.did, capability: 'tool:query',
      audienceDid: serviceB.did, now: Date.now(),
    });
    expect(result.valid).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// §7 — Capability broadening attempt
// SOMA-CAPABILITIES-SPEC.md §Attenuation Rules
// A holder tries to attenuate a delegation to add a capability not in the
// parent. Must be rejected at attenuation time. Narrowing works correctly.
// ═══════════════════════════════════════════════════════════════════════════

describe('Attack #16.7: Capability broadening attempt', () => {
  it('attenuateDelegation throws when child requests capability not in parent', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:search'],
    });

    // Bob tries to grant Carol a capability he doesn't have.
    expect(() =>
      attenuateDelegation({
        parent: del, newSubjectDid: carol.did,
        newSubjectSigningKey: bob.signingKey, newSubjectPublicKey: bob.publicKey,
        narrowedCapabilities: ['tool:search', 'tool:write'], // tool:write not in parent
      }),
    ).toThrow();
  });

  it('valid narrowing — child gets a strict subset of parent capabilities', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:search', 'tool:read', 'api:call'],
    });

    const narrowed = attenuateDelegation({
      parent: del, newSubjectDid: carol.did,
      newSubjectSigningKey: bob.signingKey, newSubjectPublicKey: bob.publicKey,
      narrowedCapabilities: ['tool:search'],
    });

    expect(verifyDelegationSignature(narrowed).valid).toBe(true);

    // Carol can use tool:search.
    expect(
      verifyDelegation(narrowed, { invokerDid: carol.did, capability: 'tool:search' }).valid,
    ).toBe(true);

    // Carol cannot use tool:read — not in the narrowed delegation.
    expect(
      verifyDelegation(narrowed, { invokerDid: carol.did, capability: 'tool:read' }).valid,
    ).toBe(false);
  });

  it('wildcard capability in parent does not allow child to invent specific capabilities beyond grant', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const carol = makeIdentity();

    // Parent has only tool:search (no wildcard).
    const del = createDelegation({
      issuerDid: alice.did, issuerPublicKey: alice.publicKey,
      issuerSigningKey: alice.signingKey, subjectDid: bob.did,
      capabilities: ['tool:search'],
    });

    // Invocation of a capability not in the grant is rejected.
    const result = verifyDelegation(del, {
      invokerDid: bob.did, capability: 'tool:admin',
    });
    expect(result.valid).toBe(false);
    expect(result.valid ? '' : result.reason).toMatch(/capability/i);
  });
});
