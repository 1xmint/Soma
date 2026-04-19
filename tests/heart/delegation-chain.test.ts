import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import {
  createDelegation,
  attenuateDelegation,
  type Delegation,
} from '../../src/heart/delegation.js';
import { verifyDelegationChain } from '../../src/heart/delegation-chain.js';
import {
  RevocationRegistry,
  createRevocation,
} from '../../src/heart/revocation.js';

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

/** Build a 3-link chain: root → mid → leaf (returned leaf-first). */
function buildThreeLinkChain(opts?: {
  midCapabilities?: string[];
  leafCapabilities?: string[];
  midAdditionalCaveats?: Parameters<typeof createDelegation>[0]['caveats'];
  leafAdditionalCaveats?: Parameters<typeof createDelegation>[0]['caveats'];
}) {
  const root = makeIdentity();
  const mid = makeIdentity();
  const leaf = makeIdentity();

  const rootDel = createDelegation({
    issuerDid: root.did,
    issuerPublicKey: root.publicKey,
    issuerSigningKey: root.kp.secretKey,
    subjectDid: mid.did,
    capabilities: ['tool:search', 'tool:db:read', 'tool:db:write'],
  });

  const midDel = attenuateDelegation({
    parent: rootDel,
    newSubjectDid: leaf.did,
    newSubjectSigningKey: mid.kp.secretKey,
    newSubjectPublicKey: mid.publicKey,
    narrowedCapabilities: opts?.midCapabilities ?? ['tool:search', 'tool:db:read'],
    additionalCaveats: opts?.midAdditionalCaveats,
  });

  const endUser = makeIdentity();

  const leafDel = attenuateDelegation({
    parent: midDel,
    newSubjectDid: endUser.did,
    newSubjectSigningKey: leaf.kp.secretKey,
    newSubjectPublicKey: leaf.publicKey,
    narrowedCapabilities: opts?.leafCapabilities ?? ['tool:search'],
    additionalCaveats: opts?.leafAdditionalCaveats,
  });

  return {
    identities: { root, mid, leaf, endUser },
    delegations: { rootDel, midDel, leafDel },
    /** Chain in leaf-first order. */
    chain: [leafDel, midDel, rootDel] as Delegation[],
  };
}

describe('verifyDelegationChain', () => {
  // ── Valid chain scenarios ──

  it('verifies a valid 3-link chain', () => {
    const { chain } = buildThreeLinkChain();
    const registry = new RevocationRegistry();
    const result = verifyDelegationChain(chain, registry);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.chain).toHaveLength(3);
    }
  });

  it('verifies a single-link chain (no parent)', () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const rootDel = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ['tool:search'],
    });
    const registry = new RevocationRegistry();
    const result = verifyDelegationChain([rootDel], registry);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.chain).toHaveLength(1);
    }
  });

  // ── Empty chain ──

  it('rejects an empty chain', () => {
    const registry = new RevocationRegistry();
    const result = verifyDelegationChain([], registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('empty chain');
      expect(result.failedAtIndex).toBe(0);
    }
  });

  // ── Signature failures ──

  it('rejects chain with broken signature at middle link', () => {
    const { chain } = buildThreeLinkChain();
    const registry = new RevocationRegistry();
    // Tamper with middle delegation's capabilities (breaks signature)
    const tampered = { ...chain[1], capabilities: ['*'] };
    const brokenChain = [chain[0], tampered, chain[2]];
    const result = verifyDelegationChain(brokenChain, registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('signature');
      expect(result.failedAtIndex).toBe(1);
    }
  });

  // ── Capability broadening ──

  it('rejects chain with broadened capability at child', () => {
    const { delegations, identities } = buildThreeLinkChain();
    const registry = new RevocationRegistry();

    // Manually create a child delegation that claims a capability
    // not in the parent. We bypass attenuateDelegation (which would
    // throw) and sign with the right key to isolate the chain-walk check.
    const rogue = createDelegation({
      issuerDid: identities.mid.did,
      issuerPublicKey: identities.mid.publicKey,
      issuerSigningKey: identities.mid.kp.secretKey,
      subjectDid: identities.leaf.did,
      capabilities: ['tool:search', 'tool:admin'], // 'tool:admin' not in parent
      parentId: delegations.rootDel.id,
    });

    const result = verifyDelegationChain(
      [rogue, delegations.rootDel],
      registry,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('capability broadening');
      expect(result.reason).toContain('tool:admin');
      expect(result.failedAtIndex).toBe(0);
    }
  });

  // ── Revocation ──

  it('revoked parent invalidates descendants', () => {
    const { chain, delegations, identities } = buildThreeLinkChain();
    const registry = new RevocationRegistry();

    // Register authority so the revocation is accepted
    registry.registerAuthority(
      delegations.rootDel.id,
      identities.root.did,
    );

    // Revoke the root delegation
    const rev = createRevocation({
      targetId: delegations.rootDel.id,
      targetKind: 'delegation',
      issuerDid: identities.root.did,
      issuerPublicKey: identities.root.publicKey,
      issuerSigningKey: identities.root.kp.secretKey,
      reason: 'compromised',
    });
    registry.add(rev);

    const result = verifyDelegationChain(chain, registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('revoked');
      // Root is at index 2 in the leaf-first chain
      expect(result.failedAtIndex).toBe(2);
    }
  });

  it('revoked middle link invalidates leaf', () => {
    const { chain, delegations, identities } = buildThreeLinkChain();
    const registry = new RevocationRegistry();

    // The mid delegation was issued by mid identity (attenuateDelegation
    // uses the attenuator as issuer), so we register the root's subject (mid)
    // as the authority for the mid delegation... actually the mid delegation
    // was issued by attenuateDelegation which makes mid.did the issuerDid.
    // But revocation authority is the ORIGINAL ISSUER — who created it.
    // attenuateDelegation creates a new delegation where issuerDid is the
    // attenuator's DID. So mid.did is the issuer of midDel.
    registry.registerAuthority(
      delegations.midDel.id,
      delegations.midDel.issuerDid,
    );

    const rev = createRevocation({
      targetId: delegations.midDel.id,
      targetKind: 'delegation',
      issuerDid: delegations.midDel.issuerDid,
      issuerPublicKey: identities.mid.publicKey,
      issuerSigningKey: identities.mid.kp.secretKey,
      reason: 'compromised',
    });
    registry.add(rev);

    const result = verifyDelegationChain(chain, registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('revoked');
      expect(result.failedAtIndex).toBe(1);
    }
  });

  // ── Structural integrity ──

  it('rejects chain with broken subject-issuer linkage', () => {
    const { delegations } = buildThreeLinkChain();
    const rogue = makeIdentity();
    const registry = new RevocationRegistry();

    // Create a rogue delegation that is properly signed but whose
    // issuerDid doesn't match rootDel.subjectDid
    const rogueDel = createDelegation({
      issuerDid: rogue.did,
      issuerPublicKey: rogue.publicKey,
      issuerSigningKey: rogue.kp.secretKey,
      subjectDid: makeIdentity().did,
      capabilities: ['tool:search'],
      parentId: delegations.rootDel.id,
    });

    const result = verifyDelegationChain(
      [rogueDel, delegations.rootDel],
      registry,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('subject-issuer linkage');
      expect(result.failedAtIndex).toBe(0);
    }
  });

  it('rejects chain where root has non-null parentId', () => {
    const { chain } = buildThreeLinkChain();
    const registry = new RevocationRegistry();
    // Make the root look like it has a parent
    const brokenRoot = { ...chain[2], parentId: 'dg-fake' };
    const brokenChain = [chain[0], chain[1], brokenRoot];
    const result = verifyDelegationChain(brokenChain, registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      // Signature will fail because we tampered with parentId
      expect(result.valid).toBe(false);
    }
  });

  it('rejects chain exceeding max depth', () => {
    const { chain } = buildThreeLinkChain();
    const registry = new RevocationRegistry();
    const result = verifyDelegationChain(chain, registry, { maxDepth: 2 });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('exceeds maximum');
    }
  });

  // ── Caveat attenuation ──

  it('rejects chain where child drops a parent caveat', () => {
    const { identities, delegations } = buildThreeLinkChain({
      midAdditionalCaveats: [{ kind: 'budget', credits: 500 }],
    });
    const registry = new RevocationRegistry();

    // Create a child that "forgets" the parent's budget caveat
    // (bypass attenuateDelegation to isolate chain-walk check)
    const rogue = createDelegation({
      issuerDid: identities.leaf.did,
      issuerPublicKey: identities.leaf.publicKey,
      issuerSigningKey: identities.leaf.kp.secretKey,
      subjectDid: identities.endUser.did,
      capabilities: ['tool:search'],
      caveats: [], // missing the parent's budget caveat
      parentId: delegations.midDel.id,
    });

    const result = verifyDelegationChain(
      [rogue, delegations.midDel, delegations.rootDel],
      registry,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('caveat attenuation');
      expect(result.failedAtIndex).toBe(0);
    }
  });

  // ── Wildcard capability attenuation ──

  it('accepts child with specific cap under parent wildcard', () => {
    const root = makeIdentity();
    const mid = makeIdentity();
    const leaf = makeIdentity();
    const registry = new RevocationRegistry();

    const rootDel = createDelegation({
      issuerDid: root.did,
      issuerPublicKey: root.publicKey,
      issuerSigningKey: root.kp.secretKey,
      subjectDid: mid.did,
      capabilities: ['tool:*'],
    });

    // Child narrows wildcard to specific cap — valid attenuation
    const childDel = createDelegation({
      issuerDid: mid.did,
      issuerPublicKey: mid.publicKey,
      issuerSigningKey: mid.kp.secretKey,
      subjectDid: leaf.did,
      capabilities: ['tool:search'],
      parentId: rootDel.id,
    });

    const result = verifyDelegationChain([childDel, rootDel], registry);
    expect(result.valid).toBe(true);
  });

  it('rejects child with broadened capability outside wildcard scope', () => {
    const root = makeIdentity();
    const mid = makeIdentity();
    const leaf = makeIdentity();
    const registry = new RevocationRegistry();

    const rootDel = createDelegation({
      issuerDid: root.did,
      issuerPublicKey: root.publicKey,
      issuerSigningKey: root.kp.secretKey,
      subjectDid: mid.did,
      capabilities: ['tool:*'],
    });

    // Child claims 'api:weather' which is NOT under 'tool:*'
    const childDel = createDelegation({
      issuerDid: mid.did,
      issuerPublicKey: mid.publicKey,
      issuerSigningKey: mid.kp.secretKey,
      subjectDid: leaf.did,
      capabilities: ['tool:search', 'api:weather'],
      parentId: rootDel.id,
    });

    const result = verifyDelegationChain([childDel, rootDel], registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('api:weather');
      expect(result.failedAtIndex).toBe(0);
    }
  });

  // ── parentId mismatch ──

  it('rejects chain with parentId pointing at wrong delegation', () => {
    const root = makeIdentity();
    const mid = makeIdentity();
    const leaf = makeIdentity();
    const registry = new RevocationRegistry();

    const rootDel = createDelegation({
      issuerDid: root.did,
      issuerPublicKey: root.publicKey,
      issuerSigningKey: root.kp.secretKey,
      subjectDid: mid.did,
      capabilities: ['tool:search'],
    });

    // Child points at a bogus parentId
    const childDel = createDelegation({
      issuerDid: mid.did,
      issuerPublicKey: mid.publicKey,
      issuerSigningKey: mid.kp.secretKey,
      subjectDid: leaf.did,
      capabilities: ['tool:search'],
      parentId: 'dg-nonexistent',
    });

    const result = verifyDelegationChain([childDel, rootDel], registry);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain('parentId mismatch');
      expect(result.failedAtIndex).toBe(0);
    }
  });
});
