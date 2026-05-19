/**
 * Tests for the rotation-aware historical key lookup wiring across all
 * four verifier call sites: delegation, revocation, birth-certificate,
 * and selective-disclosure.
 *
 * Each verifier is tested for:
 *   1. Backward compatibility (no lookup → existing behavior preserved)
 *   2. Success with correct historical key (lookup confirms effective)
 *   3. Fail-closed on rotated-out key (effectiveUntil <= issuedAt)
 *   4. Fail-closed on not-yet-effective credential (effectiveFrom > issuedAt)
 *   5. Fail-closed on credential not found (unknown identity / not in chain)
 */

import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import {
  createDelegation,
  verifyDelegationSignature,
  verifyDelegation,
} from '../../src/heart/delegation.js';
import {
  createRevocation,
  verifyRevocation,
} from '../../src/heart/revocation.js';
import {
  createBirthCertificate,
  verifyBirthCertificate,
  verifyBirthCertificateChain,
} from '../../src/heart/birth-certificate.js';
import {
  createDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
} from '../../src/heart/selective-disclosure.js';
import type {
  HistoricalKeyLookup,
  HistoricalKeyLookupResult,
} from '../../src/heart/historical-key-lookup.js';

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

// ─── Lookup factories ───────────────────────────────────────────────────────

/** Lookup that confirms the key was effective in the given window. */
function effectiveLookup(
  effectiveFrom: number,
  effectiveUntil: number | null,
): HistoricalKeyLookup {
  return {
    resolve(_publicKey: Uint8Array, _timestamp: number): HistoricalKeyLookupResult {
      return { found: true, effectiveFrom, effectiveUntil };
    },
  };
}

/** Lookup that says the credential was rotated out before the timestamp. */
function rotatedOutLookup(rotatedOutAt: number): HistoricalKeyLookup {
  return {
    resolve(): HistoricalKeyLookupResult {
      return { found: true, effectiveFrom: rotatedOutAt - 10_000, effectiveUntil: rotatedOutAt };
    },
  };
}

/** Lookup that says the credential is not yet effective. */
function notYetEffectiveLookup(effectiveFrom: number): HistoricalKeyLookup {
  return {
    resolve(): HistoricalKeyLookupResult {
      return { found: true, effectiveFrom, effectiveUntil: null };
    },
  };
}

/** Lookup where the credential's introducing event is still pending. */
function pendingLookup(): HistoricalKeyLookup {
  return {
    resolve(): HistoricalKeyLookupResult {
      return { found: true, effectiveFrom: null, effectiveUntil: null };
    },
  };
}

/** Lookup that returns not-found. */
function notFoundLookup(reason: 'unknown-identity' | 'credential-not-in-chain'): HistoricalKeyLookup {
  return {
    resolve(): HistoricalKeyLookupResult {
      return { found: false, reason };
    },
  };
}

/** Lookup that throws (resolver error). */
function throwingLookup(): HistoricalKeyLookup {
  return {
    resolve(): HistoricalKeyLookupResult {
      throw new Error('resolver exploded');
    },
  };
}

// ─── Delegation ─────────────────────────────────────────────────────────────

describe('Delegation — rotation-aware key lookup', () => {
  function makeDelegation() {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const del = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ['tool:search'],
    });
    return { issuer, subject, del };
  }

  it('backward compat: no lookup → existing behavior', () => {
    const { del } = makeDelegation();
    expect(verifyDelegationSignature(del).valid).toBe(true);
  });

  it('succeeds when lookup confirms key was effective at issuedAt', () => {
    const { del } = makeDelegation();
    const lookup = effectiveLookup(del.issuedAt - 1000, null);
    expect(verifyDelegationSignature(del, undefined, undefined, lookup).valid).toBe(true);
  });

  it('fails closed when key was rotated out before issuedAt', () => {
    const { del } = makeDelegation();
    // Key was rotated out 5s before the delegation was issued
    const lookup = rotatedOutLookup(del.issuedAt - 5000);
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('rotated out');
  });

  it('fails closed when credential not yet effective at issuedAt', () => {
    const { del } = makeDelegation();
    // Key becomes effective 10s after the delegation was issued
    const lookup = notYetEffectiveLookup(del.issuedAt + 10_000);
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not yet effective');
  });

  it('fails closed when credential is still pending (effectiveFrom null)', () => {
    const { del } = makeDelegation();
    const lookup = pendingLookup();
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not yet effective');
  });

  it('fails closed when credential not found (unknown identity)', () => {
    const { del } = makeDelegation();
    const lookup = notFoundLookup('unknown-identity');
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('unknown identity');
  });

  it('fails closed when credential not found (not in chain)', () => {
    const { del } = makeDelegation();
    const lookup = notFoundLookup('credential-not-in-chain');
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not in chain');
  });

  it('fails closed when resolver throws', () => {
    const { del } = makeDelegation();
    const lookup = throwingLookup();
    const result = verifyDelegationSignature(del, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('resolver threw');
  });

  it('lookup flows through verifyDelegation (full verification)', () => {
    const { del, subject } = makeDelegation();
    const lookup = notFoundLookup('unknown-identity');
    const result = verifyDelegation(
      del,
      { invokerDid: subject.did, capability: 'tool:search' },
      undefined,
      undefined,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('unknown identity');
  });
});

// ─── Revocation ─────────────────────────────────────────────────────────────

describe('Revocation — rotation-aware key lookup', () => {
  function makeRevocation() {
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: 'dg-test-target',
      targetKind: 'delegation',
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      reason: 'compromised',
    });
    return { issuer, rev };
  }

  it('backward compat: no lookup → existing behavior', () => {
    const { rev } = makeRevocation();
    expect(verifyRevocation(rev).valid).toBe(true);
  });

  it('succeeds when lookup confirms key was effective at issuedAt', () => {
    const { rev } = makeRevocation();
    const lookup = effectiveLookup(rev.issuedAt - 1000, null);
    expect(verifyRevocation(rev, undefined, undefined, lookup).valid).toBe(true);
  });

  it('fails closed when key was rotated out before issuedAt', () => {
    const { rev } = makeRevocation();
    const lookup = rotatedOutLookup(rev.issuedAt - 5000);
    const result = verifyRevocation(rev, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('rotated out');
  });

  it('fails closed when credential not yet effective at issuedAt', () => {
    const { rev } = makeRevocation();
    const lookup = notYetEffectiveLookup(rev.issuedAt + 10_000);
    const result = verifyRevocation(rev, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not yet effective');
  });

  it('fails closed when credential not found', () => {
    const { rev } = makeRevocation();
    const lookup = notFoundLookup('credential-not-in-chain');
    const result = verifyRevocation(rev, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not in chain');
  });

  it('fails closed when resolver throws', () => {
    const { rev } = makeRevocation();
    const lookup = throwingLookup();
    const result = verifyRevocation(rev, undefined, undefined, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('resolver threw');
  });
});

// ─── Birth Certificate ──────────────────────────────────────────────────────

describe('Birth Certificate — rotation-aware key lookup', () => {
  function makeCert() {
    const heart = makeIdentity();
    const cert = createBirthCertificate(
      'test data content',
      { type: 'human', identifier: 'user-1', heartVerified: false },
      heart.did,
      'session-1',
      heart.kp,
      [],
      undefined,
      undefined,
      Date.now(),
    );
    return { heart, cert };
  }

  it('backward compat: no lookup → existing behavior', () => {
    const { heart, cert } = makeCert();
    expect(verifyBirthCertificate(cert, heart.kp.publicKey)).toBe(true);
  });

  it('succeeds when lookup confirms key was effective at bornAt', () => {
    const { heart, cert } = makeCert();
    const lookup = effectiveLookup(cert.bornAt - 1000, null);
    expect(verifyBirthCertificate(cert, heart.kp.publicKey, undefined, lookup)).toBe(true);
  });

  it('fails closed when key was rotated out before bornAt', () => {
    const { heart, cert } = makeCert();
    const lookup = rotatedOutLookup(cert.bornAt - 5000);
    expect(verifyBirthCertificate(cert, heart.kp.publicKey, undefined, lookup)).toBe(false);
  });

  it('fails closed when credential not yet effective at bornAt', () => {
    const { heart, cert } = makeCert();
    const lookup = notYetEffectiveLookup(cert.bornAt + 10_000);
    expect(verifyBirthCertificate(cert, heart.kp.publicKey, undefined, lookup)).toBe(false);
  });

  it('fails closed when credential not found', () => {
    const { heart, cert } = makeCert();
    const lookup = notFoundLookup('unknown-identity');
    expect(verifyBirthCertificate(cert, heart.kp.publicKey, undefined, lookup)).toBe(false);
  });

  it('fails closed when resolver throws', () => {
    const { heart, cert } = makeCert();
    const lookup = throwingLookup();
    expect(verifyBirthCertificate(cert, heart.kp.publicKey, undefined, lookup)).toBe(false);
  });

  it('lookup flows through verifyBirthCertificateChain', () => {
    const { heart, cert } = makeCert();
    const keys = new Map([[heart.did, heart.kp.publicKey]]);
    // With a not-found lookup, chain verification should fail
    const lookup = notFoundLookup('credential-not-in-chain');
    const result = verifyBirthCertificateChain([cert], keys, undefined, lookup);
    expect(result.valid).toBe(false);
  });
});

// ─── Selective Disclosure ───────────────────────────────────────────────────

describe('Selective Disclosure — rotation-aware key lookup', () => {
  function makeProof() {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const doc = createDisclosableDocument({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      claims: { name: 'Alice', tier: 3 },
    });
    const proof = createDisclosureProof(doc, ['tier']);
    return { issuer, subject, doc, proof };
  }

  it('backward compat: no lookup → existing behavior', () => {
    const { proof } = makeProof();
    const result = verifyDisclosureProof(proof);
    expect(result.valid).toBe(true);
  });

  it('succeeds when lookup confirms key was effective at issuedAt', () => {
    const { proof } = makeProof();
    const lookup = effectiveLookup(proof.issuedAt - 1000, null);
    const result = verifyDisclosureProof(proof, { lookup });
    expect(result.valid).toBe(true);
  });

  it('fails closed when key was rotated out before issuedAt', () => {
    const { proof } = makeProof();
    const lookup = rotatedOutLookup(proof.issuedAt - 5000);
    const result = verifyDisclosureProof(proof, { lookup });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('rotated out');
  });

  it('fails closed when credential not yet effective at issuedAt', () => {
    const { proof } = makeProof();
    const lookup = notYetEffectiveLookup(proof.issuedAt + 10_000);
    const result = verifyDisclosureProof(proof, { lookup });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('not yet effective');
  });

  it('fails closed when credential not found', () => {
    const { proof } = makeProof();
    const lookup = notFoundLookup('unknown-identity');
    const result = verifyDisclosureProof(proof, { lookup });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('unknown identity');
  });

  it('fails closed when resolver throws', () => {
    const { proof } = makeProof();
    const lookup = throwingLookup();
    const result = verifyDisclosureProof(proof, { lookup });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain('resolver threw');
  });
});
