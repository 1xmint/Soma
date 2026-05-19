import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { canonicalizePayload } from '../../../src/heart/certificate/canonical.js';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import { loadManifest } from '../../../src/heart/certificate/vectors.js';
import {
  verifyCertificateSignature,
  type CredentialLookup,
  type CredentialLookupResult,
  type CredentialRotationReference,
  type CertificateSignatureEntry,
  type ResolvedCredential,
} from '../../../src/heart/certificate/signature.js';

const repoRoot = resolve(__dirname, '../../..');
const manifest = loadManifest(repoRoot);

// Build a lookup adapter from the rotation fixture in the manifest.
function fixtureCredentialLookup(): CredentialLookup {
  const identities = manifest.rotation_fixture.identities;

  return {
    resolve(ref: CredentialRotationReference): CredentialLookupResult {
      const match = identities.find(
        (id) =>
          id.identity_id === ref.identity_id &&
          id.credential_id === ref.credential_id &&
          id.rotation_event_hash === ref.rotation_event_hash,
      );
      if (!match) {
        return { found: false, reason: 'credential-not-in-chain' };
      }
      const cred: ResolvedCredential = {
        credential_id: match.credential_id,
        identity_id: match.identity_id,
        algorithm_suite: match.algorithm_suite,
        public_key_spki_der_base64: match.public_key_spki_der_base64,
        effective_at: match.effective_at,
        revoked_at: match.revoked_at,
      };
      return { found: true, credential: cred };
    },
  };
}

const lookup = fixtureCredentialLookup();

// -- Vector signature verification -------------------------------------------

describe('vector signature verification', () => {
  const acceptedVectors = manifest.vectors.filter(
    (v) => v.expected_result === 'accept',
  );

  for (const vector of acceptedVectors) {
    describe(vector.id, () => {
      const cert = vector.certificate as Record<string, unknown>;
      const canonical = canonicalizePayload(cert);
      const issuedAt = cert.issued_at as number;
      const sigs = cert.signatures as CertificateSignatureEntry[];

      for (const sig of sigs) {
        it(`verifies ${sig.signer_role} signature`, () => {
          const result = verifyCertificateSignature(
            canonical,
            sig,
            issuedAt,
            lookup,
          );
          expect(result.valid).toBe(true);
        });
      }
    });
  }
});

// -- Failure modes -----------------------------------------------------------

describe('signature failure modes', () => {
  const birthVector = manifest.vectors.find((v) => v.id === 'accepted-birth')!;
  const cert = birthVector.certificate as Record<string, unknown>;
  const canonical = canonicalizePayload(cert);
  const issuedAt = cert.issued_at as number;
  const validSig = (cert.signatures as CertificateSignatureEntry[])[0];

  it('rejects invalid signer role', () => {
    const badSig = { ...validSig, signer_role: 'admin' };
    const result = verifyCertificateSignature(
      canonical,
      badSig,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
    }
  });

  it('rejects unresolvable credential', () => {
    const badRef = {
      ...validSig,
      credential_rotation_reference: {
        identity_id: 'did:soma:nonexistent',
        credential_id: 'cred-none',
        rotation_event_hash: 'rot-none',
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      badRef,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects credential not yet effective at issued_at', () => {
    // cred-alpha-2026-02 has effective_at = 1770100000000,
    // but issuedAt for birth vector is 1770000000000.
    const futureSig = {
      ...validSig,
      credential_rotation_reference: {
        identity_id: 'did:soma:issuer-alpha',
        credential_id: 'cred-alpha-2026-02',
        rotation_event_hash: 'rot-alpha-effective-002',
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      futureSig,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      );
    }
  });

  it('rejects revoked credential', () => {
    // cred-delta-2026-01 has revoked_at = 1770000100000.
    // Use issuedAt after revocation.
    const revokedSig = {
      ...validSig,
      identity_id: 'did:soma:revoked-delta',
      credential_rotation_reference: {
        identity_id: 'did:soma:revoked-delta',
        credential_id: 'cred-delta-2026-01',
        rotation_event_hash: 'rot-delta-revoked-001',
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      revokedSig,
      1770000200000,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.CREDENTIAL_REVOKED);
    }
  });

  it('rejects tampered signature bytes', () => {
    const tampered = {
      ...validSig,
      signature_bytes: Buffer.alloc(64, 0).toString('base64'),
    };
    const result = verifyCertificateSignature(
      canonical,
      tampered,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
    }
  });

  it('rejects wrong-length signature', () => {
    const short = {
      ...validSig,
      signature_bytes: Buffer.alloc(32, 0).toString('base64'),
    };
    const result = verifyCertificateSignature(
      canonical,
      short,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
    }
  });

  it('rejects sig.identity_id mismatching credential_rotation_reference.identity_id', () => {
    const badSig = {
      ...validSig,
      identity_id: 'did:soma:wrong-identity',
    };
    const result = verifyCertificateSignature(
      canonical,
      badSig,
      issuedAt,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects lookup returning credential with mismatched identity_id', () => {
    const wrongIdentityLookup: CredentialLookup = {
      resolve() {
        return {
          found: true,
          credential: {
            credential_id:
              validSig.credential_rotation_reference.credential_id,
            identity_id: 'did:soma:imposter',
            algorithm_suite: 'ed25519',
            public_key_spki_der_base64:
              'MCowBQYDK2VwAyEASqcSsDSxWTBKNHFZU8OHojJ+n95mKoGPP4gfnC0Ky44=',
            effective_at: 1770000000000,
            revoked_at: null,
          },
        };
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      wrongIdentityLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects lookup returning credential with mismatched credential_id', () => {
    const wrongCredLookup: CredentialLookup = {
      resolve() {
        return {
          found: true,
          credential: {
            credential_id: 'cred-wrong-id',
            identity_id:
              validSig.credential_rotation_reference.identity_id,
            algorithm_suite: 'ed25519',
            public_key_spki_der_base64:
              'MCowBQYDK2VwAyEASqcSsDSxWTBKNHFZU8OHojJ+n95mKoGPP4gfnC0Ky44=',
            effective_at: 1770000000000,
            revoked_at: null,
          },
        };
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      wrongCredLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects unsupported algorithm_suite', () => {
    const badAlgoLookup: CredentialLookup = {
      resolve() {
        return {
          found: true,
          credential: {
            credential_id:
              validSig.credential_rotation_reference.credential_id,
            identity_id:
              validSig.credential_rotation_reference.identity_id,
            algorithm_suite: 'rsa-2048',
            public_key_spki_der_base64:
              'MCowBQYDK2VwAyEASqcSsDSxWTBKNHFZU8OHojJ+n95mKoGPP4gfnC0Ky44=',
            effective_at: 1770000000000,
            revoked_at: null,
          },
        };
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      badAlgoLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects malformed non-Ed25519 SPKI DER prefix', () => {
    // 44 bytes but wrong prefix (RSA-ish OID instead of Ed25519).
    const badDer = Buffer.alloc(44, 0);
    badDer[0] = 0x30; // SEQUENCE tag but wrong OID bytes
    const badPrefixLookup: CredentialLookup = {
      resolve() {
        return {
          found: true,
          credential: {
            credential_id:
              validSig.credential_rotation_reference.credential_id,
            identity_id:
              validSig.credential_rotation_reference.identity_id,
            algorithm_suite: 'ed25519',
            public_key_spki_der_base64: badDer.toString('base64'),
            effective_at: 1770000000000,
            revoked_at: null,
          },
        };
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      badPrefixLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('fails closed when lookup returns miss', () => {
    const missLookup: CredentialLookup = {
      resolve() {
        return { found: false, reason: 'unknown-identity' };
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      missLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('fails closed when lookup.resolve() throws', () => {
    const throwingLookup: CredentialLookup = {
      resolve() {
        throw new Error('adapter unavailable');
      },
    };
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      issuedAt,
      throwingLookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      );
    }
  });

  it('rejects NaN issuedAt as credential-ineffective', () => {
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      NaN,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      );
    }
  });

  it('rejects Infinity issuedAt as credential-ineffective', () => {
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      Infinity,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      );
    }
  });

  it('rejects non-integer issuedAt as credential-ineffective', () => {
    const result = verifyCertificateSignature(
      canonical,
      validSig,
      1770000000000.5,
      lookup,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(
        FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      );
    }
  });
});
