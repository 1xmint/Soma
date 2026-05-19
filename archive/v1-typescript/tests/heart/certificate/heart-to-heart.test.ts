import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import { loadManifest } from '../../../src/heart/certificate/vectors.js';
import {
  verifyHeartToHeartSignatures,
  type HeartToHeartCertificateInput,
} from '../../../src/heart/certificate/heart-to-heart.js';
import type {
  CredentialLookup,
  CredentialLookupResult,
  CredentialRotationReference,
  CertificateSignatureEntry,
  ResolvedCredential,
} from '../../../src/heart/certificate/signature.js';

const repoRoot = resolve(__dirname, '../../..');
const manifest = loadManifest(repoRoot);

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

describe('heart-to-heart integrated verifier (§5)', () => {
  const h2hVector = manifest.vectors.find(
    (v) => v.id === 'accepted-heart-to-heart',
  )!;
  const h2hCert = h2hVector.certificate as unknown as HeartToHeartCertificateInput;

  it('passes when heart-to-heart cert has both issuer and counterparty sigs', () => {
    const result = verifyHeartToHeartSignatures(h2hCert, lookup);
    expect(result.valid).toBe(true);
  });

  it('fails when heart-to-heart cert is missing counterparty signature', () => {
    const sigs = (h2hCert.signatures as CertificateSignatureEntry[]).filter(
      (s) => s.signer_role !== 'counterparty',
    );
    const cert = { ...h2hCert, signatures: sigs } as HeartToHeartCertificateInput;
    const result = verifyHeartToHeartSignatures(cert, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
      expect(result.detail).toMatch(/counterparty/);
    }
  });

  it('fails when heart-to-heart cert is missing issuer signature', () => {
    const sigs = (h2hCert.signatures as CertificateSignatureEntry[]).filter(
      (s) => s.signer_role !== 'issuer',
    );
    const cert = { ...h2hCert, signatures: sigs } as HeartToHeartCertificateInput;
    const result = verifyHeartToHeartSignatures(cert, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
      expect(result.detail).toMatch(/issuer/);
    }
  });

  it('skips dual-sig check for non heart-to-heart profiles', () => {
    const birthVector = manifest.vectors.find((v) => v.id === 'accepted-birth')!;
    const birthCert = birthVector.certificate as unknown as HeartToHeartCertificateInput;
    const result = verifyHeartToHeartSignatures(birthCert, lookup);
    expect(result.valid).toBe(true);
  });

  it('fails when heart-to-heart cert has no signatures at all', () => {
    const cert = { ...h2hCert, signatures: [] } as unknown as HeartToHeartCertificateInput;
    const result = verifyHeartToHeartSignatures(cert, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
    }
  });
});
