import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import { loadManifest } from '../../../src/heart/certificate/vectors.js';
import {
  evaluateChain,
  type CertificateChainLink,
} from '../../../src/heart/certificate/chain.js';
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

function vectorToChainLink(
  vectorId: string,
  issuerIdentityId: string,
  subjectIdentityId: string,
): CertificateChainLink {
  const vector = manifest.vectors.find((v) => v.id === vectorId)!;
  return {
    certificate: vector.certificate as Record<string, unknown>,
    issuer_identity_id: issuerIdentityId,
    subject_identity_id: subjectIdentityId,
  };
}

describe('certificate chain evaluation (§11.3)', () => {
  it('passes a single-cert chain (trivial case)', () => {
    const link = vectorToChainLink(
      'accepted-birth',
      'did:soma:issuer-alpha',
      'did:soma:subject-beta',
    );
    const result = evaluateChain({ links: [link] }, lookup);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.links_verified).toBe(1);
    }
  });

  it('passes a valid 2-link chain where child issuer matches parent subject', () => {
    const parent = vectorToChainLink(
      'accepted-birth',
      'did:soma:issuer-alpha',
      'did:soma:issuer-alpha',
    );
    const child = vectorToChainLink(
      'accepted-one-sided',
      'did:soma:issuer-alpha',
      'did:soma:end-entity',
    );
    const result = evaluateChain({ links: [parent, child] }, lookup);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.links_verified).toBe(2);
    }
  });

  it('fails with CHAIN_LINK_MISMATCH when issuer/subject do not match', () => {
    const parent = vectorToChainLink(
      'accepted-birth',
      'did:soma:issuer-alpha',
      'did:soma:subject-A',
    );
    const child = vectorToChainLink(
      'accepted-one-sided',
      'did:soma:issuer-alpha',
      'did:soma:end-entity',
    );
    const result = evaluateChain({ links: [parent, child] }, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.CHAIN_LINK_MISMATCH);
      expect(result.failed_link_index).toBe(1);
    }
  });

  it('fails closed when a link has a bad signature', () => {
    const vector = manifest.vectors.find((v) => v.id === 'accepted-birth')!;
    const cert = vector.certificate as Record<string, unknown>;
    const sigs = cert.signatures as CertificateSignatureEntry[];
    const tamperedSig = {
      ...sigs[0],
      signature_bytes: Buffer.alloc(64, 0).toString('base64'),
    };
    const tamperedCert = { ...cert, signatures: [tamperedSig] };
    const link: CertificateChainLink = {
      certificate: tamperedCert,
      issuer_identity_id: 'did:soma:issuer-alpha',
      subject_identity_id: 'did:soma:subject-beta',
    };
    const result = evaluateChain({ links: [link] }, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.SIGNATURE_INVALID);
      expect(result.failed_link_index).toBe(0);
    }
  });

  it('fails on empty chain', () => {
    const result = evaluateChain({ links: [] }, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE);
    }
  });

  it('returns first failure and stops processing', () => {
    const vector = manifest.vectors.find((v) => v.id === 'accepted-birth')!;
    const cert = vector.certificate as Record<string, unknown>;
    const sigs = cert.signatures as CertificateSignatureEntry[];
    const tamperedSig = {
      ...sigs[0],
      signature_bytes: Buffer.alloc(64, 0).toString('base64'),
    };
    const tamperedCert = { ...cert, signatures: [tamperedSig] };
    const badLink: CertificateChainLink = {
      certificate: tamperedCert,
      issuer_identity_id: 'did:soma:issuer-alpha',
      subject_identity_id: 'did:soma:issuer-alpha',
    };
    const goodLink = vectorToChainLink(
      'accepted-one-sided',
      'did:soma:issuer-alpha',
      'did:soma:end',
    );
    const result = evaluateChain({ links: [badLink, goodLink] }, lookup);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failed_link_index).toBe(0);
    }
  });
});
