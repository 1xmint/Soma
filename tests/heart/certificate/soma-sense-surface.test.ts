import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// This test asserts the exact public surface of:
//   1. soma-heart/certificate (public.ts) - Gate 6 full-install public surface
//   2. soma-sense/certificate - observer-safe subset
// Both MUST fail if any forbidden identifier slips in.

const repoRoot = resolve(__dirname, '../../..');

// soma-heart/certificate public entry
const heartPublic = readFileSync(
  resolve(repoRoot, 'src/heart/certificate/public.ts'),
  'utf8',
);

// soma-sense/certificate re-exports
const senseJs = readFileSync(
  resolve(repoRoot, 'packages/soma-sense/certificate.js'),
  'utf8',
);
const senseDts = readFileSync(
  resolve(repoRoot, 'packages/soma-sense/certificate.d.ts'),
  'utf8',
);

// -- Rotation / signature verification identifiers (internal-only) -----------

const ROTATION_FORBIDDEN = [
  'verifyCertificateSignature',
  'CredentialLookup',
  'CredentialLookupResult',
  'CredentialLookupHit',
  'CredentialLookupMiss',
  'CredentialRotationReference',
  'CertificateSignatureEntry',
  'ResolvedCredential',
  'SignatureVerifyResult',
  'SignatureVerifyOk',
  'SignatureVerifyFail',
];

// -- soma-sense additional forbidden (full-install-only surfaces) ------------

const SENSE_EXTRA_FORBIDDEN = [
  // Verifier-policy evaluator (area 8, full install only)
  'evaluatePolicy',
  'VerifierPolicy',
  'PolicyCertificateInput',
  'PolicyViolation',
  'PolicyEvalResult',
  'PolicyEvalOk',
  'PolicyEvalFail',
  // Soma Check binding (area 10)
  'bindSomaCheckEvidence',
  'SomaCheckReceiptInput',
  'FreshnessClaimBinding',
  'EvidenceReferenceBinding',
  'SomaCheckBindingResult',
  'SomaCheckBindingOk',
  'SomaCheckBindingFail',
  // Payment rail binding (area 11)
  'bindPaymentRailEvidence',
  'PaymentRailReceiptInput',
  'PaymentClaimBinding',
  'PaymentEvidenceBinding',
  'PaymentRailBindingResult',
  'PaymentRailBindingOk',
  'PaymentRailBindingFail',
];

// -- Gate 6 public identifiers for soma-heart/certificate --------------------

const HEART_PUBLIC_VALUES = [
  // Areas 1-3
  'CanonicalisationError', 'canonicalizePayload', 'computeCertificateId',
  'computeSignatureInput', 'computeSignatureInputHash',
  // Area 4
  'VectorLoadError', 'loadManifest',
  // Areas 5-7
  'validateProfile', 'validateClaimKind', 'validateEvidenceKind',
  // Area 12
  'FAILURE_MODES', 'isFailureMode', 'createFailure',
  // Area 8
  'evaluatePolicy',
  // Area 10
  'bindSomaCheckEvidence',
  // Area 11
  'bindPaymentRailEvidence',
];

// -- Observer-safe identifiers for soma-sense/certificate --------------------

const SENSE_ALLOWED_VALUES = [
  'CanonicalisationError', 'canonicalizePayload', 'computeCertificateId',
  'computeSignatureInput', 'computeSignatureInputHash',
  'VectorLoadError', 'loadManifest',
  'validateClaimKind', 'validateEvidenceKind', 'validateProfile',
  'FAILURE_MODES', 'isFailureMode', 'createFailure',
];

const SENSE_ALLOWED_TYPES = [
  'SignerRole',
  'Manifest', 'Vector', 'VectorSignatureInput', 'VectorVerifierPolicy',
  'RotationFixtureIdentity',
  'Disposition', 'VocabularyResult',
  'FailureMode', 'CertificateFailure',
];

// ============================================================================
// soma-heart/certificate public surface tests
// ============================================================================

describe('soma-heart/certificate public surface (public.ts)', () => {
  it('contains all Gate 6 public value exports', () => {
    for (const name of HEART_PUBLIC_VALUES) {
      expect(heartPublic).toContain(name);
    }
  });

  for (const name of ROTATION_FORBIDDEN) {
    const pattern = new RegExp(`\\b${name}\\b`);
    it(`does NOT contain forbidden rotation/signature identifier: ${name}`, () => {
      expect(heartPublic).not.toMatch(pattern);
    });
  }

  it('does not import from signature.js', () => {
    expect(heartPublic).not.toMatch(/from\s+['"]\.\/signature/);
  });
});

// ============================================================================
// soma-sense/certificate observer-safe surface tests
// ============================================================================

describe('soma-sense/certificate observer-safe surface', () => {
  it('JS re-export contains all allowed value exports', () => {
    for (const name of SENSE_ALLOWED_VALUES) {
      expect(senseJs).toContain(name);
    }
  });

  it('d.ts re-export contains all allowed type exports', () => {
    for (const name of SENSE_ALLOWED_TYPES) {
      expect(senseDts).toContain(name);
    }
  });

  it('d.ts re-export contains all allowed value exports', () => {
    for (const name of SENSE_ALLOWED_VALUES) {
      expect(senseDts).toContain(name);
    }
  });

  // Forbidden: rotation + full-install-only surfaces
  const allSenseForbidden = [...ROTATION_FORBIDDEN, ...SENSE_EXTRA_FORBIDDEN];

  for (const name of allSenseForbidden) {
    const pattern = new RegExp(`\\b${name}\\b`);

    it(`JS does NOT contain forbidden identifier: ${name}`, () => {
      expect(senseJs).not.toMatch(pattern);
    });

    it(`d.ts does NOT contain forbidden identifier: ${name}`, () => {
      expect(senseDts).not.toMatch(pattern);
    });
  }

  it('JS re-export only imports from soma-heart/certificate', () => {
    const importLines = senseJs
      .split('\n')
      .filter((l: string) => l.includes('from '));
    for (const line of importLines) {
      expect(line).toContain('soma-heart/certificate');
    }
  });

  it('d.ts re-export only imports from soma-heart/certificate', () => {
    const importLines = senseDts
      .split('\n')
      .filter((l: string) => l.includes('from '));
    for (const line of importLines) {
      expect(line).toContain('soma-heart/certificate');
    }
  });

  it('JS re-export does not use export *', () => {
    expect(senseJs).not.toMatch(/export\s+\*/);
  });

  it('d.ts re-export does not use export *', () => {
    expect(senseDts).not.toMatch(/export\s+\*/);
  });
});

// ============================================================================
// Dependency version checks
// ============================================================================

describe('soma-sense dependency version', () => {
  it('depends on soma-heart >= 0.4.0 (required for ./certificate subpath)', () => {
    const pkg = JSON.parse(
      readFileSync(
        resolve(repoRoot, 'packages/soma-sense/package.json'),
        'utf8',
      ),
    );
    const range = pkg.dependencies?.['soma-heart'] as string;
    expect(range).toBeDefined();
    // Must not be ^0.3.x which would miss the ./certificate subpath
    expect(range).not.toMatch(/\^0\.3\./);
    expect(range).toMatch(/0\.4/);
  });
});
