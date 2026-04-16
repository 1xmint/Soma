import { describe, it, expect } from 'vitest';
import {
  FAILURE_MODES,
  isFailureMode,
  createFailure,
} from '../../../src/heart/certificate/failure-modes.js';
import {
  validateProfile,
  validateClaimKind,
  validateEvidenceKind,
} from '../../../src/heart/certificate/vocabulary.js';

// Spec section 18 defines exactly 16 failure modes.

const SPEC_SECTION_18_IDENTIFIERS = [
  'profile-not-allowed',
  'profile-deferred',
  'claim-not-allowed',
  'claim-deferred',
  'evidence-not-allowed',
  'evidence-deferred',
  'signature-invalid',
  'credential-unresolvable',
  'credential-ineffective',
  'credential-revoked',
  'chain-link-mismatch',
  'chain-link-unresolvable',
  'freshness-window-expired',
  'evidence-missing',
  'disclosure-missing',
  'canonicalisation-divergence',
] as const;

describe('FAILURE_MODES constant', () => {
  it('has exactly 16 entries', () => {
    expect(Object.keys(FAILURE_MODES).length).toBe(16);
  });

  it('values match spec section 18 identifiers exactly', () => {
    const values = Object.values(FAILURE_MODES).sort();
    const expected = [...SPEC_SECTION_18_IDENTIFIERS].sort();
    expect(values).toEqual(expected);
  });

  for (const id of SPEC_SECTION_18_IDENTIFIERS) {
    it(`contains ${id}`, () => {
      expect(Object.values(FAILURE_MODES)).toContain(id);
    });
  }

  it('all values are lowercase kebab-case', () => {
    for (const value of Object.values(FAILURE_MODES)) {
      expect(value).toMatch(/^[a-z][a-z0-9-]*$/);
    }
  });

  it('contains no duplicate values', () => {
    const values = Object.values(FAILURE_MODES);
    expect(new Set(values).size).toBe(values.length);
  });
});

describe('isFailureMode', () => {
  for (const id of SPEC_SECTION_18_IDENTIFIERS) {
    it(`recognizes ${id}`, () => {
      expect(isFailureMode(id)).toBe(true);
    });
  }

  it('rejects unknown strings', () => {
    expect(isFailureMode('unknown-mode')).toBe(false);
    expect(isFailureMode('')).toBe(false);
    expect(isFailureMode('PROFILE-NOT-ALLOWED')).toBe(false);
  });
});

describe('createFailure', () => {
  it('produces a minimal failure record', () => {
    const f = createFailure(FAILURE_MODES.SIGNATURE_INVALID);
    expect(f.error_code).toBe('signature-invalid');
    expect(f.failure_mode).toBe('signature-invalid');
    expect(f.message).toBeUndefined();
    expect(f.vector_id).toBeUndefined();
  });

  it('error_code and failure_mode are always equal', () => {
    const f = createFailure(FAILURE_MODES.CANONICALISATION_DIVERGENCE);
    expect(f.error_code).toBe(f.failure_mode);
  });

  it('includes optional message', () => {
    const f = createFailure(
      FAILURE_MODES.EVIDENCE_MISSING,
      'required evidence absent',
    );
    expect(f.message).toBe('required evidence absent');
  });

  it('includes optional vector_id', () => {
    const f = createFailure(
      FAILURE_MODES.CHAIN_LINK_MISMATCH,
      'mismatch',
      'test-vector-1',
    );
    expect(f.vector_id).toBe('test-vector-1');
  });
});

describe('vocabulary validators use centralized failure modes', () => {
  it('validateProfile uses FAILURE_MODES identifiers', () => {
    const deferred = validateProfile('policy-statement');
    expect(isFailureMode(deferred.failureMode!)).toBe(true);
    expect(deferred.failureMode).toBe(FAILURE_MODES.PROFILE_DEFERRED);

    const unknown = validateProfile('nonexistent');
    expect(isFailureMode(unknown.failureMode!)).toBe(true);
    expect(unknown.failureMode).toBe(FAILURE_MODES.PROFILE_NOT_ALLOWED);
  });

  it('validateClaimKind uses FAILURE_MODES identifiers', () => {
    const deferred = validateClaimKind('capability_statement');
    expect(isFailureMode(deferred.failureMode!)).toBe(true);
    expect(deferred.failureMode).toBe(FAILURE_MODES.CLAIM_DEFERRED);

    const unknown = validateClaimKind('nonexistent');
    expect(isFailureMode(unknown.failureMode!)).toBe(true);
    expect(unknown.failureMode).toBe(FAILURE_MODES.CLAIM_NOT_ALLOWED);
  });

  it('validateEvidenceKind uses FAILURE_MODES identifiers', () => {
    const deferred = validateEvidenceKind('media_content_hash');
    expect(isFailureMode(deferred.failureMode!)).toBe(true);
    expect(deferred.failureMode).toBe(FAILURE_MODES.EVIDENCE_DEFERRED);

    const unknown = validateEvidenceKind('nonexistent');
    expect(isFailureMode(unknown.failureMode!)).toBe(true);
    expect(unknown.failureMode).toBe(FAILURE_MODES.EVIDENCE_NOT_ALLOWED);
  });
});
