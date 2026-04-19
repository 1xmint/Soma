import { describe, it, expect } from 'vitest';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import {
  validateDisclosure,
  type DisclosureCertificateInput,
} from '../../../src/heart/certificate/disclosure.js';

describe('disclosure / privacy enforcement (§16)', () => {
  it('passes when cert has private evidence and disclosure is present', () => {
    const cert: DisclosureCertificateInput = {
      evidence_references: [{ kind: 'private_evidence_pointer' }],
      disclosure: {
        withheld: ['raw_evidence_payload'],
        unverifiable_checks: ['content_integrity'],
      },
    };
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(true);
  });

  it('raises DISCLOSURE_MISSING when cert has private evidence but no disclosure', () => {
    const cert: DisclosureCertificateInput = {
      evidence_references: [{ kind: 'private_evidence_pointer' }],
    };
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.DISCLOSURE_MISSING);
    }
  });

  it('passes when cert has no private evidence and no disclosure', () => {
    const cert: DisclosureCertificateInput = {
      evidence_references: [{ kind: 'signature' }, { kind: 'timestamp' }],
    };
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(true);
  });

  it('passes when cert has no private evidence even with disclosure present', () => {
    const cert: DisclosureCertificateInput = {
      evidence_references: [{ kind: 'hash_commitment' }],
      disclosure: {
        withheld: ['something'],
        unverifiable_checks: ['something_else'],
      },
    };
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(true);
  });

  it('fails when disclosure has invalid structure', () => {
    const cert = {
      evidence_references: [{ kind: 'private_evidence_pointer' }],
      disclosure: { withheld: 'not-an-array' },
    } as unknown as DisclosureCertificateInput;
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.DISCLOSURE_MISSING);
    }
  });

  it('handles mixed evidence with one private pointer', () => {
    const cert: DisclosureCertificateInput = {
      evidence_references: [
        { kind: 'signature' },
        { kind: 'private_evidence_pointer' },
        { kind: 'timestamp' },
      ],
    };
    const result = validateDisclosure(cert);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.failureMode).toBe(FAILURE_MODES.DISCLOSURE_MISSING);
    }
  });
});
