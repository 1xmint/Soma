import { describe, it, expect } from 'vitest';
import {
  validateProfile,
  validateClaimKind,
  validateEvidenceKind,
} from '../../../src/heart/certificate/vocabulary.js';

// -- Profile validators (spec section 5) --------------------------------------

describe('validateProfile', () => {
  describe('accepted profiles', () => {
    for (const profile of [
      'birth',
      'one-sided',
      'heart-to-heart',
      'freshness-receipt-bound',
    ]) {
      it(`accepts ${profile}`, () => {
        const r = validateProfile(profile);
        expect(r.valid).toBe(true);
        expect(r.disposition).toBe('accepted');
        expect(r.failureMode).toBeNull();
      });
    }
  });

  describe('deferred profiles', () => {
    for (const profile of ['policy-statement', 'witnessed']) {
      it(`rejects ${profile} with profile-deferred`, () => {
        const r = validateProfile(profile);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('deferred');
        expect(r.failureMode).toBe('profile-deferred');
      });
    }
  });

  describe('open profiles', () => {
    it('rejects fulfillment-receipt-bound with profile-not-allowed', () => {
      const r = validateProfile('fulfillment-receipt-bound');
      expect(r.valid).toBe(false);
      expect(r.disposition).toBe('open');
      expect(r.failureMode).toBe('profile-not-allowed');
    });
  });

  describe('unknown profiles', () => {
    for (const profile of ['', 'unknown-profile', 'BIRTH', 'Birth']) {
      it(`rejects ${JSON.stringify(profile)} with profile-not-allowed`, () => {
        const r = validateProfile(profile);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('unknown');
        expect(r.failureMode).toBe('profile-not-allowed');
      });
    }
  });
});

// -- Claim validators (spec section 7) ----------------------------------------

describe('validateClaimKind', () => {
  describe('accepted claim kinds', () => {
    for (const kind of [
      'identity_control',
      'credential_validity',
      'endpoint_observation',
      'freshness_receipt',
      'payment_receipt_reference',
      'content_hash_commitment',
      'policy_statement',
    ]) {
      it(`accepts ${kind}`, () => {
        const r = validateClaimKind(kind);
        expect(r.valid).toBe(true);
        expect(r.disposition).toBe('accepted');
        expect(r.failureMode).toBeNull();
      });
    }
  });

  describe('deferred claim kinds', () => {
    for (const kind of [
      'capability_statement',
      'delegation_or_endorsement',
    ]) {
      it(`rejects ${kind} with claim-deferred`, () => {
        const r = validateClaimKind(kind);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('deferred');
        expect(r.failureMode).toBe('claim-deferred');
      });
    }
  });

  describe('open claim kinds', () => {
    it('rejects fulfillment_receipt with claim-not-allowed', () => {
      const r = validateClaimKind('fulfillment_receipt');
      expect(r.valid).toBe(false);
      expect(r.disposition).toBe('open');
      expect(r.failureMode).toBe('claim-not-allowed');
    });
  });

  describe('unknown claim kinds', () => {
    for (const kind of ['', 'unknown_claim', 'IDENTITY_CONTROL']) {
      it(`rejects ${JSON.stringify(kind)} with claim-not-allowed`, () => {
        const r = validateClaimKind(kind);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('unknown');
        expect(r.failureMode).toBe('claim-not-allowed');
      });
    }
  });
});

// -- Evidence validators (spec section 8) -------------------------------------

describe('validateEvidenceKind', () => {
  describe('accepted evidence kinds', () => {
    for (const kind of [
      'signature',
      'hash_commitment',
      'timestamp',
      'request_response_transcript_hash',
      'receipt_reference',
      'payment_rail_receipt_reference',
      'verifier_policy_reference',
    ]) {
      it(`accepts ${kind}`, () => {
        const r = validateEvidenceKind(kind);
        expect(r.valid).toBe(true);
        expect(r.disposition).toBe('accepted');
        expect(r.failureMode).toBeNull();
      });
    }
  });

  describe('deferred evidence kinds', () => {
    for (const kind of [
      'credential_presentation_reference',
      'media_content_hash',
      'third_party_attestation_reference',
    ]) {
      it(`rejects ${kind} with evidence-deferred`, () => {
        const r = validateEvidenceKind(kind);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('deferred');
        expect(r.failureMode).toBe('evidence-deferred');
      });
    }
  });

  describe('open evidence kinds', () => {
    for (const kind of [
      'observation_log_reference',
      'private_evidence_pointer',
    ]) {
      it(`rejects ${kind} with evidence-not-allowed`, () => {
        const r = validateEvidenceKind(kind);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('open');
        expect(r.failureMode).toBe('evidence-not-allowed');
      });
    }
  });

  describe('unknown evidence kinds', () => {
    for (const kind of ['', 'unknown_evidence', 'SIGNATURE']) {
      it(`rejects ${JSON.stringify(kind)} with evidence-not-allowed`, () => {
        const r = validateEvidenceKind(kind);
        expect(r.valid).toBe(false);
        expect(r.disposition).toBe('unknown');
        expect(r.failureMode).toBe('evidence-not-allowed');
      });
    }
  });
});
