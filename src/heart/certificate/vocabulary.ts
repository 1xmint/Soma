// Vocabulary validators for v0.1 certificate profiles, claims, and evidence.
// Spec sections 5, 7, and 8. Dispositions: accepted, open, deferred.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

export type Disposition = 'accepted' | 'open' | 'deferred';

export interface VocabularyResult {
  valid: boolean;
  disposition: Disposition | 'unknown';
  failureMode: FailureMode | null;
}

// -- Profiles (spec section 5) -----------------------------------------------

const PROFILE_DISPOSITIONS: ReadonlyMap<string, Disposition> = new Map([
  ['birth', 'accepted'],
  ['one-sided', 'accepted'],
  ['heart-to-heart', 'accepted'],
  ['freshness-receipt-bound', 'accepted'],
  ['fulfillment-receipt-bound', 'open'],
  ['policy-statement', 'deferred'],
  ['witnessed', 'deferred'],
]);

export function validateProfile(profile: string): VocabularyResult {
  const disposition = PROFILE_DISPOSITIONS.get(profile);
  if (disposition === undefined) {
    return {
      valid: false,
      disposition: 'unknown',
      failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
    };
  }
  if (disposition === 'deferred') {
    return { valid: false, disposition, failureMode: FAILURE_MODES.PROFILE_DEFERRED };
  }
  if (disposition === 'open') {
    return { valid: false, disposition, failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED };
  }
  return { valid: true, disposition, failureMode: null };
}

// -- Claims (spec section 7) -------------------------------------------------

const CLAIM_DISPOSITIONS: ReadonlyMap<string, Disposition> = new Map([
  ['identity_control', 'accepted'],
  ['credential_validity', 'accepted'],
  ['endpoint_observation', 'accepted'],
  ['freshness_receipt', 'accepted'],
  ['payment_receipt_reference', 'accepted'],
  ['content_hash_commitment', 'accepted'],
  ['policy_statement', 'accepted'],
  ['fulfillment_receipt', 'open'],
  ['capability_statement', 'deferred'],
  ['delegation_or_endorsement', 'deferred'],
]);

export function validateClaimKind(kind: string): VocabularyResult {
  const disposition = CLAIM_DISPOSITIONS.get(kind);
  if (disposition === undefined) {
    return {
      valid: false,
      disposition: 'unknown',
      failureMode: FAILURE_MODES.CLAIM_NOT_ALLOWED,
    };
  }
  if (disposition === 'deferred') {
    return { valid: false, disposition, failureMode: FAILURE_MODES.CLAIM_DEFERRED };
  }
  if (disposition === 'open') {
    return { valid: false, disposition, failureMode: FAILURE_MODES.CLAIM_NOT_ALLOWED };
  }
  return { valid: true, disposition, failureMode: null };
}

// -- Evidence (spec section 8) ------------------------------------------------

const EVIDENCE_DISPOSITIONS: ReadonlyMap<string, Disposition> = new Map([
  ['signature', 'accepted'],
  ['hash_commitment', 'accepted'],
  ['timestamp', 'accepted'],
  ['request_response_transcript_hash', 'accepted'],
  ['receipt_reference', 'accepted'],
  ['payment_rail_receipt_reference', 'accepted'],
  ['verifier_policy_reference', 'accepted'],
  ['observation_log_reference', 'open'],
  ['private_evidence_pointer', 'open'],
  ['credential_presentation_reference', 'deferred'],
  ['media_content_hash', 'deferred'],
  ['third_party_attestation_reference', 'deferred'],
]);

export function validateEvidenceKind(kind: string): VocabularyResult {
  const disposition = EVIDENCE_DISPOSITIONS.get(kind);
  if (disposition === undefined) {
    return {
      valid: false,
      disposition: 'unknown',
      failureMode: FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
    };
  }
  if (disposition === 'deferred') {
    return { valid: false, disposition, failureMode: FAILURE_MODES.EVIDENCE_DEFERRED };
  }
  if (disposition === 'open') {
    return {
      valid: false,
      disposition,
      failureMode: FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
    };
  }
  return { valid: true, disposition, failureMode: null };
}
