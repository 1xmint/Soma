// policy_ref shape validator (§12 verifier policy reference).
//
// Validates the runtime shape of a verifier policy reference object
// as defined in SOMA-HEART-CERTIFICATE-SPEC.md section 12.
//
// Spec requirements:
// - policy_id is REQUIRED and MUST be a stable ASCII identifier or URI.
// - policy_hash is OPTIONAL but, when present, MUST be the lowercase
//   SHA-256 hex digest (64 chars).
// - policy_version and policy_uri are OPTIONAL attribution fields.
// - A verifier MUST fail closed if a certificate references a policy
//   it cannot identify, fetch, hash, or match.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

// -- Types ------------------------------------------------------------------

/**
 * Runtime type for a §12 verifier policy reference object.
 *
 * `policy_id` is REQUIRED. All other fields are OPTIONAL.
 */
export interface PolicyRef {
  readonly policy_id: string;
  readonly policy_hash?: string;
  readonly policy_version?: string;
  readonly policy_uri?: string;
}

// -- Validation result ------------------------------------------------------

/** Successful policy_ref validation. */
export interface PolicyRefValidOk {
  readonly valid: true;
}

/** Failed policy_ref validation with failure mode and detail. */
export interface PolicyRefValidFail {
  readonly valid: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export type PolicyRefValidResult = PolicyRefValidOk | PolicyRefValidFail;

// -- ASCII check (printable, no control chars) ------------------------------

const ASCII_PRINTABLE = /^[\x20-\x7E]+$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

// -- Validator --------------------------------------------------------------

/**
 * Validates a policy_ref object against §12 requirements.
 *
 * Fail-closed: returns a typed failure if the shape is invalid.
 */
export function validatePolicyRef(ref: PolicyRef): PolicyRefValidResult {
  if (typeof ref.policy_id !== 'string' || ref.policy_id.length === 0) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
      detail: 'policy_id is required and must be a non-empty string',
    };
  }

  if (!ASCII_PRINTABLE.test(ref.policy_id)) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
      detail: 'policy_id must contain only ASCII printable characters (0x20-0x7E)',
    };
  }

  if (ref.policy_hash !== undefined) {
    if (typeof ref.policy_hash !== 'string' || !SHA256_HEX.test(ref.policy_hash)) {
      return {
        valid: false,
        failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
        detail: 'policy_hash must be a lowercase SHA-256 hex digest (64 chars)',
      };
    }
  }

  return { valid: true };
}
