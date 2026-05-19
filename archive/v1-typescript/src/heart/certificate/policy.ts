// Verifier-policy evaluator boundary (Slice 7).
//
// Evaluates a caller-supplied verifier policy against certificate-local
// profile, claim_set, and evidence_references vocabulary. Does NOT
// traverse trust chains, fetch prior certificates, or expose an
// "is-this-trusted" surface.
//
// Spec references: sections 4.3, 11, 12, 17, 18.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';
import {
  validateProfile,
  validateClaimKind,
  validateEvidenceKind,
} from './vocabulary.js';

// -- Policy shape (matches v0.1 vector manifest verifier_policy) ------------

export interface VerifierPolicy {
  readonly policy_id: string;
  readonly accepted_profiles: readonly string[];
  readonly accepted_claim_kinds: readonly string[];
  readonly accepted_evidence_kinds: readonly string[];
  readonly fail_closed: boolean;
  readonly max_chain_depth: number;
  readonly require_rotation_lookup: boolean;
}

// -- Certificate fields consumed by the evaluator ---------------------------

export interface PolicyCertificateInput {
  readonly profile: string;
  readonly claim_set: readonly { readonly kind: string }[];
  readonly evidence_references: readonly { readonly kind: string }[];
  readonly prior_certificate_ids?: readonly string[];
}

// -- Evaluation result ------------------------------------------------------

export interface PolicyViolation {
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export interface PolicyEvalOk {
  readonly accepted: true;
  readonly violations: readonly [];
}

export interface PolicyEvalFail {
  readonly accepted: false;
  readonly violations: readonly [PolicyViolation, ...PolicyViolation[]];
}

export type PolicyEvalResult = PolicyEvalOk | PolicyEvalFail;

// -- Evaluator --------------------------------------------------------------

export function evaluatePolicy(
  policy: VerifierPolicy,
  cert: PolicyCertificateInput,
): PolicyEvalResult {
  const violations: PolicyViolation[] = [];

  // v0.1: fail_closed must be true. Reject policies that attempt open evaluation.
  if (!policy.fail_closed) {
    violations.push({
      failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
      detail: 'v0.1 requires fail_closed: true',
    });
    return fail(violations);
  }

  // -- Profile ---------------------------------------------------------------

  const profileVocab = validateProfile(cert.profile);
  if (!profileVocab.valid) {
    violations.push({
      failureMode: profileVocab.failureMode!,
      detail: `profile "${cert.profile}" disposition: ${profileVocab.disposition}`,
    });
    return fail(violations);
  }

  if (!policy.accepted_profiles.includes(cert.profile)) {
    violations.push({
      failureMode: FAILURE_MODES.PROFILE_NOT_ALLOWED,
      detail: `profile "${cert.profile}" not in policy accepted_profiles`,
    });
    return fail(violations);
  }

  // -- Claims ----------------------------------------------------------------

  if (!Array.isArray(cert.claim_set) || cert.claim_set.length === 0) {
    violations.push({
      failureMode: FAILURE_MODES.CLAIM_NOT_ALLOWED,
      detail: 'claim_set is missing or empty',
    });
    return fail(violations);
  }

  for (const claim of cert.claim_set) {
    const claimVocab = validateClaimKind(claim.kind);
    if (!claimVocab.valid) {
      violations.push({
        failureMode: claimVocab.failureMode!,
        detail: `claim kind "${claim.kind}" disposition: ${claimVocab.disposition}`,
      });
    } else if (!policy.accepted_claim_kinds.includes(claim.kind)) {
      violations.push({
        failureMode: FAILURE_MODES.CLAIM_NOT_ALLOWED,
        detail: `claim kind "${claim.kind}" not in policy accepted_claim_kinds`,
      });
    }
  }

  if (violations.length > 0) return fail(violations);

  // -- Evidence --------------------------------------------------------------

  if (
    !Array.isArray(cert.evidence_references) ||
    cert.evidence_references.length === 0
  ) {
    violations.push({
      failureMode: FAILURE_MODES.EVIDENCE_MISSING,
      detail: 'evidence_references is missing or empty',
    });
    return fail(violations);
  }

  for (const ev of cert.evidence_references) {
    const evVocab = validateEvidenceKind(ev.kind);
    if (!evVocab.valid) {
      violations.push({
        failureMode: evVocab.failureMode!,
        detail: `evidence kind "${ev.kind}" disposition: ${evVocab.disposition}`,
      });
    } else if (!policy.accepted_evidence_kinds.includes(ev.kind)) {
      violations.push({
        failureMode: FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
        detail: `evidence kind "${ev.kind}" not in policy accepted_evidence_kinds`,
      });
    }
  }

  if (violations.length > 0) return fail(violations);

  // -- Chain depth (caller-supplied, no traversal) ---------------------------

  const priorCount = cert.prior_certificate_ids?.length ?? 0;
  if (priorCount > policy.max_chain_depth) {
    violations.push({
      failureMode: FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
      detail: `prior_certificate_ids count ${priorCount} exceeds max_chain_depth ${policy.max_chain_depth}`,
    });
    return fail(violations);
  }

  return { accepted: true, violations: [] as const };
}

function fail(violations: PolicyViolation[]): PolicyEvalFail {
  return {
    accepted: false,
    violations: violations as [PolicyViolation, ...PolicyViolation[]],
  };
}
