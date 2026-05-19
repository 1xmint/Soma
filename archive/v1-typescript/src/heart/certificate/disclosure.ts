// Disclosure / privacy enforcement (§16).
//
// When a certificate contains evidence of kind `private_evidence_pointer`,
// the `disclosure` field MUST be present declaring what was withheld and
// which verification checks are impossible.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

// -- Types ------------------------------------------------------------------

export interface DisclosureField {
  readonly withheld: readonly string[];
  readonly unverifiable_checks: readonly string[];
}

export interface DisclosureCertificateInput {
  readonly evidence_references: readonly { readonly kind: string }[];
  readonly disclosure?: DisclosureField;
}

export interface DisclosureValidOk {
  readonly valid: true;
}

export interface DisclosureValidFail {
  readonly valid: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export type DisclosureValidResult = DisclosureValidOk | DisclosureValidFail;

// -- Private-evidence detection ----------------------------------------------

const PRIVATE_EVIDENCE_KINDS: ReadonlySet<string> = new Set([
  'private_evidence_pointer',
]);

function hasPrivateEvidence(
  refs: readonly { readonly kind: string }[],
): boolean {
  return refs.some((r) => PRIVATE_EVIDENCE_KINDS.has(r.kind));
}

// -- Validator ---------------------------------------------------------------

export function validateDisclosure(
  cert: DisclosureCertificateInput,
): DisclosureValidResult {
  if (!hasPrivateEvidence(cert.evidence_references)) {
    return { valid: true };
  }

  if (cert.disclosure === undefined || cert.disclosure === null) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.DISCLOSURE_MISSING,
      detail:
        'certificate has private evidence but disclosure field is absent',
    };
  }

  if (
    !Array.isArray(cert.disclosure.withheld) ||
    !Array.isArray(cert.disclosure.unverifiable_checks)
  ) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.DISCLOSURE_MISSING,
      detail:
        'disclosure must declare withheld items and unverifiable_checks',
    };
  }

  return { valid: true };
}
