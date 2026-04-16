// v0.1 failure-mode identifiers from SOMA-HEART-CERTIFICATE-SPEC.md section 18.
// These are the only error identifiers the certificate module may emit
// for the mapped failure modes. No extra identifiers beyond this list.

export const FAILURE_MODES = {
  PROFILE_NOT_ALLOWED: 'profile-not-allowed',
  PROFILE_DEFERRED: 'profile-deferred',
  CLAIM_NOT_ALLOWED: 'claim-not-allowed',
  CLAIM_DEFERRED: 'claim-deferred',
  EVIDENCE_NOT_ALLOWED: 'evidence-not-allowed',
  EVIDENCE_DEFERRED: 'evidence-deferred',
  SIGNATURE_INVALID: 'signature-invalid',
  CREDENTIAL_UNRESOLVABLE: 'credential-unresolvable',
  CREDENTIAL_INEFFECTIVE: 'credential-ineffective',
  CREDENTIAL_REVOKED: 'credential-revoked',
  CHAIN_LINK_MISMATCH: 'chain-link-mismatch',
  CHAIN_LINK_UNRESOLVABLE: 'chain-link-unresolvable',
  FRESHNESS_WINDOW_EXPIRED: 'freshness-window-expired',
  EVIDENCE_MISSING: 'evidence-missing',
  DISCLOSURE_MISSING: 'disclosure-missing',
  CANONICALISATION_DIVERGENCE: 'canonicalisation-divergence',
} as const;

export type FailureMode = (typeof FAILURE_MODES)[keyof typeof FAILURE_MODES];

const ALL_FAILURE_MODES: ReadonlySet<string> = new Set(
  Object.values(FAILURE_MODES),
);

export function isFailureMode(value: string): value is FailureMode {
  return ALL_FAILURE_MODES.has(value);
}

export interface CertificateFailure {
  error_code: FailureMode;
  failure_mode: FailureMode;
  message?: string;
  vector_id?: string;
}

export function createFailure(
  mode: FailureMode,
  message?: string,
  vectorId?: string,
): CertificateFailure {
  const failure: CertificateFailure = {
    error_code: mode,
    failure_mode: mode,
  };
  if (message !== undefined) failure.message = message;
  if (vectorId !== undefined) failure.vector_id = vectorId;
  return failure;
}
