// Soma Heart certificate module -- internal barrel.
//
// Source directory: src/heart/certificate/
// Accepted subpath: soma-heart/certificate
// Gate 6 proposal: docs/proposals/soma-heart-certificate-gate6-stabilisation.md
// Spec: SOMA-HEART-CERTIFICATE-SPEC.md
//
// This directory reconciles the Gate 6 conceptual source directory
// (packages/soma-heart/src/certificate/) with the existing build
// convention (src/heart/<module>/ -> dist/heart/<module>/).
//
// Each functional area is added by a separate slice per the
// implementation readiness packet
// (docs/proposals/soma-heart-certificate-implementation-readiness.md).

export {
  CanonicalisationError,
  canonicalizePayload,
  computeCertificateId,
  computeSignatureInput,
  computeSignatureInputHash,
  type SignerRole,
} from './canonical.js';

export {
  VectorLoadError,
  loadManifest,
  type Manifest,
  type Vector,
  type VectorSignatureInput,
  type VectorVerifierPolicy,
  type RotationFixtureIdentity,
} from './vectors.js';

export {
  validateProfile,
  validateClaimKind,
  validateEvidenceKind,
  type Disposition,
  type VocabularyResult,
} from './vocabulary.js';

export {
  FAILURE_MODES,
  isFailureMode,
  createFailure,
  type FailureMode,
  type CertificateFailure,
} from './failure-modes.js';

export {
  evaluatePolicy,
  type VerifierPolicy,
  type PolicyCertificateInput,
  type PolicyViolation,
  type PolicyEvalResult,
  type PolicyEvalOk,
  type PolicyEvalFail,
} from './policy.js';

export {
  bindSomaCheckEvidence,
  type SomaCheckReceiptInput,
  type FreshnessClaimBinding,
  type EvidenceReferenceBinding,
  type SomaCheckBindingResult,
  type SomaCheckBindingOk,
  type SomaCheckBindingFail,
} from './soma-check-binding.js';

export {
  bindPaymentRailEvidence,
  type PaymentRailReceiptInput,
  type PaymentClaimBinding,
  type PaymentEvidenceBinding,
  type PaymentRailBindingResult,
  type PaymentRailBindingOk,
  type PaymentRailBindingFail,
} from './payment-rail-binding.js';

export {
  verifyCertificateSignature,
  type CredentialLookup,
  type CredentialLookupResult,
  type CredentialLookupHit,
  type CredentialLookupMiss,
  type CredentialRotationReference,
  type CertificateSignatureEntry,
  type ResolvedCredential,
  type SignatureVerifyResult,
  type SignatureVerifyOk,
  type SignatureVerifyFail,
} from './signature.js';
