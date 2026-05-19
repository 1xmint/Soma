// Soma Heart certificate module -- public package entry.
//
// This file is the package-level entry for soma-heart/certificate.
// It exports only the Gate 6 accepted public surfaces. Internal
// rotation lookup, credential resolution, and signature verification
// primitives are NOT exported here; they remain available only via
// the internal barrel (index.ts) for in-repo use.
//
// Gate 6 public surface:
//   Areas 1-7:  canonicalization, cert ID, sig input, vectors,
//               claim/evidence/profile validators
//   Area 8:     verifier-policy evaluator (full install only)
//   Area 10:    Soma Check binding helper
//   Area 11:    payment rail binding interface
//   Area 12:    failure modes
//
// NOT exported:
//   Area 9:     rotation lookup adapter (internal-only)
//   Slice 6:    signature verification + credential resolution types

// Area 1: Canonicalization helpers
export {
  CanonicalisationError,
  canonicalizePayload,
  computeCertificateId,
  computeSignatureInput,
  computeSignatureInputHash,
  type SignerRole,
} from './canonical.js';

// Area 4: Vector loading / conformance helpers
export {
  VectorLoadError,
  loadManifest,
  type Manifest,
  type Vector,
  type VectorSignatureInput,
  type VectorVerifierPolicy,
  type RotationFixtureIdentity,
} from './vectors.js';

// Areas 5-7: Vocabulary validators
export {
  validateProfile,
  validateClaimKind,
  validateEvidenceKind,
  type Disposition,
  type VocabularyResult,
} from './vocabulary.js';

// Area 12: Failure-mode / error mapping
export {
  FAILURE_MODES,
  isFailureMode,
  createFailure,
  type FailureMode,
  type CertificateFailure,
} from './failure-modes.js';

// Area 8: Verifier-policy evaluator (full install only)
export {
  evaluatePolicy,
  type VerifierPolicy,
  type PolicyCertificateInput,
  type PolicyViolation,
  type PolicyEvalResult,
  type PolicyEvalOk,
  type PolicyEvalFail,
} from './policy.js';

// Area 10: Soma Check binding helper
export {
  bindSomaCheckEvidence,
  type SomaCheckReceiptInput,
  type FreshnessClaimBinding,
  type EvidenceReferenceBinding,
  type SomaCheckBindingResult,
  type SomaCheckBindingOk,
  type SomaCheckBindingFail,
} from './soma-check-binding.js';

// Area 11: Payment rail binding interface
export {
  bindPaymentRailEvidence,
  type PaymentRailReceiptInput,
  type PaymentClaimBinding,
  type PaymentEvidenceBinding,
  type PaymentRailBindingResult,
  type PaymentRailBindingOk,
  type PaymentRailBindingFail,
} from './payment-rail-binding.js';

// §12: policy_ref shape validator
export {
  validatePolicyRef,
  type PolicyRef,
  type PolicyRefValidResult,
  type PolicyRefValidOk,
  type PolicyRefValidFail,
} from './policy-ref.js';

// §11.3: Certificate chain evaluator
export {
  evaluateChain,
  type CertificateChainLink,
  type CertificateChainInput,
  type CertificateChainResult,
  type ChainEvalOk,
  type ChainEvalFail,
} from './chain.js';

// §16: Disclosure / privacy enforcement
export {
  validateDisclosure,
  type DisclosureField,
  type DisclosureCertificateInput,
  type DisclosureValidResult,
  type DisclosureValidOk,
  type DisclosureValidFail,
} from './disclosure.js';

// §5: Heart-to-heart integrated verifier
export {
  verifyHeartToHeartSignatures,
  type HeartToHeartCertificateInput,
  type HeartToHeartResult,
  type HeartToHeartOk,
  type HeartToHeartFail,
} from './heart-to-heart.js';
