// soma-sense/certificate - observer-safe type re-export
//
// Areas 1-7 and 12 only (Gate 6 accepted observer-safe set).

// Area 1: Canonicalization helpers
export {
  CanonicalisationError,
  canonicalizePayload,
  type SignerRole,
} from "soma-heart/certificate";

// Area 2: Certificate identifier helpers
export { computeCertificateId } from "soma-heart/certificate";

// Area 3: Signature input helpers (read-path only)
export {
  computeSignatureInput,
  computeSignatureInputHash,
} from "soma-heart/certificate";

// Area 4: Vector loading / conformance helpers
export {
  VectorLoadError,
  loadManifest,
  type Manifest,
  type Vector,
  type VectorSignatureInput,
  type VectorVerifierPolicy,
  type RotationFixtureIdentity,
} from "soma-heart/certificate";

// Area 5: Claim vocabulary validator
export { validateClaimKind } from "soma-heart/certificate";

// Area 6: Evidence vocabulary validator
export { validateEvidenceKind } from "soma-heart/certificate";

// Area 7: Profile validator
export { validateProfile } from "soma-heart/certificate";

// Area 5-7 shared types
export {
  type Disposition,
  type VocabularyResult,
} from "soma-heart/certificate";

// Area 12: Failure-mode / error mapping
export {
  FAILURE_MODES,
  isFailureMode,
  createFailure,
  type FailureMode,
  type CertificateFailure,
} from "soma-heart/certificate";
