// soma-sense/certificate - observer-safe re-export of soma-heart/certificate
//
// Areas 1-7 and 12 only (Gate 6 accepted observer-safe set).
// Does NOT re-export: signature verification (area 3 signing),
// verifier-policy evaluator (area 8), rotation lookup (area 9),
// Soma Check binding (area 10), payment rail binding (area 11).

// Area 1: Canonicalization helpers
export {
  CanonicalisationError,
  canonicalizePayload,
} from "soma-heart/certificate";

// Area 2: Certificate identifier helpers
export { computeCertificateId } from "soma-heart/certificate";

// Area 3: Signature input helpers (read-path only, no signing)
export {
  computeSignatureInput,
  computeSignatureInputHash,
} from "soma-heart/certificate";

// Area 4: Vector loading / conformance helpers
export {
  VectorLoadError,
  loadManifest,
} from "soma-heart/certificate";

// Area 5: Claim vocabulary validator
export { validateClaimKind } from "soma-heart/certificate";

// Area 6: Evidence vocabulary validator
export { validateEvidenceKind } from "soma-heart/certificate";

// Area 7: Profile validator
export { validateProfile } from "soma-heart/certificate";

// Area 12: Failure-mode / error mapping
export {
  FAILURE_MODES,
  isFailureMode,
  createFailure,
} from "soma-heart/certificate";
