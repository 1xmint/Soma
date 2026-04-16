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
