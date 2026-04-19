/**
 * Supply-chain attestation — provable release integrity for Soma packages.
 *
 * Lets users verify that the `soma-heart` (or any tracked) tarball they
 * installed matches a maintainer-signed entry in an append-only release
 * log. Closes audit limit #10.
 */

export {
  ReleaseLog,
  verifyInstalledPackage,
  detectReleaseFork,
  type ReleaseEntry,
  type ReleaseChainHead,
  type ReleaseVerification,
  type ReleaseForkProof,
  type InstallVerification,
} from "./release-log.js";

export {
  createUpdateCertificate,
  addAuthorization,
  verifyUpdateCertificate,
  computeUpdateCertificateSigningInput,
  computeUpdateCertificateHash,
  verifyPackageProvenance,
  type UpdateCertificate,
  type UpdateAuthorization,
  type AuthorizerRole,
  type UpdateCertificateVerification,
  type PackageProvenance,
  type PackageProvenanceVerification,
} from "./update-certificate.js";
