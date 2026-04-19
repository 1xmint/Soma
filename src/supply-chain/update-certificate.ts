/**
 * UpdateCertificate — multi-party authorisation for package updates.
 *
 * When a maintainer publishes a new version of a Soma package, the
 * UpdateCertificate binds together:
 *   - what was released (package name, version, tarball hash)
 *   - who authorised it (one or more maintainer DIDs with signatures)
 *   - what ceremony tier was achieved (L0–L3)
 *   - what threshold was required and met
 *
 * The certificate is a multi-signature envelope: the primary maintainer
 * creates the certificate, then co-signers add their authorisations via
 * `addAuthorization()`. Each authorisation is independently verifiable.
 *
 * Verification (§2.2 order):
 *   1. Version tag matches expected domain.
 *   2. All authorization signatures verify against their stated pubkeys.
 *   3. Each authorizer's DID binds to their pubkey.
 *   4. Threshold is met (enough valid authorizations).
 *   5. Certificate is not expired (if expiresAt is set).
 *   6. Ceremony tier is at least the required minimum.
 *
 * Domain separation: all signatures use
 *   `domainSigningInput('soma/update-certificate/v1', ...)`
 * so they cannot be replayed as any other Soma signature type.
 *
 * See the task packet for the full specification.
 */

import { canonicalJson, domainSigningInput } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';
import type { CeremonyTier } from '../heart/human-delegation.js';

const UPDATE_CERTIFICATE_DOMAIN = 'soma/update-certificate/v1';

// ─── Types ──────────────────────────────────────────────────────────────────

/** Role of an authorizer within an UpdateCertificate. */
export type AuthorizerRole = 'maintainer' | 'consumer-heart' | 'council-member';

/**
 * A single authorisation within an UpdateCertificate.
 *
 * Each authorization attests: "I, `authorizerDid`, approve this exact
 * certificate payload." The signature covers the canonical signing input
 * of the certificate body (excluding all authorizations), so adding a
 * new authorization does not invalidate existing ones.
 */
export interface UpdateAuthorization {
  /** Role of this authorizer in the ceremony. */
  role: AuthorizerRole;
  /** DID of the authorizing party. */
  authorizerDid: string;
  /** Base64-encoded public key of the authorizer. */
  authorizerPublicKey: string;
  /** Ceremony tier this authorizer achieved (null for consumer hearts). */
  authorizerCeremonyTier: CeremonyTier | null;
  /**
   * Hash of the HumanDelegation that authorised this action (maintainer
   * only). Enables audit trail back to the biometric ceremony. Null for
   * consumer hearts and council members.
   */
  delegationHash: string | null;
  /** Base64-encoded Ed25519 signature over the certificate signing input. */
  signature: string;
  /** Timestamp when this authorization was issued (ms). */
  authorizedAt: number;
}

/**
 * Multi-party authorisation certificate for a package update.
 *
 * The certificate body (everything except `authorizations`) is signed
 * by each authorizer independently. This means:
 *   - Authorizations can be collected asynchronously.
 *   - Adding a new authorization never invalidates existing ones.
 *   - Verification checks each authorization independently, then
 *     confirms the threshold is met.
 */
export interface UpdateCertificate {
  /** Domain version tag — always `'soma/update-certificate/v1'`. */
  version: typeof UPDATE_CERTIFICATE_DOMAIN;
  /** Package name (e.g. `'soma-heart'`). */
  package: string;
  /** Semver version being authorised. */
  targetVersion: string;
  /** SHA-256 of the published tarball (64-char lowercase hex). */
  tarballSha256: string;
  /** Git commit SHA the tarball was built from. */
  gitCommit: string;
  /** Sequence number in the release log. */
  releaseLogSequence: number;
  /** Hash of the release log entry this certificate covers. */
  releaseLogEntryHash: string;
  /** Minimum number of valid authorizations required. */
  threshold: number;
  /** The ceremony tier achieved for this update. */
  ceremonyTier: CeremonyTier;
  /** Anti-replay nonce (base64). */
  nonce: string;
  /** Certificate creation timestamp (ms). */
  createdAt: number;
  /** Optional expiry — authorizations collected after this are invalid. */
  expiresAt: number | null;
  /** Collected authorizations. */
  authorizations: UpdateAuthorization[];
}

/** Verification result for an UpdateCertificate. */
export type UpdateCertificateVerification =
  | { valid: true; ceremonyTier: CeremonyTier }
  | { valid: false; reason: string };

/** Provenance record embedded in a BirthCertificate. */
export interface PackageProvenance {
  /** Package name. */
  package: string;
  /** Semver version. */
  version: string;
  /** SHA-256 of the tarball (64-char lowercase hex). */
  tarballSha256: string;
  /** Position in the release log. */
  releaseLogSequence: number;
  /** Hash of the UpdateCertificate that authorised this release. */
  updateCertificateHash: string;
  /** Ceremony tier achieved. */
  ceremonyTier: CeremonyTier;
}

/** Regex for SHA-256 hex strings (64 lowercase hex chars). */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

// ─── Canonical signing input ────────────────────────────────────────────────

/**
 * Compute the canonical signing input for an UpdateCertificate.
 *
 * This is what each authorizer signs. It covers the full certificate body
 * EXCLUDING the `authorizations` array, so adding a new authorization
 * does not invalidate existing signatures.
 *
 * Uses `domainSigningInput('soma/update-certificate/v1', ...)` for domain
 * separation — a signature over this cannot be replayed as any other Soma
 * signature type.
 */
export function computeUpdateCertificateSigningInput(
  cert: Omit<UpdateCertificate, 'authorizations'>,
): Uint8Array {
  const payload = {
    version: cert.version,
    package: cert.package,
    targetVersion: cert.targetVersion,
    tarballSha256: cert.tarballSha256,
    gitCommit: cert.gitCommit,
    releaseLogSequence: cert.releaseLogSequence,
    releaseLogEntryHash: cert.releaseLogEntryHash,
    threshold: cert.threshold,
    ceremonyTier: cert.ceremonyTier,
    nonce: cert.nonce,
    createdAt: cert.createdAt,
    expiresAt: cert.expiresAt,
  };
  return domainSigningInput(UPDATE_CERTIFICATE_DOMAIN, payload);
}

// ─── Creation ───────────────────────────────────────────────────────────────

/**
 * Create a new UpdateCertificate with the first maintainer's authorization.
 *
 * The creator signs the certificate body and becomes the first authorizer.
 * Additional authorizers can be added via `addAuthorization()`.
 *
 * @param opts.package          — Package name (e.g. `'soma-heart'`).
 * @param opts.targetVersion    — Semver version being authorised.
 * @param opts.tarballSha256    — SHA-256 of the published tarball (64-char lowercase hex).
 * @param opts.gitCommit        — Git commit SHA the tarball was built from.
 * @param opts.releaseLogSequence — Sequence number in the release log.
 * @param opts.releaseLogEntryHash — Hash of the release log entry.
 * @param opts.threshold        — Minimum authorizations required (≥ 1).
 * @param opts.ceremonyTier     — Ceremony tier achieved for this update.
 * @param opts.signingKey       — Creator's Ed25519 signing key (raw bytes).
 * @param opts.publicKey        — Creator's public key (raw bytes).
 * @param opts.role             — Role of the creator (default: `'maintainer'`).
 * @param opts.delegationHash   — Hash of the HumanDelegation for audit trail (default: null).
 * @param opts.expiresAt        — Optional expiry timestamp (ms). Null means no expiry.
 * @param opts.provider         — Optional CryptoProvider override.
 */
export function createUpdateCertificate(opts: {
  package: string;
  targetVersion: string;
  tarballSha256: string;
  gitCommit: string;
  releaseLogSequence: number;
  releaseLogEntryHash: string;
  threshold: number;
  ceremonyTier: CeremonyTier;
  signingKey: Uint8Array;
  publicKey: Uint8Array;
  role?: AuthorizerRole;
  delegationHash?: string | null;
  expiresAt?: number | null;
  provider?: CryptoProvider;
}): UpdateCertificate {
  const p = opts.provider ?? getCryptoProvider();

  if (!opts.package || typeof opts.package !== 'string') {
    throw new Error('createUpdateCertificate: package name required');
  }
  if (!opts.targetVersion || typeof opts.targetVersion !== 'string') {
    throw new Error('createUpdateCertificate: targetVersion required');
  }
  if (!SHA256_HEX_RE.test(opts.tarballSha256)) {
    throw new Error('createUpdateCertificate: tarballSha256 must be 64-char lowercase hex');
  }
  if (!opts.gitCommit || typeof opts.gitCommit !== 'string') {
    throw new Error('createUpdateCertificate: gitCommit required');
  }
  if (opts.threshold < 1) {
    throw new Error('createUpdateCertificate: threshold must be ≥ 1');
  }
  if (opts.expiresAt != null && opts.expiresAt <= Date.now()) {
    throw new Error('createUpdateCertificate: expiresAt must be in the future');
  }

  const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));
  const creatorDid = publicKeyToDid(opts.publicKey, p);
  const creatorPubB64 = p.encoding.encodeBase64(opts.publicKey);
  const createdAt = Date.now();
  const expiresAt = opts.expiresAt ?? null;

  const body: Omit<UpdateCertificate, 'authorizations'> = {
    version: UPDATE_CERTIFICATE_DOMAIN,
    package: opts.package,
    targetVersion: opts.targetVersion,
    tarballSha256: opts.tarballSha256.toLowerCase(),
    gitCommit: opts.gitCommit.toLowerCase(),
    releaseLogSequence: opts.releaseLogSequence,
    releaseLogEntryHash: opts.releaseLogEntryHash,
    threshold: opts.threshold,
    ceremonyTier: opts.ceremonyTier,
    nonce,
    createdAt,
    expiresAt,
  };

  const signingInput = computeUpdateCertificateSigningInput(body);
  const signature = p.signing.sign(signingInput, opts.signingKey);

  const authorization: UpdateAuthorization = {
    role: opts.role ?? 'maintainer',
    authorizerDid: creatorDid,
    authorizerPublicKey: creatorPubB64,
    authorizerCeremonyTier: opts.ceremonyTier,
    delegationHash: opts.delegationHash ?? null,
    signature: p.encoding.encodeBase64(signature),
    authorizedAt: createdAt,
  };

  return {
    ...body,
    authorizations: [authorization],
  };
}

// ─── Co-signing ─────────────────────────────────────────────────────────────

/**
 * Add a co-signer's authorization to an existing UpdateCertificate.
 *
 * Returns a new certificate with the additional authorization appended.
 * The original certificate is not mutated. Each co-signer signs the same
 * canonical body, so their authorization is independently verifiable.
 *
 * @param cert       — The existing UpdateCertificate.
 * @param signingKey — Co-signer's Ed25519 signing key (raw bytes).
 * @param publicKey  — Co-signer's public key (raw bytes).
 * @param opts.role  — Role of this co-signer (default: `'consumer-heart'`).
 * @param opts.ceremonyTier — Ceremony tier this co-signer achieved (default: null).
 * @param opts.delegationHash — HumanDelegation hash for audit trail (default: null).
 * @param opts.provider — Optional CryptoProvider override.
 */
export function addAuthorization(
  cert: UpdateCertificate,
  signingKey: Uint8Array,
  publicKey: Uint8Array,
  opts?: {
    role?: AuthorizerRole;
    ceremonyTier?: CeremonyTier | null;
    delegationHash?: string | null;
    provider?: CryptoProvider;
  },
): UpdateCertificate {
  const p = opts?.provider ?? getCryptoProvider();
  const authorizerDid = publicKeyToDid(publicKey, p);

  if (cert.authorizations.some((a) => a.authorizerDid === authorizerDid)) {
    throw new Error(`addAuthorization: ${authorizerDid} has already authorized`);
  }

  const { authorizations: _, ...body } = cert;
  const signingInput = computeUpdateCertificateSigningInput(body);
  const signature = p.signing.sign(signingInput, signingKey);

  const authorization: UpdateAuthorization = {
    role: opts?.role ?? 'consumer-heart',
    authorizerDid,
    authorizerPublicKey: p.encoding.encodeBase64(publicKey),
    authorizerCeremonyTier: opts?.ceremonyTier ?? null,
    delegationHash: opts?.delegationHash ?? null,
    signature: p.encoding.encodeBase64(signature),
    authorizedAt: Date.now(),
  };

  return {
    ...cert,
    authorizations: [...cert.authorizations, authorization],
  };
}

// ─── Verification ───────────────────────────────────────────────────────────

/**
 * Verify an UpdateCertificate end-to-end.
 *
 * Checks (§2.2 order):
 *   1. Version tag matches `'soma/update-certificate/v1'`.
 *   2. Each authorization's signature verifies against its stated pubkey.
 *   3. Each authorizer's DID matches their pubkey.
 *   4. Threshold is met (enough valid authorizations).
 *   5. Certificate is not expired (if `expiresAt` is set and `now` given).
 *   6. Ceremony tier is at least `minCeremonyTier` (if specified).
 *
 * @param cert              — The certificate to verify.
 * @param now               — Current timestamp (ms) for expiry check.
 * @param opts.minCeremonyTier — Optional minimum ceremony tier required.
 * @param opts.trustedDids  — Optional allowlist of trusted maintainer DIDs.
 *                            If set, at least `threshold` authorizers must
 *                            be in this set.
 * @param opts.provider     — Optional CryptoProvider override.
 */
export function verifyUpdateCertificate(
  cert: UpdateCertificate,
  now: number,
  opts?: {
    minCeremonyTier?: CeremonyTier;
    trustedDids?: string[];
    provider?: CryptoProvider;
  },
): UpdateCertificateVerification {
  const p = opts?.provider ?? getCryptoProvider();

  // 1. Version check.
  if (cert.version !== UPDATE_CERTIFICATE_DOMAIN) {
    return { valid: false, reason: `unknown version: ${cert.version}` };
  }

  // 5. Expiry check (before doing expensive sig verification).
  if (cert.expiresAt !== null && now >= cert.expiresAt) {
    return { valid: false, reason: 'certificate expired' };
  }

  // 6. Ceremony tier check.
  if (opts?.minCeremonyTier) {
    if (tierRank(cert.ceremonyTier) < tierRank(opts.minCeremonyTier)) {
      return {
        valid: false,
        reason: `ceremony tier ${cert.ceremonyTier} below required ${opts.minCeremonyTier}`,
      };
    }
  }

  // 2 + 3. Verify each authorization.
  const { authorizations, ...body } = cert;
  const signingInput = computeUpdateCertificateSigningInput(body);
  let validCount = 0;
  const seenDids = new Set<string>();

  for (let i = 0; i < authorizations.length; i++) {
    const auth = authorizations[i];

    // Detect duplicate authorizer DIDs.
    if (seenDids.has(auth.authorizerDid)) {
      return { valid: false, reason: `duplicate authorizer DID at index ${i}` };
    }
    seenDids.add(auth.authorizerDid);

    // 3. DID ↔ pubkey binding.
    const pubKey = p.encoding.decodeBase64(auth.authorizerPublicKey);
    const expectedDid = publicKeyToDid(pubKey, p);
    if (auth.authorizerDid !== expectedDid) {
      return {
        valid: false,
        reason: `authorization ${i}: DID does not match public key`,
      };
    }

    // 2. Signature verification.
    const sigBytes = p.encoding.decodeBase64(auth.signature);
    if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
      return {
        valid: false,
        reason: `authorization ${i}: invalid signature`,
      };
    }

    // If trusted DIDs allowlist is set, only count trusted authorizers.
    if (opts?.trustedDids) {
      if (opts.trustedDids.includes(auth.authorizerDid)) {
        validCount++;
      }
    } else {
      validCount++;
    }
  }

  // 4. Threshold check.
  if (validCount < cert.threshold) {
    return {
      valid: false,
      reason: `threshold not met: ${validCount} valid authorizations, need ${cert.threshold}`,
    };
  }

  return { valid: true, ceremonyTier: cert.ceremonyTier };
}

// ─── Certificate hash ───────────────────────────────────────────────────────

/**
 * Compute the content-addressed hash of an UpdateCertificate.
 *
 * Hashes the canonical signing input concatenated with each authorization's
 * signature (sorted by DID for determinism). This is the value stored in
 * `PackageProvenance.updateCertificateHash`.
 */
export function computeUpdateCertificateHash(
  cert: UpdateCertificate,
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  const { authorizations, ...body } = cert;
  const bodyJson = canonicalJson(body);
  const sortedSigs = [...authorizations]
    .sort((a, b) => (a.authorizerDid < b.authorizerDid ? -1 : 1))
    .map((a) => a.signature)
    .join('|');
  return p.hashing.hash(`${bodyJson}|${sortedSigs}`);
}

// ─── Package provenance verification ────────────────────────────────────────

/** Result of verifying package provenance. */
export type PackageProvenanceVerification =
  | { official: true; ceremonyTier: CeremonyTier }
  | { official: false; reason: string };

/**
 * Verify that a package's provenance record is genuine (§3.6).
 *
 * Cross-references the provenance embedded in a BirthCertificate against
 * the UpdateCertificate to confirm the package was officially released
 * through the ceremony system.
 *
 * Verification steps:
 *   1. Compute hash of the UpdateCertificate; must match
 *      `provenance.updateCertificateHash`.
 *   2. Package, version, and tarball hash must match between provenance
 *      and certificate.
 *   3. Verify the UpdateCertificate itself (signatures, threshold, expiry).
 *   4. At least one authorizer's DID must be in `trustedMaintainers`.
 *   5. At least one authorizer's DID must be in `trustedConsumerHearts`.
 *   6. `ceremonyTier` must meet `minCeremonyTier` if specified.
 *
 * Pure — no I/O, no network, no state.
 *
 * @param opts.provenance           — PackageProvenance from BirthCertificate.
 * @param opts.updateCertificate    — The UpdateCertificate to verify against.
 * @param opts.trustedMaintainers   — DIDs of trusted maintainers.
 * @param opts.trustedConsumerHearts — DIDs of trusted consumer hearts.
 * @param opts.minCeremonyTier      — Optional minimum ceremony tier.
 * @param opts.provider             — Optional CryptoProvider override.
 */
export function verifyPackageProvenance(opts: {
  provenance: PackageProvenance | undefined | null;
  updateCertificate: UpdateCertificate | undefined | null;
  trustedMaintainers: string[];
  trustedConsumerHearts: string[];
  minCeremonyTier?: CeremonyTier;
  provider?: CryptoProvider;
}): PackageProvenanceVerification {
  const p = opts.provider ?? getCryptoProvider();

  if (!opts.provenance) {
    return { official: false, reason: 'no provenance record' };
  }

  if (!opts.updateCertificate) {
    return { official: false, reason: 'no update certificate provided' };
  }

  const prov = opts.provenance;
  const cert = opts.updateCertificate;

  // 1. Hash binding — provenance must reference the exact certificate.
  const certHash = computeUpdateCertificateHash(cert, p);
  if (prov.updateCertificateHash !== certHash) {
    return { official: false, reason: 'update certificate hash mismatch' };
  }

  // 2. Cross-reference provenance fields against the certificate.
  if (prov.package !== cert.package) {
    return { official: false, reason: 'package name mismatch' };
  }
  if (prov.version !== cert.targetVersion) {
    return { official: false, reason: 'version mismatch' };
  }
  if (prov.tarballSha256 !== cert.tarballSha256) {
    return { official: false, reason: 'tarball hash mismatch' };
  }
  if (prov.releaseLogSequence !== cert.releaseLogSequence) {
    return { official: false, reason: 'release log sequence mismatch' };
  }

  // 3. Verify the certificate itself (signatures, threshold, expiry, tier).
  const certResult = verifyUpdateCertificate(cert, Date.now(), {
    minCeremonyTier: opts.minCeremonyTier,
    provider: p,
  });
  if (!certResult.valid) {
    return { official: false, reason: `certificate invalid: ${certResult.reason}` };
  }

  // 4. At least one authorizer must be in trustedMaintainers.
  const hasTrustedMaintainer = cert.authorizations.some(
    (a) => opts.trustedMaintainers.includes(a.authorizerDid),
  );
  if (!hasTrustedMaintainer) {
    return { official: false, reason: 'no trusted maintainer among authorizers' };
  }

  // 5. At least one authorizer must be in trustedConsumerHearts.
  const hasTrustedConsumer = cert.authorizations.some(
    (a) => opts.trustedConsumerHearts.includes(a.authorizerDid),
  );
  if (!hasTrustedConsumer) {
    return { official: false, reason: 'no trusted consumer heart among authorizers' };
  }

  // 6. Ceremony tier on provenance must match certificate.
  if (prov.ceremonyTier !== cert.ceremonyTier) {
    return { official: false, reason: 'ceremony tier mismatch' };
  }

  return { official: true, ceremonyTier: certResult.ceremonyTier };
}

// ─── Internals ──────────────────────────────────────────────────────────────

function tierRank(tier: CeremonyTier): number {
  switch (tier) {
    case 'L0': return 0;
    case 'L1': return 1;
    case 'L2': return 2;
    case 'L3': return 3;
  }
}
