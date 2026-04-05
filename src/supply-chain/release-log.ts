/**
 * Supply-chain attestation — signed, append-only release log for Soma packages.
 *
 * Audit limit #10: users installing `soma-heart` today have no cryptographic
 * link between:
 *   - the git commit that was tagged,
 *   - the tarball on npm that they download,
 *   - a maintainer identity that authorised the release.
 *
 * If an attacker steals an npm token, they can publish a backdoored version
 * and every new install gets it. No detection, no recourse.
 *
 * This module gives Soma the same primitive we give delegations and
 * revocations: an append-only, hash-chained log of signed releases. Each
 * entry commits to:
 *   - the package name + version (what)
 *   - the SHA-256 of the published tarball (what exactly)
 *   - the git commit (where the source lives)
 *   - the maintainer DID (who authorised it)
 *
 * Same chain semantics as RevocationLog / KeyHistory / SpendLog:
 *   - monotonic sequence per package
 *   - previousHash links entries
 *   - signed heads commit to current tip
 *   - two conflicting heads from the same maintainer at the same sequence
 *     are a provable fork
 *
 * Install-time verification:
 *   1. Compute SHA-256 of the installed tarball (or verifiable equivalent).
 *   2. Look up the entry for the target version.
 *   3. Compare hashes — mismatch = tampered.
 *   4. Check the entry's maintainerDid is in the user's trust set.
 *
 * Legitimate update signalling:
 *   - Maintainer publishes a new version.
 *   - Appends a signed entry to the release log (chain advances by 1).
 *   - Publishes the updated log alongside the tarball.
 *   - Users (or automation) pull the log, verify new tip, see new entry,
 *     decide whether to trust (sig from known maintainer, chain advances
 *     from previously-trusted head).
 *
 * This is a Certificate-Transparency-style log scoped to package releases.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** One signed release. */
export interface ReleaseEntry {
  /** Package name (e.g. "soma-heart"). */
  package: string;
  /** Semver version string. */
  version: string;
  /** Position in this package's chain (starts at 0). */
  sequence: number;
  /** Hash of the previous entry, or genesis hash for sequence=0. */
  previousHash: string;
  /** SHA-256 of the published tarball (hex). */
  tarballSha256: string;
  /** Git commit SHA the tarball was built from (hex). */
  gitCommit: string;
  /** Release timestamp (ms). */
  releasedAt: number;
  /** Anti-replay nonce. */
  nonce: string;
  /** Self-hash binding all fields + signature. */
  hash: string;
  /** Maintainer DID (signer). */
  maintainerDid: string;
  /** Maintainer base64 public key. */
  maintainerPublicKey: string;
  /** Maintainer's Ed25519 signature. */
  signature: string;
}

/** Signed commitment to the current tip of a release log. */
export interface ReleaseChainHead {
  package: string;
  sequence: number;
  hash: string;
  signedAt: number;
  maintainerDid: string;
  maintainerPublicKey: string;
  signature: string;
}

export type ReleaseVerification =
  | { valid: true }
  | { valid: false; reason: string };

export interface InstallVerification {
  valid: boolean;
  reason?: string;
  entry?: ReleaseEntry;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const GENESIS_INPUT_PREFIX = 'soma-release-log:genesis:';
/** Regex for SHA-256 hex strings (64 lowercase hex chars). */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

// ─── Log ────────────────────────────────────────────────────────────────────

/** Append-only, hash-chained release log for a single package. */
export class ReleaseLog {
  private readonly entries: ReleaseEntry[] = [];
  private readonly seenVersions = new Set<string>();
  private readonly provider: CryptoProvider;
  readonly package: string;
  readonly genesisHash: string;

  constructor(opts: { package: string; provider?: CryptoProvider }) {
    this.provider = opts.provider ?? getCryptoProvider();
    this.package = opts.package;
    this.genesisHash = this.provider.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${this.package}`,
    );
  }

  /**
   * Append a new release entry. Throws if version is duplicate or inputs
   * are malformed.
   */
  append(opts: {
    version: string;
    tarballSha256: string;
    gitCommit: string;
    maintainerSigningKey: Uint8Array;
    maintainerPublicKey: Uint8Array;
  }): ReleaseEntry {
    if (!opts.version || typeof opts.version !== 'string') {
      throw new Error('cannot append: version required');
    }
    if (this.seenVersions.has(opts.version)) {
      throw new Error(`cannot append: version ${opts.version} already released`);
    }
    if (!SHA256_HEX_RE.test(opts.tarballSha256)) {
      throw new Error('cannot append: tarballSha256 must be 64-char lowercase hex');
    }
    if (!opts.gitCommit || typeof opts.gitCommit !== 'string') {
      throw new Error('cannot append: gitCommit required');
    }

    const sequence = this.entries.length;
    const previousHash =
      sequence === 0 ? this.genesisHash : this.entries[sequence - 1].hash;
    const nonce = this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(12),
    );
    const maintainerDid = publicKeyToDid(opts.maintainerPublicKey, this.provider);
    const maintainerPublicKeyB64 = this.provider.encoding.encodeBase64(
      opts.maintainerPublicKey,
    );

    const payload = {
      package: this.package,
      version: opts.version,
      sequence,
      previousHash,
      tarballSha256: opts.tarballSha256.toLowerCase(),
      gitCommit: opts.gitCommit.toLowerCase(),
      releasedAt: Date.now(),
      nonce,
      maintainerDid,
      maintainerPublicKey: maintainerPublicKeyB64,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = this.provider.signing.sign(
      signingInput,
      opts.maintainerSigningKey,
    );
    const signatureB64 = this.provider.encoding.encodeBase64(signature);
    const hash = computeEntryHash(payload, signatureB64, this.provider);

    const entry: ReleaseEntry = {
      ...payload,
      hash,
      signature: signatureB64,
    };
    this.entries.push(entry);
    this.seenVersions.add(opts.version);
    return entry;
  }

  /** Current head — last entry's hash, or genesis for empty logs. */
  get head(): string {
    return this.entries.length === 0
      ? this.genesisHash
      : this.entries[this.entries.length - 1].hash;
  }

  /** Number of releases. */
  get length(): number {
    return this.entries.length;
  }

  /** Read-only snapshot. */
  getEntries(): readonly ReleaseEntry[] {
    return this.entries;
  }

  /** Look up a specific version. Returns null if not released. */
  getByVersion(version: string): ReleaseEntry | null {
    return this.entries.find((e) => e.version === version) ?? null;
  }

  /** Sign a commitment to the current head. */
  signHead(
    maintainerSigningKey: Uint8Array,
    maintainerPublicKey: Uint8Array,
  ): ReleaseChainHead {
    const maintainerDid = publicKeyToDid(maintainerPublicKey, this.provider);
    const maintainerPublicKeyB64 = this.provider.encoding.encodeBase64(maintainerPublicKey);
    const payload = {
      package: this.package,
      sequence: this.entries.length - 1, // -1 for empty logs
      hash: this.head,
      signedAt: Date.now(),
      maintainerDid,
      maintainerPublicKey: maintainerPublicKeyB64,
    };
    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = this.provider.signing.sign(signingInput, maintainerSigningKey);
    return {
      ...payload,
      signature: this.provider.encoding.encodeBase64(signature),
    };
  }

  /** Verify this log's own chain integrity. */
  verify(): ReleaseVerification {
    return ReleaseLog.verifyChain(this.entries, this.package, this.provider);
  }

  /**
   * Replace contents with an imported chain. Leaves log untouched on
   * failure. Package name must match.
   */
  replaceWith(entries: ReleaseEntry[]): ReleaseVerification {
    const check = ReleaseLog.verifyChain(entries, this.package, this.provider);
    if (!check.valid) return check;
    this.entries.length = 0;
    this.seenVersions.clear();
    for (const e of entries) {
      this.entries.push(e);
      this.seenVersions.add(e.version);
    }
    return { valid: true };
  }

  // ─── Static verification ──────────────────────────────────────────────────

  /**
   * Verify a standalone chain of release entries. Checks:
   *   1. All entries share the expected package name.
   *   2. Monotonic sequence starting at 0.
   *   3. Hash chain linkage.
   *   4. Each entry's hash computed correctly.
   *   5. Each entry's signature verifies with its maintainerPublicKey.
   *   6. maintainerDid matches maintainerPublicKey.
   *   7. No duplicate versions.
   *   8. tarballSha256 is 64-char lowercase hex.
   */
  static verifyChain(
    entries: readonly ReleaseEntry[],
    expectedPackage: string,
    provider?: CryptoProvider,
  ): ReleaseVerification {
    const p = provider ?? getCryptoProvider();
    if (entries.length === 0) return { valid: true };

    const genesisHash = p.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${expectedPackage}`,
    );
    const seenVersions = new Set<string>();

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];

      if (e.package !== expectedPackage) {
        return { valid: false, reason: `entry ${i} package mismatch` };
      }
      if (e.sequence !== i) {
        return { valid: false, reason: `entry ${i} sequence=${e.sequence}` };
      }
      if (!SHA256_HEX_RE.test(e.tarballSha256)) {
        return { valid: false, reason: `entry ${i} tarballSha256 malformed` };
      }
      if (seenVersions.has(e.version)) {
        return { valid: false, reason: `entry ${i} duplicate version ${e.version}` };
      }
      seenVersions.add(e.version);

      const expectedPrev = i === 0 ? genesisHash : entries[i - 1].hash;
      if (e.previousHash !== expectedPrev) {
        return { valid: false, reason: `entry ${i} previousHash broken` };
      }

      const pubKey = p.encoding.decodeBase64(e.maintainerPublicKey);
      const expectedDid = publicKeyToDid(pubKey, p);
      if (e.maintainerDid !== expectedDid) {
        return { valid: false, reason: `entry ${i} maintainerDid mismatch` };
      }

      const { hash, signature, ...payload } = e;
      const signingInput = new TextEncoder().encode(canonicalJson(payload));
      const sigBytes = p.encoding.decodeBase64(signature);
      if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
        return { valid: false, reason: `entry ${i} bad signature` };
      }

      const expectedHash = computeEntryHash(payload, signature, p);
      if (hash !== expectedHash) {
        return { valid: false, reason: `entry ${i} hash mismatch` };
      }
    }

    return { valid: true };
  }

  /** Verify a signed release chain head. */
  static verifyHead(
    head: ReleaseChainHead,
    provider?: CryptoProvider,
  ): ReleaseVerification {
    const p = provider ?? getCryptoProvider();
    const { signature, ...payload } = head;
    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const sigBytes = p.encoding.decodeBase64(signature);
    const pubKey = p.encoding.decodeBase64(head.maintainerPublicKey);
    if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
      return { valid: false, reason: 'invalid signature' };
    }
    const expectedDid = publicKeyToDid(pubKey, p);
    if (head.maintainerDid !== expectedDid) {
      return { valid: false, reason: 'maintainerDid mismatch' };
    }
    return { valid: true };
  }
}

// ─── Install-time verification ──────────────────────────────────────────────

/**
 * Verify an installed package against a release log.
 *
 * Caller supplies:
 *   - the full release chain (verified before use)
 *   - the package name + version they installed
 *   - the SHA-256 of the tarball they actually received
 *   - (optional) a trust set of accepted maintainer DIDs
 *
 * Returns `valid: true` only if:
 *   - chain verifies end-to-end
 *   - an entry exists for (package, version)
 *   - the entry's tarballSha256 matches the installed hash
 *   - if trust set is set, the entry's maintainerDid is in it
 */
export function verifyInstalledPackage(opts: {
  releaseLog: readonly ReleaseEntry[];
  packageName: string;
  version: string;
  installedTarballSha256: string;
  trustedMaintainers?: string[];
  provider?: CryptoProvider;
}): InstallVerification {
  const p = opts.provider ?? getCryptoProvider();

  const chainCheck = ReleaseLog.verifyChain(opts.releaseLog, opts.packageName, p);
  if (!chainCheck.valid) {
    return { valid: false, reason: `release chain invalid: ${chainCheck.reason}` };
  }

  const entry = opts.releaseLog.find(
    (e) => e.package === opts.packageName && e.version === opts.version,
  );
  if (!entry) {
    return {
      valid: false,
      reason: `no release entry for ${opts.packageName}@${opts.version}`,
    };
  }

  const expected = entry.tarballSha256.toLowerCase();
  const actual = opts.installedTarballSha256.toLowerCase();
  if (actual !== expected) {
    return {
      valid: false,
      reason: `tarball hash mismatch (expected ${expected}, got ${actual})`,
      entry,
    };
  }

  if (opts.trustedMaintainers && opts.trustedMaintainers.length > 0) {
    if (!opts.trustedMaintainers.includes(entry.maintainerDid)) {
      return {
        valid: false,
        reason: `maintainer ${entry.maintainerDid} not in trust set`,
        entry,
      };
    }
  }

  return { valid: true, entry };
}

// ─── Fork detection ─────────────────────────────────────────────────────────

export interface ReleaseForkProof {
  package: string;
  sequence: number;
  maintainerDid: string;
  headA: ReleaseChainHead;
  headB: ReleaseChainHead;
}

/**
 * Detect a fork: two signed heads from the same maintainer over the same
 * package at the same sequence, with different hashes. Both heads must
 * verify independently.
 */
export function detectReleaseFork(
  a: ReleaseChainHead,
  b: ReleaseChainHead,
  provider?: CryptoProvider,
): ReleaseForkProof | null {
  if (!ReleaseLog.verifyHead(a, provider).valid) return null;
  if (!ReleaseLog.verifyHead(b, provider).valid) return null;
  if (a.package !== b.package) return null;
  if (a.maintainerDid !== b.maintainerDid) return null;
  if (a.sequence !== b.sequence) return null;
  if (a.hash === b.hash) return null;
  return {
    package: a.package,
    sequence: a.sequence,
    maintainerDid: a.maintainerDid,
    headA: a,
    headB: b,
  };
}

// ─── Internals ──────────────────────────────────────────────────────────────

function computeEntryHash(
  payload: Omit<ReleaseEntry, 'hash' | 'signature'>,
  signatureB64: string,
  provider: CryptoProvider,
): string {
  return provider.hashing.hash(`${canonicalJson(payload)}|${signatureB64}`);
}
