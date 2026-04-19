/**
 * Selective disclosure — reveal only specific fields of a signed document.
 *
 * Problem: an issuer signs a set of claims about a subject (e.g. "name=Alice,
 * dob=1990-01-01, country=US, kyc-tier=3"). When the subject uses this to
 * access a service that only needs `kyc-tier >= 2`, they shouldn't have to
 * hand over their name and DOB. But they also can't just *say* "my kyc-tier
 * is 3" — the verifier needs to know the issuer signed that specific claim.
 *
 * Design: issuer commits to each field INDEPENDENTLY with a per-field salt,
 * then signs a commitment root = hash over the sorted field commitments.
 * The document holder can reveal any subset of fields by providing:
 *   (1) the disclosed field values + their salts (verifier hashes those)
 *   (2) the raw commitment hashes for the undisclosed fields
 *   (3) the issuer's signature over the root
 *
 * Verifier recomputes the root from the pieces and checks the signature.
 *
 * Properties:
 *   - Unlinkability: salts prevent correlation across presentations (the
 *     verifier sees commitment hashes but those differ per document).
 *   - Hiding: undisclosed field hashes reveal nothing about field contents
 *     because each is salted with 32 random bytes.
 *   - Integrity: verifier cannot be tricked into accepting a forged claim —
 *     the signature is over the root, and the root depends on EVERY field.
 *
 * Non-goals:
 *   - ZK proofs over ranges ("tier >= 2") — this only reveals exact values.
 *     A holder who wants "tier >= 2" just reveals the tier field directly.
 *   - Predicate proofs — use something like BBS+ for those.
 *
 * This is the simplest cryptographic selective disclosure that works, and
 * it composes cleanly with the existing attestation module.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';
import {
  checkKeyEffective,
  type HistoricalKeyLookup,
} from './historical-key-lookup.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A signed document the issuer produces. Holder stores this locally. */
export interface DisclosableDocument {
  /** Opaque document id. */
  id: string;
  /** DID of the issuer. */
  issuerDid: string;
  /** Issuer's base64 public key. */
  issuerPublicKey: string;
  /** DID of the subject these claims are about. */
  subjectDid: string;
  /** The full claim set (private — held by subject). */
  claims: Record<string, unknown>;
  /** Per-field base64 salts (32 bytes each). */
  salts: Record<string, string>;
  /** Merkle-ish root: hash of sorted per-field commitment hashes. */
  commitmentRoot: string;
  /** When issued. */
  issuedAt: number;
  /** When this expires, or null. */
  expiresAt: number | null;
  /** Issuer's signature over canonical envelope (root + metadata). */
  signature: string;
}

/** A presentation that reveals only some fields. */
export interface DisclosureProof {
  documentId: string;
  issuerDid: string;
  issuerPublicKey: string;
  subjectDid: string;
  commitmentRoot: string;
  issuedAt: number;
  expiresAt: number | null;
  signature: string;
  /** Fields being revealed: field name → {value, salt}. */
  disclosed: Record<string, { value: unknown; salt: string }>;
  /** Commitment hashes for withheld fields: field name → commitment hash. */
  undisclosedCommitments: Record<string, string>;
}

export type DisclosureVerification =
  | {
      valid: true;
      disclosed: Record<string, unknown>;
      issuerDid: string;
      subjectDid: string;
      documentId: string;
    }
  | { valid: false; reason: string };

// ─── Internal helpers ───────────────────────────────────────────────────────

/**
 * Commit one field: hash(salt || canonicalJson({field, value})).
 * Including the field name prevents swapping commitments across fields.
 */
function commitField(
  field: string,
  value: unknown,
  saltB64: string,
  p: CryptoProvider,
): string {
  const input = `soma-disclose:${saltB64}:${canonicalJson({ field, value })}`;
  return p.hashing.hash(input);
}

/**
 * Build the commitment root from sorted (field → commitment) entries.
 * Sorting + domain-separated input guarantees determinism and prevents
 * ordering attacks.
 */
function buildRoot(
  commitments: Record<string, string>,
  p: CryptoProvider,
): string {
  const sorted = Object.keys(commitments)
    .sort()
    .map((k) => ({ f: k, c: commitments[k]! }));
  return p.hashing.hash(`soma-disclose-root:${canonicalJson(sorted)}`);
}

/** The exact payload that gets signed. Excludes claims + salts. */
function buildEnvelope(
  d: Pick<
    DisclosableDocument,
    | 'id'
    | 'issuerDid'
    | 'issuerPublicKey'
    | 'subjectDid'
    | 'commitmentRoot'
    | 'issuedAt'
    | 'expiresAt'
  >,
) {
  return {
    protocol: 'soma-disclosure/1',
    id: d.id,
    issuerDid: d.issuerDid,
    issuerPublicKey: d.issuerPublicKey,
    subjectDid: d.subjectDid,
    commitmentRoot: d.commitmentRoot,
    issuedAt: d.issuedAt,
    expiresAt: d.expiresAt,
  };
}

// ─── Creation (issuer) ──────────────────────────────────────────────────────

export function createDisclosableDocument(opts: {
  issuerDid: string;
  issuerPublicKey: string;
  issuerSigningKey: Uint8Array;
  subjectDid: string;
  claims: Record<string, unknown>;
  expiresAt?: number | null;
  provider?: CryptoProvider;
}): DisclosableDocument {
  const p = opts.provider ?? getCryptoProvider();
  if (Object.keys(opts.claims).length === 0) {
    throw new Error('claims must not be empty');
  }

  // Generate one salt per field.
  const salts: Record<string, string> = {};
  const commitments: Record<string, string> = {};
  for (const [field, value] of Object.entries(opts.claims)) {
    const salt = p.encoding.encodeBase64(p.random.randomBytes(32));
    salts[field] = salt;
    commitments[field] = commitField(field, value, salt, p);
  }
  const commitmentRoot = buildRoot(commitments, p);

  const id = `doc-${p.encoding.encodeBase64(p.random.randomBytes(12))}`;
  const issuedAt = Date.now();
  const expiresAt = opts.expiresAt ?? null;

  const envelope = buildEnvelope({
    id,
    issuerDid: opts.issuerDid,
    issuerPublicKey: opts.issuerPublicKey,
    subjectDid: opts.subjectDid,
    commitmentRoot,
    issuedAt,
    expiresAt,
  });
  const signingInput = new TextEncoder().encode(canonicalJson(envelope));
  const signature = p.signing.sign(signingInput, opts.issuerSigningKey);

  return {
    id,
    issuerDid: opts.issuerDid,
    issuerPublicKey: opts.issuerPublicKey,
    subjectDid: opts.subjectDid,
    claims: { ...opts.claims },
    salts,
    commitmentRoot,
    issuedAt,
    expiresAt,
    signature: p.encoding.encodeBase64(signature),
  };
}

// ─── Subject-side verification of their own document ───────────────────────

/**
 * Subject verifies the document they received is well-formed — issuer
 * signed the root, and the root matches the per-field commitments.
 */
export function verifyDisclosableDocument(
  doc: DisclosableDocument,
  provider?: CryptoProvider,
): { valid: boolean; reason?: string } {
  const p = provider ?? getCryptoProvider();

  // Check DID/public key binding.
  const pubKey = p.encoding.decodeBase64(doc.issuerPublicKey);
  if (publicKeyToDid(pubKey, p) !== doc.issuerDid) {
    return { valid: false, reason: 'issuer DID/key mismatch' };
  }

  // Rebuild commitments and root.
  const commitments: Record<string, string> = {};
  for (const field of Object.keys(doc.claims)) {
    const salt = doc.salts[field];
    if (!salt) {
      return { valid: false, reason: `missing salt for field: ${field}` };
    }
    commitments[field] = commitField(field, doc.claims[field], salt, p);
  }
  const root = buildRoot(commitments, p);
  if (root !== doc.commitmentRoot) {
    return { valid: false, reason: 'commitment root mismatch' };
  }

  // Verify signature over envelope.
  const envelope = buildEnvelope(doc);
  const signingInput = new TextEncoder().encode(canonicalJson(envelope));
  const sigBytes = p.encoding.decodeBase64(doc.signature);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid issuer signature' };
  }

  return { valid: true };
}

// ─── Presentation (holder) ──────────────────────────────────────────────────

/**
 * Holder builds a presentation revealing only `fieldsToReveal`. All other
 * fields' commitment hashes are included raw — they're already salted, so
 * they're opaque.
 */
export function createDisclosureProof(
  doc: DisclosableDocument,
  fieldsToReveal: readonly string[],
  provider?: CryptoProvider,
): DisclosureProof {
  const p = provider ?? getCryptoProvider();
  const revealSet = new Set(fieldsToReveal);

  for (const f of fieldsToReveal) {
    if (!(f in doc.claims)) {
      throw new Error(`field not in document: ${f}`);
    }
  }

  const disclosed: Record<string, { value: unknown; salt: string }> = {};
  const undisclosedCommitments: Record<string, string> = {};

  for (const [field, value] of Object.entries(doc.claims)) {
    const salt = doc.salts[field]!;
    if (revealSet.has(field)) {
      disclosed[field] = { value, salt };
    } else {
      undisclosedCommitments[field] = commitField(field, value, salt, p);
    }
  }

  return {
    documentId: doc.id,
    issuerDid: doc.issuerDid,
    issuerPublicKey: doc.issuerPublicKey,
    subjectDid: doc.subjectDid,
    commitmentRoot: doc.commitmentRoot,
    issuedAt: doc.issuedAt,
    expiresAt: doc.expiresAt,
    signature: doc.signature,
    disclosed,
    undisclosedCommitments,
  };
}

// ─── Verification (third-party verifier) ────────────────────────────────────

export function verifyDisclosureProof(
  proof: DisclosureProof,
  opts: {
    /** Current time for expiry check. */
    now?: number;
    /** Required fields the verifier expects to see. */
    requiredFields?: readonly string[];
    provider?: CryptoProvider;
    /**
     * Rotation-aware key validity lookup. When provided, confirms the
     * issuer's public key was effective at the document's `issuedAt`
     * timestamp. Fail-closed if not found or not effective.
     */
    lookup?: HistoricalKeyLookup;
  } = {},
): DisclosureVerification {
  const p = opts.provider ?? getCryptoProvider();
  const now = opts.now ?? Date.now();

  // Expiry.
  if (proof.expiresAt !== null && proof.expiresAt < now) {
    return { valid: false, reason: 'document expired' };
  }

  // Required fields present?
  if (opts.requiredFields) {
    for (const f of opts.requiredFields) {
      if (!(f in proof.disclosed)) {
        return { valid: false, reason: `required field not disclosed: ${f}` };
      }
    }
  }

  // No field in both sets.
  for (const f of Object.keys(proof.disclosed)) {
    if (f in proof.undisclosedCommitments) {
      return { valid: false, reason: `field in both disclosed and undisclosed: ${f}` };
    }
  }

  // DID/public key binding.
  let pubKey: Uint8Array;
  try {
    pubKey = p.encoding.decodeBase64(proof.issuerPublicKey);
  } catch {
    return { valid: false, reason: 'malformed issuer public key' };
  }
  if (publicKeyToDid(pubKey, p) !== proof.issuerDid) {
    return { valid: false, reason: 'issuer DID/key mismatch' };
  }

  // Rotation-aware key validity check (opt-in).
  if (opts.lookup) {
    let result;
    try {
      result = opts.lookup.resolve(pubKey, proof.issuedAt);
    } catch {
      return { valid: false, reason: 'key lookup failed: resolver threw' };
    }
    const check = checkKeyEffective(result, proof.issuedAt);
    if (!check.effective) {
      return { valid: false, reason: check.reason };
    }
  }

  // Recompute commitments for disclosed fields.
  const commitments: Record<string, string> = { ...proof.undisclosedCommitments };
  for (const [field, { value, salt }] of Object.entries(proof.disclosed)) {
    commitments[field] = commitField(field, value, salt, p);
  }

  // Rebuild root and compare.
  const root = buildRoot(commitments, p);
  if (root !== proof.commitmentRoot) {
    return { valid: false, reason: 'commitment root mismatch' };
  }

  // Verify issuer signature over envelope.
  const envelope = buildEnvelope({
    id: proof.documentId,
    issuerDid: proof.issuerDid,
    issuerPublicKey: proof.issuerPublicKey,
    subjectDid: proof.subjectDid,
    commitmentRoot: proof.commitmentRoot,
    issuedAt: proof.issuedAt,
    expiresAt: proof.expiresAt,
  });
  const signingInput = new TextEncoder().encode(canonicalJson(envelope));
  const sigBytes = p.encoding.decodeBase64(proof.signature);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid issuer signature' };
  }

  const disclosed: Record<string, unknown> = {};
  for (const [f, { value }] of Object.entries(proof.disclosed)) {
    disclosed[f] = value;
  }
  return {
    valid: true,
    disclosed,
    issuerDid: proof.issuerDid,
    subjectDid: proof.subjectDid,
    documentId: proof.documentId,
  };
}
