/**
 * Birth certificates — data provenance sealing with co-signing.
 *
 * When data enters the digital world — a human types something, a sensor
 * reads a temperature, an API returns a response — the first heart it
 * touches seals it with a birth certificate: who created it, when, through
 * what interface, and a hash of the original content.
 *
 * For hearted-to-hearted data flows, birth certificates require TWO signatures
 * — cryptographic co-signing that makes dishonesty impossible, not just detectable:
 *
 * 1. Source heart signs: "I provided data with hash H to DID X at time T"
 * 2. Receiving heart signs: "I received data with hash H from DID Y at time T"
 *
 * Three trust tiers:
 * - dual-signed: both hearts attest. Dishonesty requires collusion.
 * - single-signed: one heart attests, source unhearted. Trust depends on heart's honesty.
 * - unsigned: no heart. Consumer decides trust level.
 */

import { sha256 } from "../core/genome.js";
import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from "../core/crypto-provider.js";
import {
  checkKeyEffective,
  type HistoricalKeyLookup,
} from './historical-key-lookup.js';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Source types for data entering the system. */
export type DataSourceType = "agent" | "api" | "human" | "sensor" | "file";

/** Trust tier — how many hearts attest to this data's provenance. */
export type TrustTier = "dual-signed" | "single-signed" | "unsigned";

/** Description of where data came from. */
export interface DataSource {
  type: DataSourceType;
  /** DID if agent, URL if API, human ID if human, path if file. */
  identifier: string;
  /** Did this source have its own heart? */
  heartVerified: boolean;
}

/**
 * A data provenance payload — signed by the source heart during co-signing.
 * The source heart signs this to attest: "I provided this data."
 */
export interface DataProvenance {
  /** Hash of the data being attested. */
  dataHash: string;
  /** DID of the source heart providing the data. */
  sourceDid: string;
  /** DID of the receiving heart. */
  receiverDid: string;
  /** Timestamp of the attestation. */
  timestamp: number;
}

/** A birth certificate — seals data at its genesis point. */
export interface BirthCertificate {
  /** Hash of the raw data content. */
  dataHash: string;
  /** Where the data came from. */
  source: DataSource;
  /** Timestamp of creation. */
  bornAt: number;
  /** DID of the heart that first received this data. */
  bornThrough: string;
  /** Session ID linking to the heartbeat chain. */
  bornInSession: string;
  /** If derived from other certificated data. */
  parentCertificates: string[];
  /** Signature by the receiving heart's key. */
  receiverSignature: string;
  /** Signature by the source heart's key (null if unhearted source). */
  sourceSignature: string | null;
  /** Trust tier based on signature coverage. */
  trustTier: TrustTier;
}

// ─── Co-signing Protocol ─────────────────────────────────────────────────────

/**
 * Create a data provenance payload for the source heart to sign.
 * This is step 1 of the co-signing handshake: the receiving heart
 * prepares the payload and sends it to the source for signing.
 */
export function createDataProvenance(
  data: string,
  sourceDid: string,
  receiverDid: string,
  provider?: CryptoProvider
): DataProvenance {
  const p = provider ?? getCryptoProvider();
  return {
    dataHash: sha256(data, p),
    sourceDid,
    receiverDid,
    timestamp: Date.now(),
  };
}

/**
 * Sign a data provenance payload as the source heart.
 * This is step 2 of the co-signing handshake: the source heart
 * signs the payload to attest "I provided this data to receiver X."
 */
export function signDataProvenance(
  provenance: DataProvenance,
  signingKeyPair: SignKeyPair,
  provider?: CryptoProvider
): string {
  const p = provider ?? getCryptoProvider();
  const content = canonicalizeProvenance(provenance);
  const contentBytes = new TextEncoder().encode(content);
  const signature = p.signing.sign(contentBytes, signingKeyPair.secretKey);
  return p.encoding.encodeBase64(signature);
}

/**
 * Verify a source's data provenance signature.
 */
export function verifyDataProvenance(
  provenance: DataProvenance,
  signature: string,
  publicKey: Uint8Array,
  provider?: CryptoProvider
): boolean {
  const p = provider ?? getCryptoProvider();
  const content = canonicalizeProvenance(provenance);
  const contentBytes = new TextEncoder().encode(content);
  const sigBytes = p.encoding.decodeBase64(signature);
  return p.signing.verify(contentBytes, sigBytes, publicKey);
}

// ─── Birth Certificate Creation ──────────────────────────────────────────────

/**
 * Create a birth certificate with full co-signing support.
 *
 * For hearted sources: provide sourceSignature from the co-signing handshake.
 * For unhearted sources: sourceSignature is null, trustTier is "single-signed".
 */
export function createBirthCertificate(
  data: string,
  source: DataSource,
  heartDid: string,
  sessionId: string,
  signingKeyPair: SignKeyPair,
  parentCertificates: string[] = [],
  provider?: CryptoProvider,
  sourceSignature?: string | null,
  bornAt?: number
): BirthCertificate {
  const p = provider ?? getCryptoProvider();
  const dataHash = sha256(data, p);
  const resolvedBornAt = bornAt ?? Date.now();

  // Determine trust tier
  const resolvedSourceSig = sourceSignature ?? null;
  let trustTier: TrustTier;
  if (source.heartVerified && resolvedSourceSig !== null) {
    trustTier = "dual-signed";
  } else if (source.heartVerified || resolvedSourceSig !== null) {
    // Source claims to be hearted but no co-signature — treat as single-signed
    trustTier = "single-signed";
  } else {
    trustTier = "single-signed"; // Receiver's heart always signs
  }

  const certContent = canonicalizeCertContent({
    dataHash,
    source,
    bornAt: resolvedBornAt,
    bornThrough: heartDid,
    bornInSession: sessionId,
    parentCertificates,
    trustTier,
  });

  // Receiver signs
  const contentBytes = new TextEncoder().encode(certContent);
  const receiverSignature = p.encoding.encodeBase64(
    p.signing.sign(contentBytes, signingKeyPair.secretKey)
  );

  return {
    dataHash,
    source,
    bornAt: resolvedBornAt,
    bornThrough: heartDid,
    bornInSession: sessionId,
    parentCertificates,
    receiverSignature,
    sourceSignature: resolvedSourceSig,
    trustTier,
  };
}

/**
 * Create an unsigned birth certificate placeholder — no heart attests.
 * The consumer decides how much to trust unsigned data.
 */
export function createUnsignedBirthCertificate(
  data: string,
  source: DataSource,
  sessionId: string,
  provider?: CryptoProvider
): BirthCertificate {
  const p = provider ?? getCryptoProvider();
  return {
    dataHash: sha256(data, p),
    source: { ...source, heartVerified: false },
    bornAt: Date.now(),
    bornThrough: "",
    bornInSession: sessionId,
    parentCertificates: [],
    receiverSignature: "",
    sourceSignature: null,
    trustTier: "unsigned",
  };
}

// ─── Content-addressed fingerprint ───────────────────────────────────────────

/**
 * Content-addressed fingerprint of a birth certificate — hashes the full
 * canonicalized body plus both signatures. This is the canonical parent
 * reference format used in `parentCertificates[]`.
 *
 * Why the full cert, not just the signature: a child cert that only
 * commits to its parent's signature string is weakly bound. An attacker
 * cannot forge a valid parent with a matching signature (Ed25519 binds
 * signature to body), but an offline verifier inspecting a child cert
 * alone cannot tell which parent body the child intended. Hashing the
 * full cert makes the parent reference a true content address: exactly
 * one cert can satisfy it, the child's intent is unambiguous, and
 * tampering with any field of the parent invalidates the link.
 *
 * Never sign this hash. It exists only for chain-walking and parent
 * resolution. Signatures are always over `canonicalizeCertContent`.
 */
export function birthCertificateFingerprint(
  cert: BirthCertificate,
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  const body = canonicalizeCertContent({
    dataHash: cert.dataHash,
    source: cert.source,
    bornAt: cert.bornAt,
    bornThrough: cert.bornThrough,
    bornInSession: cert.bornInSession,
    parentCertificates: cert.parentCertificates,
    trustTier: cert.trustTier,
  });
  // Newline separators are not ambiguous because canonicalizeCertContent
  // emits compact JSON with no literal newlines, and base64 signatures
  // never contain newlines.
  const payload = `${body}\n${cert.receiverSignature}\n${cert.sourceSignature ?? ''}`;
  return sha256(payload, p);
}

// ─── Verification ────────────────────────────────────────────────────────────

/**
 * Verify a birth certificate's receiver signature.
 * Confirms the certificate was issued by the claimed receiving heart.
 *
 * When `lookup` is provided, additionally confirms that the public key
 * was effective at the certificate's `bornAt` timestamp via the rotation
 * subsystem. Fail-closed if the key is not found or was not effective.
 * When omitted, existing behavior is preserved.
 */
export function verifyBirthCertificate(
  cert: BirthCertificate,
  publicKey: Uint8Array,
  provider?: CryptoProvider,
  lookup?: HistoricalKeyLookup,
): boolean {
  const p = provider ?? getCryptoProvider();

  if (cert.trustTier === "unsigned") return false;

  // Rotation-aware key validity check (opt-in).
  if (lookup) {
    let result;
    try {
      result = lookup.resolve(publicKey, cert.bornAt);
    } catch {
      return false;
    }
    const check = checkKeyEffective(result, cert.bornAt);
    if (!check.effective) {
      return false;
    }
  }

  const certContent = canonicalizeCertContent({
    dataHash: cert.dataHash,
    source: cert.source,
    bornAt: cert.bornAt,
    bornThrough: cert.bornThrough,
    bornInSession: cert.bornInSession,
    parentCertificates: cert.parentCertificates,
    trustTier: cert.trustTier,
  });

  const contentBytes = new TextEncoder().encode(certContent);
  const signature = p.encoding.decodeBase64(cert.receiverSignature);
  return p.signing.verify(contentBytes, signature, publicKey);
}

/**
 * Verify the source's co-signature on a birth certificate.
 * Only applicable for dual-signed certificates.
 *
 * The source signed a DataProvenance payload, not the full certificate.
 * We need the provenance data to reconstruct what was signed.
 */
export function verifySourceSignature(
  cert: BirthCertificate,
  sourcePublicKey: Uint8Array,
  provider?: CryptoProvider
): boolean {
  const p = provider ?? getCryptoProvider();

  if (!cert.sourceSignature || cert.trustTier !== "dual-signed") return false;

  // Reconstruct the provenance payload that the source signed
  const provenance: DataProvenance = {
    dataHash: cert.dataHash,
    sourceDid: cert.source.identifier,
    receiverDid: cert.bornThrough,
    timestamp: cert.bornAt,
  };

  return verifyDataProvenance(provenance, cert.sourceSignature, sourcePublicKey, p);
}

/**
 * Verify that the data content matches the certificate's hash.
 * Detects tampering — if the data was modified after certification,
 * the hash won't match.
 */
export function verifyDataIntegrity(data: string, cert: BirthCertificate, provider?: CryptoProvider): boolean {
  return sha256(data, provider) === cert.dataHash;
}

/**
 * Verify a chain of birth certificates — hearts all the way down.
 * Each certificate's parent must be verifiable.
 *
 * When `lookup` is provided, each certificate's receiver key is checked
 * against the rotation subsystem for validity at `bornAt`. When omitted,
 * existing behavior is preserved.
 */
export function verifyBirthCertificateChain(
  chain: BirthCertificate[],
  publicKeys: Map<string, Uint8Array>,
  provider?: CryptoProvider,
  lookup?: HistoricalKeyLookup,
): { valid: boolean; brokenAt: number; reason: string } {
  const p = provider ?? getCryptoProvider();

  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];

    // Skip unsigned certificates
    if (cert.trustTier === "unsigned") {
      return { valid: false, brokenAt: i, reason: `Unsigned certificate at index ${i}` };
    }

    const pubKey = publicKeys.get(cert.bornThrough);
    if (!pubKey) {
      return { valid: false, brokenAt: i, reason: `Unknown heart DID: ${cert.bornThrough}` };
    }

    if (!verifyBirthCertificate(cert, pubKey, p, lookup)) {
      return { valid: false, brokenAt: i, reason: `Invalid receiver signature at index ${i}` };
    }

    // For dual-signed certs, verify source signature too
    if (cert.trustTier === "dual-signed" && cert.sourceSignature) {
      const sourceKey = publicKeys.get(cert.source.identifier);
      if (!sourceKey) {
        return { valid: false, brokenAt: i, reason: `Unknown source DID: ${cert.source.identifier}` };
      }
      if (!verifySourceSignature(cert, sourceKey, p)) {
        return { valid: false, brokenAt: i, reason: `Invalid source co-signature at index ${i}` };
      }
    }

    // Verify parent references exist in earlier chain entries.
    // Parents are referenced by their content-addressed fingerprint, which
    // commits to the full canonicalized body plus both signatures. Binding
    // only to the receiver signature string would let any cert sharing that
    // signature satisfy the reference — fingerprinting the whole cert makes
    // the child's intent unambiguous.
    for (const parentHash of cert.parentCertificates) {
      const parentExists = chain
        .slice(0, i)
        .some(c => birthCertificateFingerprint(c, p) === parentHash);
      if (!parentExists) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Missing parent certificate: ${parentHash}`,
        };
      }
    }
  }

  return { valid: true, brokenAt: -1, reason: "Chain intact" };
}

// ─── Canonicalization ────────────────────────────────────────────────────────

/** Deterministic serialization of certificate content for signing. */
function canonicalizeCertContent(content: {
  dataHash: string;
  source: DataSource;
  bornAt: number;
  bornThrough: string;
  bornInSession: string;
  parentCertificates: string[];
  trustTier: TrustTier;
}): string {
  return JSON.stringify({
    bornAt: content.bornAt,
    bornInSession: content.bornInSession,
    bornThrough: content.bornThrough,
    dataHash: content.dataHash,
    parentCertificates: [...content.parentCertificates].sort(),
    source: {
      heartVerified: content.source.heartVerified,
      identifier: content.source.identifier,
      type: content.source.type,
    },
    trustTier: content.trustTier,
  });
}

/** Deterministic serialization of provenance payload for co-signing. */
function canonicalizeProvenance(provenance: DataProvenance): string {
  return JSON.stringify({
    dataHash: provenance.dataHash,
    receiverDid: provenance.receiverDid,
    sourceDid: provenance.sourceDid,
    timestamp: provenance.timestamp,
  });
}
