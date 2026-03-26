/**
 * Birth certificates — data provenance sealing.
 *
 * When data enters the digital world — a human types something, a sensor
 * reads a temperature, an API returns a response — the first heart it
 * touches seals it with a birth certificate: who created it, when, through
 * what interface, and a hash of the original content.
 *
 * From that moment, the data is alive. Every agent that processes it adds
 * its own heartbeat to the chain. The chain is immutable. Lies are
 * permanently, inescapably attributed to their source.
 */

import { sha256 } from "../core/genome.js";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";

/** Source types for data entering the system. */
export type DataSourceType = "agent" | "api" | "human" | "sensor" | "file";

/** Description of where data came from. */
export interface DataSource {
  type: DataSourceType;
  /** DID if agent, URL if API, human ID if human, path if file. */
  identifier: string;
  /** Did this source have its own heart? */
  heartVerified: boolean;
}

/** A birth certificate — seals data at its genesis point. */
export interface BirthCertificate {
  /** SHA-256 of the raw data content. */
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
  /** Ed25519 signature by the heart's DID key. */
  signature: string;
}

/**
 * Create a birth certificate for data entering the system.
 *
 * The first heart that touches new data seals it. From that moment,
 * the data has provenance — authorship is guaranteed, truth is not.
 */
export function createBirthCertificate(
  data: string,
  source: DataSource,
  heartDid: string,
  sessionId: string,
  signingKeyPair: nacl.SignKeyPair,
  parentCertificates: string[] = []
): BirthCertificate {
  const dataHash = sha256(data);
  const bornAt = Date.now();

  const certContent = canonicalizeCertContent({
    dataHash,
    source,
    bornAt,
    bornThrough: heartDid,
    bornInSession: sessionId,
    parentCertificates,
  });

  // Sign with the heart's Ed25519 key
  const contentBytes = new TextEncoder().encode(certContent);
  const signature = nacl.sign.detached(contentBytes, signingKeyPair.secretKey);

  return {
    dataHash,
    source,
    bornAt,
    bornThrough: heartDid,
    bornInSession: sessionId,
    parentCertificates,
    signature: encodeBase64(signature),
  };
}

/**
 * Verify a birth certificate's signature.
 * Confirms the certificate was issued by the claimed heart.
 */
export function verifyBirthCertificate(
  cert: BirthCertificate,
  publicKey: Uint8Array
): boolean {
  const certContent = canonicalizeCertContent({
    dataHash: cert.dataHash,
    source: cert.source,
    bornAt: cert.bornAt,
    bornThrough: cert.bornThrough,
    bornInSession: cert.bornInSession,
    parentCertificates: cert.parentCertificates,
  });

  const contentBytes = new TextEncoder().encode(certContent);
  const signature = decodeBase64(cert.signature);

  return nacl.sign.detached.verify(contentBytes, signature, publicKey);
}

/**
 * Verify that the data content matches the certificate's hash.
 * Detects tampering — if the data was modified after certification,
 * the hash won't match.
 */
export function verifyDataIntegrity(data: string, cert: BirthCertificate): boolean {
  return sha256(data) === cert.dataHash;
}

/**
 * Verify a chain of birth certificates — hearts all the way down.
 * Each certificate's parent must be verifiable.
 */
export function verifyBirthCertificateChain(
  chain: BirthCertificate[],
  publicKeys: Map<string, Uint8Array>
): { valid: boolean; brokenAt: number; reason: string } {
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const pubKey = publicKeys.get(cert.bornThrough);

    if (!pubKey) {
      return { valid: false, brokenAt: i, reason: `Unknown heart DID: ${cert.bornThrough}` };
    }

    if (!verifyBirthCertificate(cert, pubKey)) {
      return { valid: false, brokenAt: i, reason: `Invalid signature at index ${i}` };
    }

    // Verify parent references exist in earlier chain entries
    for (const parentHash of cert.parentCertificates) {
      const parentExists = chain
        .slice(0, i)
        .some((c) => sha256(c.signature) === parentHash);
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

/** Deterministic serialization of certificate content for signing. */
function canonicalizeCertContent(content: {
  dataHash: string;
  source: DataSource;
  bornAt: number;
  bornThrough: string;
  bornInSession: string;
  parentCertificates: string[];
}): string {
  // Keys sorted alphabetically for deterministic output
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
  });
}
