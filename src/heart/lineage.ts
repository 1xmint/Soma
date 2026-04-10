/**
 * Heart Lineage — cryptographic parent-child relationships between hearts.
 *
 * A parent heart can fork a child heart with its own keypair. The parent
 * signs a lineage certificate binding the child's public key, genome,
 * capabilities, and TTL to the parent's identity. The child carries the
 * full chain back to the root, so observers can verify:
 *
 *   - Who spawned this heart (direct parent)
 *   - The full ancestry (chain back to root)
 *   - What the child was authorized to do (capabilities)
 *   - When the child's authority expires (TTL)
 *
 * This is the foundation for agent economies: orchestrators fork workers,
 * workers fork sub-workers, reputation flows up the tree, revocation flows
 * down. No lineage, no multi-agent trust.
 */

import { domainSigningInput } from '../core/canonicalize.js';

const LINEAGE_DOMAIN = 'soma/lineage/v1';
import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../core/crypto-provider.js';
import {
  type GenomeCommitment,
  publicKeyToDid,
} from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A single link in the lineage chain — parent signs over child's identity. */
export interface LineageCertificate {
  /** Opaque ID for this lineage cert (used for revocation). */
  id: string;
  /** Parent heart's DID. */
  parentDid: string;
  /** Parent's genome hash at the time of forking. */
  parentGenomeHash: string;
  /** Child heart's DID. */
  childDid: string;
  /** Child's genome hash. */
  childGenomeHash: string;
  /** Capabilities granted to the child (empty = inherit all from parent). */
  capabilities: string[];
  /** When this lineage cert was issued. */
  issuedAt: number;
  /** When this lineage cert expires (null = no expiry). */
  expiresAt: number | null;
  /** Optional budget in credits granted to child. */
  budgetCredits: number | null;
  /** Random nonce to prevent replay of forking. */
  nonce: string;
  /** Parent's signature over the canonical form of this cert (minus signature). */
  signature: string;
  /** Parent's public key (base64) for verification. */
  parentPublicKey: string;
}

/** The full lineage chain: root → ... → direct parent → this heart. */
export interface HeartLineage {
  /** The heart's own DID. */
  did: string;
  /** The root ancestor's DID (the oldest heart in this line). */
  rootDid: string;
  /** Ordered chain of lineage certs — [0] is root's child, [n-1] is this heart's cert. */
  chain: LineageCertificate[];
}

// ─── Creation ───────────────────────────────────────────────────────────────

/**
 * Create a lineage certificate — parent signs over child's identity.
 * Call this when a parent heart is forking a new child.
 */
export function createLineageCertificate(opts: {
  parent: GenomeCommitment;
  parentSigningKey: Uint8Array;
  child: GenomeCommitment;
  capabilities?: string[];
  ttl?: number;
  budgetCredits?: number;
  provider?: CryptoProvider;
}): LineageCertificate {
  const p = opts.provider ?? getCryptoProvider();
  const now = Date.now();
  const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

  const payload = {
    id: `lc-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    parentDid: opts.parent.did,
    parentGenomeHash: opts.parent.hash,
    childDid: opts.child.did,
    childGenomeHash: opts.child.hash,
    capabilities: opts.capabilities ?? [],
    issuedAt: now,
    expiresAt: opts.ttl ? now + opts.ttl : null,
    budgetCredits: opts.budgetCredits ?? null,
    nonce,
    parentPublicKey: opts.parent.publicKey,
  };

  const signingInput = domainSigningInput(LINEAGE_DOMAIN, payload);
  const signature = p.signing.sign(signingInput, opts.parentSigningKey);

  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

// ─── Verification ───────────────────────────────────────────────────────────

export type LineageVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a single lineage certificate — signature + expiry + well-formedness.
 * Does NOT check revocation (that's the caller's responsibility).
 */
export function verifyLineageCertificate(
  cert: LineageCertificate,
  provider?: CryptoProvider,
): LineageVerification {
  const p = provider ?? getCryptoProvider();

  // Reconstruct signing payload (everything except signature itself)
  const { signature, ...payload } = cert;
  const signingInput = domainSigningInput(LINEAGE_DOMAIN, payload);
  const sigBytes = p.encoding.decodeBase64(signature);
  const parentPubKey = p.encoding.decodeBase64(cert.parentPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, parentPubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }

  // Verify parentDid matches parentPublicKey
  const expectedParentDid = publicKeyToDid(parentPubKey, p);
  if (cert.parentDid !== expectedParentDid) {
    return { valid: false, reason: 'parentDid does not match parentPublicKey' };
  }

  if (cert.expiresAt !== null && Date.now() > cert.expiresAt) {
    return { valid: false, reason: 'certificate expired' };
  }

  if (cert.issuedAt > Date.now() + 60_000) {
    return { valid: false, reason: 'certificate issued in the future' };
  }

  return { valid: true };
}

/**
 * Verify an entire lineage chain — every cert must validate AND each parent
 * must be the previous cert's child. The first cert's parentDid is the root.
 */
export function verifyLineageChain(
  lineage: HeartLineage,
  provider?: CryptoProvider,
): LineageVerification {
  if (lineage.chain.length === 0) {
    return { valid: false, reason: 'empty chain' };
  }

  // First cert's parent should be the root
  if (lineage.chain[0].parentDid !== lineage.rootDid) {
    return { valid: false, reason: 'first cert parent does not match rootDid' };
  }

  for (let i = 0; i < lineage.chain.length; i++) {
    const cert = lineage.chain[i];
    const check = verifyLineageCertificate(cert, provider);
    if (!check.valid) {
      return { valid: false, reason: `chain[${i}]: ${check.reason}` };
    }

    // Each cert's parent must match the previous cert's child
    if (i > 0 && cert.parentDid !== lineage.chain[i - 1].childDid) {
      return { valid: false, reason: `chain[${i}]: parent does not match previous child` };
    }
  }

  // Last cert's child must match this heart's DID
  const last = lineage.chain[lineage.chain.length - 1];
  if (last.childDid !== lineage.did) {
    return { valid: false, reason: 'last cert child does not match heart DID' };
  }

  return { valid: true };
}

// ─── Capability Resolution ──────────────────────────────────────────────────

/**
 * Compute the effective capabilities of a heart given its lineage chain.
 * Capabilities can only narrow down the chain — a child never has capabilities
 * its parent lacks. Empty parent capabilities means "inherit all".
 */
export function effectiveCapabilities(lineage: HeartLineage): string[] | null {
  if (lineage.chain.length === 0) return null; // no restrictions

  let current: string[] | null = null; // null = unrestricted
  for (const cert of lineage.chain) {
    if (cert.capabilities.length === 0) continue; // inherit
    if (current === null) {
      current = [...cert.capabilities];
    } else {
      // Intersect with previous capabilities — can only narrow
      current = current.filter((c) => hasCapability(cert.capabilities, c));
    }
  }

  return current;
}

/**
 * Check whether a capability set grants a specific requested capability.
 * Supports wildcards: `tool:*` grants `tool:search`, `tool:db`, etc.
 * Special `*` grants everything.
 */
export function hasCapability(granted: string[], requested: string): boolean {
  if (granted.includes('*')) return true;
  if (granted.includes(requested)) return true;

  for (const cap of granted) {
    if (cap.endsWith(':*')) {
      const prefix = cap.slice(0, -1); // e.g. "tool:"
      if (requested.startsWith(prefix)) return true;
    }
  }

  return false;
}
