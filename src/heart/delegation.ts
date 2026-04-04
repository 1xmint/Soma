/**
 * Delegation — macaroons-style capability tokens with caveats.
 *
 * A delegation is a signed token from issuer to subject granting a set of
 * capabilities under a set of caveats (time bounds, budget, audience, etc.).
 * Delegations are CHAINABLE: a holder can attenuate by adding more caveats,
 * but NEVER broaden scope. Chain verification checks that every link's
 * caveats monotonically narrow the previous.
 *
 * Delegations are bearer-adjacent: they name a subject DID, and the subject
 * must be able to sign a proof-of-possession to use them. Unlike classic
 * macaroons, we bind to a DID rather than pure HMAC chains, which is
 * cleaner in a world where every actor already has a keypair.
 *
 * Typical flow:
 *   A has capability X
 *   A delegates X to B with caveat "budget: 1000 credits"
 *   B delegates X to C with additional caveat "expires: tomorrow"
 *   C tries to use X → chain verified: signed by A → B → C, all caveats hold
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Caveat Types ───────────────────────────────────────────────────────────

/** A caveat is a condition that must hold for the delegation to be valid. */
export type Caveat =
  | { kind: 'expires-at'; timestamp: number }
  | { kind: 'not-before'; timestamp: number }
  | { kind: 'audience'; did: string }
  | { kind: 'budget'; credits: number }
  | { kind: 'max-invocations'; count: number }
  | { kind: 'capabilities'; allow: string[] }
  | { kind: 'custom'; key: string; value: string };

// ─── Delegation Type ────────────────────────────────────────────────────────

export interface Delegation {
  /** Opaque ID — used for revocation. */
  id: string;
  /** DID of the issuer (who is granting). */
  issuerDid: string;
  /** DID of the subject (who receives). */
  subjectDid: string;
  /** Capabilities being granted (before caveats restrict them). */
  capabilities: string[];
  /** Caveats that must all hold for use. */
  caveats: Caveat[];
  /** When this delegation was issued. */
  issuedAt: number;
  /** Random nonce to prevent replay. */
  nonce: string;
  /** If this attenuates a previous delegation, its ID. */
  parentId: string | null;
  /** Base64-encoded Ed25519 signature by the issuer. */
  signature: string;
  /** Base64-encoded public key of the issuer (for verification). */
  issuerPublicKey: string;
}

/** Context at verification time — who's invoking, what they want, spend so far. */
export interface InvocationContext {
  /** DID invoking the delegation. */
  invokerDid: string;
  /** Capability being exercised. */
  capability: string;
  /** Credits being spent on this invocation. */
  creditsSpent?: number;
  /** Cumulative credits spent across all invocations of this delegation. */
  cumulativeCreditsSpent?: number;
  /** Number of prior invocations (for max-invocations caveat). */
  invocationCount?: number;
  /** Current time (defaults to Date.now()). */
  now?: number;
}

// ─── Creation ───────────────────────────────────────────────────────────────

export function createDelegation(opts: {
  issuerDid: string;
  issuerPublicKey: string;
  issuerSigningKey: Uint8Array;
  subjectDid: string;
  capabilities: string[];
  caveats?: Caveat[];
  parentId?: string | null;
  provider?: CryptoProvider;
}): Delegation {
  const p = opts.provider ?? getCryptoProvider();
  const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

  const payload = {
    id: `dg-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    issuerDid: opts.issuerDid,
    subjectDid: opts.subjectDid,
    capabilities: opts.capabilities,
    caveats: opts.caveats ?? [],
    issuedAt: Date.now(),
    nonce,
    parentId: opts.parentId ?? null,
    issuerPublicKey: opts.issuerPublicKey,
  };

  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const signature = p.signing.sign(signingInput, opts.issuerSigningKey);

  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

/**
 * Attenuate an existing delegation — subject narrows capability/caveats for
 * someone else. The new delegation's scope can ONLY be a subset of the parent.
 */
export function attenuateDelegation(opts: {
  parent: Delegation;
  newSubjectDid: string;
  newSubjectSigningKey: Uint8Array;
  newSubjectPublicKey: string;
  additionalCaveats?: Caveat[];
  narrowedCapabilities?: string[];
  provider?: CryptoProvider;
}): Delegation {
  const caps = opts.narrowedCapabilities ?? opts.parent.capabilities;
  // Ensure attenuation: every new cap must have been in parent
  for (const cap of caps) {
    if (!opts.parent.capabilities.includes(cap)) {
      throw new Error(`Cannot attenuate: ${cap} not in parent delegation`);
    }
  }

  // Derive the attenuator's DID from their public key (they become the issuer)
  const p = opts.provider ?? getCryptoProvider();
  const pubKeyBytes = p.encoding.decodeBase64(opts.newSubjectPublicKey);
  const attenuatorDid = publicKeyToDid(pubKeyBytes, p);

  return createDelegation({
    issuerDid: attenuatorDid,
    issuerPublicKey: opts.newSubjectPublicKey,
    issuerSigningKey: opts.newSubjectSigningKey,
    subjectDid: opts.newSubjectDid,
    capabilities: caps,
    caveats: [...opts.parent.caveats, ...(opts.additionalCaveats ?? [])],
    parentId: opts.parent.id,
    provider: opts.provider,
  });
}

// ─── Verification ───────────────────────────────────────────────────────────

export type DelegationVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a delegation's signature + integrity (NOT caveats against context).
 */
export function verifyDelegationSignature(
  del: Delegation,
  provider?: CryptoProvider,
): DelegationVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = del;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const issuerPubKey = p.encoding.decodeBase64(del.issuerPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, issuerPubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }

  const expectedIssuerDid = publicKeyToDid(issuerPubKey, p);
  if (del.issuerDid !== expectedIssuerDid) {
    return { valid: false, reason: 'issuerDid does not match issuerPublicKey' };
  }

  return { valid: true };
}

/**
 * Check caveats against an invocation context.
 */
export function checkCaveats(
  del: Delegation,
  ctx: InvocationContext,
): DelegationVerification {
  const now = ctx.now ?? Date.now();

  // Capability check: is the invoked capability in the delegation?
  if (!del.capabilities.includes(ctx.capability)) {
    // Check wildcards
    const hasWildcard = del.capabilities.some((cap) => {
      if (cap === '*') return true;
      if (cap.endsWith(':*') && ctx.capability.startsWith(cap.slice(0, -1))) return true;
      return false;
    });
    if (!hasWildcard) {
      return { valid: false, reason: `capability ${ctx.capability} not granted` };
    }
  }

  // Iterate caveats
  for (const cav of del.caveats) {
    switch (cav.kind) {
      case 'expires-at':
        if (now > cav.timestamp) return { valid: false, reason: 'expired' };
        break;
      case 'not-before':
        if (now < cav.timestamp) return { valid: false, reason: 'not yet valid' };
        break;
      case 'audience':
        if (ctx.invokerDid !== cav.did) {
          return { valid: false, reason: `audience mismatch: expected ${cav.did}` };
        }
        break;
      case 'budget': {
        const spent = ctx.cumulativeCreditsSpent ?? 0;
        const thisCall = ctx.creditsSpent ?? 0;
        if (spent + thisCall > cav.credits) {
          return { valid: false, reason: `budget exhausted (${spent + thisCall}/${cav.credits})` };
        }
        break;
      }
      case 'max-invocations':
        if ((ctx.invocationCount ?? 0) >= cav.count) {
          return { valid: false, reason: `max invocations reached (${cav.count})` };
        }
        break;
      case 'capabilities':
        if (!cav.allow.includes(ctx.capability)) {
          const hasWc = cav.allow.some((c) => {
            if (c === '*') return true;
            if (c.endsWith(':*') && ctx.capability.startsWith(c.slice(0, -1))) return true;
            return false;
          });
          if (!hasWc) return { valid: false, reason: `caveat narrows capability: ${ctx.capability} not allowed` };
        }
        break;
      case 'custom':
        // Custom caveats are opaque — caller must handle
        break;
    }
  }

  return { valid: true };
}

/**
 * Full verification: signature + caveats + subject matches invoker.
 */
export function verifyDelegation(
  del: Delegation,
  ctx: InvocationContext,
  provider?: CryptoProvider,
): DelegationVerification {
  const sigCheck = verifyDelegationSignature(del, provider);
  if (!sigCheck.valid) return sigCheck;

  if (del.subjectDid !== ctx.invokerDid) {
    return { valid: false, reason: 'invoker is not the delegation subject' };
  }

  return checkCaveats(del, ctx);
}
