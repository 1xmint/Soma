/**
 * Revocation — signed events that nullify previously-issued credentials.
 *
 * Revocation is the counterpart to lineage/delegation: when a heart issues a
 * lineage certificate or delegation, it retains the right to revoke it. A
 * revocation event is a signed declaration that a specific credential should
 * no longer be honored, with an optional reason code.
 *
 * Revocations are signed by the ORIGINAL ISSUER, not the holder. Only the
 * party that created a credential can revoke it — this preserves the trust
 * chain (if A delegated to B, only A can revoke; B cannot "revoke A's grant").
 *
 * Propagation is out of band: producers publish revocation events to a feed,
 * consumers subscribe and check each use. In the simplest deployment, a heart
 * keeps a local registry and consults it before accepting any credential.
 *
 * A revocation is irreversible — once published, the target is dead forever.
 * If you want temporary disablement, use short TTLs instead.
 */

import { domainSigningInput } from '../core/canonicalize.js';

const REVOCATION_DOMAIN = 'soma/revocation/v1';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import {
  verifyDidBinding,
  type DidMethodRegistry,
} from '../core/did-method.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export type RevocationReason =
  | 'compromised'      // keys leaked / subject misbehaving
  | 'rotated'          // superseded by a new credential
  | 'completed'        // task done, no longer needed
  | 'expired-early'    // revoked before TTL for policy reasons
  | 'abuse'            // subject exceeded acceptable use
  | 'unknown';         // no reason given

/** Kind of credential being revoked. */
export type RevocationTarget = 'lineage' | 'delegation' | 'heart';

/** A signed revocation — the issuer declares a credential dead. */
export interface RevocationEvent {
  /** Opaque ID for this revocation event itself. */
  id: string;
  /** The ID of the thing being revoked. */
  targetId: string;
  /** What kind of credential is being revoked. */
  targetKind: RevocationTarget;
  /** DID of the issuer (who has authority to revoke). */
  issuerDid: string;
  /** Reason for revocation. */
  reason: RevocationReason;
  /** Optional free-form detail (e.g. incident ID). */
  detail?: string;
  /** When this revocation was issued. */
  issuedAt: number;
  /** Random nonce to prevent replay. */
  nonce: string;
  /** Issuer's Ed25519 signature over the payload. */
  signature: string;
  /** Issuer's public key (base64). */
  issuerPublicKey: string;
}

// ─── Creation ───────────────────────────────────────────────────────────────

export function createRevocation(opts: {
  targetId: string;
  targetKind: RevocationTarget;
  issuerDid: string;
  issuerPublicKey: string;
  issuerSigningKey: Uint8Array;
  reason?: RevocationReason;
  detail?: string;
  provider?: CryptoProvider;
}): RevocationEvent {
  const p = opts.provider ?? getCryptoProvider();
  const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

  const payload = {
    id: `rv-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    targetId: opts.targetId,
    targetKind: opts.targetKind,
    issuerDid: opts.issuerDid,
    reason: opts.reason ?? 'unknown',
    detail: opts.detail,
    issuedAt: Date.now(),
    nonce,
    issuerPublicKey: opts.issuerPublicKey,
  };

  const signingInput = domainSigningInput(REVOCATION_DOMAIN, payload);
  const signature = p.signing.sign(signingInput, opts.issuerSigningKey);

  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

// ─── Verification ───────────────────────────────────────────────────────────

export type RevocationVerification =
  | { valid: true }
  | { valid: false; reason: string };

export function verifyRevocation(
  rev: RevocationEvent,
  provider?: CryptoProvider,
  registry?: DidMethodRegistry,
): RevocationVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = rev;
  const signingInput = domainSigningInput(REVOCATION_DOMAIN, payload);
  const sigBytes = p.encoding.decodeBase64(signature);
  const issuerPubKey = p.encoding.decodeBase64(rev.issuerPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, issuerPubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }

  const binding = verifyDidBinding(rev.issuerDid, issuerPubKey, registry, p);
  if (!binding.bound) {
    return {
      valid: false,
      reason: `issuerDid does not match issuerPublicKey: ${binding.reason}`,
    };
  }

  return { valid: true };
}

// ─── Registry ───────────────────────────────────────────────────────────────

/**
 * Resolves the DID that has legitimate authority to revoke a given target.
 * Typically backed by the delegation/lineage store that originally issued
 * the target. Return `undefined` if the target is unknown to the resolver;
 * fail-closed semantics apply (unknown-authority revocations are rejected).
 */
export type AuthorityResolver = (
  targetId: string,
  targetKind: RevocationTarget,
) => string | undefined;

/**
 * In-memory registry of revocations. Subscribers feed events in, consumers
 * ask `isRevoked()` before honoring any credential. Persistence is the
 * caller's job — the registry exposes import/export for that.
 *
 * **Authority enforcement.** `add()` verifies that the revocation's
 * `issuerDid` matches the expected issuer for the target. The expected
 * issuer is supplied either as an explicit argument to `add()` or via an
 * `authority` resolver configured at construction time. Unknown-authority
 * revocations are rejected by default (fail-closed). This closes the
 * "any fresh key can revoke any delegation" hole.
 */
export class RevocationRegistry {
  private readonly byTarget = new Map<string, RevocationEvent>();
  private readonly provider: CryptoProvider;
  private readonly authority?: AuthorityResolver;
  private readonly internalAuthority = new Map<string, string>();

  constructor(
    opts: {
      provider?: CryptoProvider;
      /**
       * Resolver consulted when `add()` is called without an explicit
       * expected issuer DID. If omitted and no internal authority is
       * registered via {@link registerAuthority}, such calls fail closed.
       */
      authority?: AuthorityResolver;
    } = {},
  ) {
    this.provider = opts.provider ?? getCryptoProvider();
    this.authority = opts.authority;
  }

  /**
   * Register the legitimate issuer for a target. Called by the code that
   * creates the delegation/lineage/heart credential being tracked, so that
   * when a revocation arrives the registry can cross-check authority.
   */
  registerAuthority(targetId: string, issuerDid: string): void {
    this.internalAuthority.set(targetId, issuerDid);
  }

  /**
   * Add a revocation event. The revocation is accepted only if:
   *   1. its signature verifies against the declared issuer public key
   *   2. its `issuerDid` equals the expected authority for the target
   *   3. the target has not already been revoked in this registry
   *
   * The expected issuer is resolved in this order:
   *   - `expectedIssuerDid` argument (if provided)
   *   - internal authority map (populated via `registerAuthority`)
   *   - `authority` resolver supplied at construction time
   * If none resolves a value, the revocation is rejected (fail-closed).
   *
   * Returns `{ accepted: true }` on success, `{ accepted: false, reason }`
   * otherwise. The reason is a short tag suitable for logging.
   */
  add(
    event: RevocationEvent,
    expectedIssuerDid?: string,
  ): { accepted: boolean; reason?: string } {
    const check = verifyRevocation(event, this.provider);
    if (!check.valid) return { accepted: false, reason: `invalid: ${check.reason}` };
    if (this.byTarget.has(event.targetId)) {
      return { accepted: false, reason: "duplicate" };
    }
    const expected =
      expectedIssuerDid ??
      this.internalAuthority.get(event.targetId) ??
      this.authority?.(event.targetId, event.targetKind);
    if (!expected) {
      return { accepted: false, reason: "unknown authority" };
    }
    if (expected !== event.issuerDid) {
      return { accepted: false, reason: "issuer not authorized for target" };
    }
    this.byTarget.set(event.targetId, event);
    return { accepted: true };
  }

  /** Is this target ID revoked? */
  isRevoked(targetId: string): boolean {
    return this.byTarget.has(targetId);
  }

  /** Look up the revocation for a target, if any. */
  get(targetId: string): RevocationEvent | undefined {
    return this.byTarget.get(targetId);
  }

  /** Number of revocations held. */
  get size(): number {
    return this.byTarget.size;
  }

  /** Export all events (for persistence / sync). */
  export(): RevocationEvent[] {
    return Array.from(this.byTarget.values());
  }

  /**
   * Bulk import events (e.g. from a feed). Returns count accepted. Each
   * event is resolved via the registry's configured authority (internal
   * map or constructor resolver). Events whose authority is unknown are
   * rejected.
   */
  import(events: RevocationEvent[]): number {
    let accepted = 0;
    for (const ev of events) {
      if (this.add(ev).accepted) accepted++;
    }
    return accepted;
  }

  /** Clear the registry (testing only — revocations are forever in production). */
  clear(): void {
    this.byTarget.clear();
    this.internalAuthority.clear();
  }
}
