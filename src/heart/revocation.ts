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

import { canonicalJson } from '../core/canonicalize.js';
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

  const signingInput = new TextEncoder().encode(canonicalJson(payload));
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
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
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
 * In-memory registry of revocations. Subscribers feed events in, consumers
 * ask `isRevoked()` before honoring any credential. Persistence is the
 * caller's job — the registry exposes import/export for that.
 */
export class RevocationRegistry {
  private readonly byTarget = new Map<string, RevocationEvent>();
  private readonly provider: CryptoProvider;

  constructor(provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
  }

  /**
   * Add a revocation event. Returns true if accepted, false if signature
   * invalid or already present.
   *
   * NOTE: this does NOT verify the issuer had authority over the target —
   * callers must enforce that policy themselves (e.g. "the delegation's
   * issuerDid matches the revocation's issuerDid").
   */
  add(event: RevocationEvent): boolean {
    const check = verifyRevocation(event, this.provider);
    if (!check.valid) return false;
    if (this.byTarget.has(event.targetId)) return false;
    this.byTarget.set(event.targetId, event);
    return true;
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

  /** Bulk import events (e.g. from a feed). Returns count accepted. */
  import(events: RevocationEvent[]): number {
    let accepted = 0;
    for (const ev of events) {
      if (this.add(ev)) accepted++;
    }
    return accepted;
  }

  /** Clear the registry (testing only — revocations are forever in production). */
  clear(): void {
    this.byTarget.clear();
  }
}
