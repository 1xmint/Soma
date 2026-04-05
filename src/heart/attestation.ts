/**
 * Identity attestations — sybil-resistance primitives.
 *
 * Problem: `did:key` identities are free to mint. An adversary can spin up
 * a million fresh DIDs in seconds to vote in consensus, drain rate limits,
 * poison reputation systems, or game open marketplaces. Soma has no
 * built-in defense against this today.
 *
 * This module gives applications the raw material to defend themselves:
 * cryptographically-signed claims by issuers about subjects. An
 * `IdentityAttestation` is a signed statement "I, issuer D, vouch that
 * subject S has property X". It is NOT a credential the subject carries —
 * it is a record issuers publish, that verifiers look up, to decide how
 * much weight a subject's identity carries.
 *
 * Attestation layers (from simplest to strongest):
 *   1. `peer-vouched` — another identity (possibly also anonymous) mentions
 *      this subject. Cheap. Millions of these != trust.
 *   2. `time-in-network` — subject has been active for N days (signed by
 *      a timekeeper). Hard to fake if timekeepers are honest.
 *   3. `organization-member` — org signs that subject is part of it.
 *   4. `stake-bonded` — subject has posted economic collateral.
 *   5. `kyc-verified` — issuer has verified subject against real-world ID.
 *
 * The weight knob and type multipliers let applications decide policy
 * (e.g. "only subjects with tier >= staked can participate in governance").
 *
 * The registry supports expiry + revocation, and a reputation score that
 * decays with time so an attestation from three years ago carries less
 * weight than one from last week. Decay rates are configurable.
 *
 * This is deliberately PASSIVE: it does not talk to any chain, registry,
 * or oracle. Applications inject attestations from whatever source they
 * trust (on-chain ERC-8004, off-chain signed claims, Soul-bound tokens).
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export type AttestationType =
  | 'peer-vouched'
  | 'time-in-network'
  | 'organization-member'
  | 'stake-bonded'
  | 'kyc-verified'
  | 'skill-verified'
  | 'custom';

export interface IdentityAttestation {
  /** Opaque attestation ID. */
  id: string;
  /** DID of the subject this attestation is about. */
  subjectDid: string;
  /** DID of the issuer making this claim. */
  issuerDid: string;
  /** Kind of claim being made. */
  attestationType: AttestationType;
  /** Weight, 0-100. Lets the issuer grade how strong their claim is. */
  weight: number;
  /** When issued (ms epoch). */
  issuedAt: number;
  /** When this expires, or null for never-expires. */
  expiresAt: number | null;
  /** Optional hex hash of off-chain evidence. */
  evidence: string | null;
  /** Optional custom label when type='custom'. */
  customLabel: string | null;
  /** Anti-replay nonce. */
  nonce: string;
  /** Issuer's base64 public key. */
  issuerPublicKey: string;
  /** Issuer's Ed25519 signature over the canonical payload. */
  signature: string;
}

export type AttestationVerification =
  | { valid: true }
  | { valid: false; reason: string };

export type IdentityTier = 'anonymous' | 'attested' | 'staked' | 'verified';

export interface ReputationScore {
  subjectDid: string;
  score: number;
  tier: IdentityTier;
  attestationCount: number;
  countByType: Record<string, number>;
  computedAt: number;
}

/** Configuration for score computation. */
export interface ScoreConfig {
  /** Half-life for freshness decay, ms. Default 180 days. */
  halfLifeMs: number;
  /** Per-type multipliers (default set provides sensible ordering). */
  typeMultipliers: Record<AttestationType, number>;
  /** Trusted issuer DIDs — only their attestations count. Empty = any. */
  trustedIssuers: string[] | null;
  /** Current time (for tests). */
  now: number;
}

const DEFAULT_SCORE_CONFIG: ScoreConfig = {
  halfLifeMs: 180 * 24 * 60 * 60 * 1000,
  typeMultipliers: {
    'peer-vouched': 0.5,
    'time-in-network': 0.8,
    'organization-member': 1.5,
    'stake-bonded': 2.0,
    'kyc-verified': 2.5,
    'skill-verified': 1.2,
    custom: 1.0,
  },
  trustedIssuers: null,
  now: 0, // will be replaced with Date.now() at call time
};

// ─── Creation ───────────────────────────────────────────────────────────────

export function createAttestation(opts: {
  subjectDid: string;
  issuerDid: string;
  issuerPublicKey: string;
  issuerSigningKey: Uint8Array;
  attestationType: AttestationType;
  weight: number;
  expiresAt?: number | null;
  evidence?: string | null;
  customLabel?: string | null;
  provider?: CryptoProvider;
}): IdentityAttestation {
  if (opts.weight < 0 || opts.weight > 100) {
    throw new Error('weight must be in [0, 100]');
  }
  const p = opts.provider ?? getCryptoProvider();
  const nonce = p.encoding.encodeBase64(p.random.randomBytes(12));
  const payload = {
    id: `at-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    subjectDid: opts.subjectDid,
    issuerDid: opts.issuerDid,
    attestationType: opts.attestationType,
    weight: opts.weight,
    issuedAt: Date.now(),
    expiresAt: opts.expiresAt ?? null,
    evidence: opts.evidence ?? null,
    customLabel: opts.customLabel ?? null,
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

export function verifyAttestation(
  at: IdentityAttestation,
  provider?: CryptoProvider,
): AttestationVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = at;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(at.issuerPublicKey);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }
  const expectedDid = publicKeyToDid(pubKey, p);
  if (at.issuerDid !== expectedDid) {
    return { valid: false, reason: 'issuerDid does not match public key' };
  }
  if (at.weight < 0 || at.weight > 100) {
    return { valid: false, reason: 'weight out of range' };
  }
  return { valid: true };
}

// ─── Registry ───────────────────────────────────────────────────────────────

/**
 * Pluggable storage for attestations, with sybil-resistance scoring built-in.
 * Stateless over identity: query by subjectDid, filter by issuer.
 */
export class AttestationRegistry {
  private readonly bySubject = new Map<string, IdentityAttestation[]>();
  private readonly byId = new Map<string, IdentityAttestation>();
  private readonly revoked = new Set<string>();
  private readonly provider: CryptoProvider;

  constructor(provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
  }

  /** Add an attestation. Returns true if accepted, false if invalid or duplicate. */
  add(at: IdentityAttestation): boolean {
    const check = verifyAttestation(at, this.provider);
    if (!check.valid) return false;
    if (this.byId.has(at.id)) return false;
    this.byId.set(at.id, at);
    const list = this.bySubject.get(at.subjectDid) ?? [];
    list.push(at);
    this.bySubject.set(at.subjectDid, list);
    return true;
  }

  /** Mark an attestation as revoked. Revocation can come from the issuer. */
  revoke(attestationId: string): boolean {
    if (!this.byId.has(attestationId)) return false;
    this.revoked.add(attestationId);
    return true;
  }

  /** Check if an attestation is currently valid (not revoked, not expired). */
  isActive(attestationId: string, now: number = Date.now()): boolean {
    const at = this.byId.get(attestationId);
    if (!at) return false;
    if (this.revoked.has(attestationId)) return false;
    if (at.expiresAt !== null && at.expiresAt < now) return false;
    return true;
  }

  /** Get all attestations for a subject (active + expired + revoked). */
  getForSubject(subjectDid: string): readonly IdentityAttestation[] {
    return this.bySubject.get(subjectDid) ?? [];
  }

  /** Get only currently-active attestations for a subject. */
  getActiveForSubject(
    subjectDid: string,
    now: number = Date.now(),
  ): IdentityAttestation[] {
    const all = this.bySubject.get(subjectDid) ?? [];
    return all.filter((a) => this.isActive(a.id, now));
  }

  /** Compute a subject's tier qualitatively. */
  getTier(
    subjectDid: string,
    opts?: { trustedIssuers?: string[]; now?: number },
  ): IdentityTier {
    const now = opts?.now ?? Date.now();
    const active = this.getActiveForSubject(subjectDid, now);
    const filtered = opts?.trustedIssuers
      ? active.filter((a) => opts.trustedIssuers!.includes(a.issuerDid))
      : active;

    if (filtered.length === 0) return 'anonymous';
    const hasKyc = filtered.some((a) => a.attestationType === 'kyc-verified');
    const hasStake = filtered.some((a) => a.attestationType === 'stake-bonded');
    if (hasKyc && hasStake) return 'verified';
    if (hasStake) return 'staked';
    return 'attested';
  }

  /**
   * Compute a quantitative reputation score with freshness decay.
   * Returns score + tier + metadata.
   */
  getScore(
    subjectDid: string,
    config?: Partial<ScoreConfig>,
  ): ReputationScore {
    const now = config?.now ?? Date.now();
    const cfg: ScoreConfig = {
      ...DEFAULT_SCORE_CONFIG,
      ...config,
      now,
      typeMultipliers: {
        ...DEFAULT_SCORE_CONFIG.typeMultipliers,
        ...config?.typeMultipliers,
      },
    };
    const active = this.getActiveForSubject(subjectDid, now);
    const filtered = cfg.trustedIssuers
      ? active.filter((a) => cfg.trustedIssuers!.includes(a.issuerDid))
      : active;

    let rawScore = 0;
    const countByType: Record<string, number> = {};
    for (const at of filtered) {
      const ageMs = Math.max(0, now - at.issuedAt);
      const freshness = Math.pow(0.5, ageMs / cfg.halfLifeMs);
      const typeMul = cfg.typeMultipliers[at.attestationType] ?? 1;
      rawScore += at.weight * freshness * typeMul;
      countByType[at.attestationType] = (countByType[at.attestationType] ?? 0) + 1;
    }

    // Normalize: 100 × a kyc-verified attestation = 250 raw. Cap at 100.
    const score = Math.min(100, rawScore);

    return {
      subjectDid,
      score,
      tier: this.getTier(subjectDid, {
        trustedIssuers: cfg.trustedIssuers ?? undefined,
        now,
      }),
      attestationCount: filtered.length,
      countByType,
      computedAt: now,
    };
  }

  /** Export all attestations for persistence. */
  export(): IdentityAttestation[] {
    return Array.from(this.byId.values());
  }

  /** Import attestations (signatures re-verified). Returns count accepted. */
  import(attestations: IdentityAttestation[]): number {
    let accepted = 0;
    for (const at of attestations) if (this.add(at)) accepted++;
    return accepted;
  }

  /** Number of attestations stored (including revoked/expired). */
  get size(): number {
    return this.byId.size;
  }
}
