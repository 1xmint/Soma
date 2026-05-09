/**
 * Login Challenge — Soma-native initial authentication protocol.
 *
 * Mode A (soma-direct) login path for returning users. A user with at
 * least one registered authenticator proves control of their Soma
 * identity through a challenge-response ceremony.
 *
 * The contract is library-agnostic: Soma defines the canonical challenge
 * shape and verification protocol. Factor verification is pluggable —
 * Soma does not know or care whether the factor is WebAuthn, TOTP, or a
 * hardware key. The `LoginFactorVerifier` plugin does that.
 *
 * Flow:
 *   1. Product server calls `createChallenge(subjectDid)`.
 *   2. Server delivers the challenge to the user (orthogonal to Soma).
 *   3. User's authenticator produces a `LoginAssertion`.
 *   4. Server calls `verifyLogin(assertion)`.
 *   5. On success, server gets a signed `LoginVerification` usable for
 *      ProductSession issuance via `HeartRuntime.issueProductSessionFromLogin`.
 *
 * Parallel to StepUpService but distinct in purpose:
 *   - StepUpService: elevate an existing session's authority tier.
 *   - LoginChallengeService: establish initial authentication.
 *
 * Cross-ref:
 *   - stepup.ts (parallel pattern, same verifier shape)
 *   - factor-registry.ts (factor lookup)
 *   - human-delegation.ts (CeremonyTier)
 *   - product-session.ts (ProductSession issuance from verification)
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { FactorRegistry } from './factor-registry.js';
import type { CeremonyTier } from './human-delegation.js';

// ─── Tier helpers ────────────────────────────────────────────────────────────

const TIER_RANK: Record<CeremonyTier, number> = {
  L0: 0,
  L1: 1,
  L2: 2,
  L3: 3,
};
const TIER_FROM_NUMBER: Record<number, CeremonyTier | undefined> = {
  0: 'L0',
  1: 'L1',
  2: 'L2',
  3: 'L3',
};

/**
 * Factor types that are recovery evidence (Layer 3), not authenticators
 * (Layer 2). Excluded from login challenge creation — a user who only
 * has recovery factors cannot log in; they must recover first.
 */
const RECOVERY_ONLY_TYPES = new Set<string>(['recovery-seed']);

// ─── Login Challenge ─────────────────────────────────────────────────────────

/**
 * A signed challenge the server emits to request initial authentication.
 * Delivered to the user's factor device; the factor produces a
 * `LoginAssertion` in response.
 */
export interface LoginChallenge {
  /** Opaque challenge ID — used to prevent replay. */
  id: string;
  /** Protocol version identifier. */
  protocol: 'soma-login/1';
  /** DID the login is for (the returning user's Soma identity). */
  subjectDid: string;
  /** Minimum tier the login must achieve. */
  requestedTier: CeremonyTier;
  /** Unix ms of issuance. */
  issuedAt: number;
  /** Unix ms after which the challenge is no longer valid. */
  expiresAt: number;
  /** Random nonce, base64 16 bytes. */
  nonce: string;
  /** DID of the heart that issued this challenge. */
  heartDid: string;
  /** Base64 Ed25519 public key of the heart. */
  heartPublicKey: string;
  /** Base64 Ed25519 signature over the canonical JSON payload. */
  signature: string;
}

// ─── Login Assertion ─────────────────────────────────────────────────────────

/**
 * The factor-side response to a login challenge. Library-agnostic —
 * `rawAssertion` is opaque base64 whose format depends on `factorType`.
 * The `LoginFactorVerifier` plugin interprets it.
 */
export interface LoginAssertion {
  /** Which challenge this assertion answers. */
  challengeId: string;
  /** Factor ID from the FactorRegistry. */
  factorId: string;
  /** Factor type (e.g. 'webauthn-platform', 'totp'). */
  factorType: string;
  /** Base64 raw assertion bytes — format depends on factorType. */
  rawAssertion: string;
  /** Unix ms when the factor produced this assertion. */
  assertedAt: number;
  /** Optional metadata the factor wants to include. */
  metadata?: Record<string, string>;
}

// ─── Login Verification ──────────────────────────────────────────────────────

/**
 * A signed record the server returns after successful login verification.
 * Used to issue a ProductSession via `HeartRuntime.issueProductSessionFromLogin`.
 */
export interface LoginVerification {
  protocol: 'soma-login/1';
  /** The challenge this verification answers. */
  challengeId: string;
  /** The authenticated Soma identity DID. */
  subjectDid: string;
  /** Factor type that was used. */
  factorType: string;
  /** Factor ID that was used. */
  factorId: string;
  /** Ceremony tier achieved by the factor. */
  tierAchieved: CeremonyTier;
  /** Unix ms when the factor produced its assertion. */
  assertedAt: number;
  /** Unix ms when the server verified and accepted the assertion. */
  verifiedAt: number;
  /** Heart DID that verified the login. */
  heartDid: string;
  /** Heart Ed25519 public key, base64. */
  heartPublicKey: string;
  /** Heart Ed25519 signature over the canonical JSON payload. */
  signature: string;
}

// ─── Pluggable Factor Verification ──────────────────────────────────────────

/**
 * Result of verifying a factor-produced assertion against a login
 * challenge. `tierAchieved` is the factor's claim about its strength.
 */
export interface LoginFactorVerificationResult {
  valid: boolean;
  reason?: string;
  /** Numeric tier (0-3) the factor claims to support. */
  tierAchieved?: number;
}

/**
 * A verifier plugin for one factor type in the login context.
 * Implementations live outside Soma core (e.g. a WebAuthn verifier
 * package) so this module has no browser-library dependencies.
 *
 * The verifier receives the login challenge, the factor's assertion,
 * and the registered factor's public material, and decides if the
 * assertion is valid.
 */
export type LoginFactorVerifier = (input: {
  challenge: LoginChallenge;
  assertion: LoginAssertion;
  registered: {
    publicMaterial: string;
    attestation: string | null;
    metadata: Record<string, string>;
  };
}) => LoginFactorVerificationResult | Promise<LoginFactorVerificationResult>;

/** Registry mapping factor type → login verifier plugin. */
export class LoginFactorVerifierRegistry {
  private readonly verifiers = new Map<string, LoginFactorVerifier>();

  register(factorType: string, verifier: LoginFactorVerifier): void {
    this.verifiers.set(factorType, verifier);
  }

  get(factorType: string): LoginFactorVerifier | null {
    return this.verifiers.get(factorType) ?? null;
  }

  supported(): string[] {
    return [...this.verifiers.keys()];
  }
}

// ─── Service Config ─────────────────────────────────────────────────────────

export interface LoginChallengeServiceConfig {
  heartDid: string;
  heartPublicKey: string;
  heartSigningKey: Uint8Array;
  factorRegistry: FactorRegistry;
  verifiers: LoginFactorVerifierRegistry;
  /** Tier ladder evaluator — receives the verifier's tier, returns the
   *  policy-adjusted tier. */
  evaluateTier?: (input: {
    factorType: string;
    factorTier: number;
    subjectDid: string;
  }) => number;
  /** Clock override for tests. */
  now?: () => number;
  /** Default challenge TTL in ms. Defaults to 120 000 (2 minutes). */
  defaultTtlMs?: number;
  provider?: CryptoProvider;
}

// ─── Login Challenge Service ────────────────────────────────────────────────

/**
 * Stateful login challenge service. Tracks outstanding challenges,
 * prevents replay, and signs verifications on successful login.
 *
 * Constructed by the product server alongside the HeartRuntime.
 * The service needs the heart's signing key for challenge and
 * verification signing.
 */
export class LoginChallengeService {
  private readonly outstanding = new Map<string, LoginChallenge>();
  private readonly consumed = new Set<string>();

  constructor(private readonly opts: LoginChallengeServiceConfig) {}

  /**
   * Create a signed login challenge for a subject DID.
   *
   * Throws if the subject has no active non-recovery authenticators —
   * a user with only recovery factors cannot log in; they must recover
   * first.
   */
  createChallenge(input: {
    subjectDid: string;
    requestedTier?: CeremonyTier;
    ttlMs?: number;
  }): LoginChallenge {
    const p = this.opts.provider ?? getCryptoProvider();
    const now = (this.opts.now ?? Date.now)();
    const ttl = input.ttlMs ?? this.opts.defaultTtlMs ?? 120_000;

    const activeFactors = this.opts.factorRegistry.listActive(input.subjectDid);
    const loginFactors = activeFactors.filter(
      (f) => !RECOVERY_ONLY_TYPES.has(f.factorType),
    );
    if (loginFactors.length === 0) {
      throw new Error(
        `no active login factors for ${input.subjectDid} — cannot create login challenge`,
      );
    }

    const id = `login-${p.encoding.encodeBase64(p.random.randomBytes(12))}`;
    const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

    const payload = {
      id,
      protocol: 'soma-login/1' as const,
      subjectDid: input.subjectDid,
      requestedTier: (input.requestedTier ?? 'L1') as CeremonyTier,
      issuedAt: now,
      expiresAt: now + ttl,
      nonce,
      heartDid: this.opts.heartDid,
      heartPublicKey: this.opts.heartPublicKey,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const sig = p.signing.sign(signingInput, this.opts.heartSigningKey);

    const challenge: LoginChallenge = {
      ...payload,
      signature: p.encoding.encodeBase64(sig),
    };

    this.outstanding.set(id, challenge);
    return challenge;
  }

  /**
   * Verify a login assertion against an outstanding challenge.
   *
   * On success, the challenge is consumed (single use) and a signed
   * `LoginVerification` is returned. On failure, the challenge remains
   * outstanding (the user can retry with a different factor or fix
   * the assertion).
   */
  async verifyLogin(
    assertion: LoginAssertion,
  ): Promise<
    | { ok: true; verification: LoginVerification }
    | { ok: false; reason: string }
  > {
    const p = this.opts.provider ?? getCryptoProvider();
    const now = (this.opts.now ?? Date.now)();

    // ── Replay prevention ────────────────────────────────────────────
    if (this.consumed.has(assertion.challengeId)) {
      return { ok: false, reason: 'challenge already consumed' };
    }

    // ── Challenge lookup ─────────────────────────────────────────────
    const challenge = this.outstanding.get(assertion.challengeId);
    if (!challenge) {
      return { ok: false, reason: 'unknown challenge id' };
    }

    // ── Challenge expiry ─────────────────────────────────────────────
    if (now > challenge.expiresAt) {
      this.outstanding.delete(assertion.challengeId);
      return { ok: false, reason: 'challenge expired' };
    }

    // ── Assertion timing ─────────────────────────────────────────────
    if (assertion.assertedAt < challenge.issuedAt) {
      return { ok: false, reason: 'assertion predates challenge' };
    }
    if (assertion.assertedAt > now + 60_000) {
      // Allow 60s clock skew, reject obviously-future assertions
      return { ok: false, reason: 'assertion timestamp is in the future' };
    }

    // ── Factor registration ──────────────────────────────────────────
    const registered = this.opts.factorRegistry.get(
      challenge.subjectDid,
      assertion.factorId,
    );
    if (!registered) {
      return { ok: false, reason: 'factor not registered for subject' };
    }
    if (registered.revokedAt !== null) {
      return { ok: false, reason: 'factor is revoked' };
    }
    if (registered.factorType !== assertion.factorType) {
      return { ok: false, reason: 'factor type mismatch with registered entry' };
    }

    // ── Pluggable factor verification ────────────────────────────────
    const verifier = this.opts.verifiers.get(assertion.factorType);
    if (!verifier) {
      return {
        ok: false,
        reason: `no verifier registered for factor type ${assertion.factorType}`,
      };
    }

    const result = await verifier({
      challenge,
      assertion,
      registered: {
        publicMaterial: registered.publicMaterial,
        attestation: registered.attestation,
        metadata: registered.metadata,
      },
    });

    if (!result.valid) {
      return { ok: false, reason: result.reason ?? 'factor assertion invalid' };
    }

    // ── Tier evaluation ──────────────────────────────────────────────
    const rawTier = result.tierAchieved ?? 0;
    const policyTier = this.opts.evaluateTier
      ? this.opts.evaluateTier({
          factorType: assertion.factorType,
          factorTier: rawTier,
          subjectDid: challenge.subjectDid,
        })
      : rawTier;
    // Policy can lower but never raise above what the factor proved
    const tierNum = Math.min(policyTier, rawTier);

    const tierAchieved = TIER_FROM_NUMBER[tierNum];
    if (!tierAchieved) {
      return {
        ok: false,
        reason: `invalid tier ${tierNum} from factor verifier`,
      };
    }

    if (TIER_RANK[tierAchieved] < TIER_RANK[challenge.requestedTier]) {
      return {
        ok: false,
        reason: `tier achieved ${tierAchieved} < required ${challenge.requestedTier}`,
      };
    }

    // ── Mint signed verification ─────────────────────────────────────
    const verificationPayload = {
      protocol: 'soma-login/1' as const,
      challengeId: challenge.id,
      subjectDid: challenge.subjectDid,
      factorType: assertion.factorType,
      factorId: assertion.factorId,
      tierAchieved,
      assertedAt: assertion.assertedAt,
      verifiedAt: now,
      heartDid: this.opts.heartDid,
      heartPublicKey: this.opts.heartPublicKey,
    };

    const signingInput = new TextEncoder().encode(
      canonicalJson(verificationPayload),
    );
    const sig = p.signing.sign(signingInput, this.opts.heartSigningKey);

    const verification: LoginVerification = {
      ...verificationPayload,
      signature: p.encoding.encodeBase64(sig),
    };

    // ── Consume challenge + mark factor used ─────────────────────────
    this.outstanding.delete(challenge.id);
    this.consumed.add(challenge.id);
    this.opts.factorRegistry.markUsed(
      challenge.subjectDid,
      assertion.factorId,
      now,
    );

    return { ok: true, verification };
  }

  /** Drop challenges past their expiry. Call from a periodic sweep. */
  pruneExpired(now?: number): number {
    const ts = now ?? (this.opts.now ?? Date.now)();
    let dropped = 0;
    for (const [id, ch] of this.outstanding) {
      if (ts > ch.expiresAt) {
        this.outstanding.delete(id);
        dropped += 1;
      }
    }
    return dropped;
  }

  /** Count of challenges still awaiting an assertion. */
  outstandingCount(): number {
    return this.outstanding.size;
  }
}

// ─── Standalone Verification (for downstream verifiers) ─────────────────────

export type LoginChallengeVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a LoginChallenge's signature. Doesn't check expiry or
 * consumption — callers do that against their own clock / replay cache.
 */
export function verifyLoginChallengeSignature(
  challenge: LoginChallenge,
  provider?: CryptoProvider,
): LoginChallengeVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = challenge;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(challenge.heartPublicKey);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid challenge signature' };
  }
  return { valid: true };
}

/**
 * Verify a LoginVerification's heart signature and basic shape.
 * Used by downstream consumers (product servers, middleware) before
 * trusting the verification to issue a ProductSession.
 */
export function verifyLoginVerificationSignature(
  verification: LoginVerification,
  opts?: {
    expectedSubjectDid?: string;
    trustedHeartPublicKeys?: string[];
    maxAgeMs?: number;
    now?: number;
    provider?: CryptoProvider;
  },
): LoginChallengeVerification {
  const p = opts?.provider ?? getCryptoProvider();
  const now = opts?.now ?? Date.now();

  if (verification.protocol !== 'soma-login/1') {
    return {
      valid: false,
      reason: `unsupported protocol ${verification.protocol}`,
    };
  }
  if (
    opts?.expectedSubjectDid &&
    verification.subjectDid !== opts.expectedSubjectDid
  ) {
    return { valid: false, reason: 'subject mismatch' };
  }
  if (
    opts?.trustedHeartPublicKeys !== undefined &&
    opts.trustedHeartPublicKeys.length > 0 &&
    !opts.trustedHeartPublicKeys.includes(verification.heartPublicKey)
  ) {
    return { valid: false, reason: 'heart public key not trusted' };
  }
  if (
    opts?.maxAgeMs !== undefined &&
    now - verification.verifiedAt > opts.maxAgeMs
  ) {
    return { valid: false, reason: 'verification too old' };
  }

  const { signature, ...payload } = verification;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(verification.heartPublicKey);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid verification signature' };
  }

  return { valid: true };
}
