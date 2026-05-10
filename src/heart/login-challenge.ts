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
import { evaluateLadder, type TierLadder, type TierEvalInput } from './tier-ladder.js';

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

// ─── Login Ceremony Evidence ────────────────────────────────────────────────

/**
 * Device trust level as reported by the login factor verifier.
 * Parallel to `DeviceTrustLevel` in product-session.ts but scoped to login
 * context — no 'adapter' value since adapters don't go through login challenge.
 */
export type LoginDeviceTrust = 'hardware-attested' | 'platform' | 'software';

const DEVICE_TRUST_RANK: Record<LoginDeviceTrust, number> = {
  'hardware-attested': 2,
  'platform': 1,
  'software': 0,
};

/**
 * A factor that was actually proven during a login ceremony.
 * Built from the verifier's result + the registered factor's metadata.
 * Only factors that passed verification appear here — enrolled-but-unused
 * factors do NOT.
 */
export interface ProvenFactor {
  factorId: string;
  factorType: string;
  verifierTierClaim: number;
  hasUserVerification: boolean;
  hasHardwareAttestation: boolean;
  deviceId: string | null;
  deviceTrust: LoginDeviceTrust;
}

/**
 * Structured evidence of what was actually proven during the login ceremony.
 * Tier evaluation and device binding are derived from this evidence, not
 * from factor registry inventory.
 */
export interface LoginCeremonyEvidence {
  provenFactors: ProvenFactor[];
}

function deriveDeviceTrust(
  result: LoginFactorVerificationResult,
  factorType: string,
): LoginDeviceTrust {
  if (result.deviceTrust) return result.deviceTrust;
  if (result.hasHardwareAttestation) return 'hardware-attested';
  if (
    factorType === 'webauthn-platform' ||
    factorType === 'apple-app-attest' ||
    factorType === 'android-key-attest'
  ) return 'platform';
  return 'software';
}

function buildProvenFactor(
  assertion: LoginAssertion,
  result: LoginFactorVerificationResult,
  registeredMetadata: Record<string, string>,
): ProvenFactor {
  return {
    factorId: assertion.factorId,
    factorType: assertion.factorType,
    verifierTierClaim: result.tierAchieved ?? 0,
    hasUserVerification: result.hasUserVerification ?? false,
    hasHardwareAttestation: result.hasHardwareAttestation ?? false,
    deviceId: registeredMetadata.deviceId ?? null,
    deviceTrust: deriveDeviceTrust(result, assertion.factorType),
  };
}

function pickStrongestFactor(factors: ProvenFactor[]): ProvenFactor {
  return factors.reduce((best, f) =>
    f.verifierTierClaim > best.verifierTierClaim ||
    (f.verifierTierClaim === best.verifierTierClaim &&
      DEVICE_TRUST_RANK[f.deviceTrust] > DEVICE_TRUST_RANK[best.deviceTrust])
      ? f : best,
  );
}

function evidenceToTierInput(
  evidence: LoginCeremonyEvidence,
  subjectDid: string,
): TierEvalInput {
  const primary = pickStrongestFactor(evidence.provenFactors);
  return {
    factorType: primary.factorType,
    factorTier: primary.verifierTierClaim,
    subjectDid,
    hasUserVerification: evidence.provenFactors.some(f => f.hasUserVerification),
    hasHardwareAttestation: evidence.provenFactors.some(f => f.hasHardwareAttestation),
    registeredActive: evidence.provenFactors.map(f => ({
      factorType: f.factorType,
      factorId: f.factorId,
      metadata: f.deviceId ? { deviceId: f.deviceId } : {} as Record<string, string>,
    })),
  };
}

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
 *
 * The `evidence` field carries what was actually proven in the ceremony.
 * Tier and device binding on the resulting ProductSession are derived from
 * this evidence, not from factor registry inventory.
 */
export interface LoginVerification {
  protocol: 'soma-login/1';
  /** The challenge this verification answers. */
  challengeId: string;
  /** The authenticated Soma identity DID. */
  subjectDid: string;
  /** Primary factor type (strongest proven factor). */
  factorType: string;
  /** Primary factor ID (strongest proven factor). */
  factorId: string;
  /** Ceremony tier achieved, evaluated from evidence via tier ladder. */
  tierAchieved: CeremonyTier;
  /** Structured evidence of what was actually proven. */
  evidence: LoginCeremonyEvidence;
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
 * challenge. Includes both the validity verdict and structured evidence
 * about what the factor actually proved.
 *
 * The evidence fields are optional for backward compatibility — verifiers
 * that don't report them get safe defaults (false / null / 'software').
 */
export interface LoginFactorVerificationResult {
  valid: boolean;
  reason?: string;
  /** Numeric tier (0-3) the factor claims to support. */
  tierAchieved?: number;
  /** True if the assertion included a user-verification (biometric/PIN) flag. */
  hasUserVerification?: boolean;
  /** True if the factor has a verified hardware attestation (FIDO2 AAGUID, etc.). */
  hasHardwareAttestation?: boolean;
  /** Device identifier from the assertion, if available. */
  deviceId?: string | null;
  /** Device trust level. Derived from factor type if not reported. */
  deviceTrust?: LoginDeviceTrust;
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
  /**
   * Tier ladder for evaluating login ceremony evidence. The ladder's
   * `TierEvalInput.registeredActive` is populated from proven factors
   * only — enrolled-but-unused factors do not inflate the tier.
   *
   * If omitted, the tier defaults to the verifier's `tierAchieved` claim.
   */
  tierLadder?: TierLadder;
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
   * Verify a single login assertion against an outstanding challenge.
   *
   * On success, the challenge is consumed (single use) and a signed
   * `LoginVerification` is returned with ceremony evidence. On failure,
   * the challenge remains outstanding (the user can retry).
   */
  async verifyLogin(
    assertion: LoginAssertion,
  ): Promise<
    | { ok: true; verification: LoginVerification }
    | { ok: false; reason: string }
  > {
    return this.verifyMultiFactorLogin([assertion]);
  }

  /**
   * Verify one or more login assertions against the same outstanding
   * challenge. All assertions must reference the same challengeId. The
   * tier is evaluated from the combined ceremony evidence — only factors
   * that actually pass verification contribute to the tier.
   *
   * On success, the challenge is consumed and a signed `LoginVerification`
   * is returned. On failure, the challenge stays outstanding.
   */
  async verifyMultiFactorLogin(
    assertions: LoginAssertion[],
  ): Promise<
    | { ok: true; verification: LoginVerification }
    | { ok: false; reason: string }
  > {
    if (assertions.length === 0) {
      return { ok: false, reason: 'no assertions provided' };
    }

    const p = this.opts.provider ?? getCryptoProvider();
    const now = (this.opts.now ?? Date.now)();

    // ── All assertions must reference the same challenge ─────────────
    const challengeId = assertions[0].challengeId;
    if (assertions.some(a => a.challengeId !== challengeId)) {
      return { ok: false, reason: 'all assertions must reference the same challenge' };
    }

    // ── No duplicate factor IDs ──────────────────────────────────────
    const factorIds = new Set(assertions.map(a => a.factorId));
    if (factorIds.size !== assertions.length) {
      return { ok: false, reason: 'duplicate factor ID in assertions' };
    }

    // ── Replay prevention ────────────────────────────────────────────
    if (this.consumed.has(challengeId)) {
      return { ok: false, reason: 'challenge already consumed' };
    }

    // ── Challenge lookup ─────────────────────────────────────────────
    const challenge = this.outstanding.get(challengeId);
    if (!challenge) {
      return { ok: false, reason: 'unknown challenge id' };
    }

    // ── Challenge expiry ─────────────────────────────────────────────
    if (now > challenge.expiresAt) {
      this.outstanding.delete(challengeId);
      return { ok: false, reason: 'challenge expired' };
    }

    // ── Verify each assertion and build proven factors ────────────────
    const provenFactors: ProvenFactor[] = [];

    for (const assertion of assertions) {
      // ── Assertion timing ─────────────────────────────────────────
      if (assertion.assertedAt < challenge.issuedAt) {
        return { ok: false, reason: 'assertion predates challenge' };
      }
      if (assertion.assertedAt > now + 60_000) {
        return { ok: false, reason: 'assertion timestamp is in the future' };
      }

      // ── Factor registration ──────────────────────────────────────
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

      // ── Pluggable factor verification ────────────────────────────
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

      provenFactors.push(
        buildProvenFactor(assertion, result, registered.metadata),
      );
    }

    // ── Build ceremony evidence ──────────────────────────────────────
    const evidence: LoginCeremonyEvidence = { provenFactors };
    const primary = pickStrongestFactor(provenFactors);

    // ── Tier evaluation from evidence ────────────────────────────────
    let tierNum: number;
    if (this.opts.tierLadder) {
      const tierInput = evidenceToTierInput(evidence, challenge.subjectDid);
      tierNum = evaluateLadder(this.opts.tierLadder, tierInput);
    } else {
      tierNum = primary.verifierTierClaim;
    }

    const tierAchieved = TIER_FROM_NUMBER[tierNum];
    if (!tierAchieved) {
      return {
        ok: false,
        reason: `invalid tier ${tierNum} from evaluation`,
      };
    }

    if (TIER_RANK[tierAchieved] < TIER_RANK[challenge.requestedTier]) {
      return {
        ok: false,
        reason: `tier achieved ${tierAchieved} < required ${challenge.requestedTier}`,
      };
    }

    // ── Mint signed verification ─────────────────────────────────────
    const latestAssertion = assertions.reduce((latest, a) =>
      a.assertedAt > latest.assertedAt ? a : latest,
    );

    const verificationPayload = {
      protocol: 'soma-login/1' as const,
      challengeId: challenge.id,
      subjectDid: challenge.subjectDid,
      factorType: primary.factorType,
      factorId: primary.factorId,
      tierAchieved,
      evidence,
      assertedAt: latestAssertion.assertedAt,
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

    // ── Consume challenge + mark all proven factors used ─────────────
    this.outstanding.delete(challenge.id);
    this.consumed.add(challenge.id);
    for (const pf of provenFactors) {
      this.opts.factorRegistry.markUsed(
        challenge.subjectDid,
        pf.factorId,
        now,
      );
    }

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
