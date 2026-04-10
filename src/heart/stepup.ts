/**
 * Step-Up Authentication — live human approval for high-risk actions.
 *
 * A step-up is the live half of capability delegation. A delegation with a
 * `requires-stepup` caveat (see soma-capabilities/1.1) cannot be used just
 * by presenting the token — the holder must ALSO present a fresh, signed
 * attestation proving that a registered factor (see `factor-registry.ts`)
 * approved this specific action, and that the factor achieved at least the
 * required tier on the deployment's ladder (see `tier-ladder.ts`).
 *
 * Why a separate primitive: delegation grants persistent authority, but
 * some actions (sudo, deploy, rm -rf) need a human look-at-this-moment
 * check that can't be pre-baked into a long-lived token. Step-up fills
 * that gap without destroying delegation's "no round-trip per call" win
 * for the 90% of actions that don't need it.
 *
 * Flow (high level):
 *   1. A verifier (SSH guard, API middleware, etc.) evaluating a delegation
 *      encounters a `requires-stepup` caveat. It computes an action digest
 *      (host, command, args) and asks the heart for a challenge.
 *   2. `createChallenge` returns a signed `StepUpChallenge`. The heart
 *      remembers the challenge in its outstanding set.
 *   3. The challenge travels via a `StepUpOracle` to the human's device.
 *      The oracle is orthogonal to this module — email, web push, native
 *      app, CLI, whatever.
 *   4. The human approves on their device. The registered factor produces
 *      an assertion over the challenge's action digest.
 *   5. The verifier (or any intermediary) calls `submitAttestation` with
 *      the factor-signed assertion. The heart checks: factor is registered
 *      and active, assertion verifies under the factor's verifier, tier is
 *      at least the requested minimum, challenge is not expired, not
 *      replayed, and the action digest matches.
 *   6. On success the heart returns a signed `StepUpAttestation` that the
 *      verifier can present alongside the delegation at use time. The
 *      outstanding challenge is consumed (single use).
 *
 * Everything is fail-closed: missing fields, expired challenges, replayed
 * challenges, unknown factor types, mismatched action digests — all reject.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { FactorRegistry } from './factor-registry.js';

// ─── Core Types ─────────────────────────────────────────────────────────────

/**
 * A signed challenge the heart emits to request human approval for an
 * action. The holder (or verifier) carries this to the human's factor
 * device, gets a factor assertion over `actionDigest`, then submits.
 */
export interface StepUpChallenge {
  /** Opaque challenge ID — used to prevent replay. */
  id: string;
  /** Protocol version identifier. */
  protocol: 'soma-stepup/1';
  /** DID the approval is requested from. */
  subjectDid: string;
  /**
   * Hash of the action being authorized. Base64 of SHA-256 over the
   * verifier-chosen canonical representation of the action (e.g. the
   * SSH host + command argv, a canonical HTTP request, a DB query plan).
   * The factor signs this digest — not the raw action — so the factor
   * doesn't need to understand the action format.
   */
  actionDigest: string;
  /**
   * Minimum tier the resulting attestation must achieve on the
   * deployment's tier ladder to satisfy the caveat that triggered this
   * challenge.
   */
  minTier: number;
  /** Unix ms of issuance. */
  issuedAt: number;
  /** Unix ms after which the challenge is no longer valid. */
  expiresAt: number;
  /** Random nonce, base64 16 bytes. */
  nonce: string;
  /**
   * DID of the heart that issued this challenge. The heart's public key
   * must be trusted out-of-band by verifiers.
   */
  heartDid: string;
  /** Base64 Ed25519 public key of the heart (for verification). */
  heartPublicKey: string;
  /** Base64 Ed25519 signature by the heart over the canonical JSON. */
  signature: string;
}

/**
 * The factor-side input to step-up: the assertion produced by whatever
 * device the human used. The heart passes `rawAssertion` to a pluggable
 * verifier for the factor type.
 */
export interface FactorAssertion {
  /** Which challenge this is answering. */
  challengeId: string;
  /** The factor ID that produced this assertion (matches FactorRegistry). */
  factorId: string;
  /** The factor type (matches FactorRegistry entry). */
  factorType: string;
  /** Base64 raw assertion bytes — format depends on factorType. */
  rawAssertion: string;
  /** Unix ms when the factor signed. */
  assertedAt: number;
  /** Optional metadata the factor wants to include. */
  metadata?: Record<string, string>;
}

/**
 * A fully verified step-up record the heart returns after a successful
 * `submitAttestation`. Verifiers present this alongside a delegation at
 * use time to satisfy `requires-stepup` caveats.
 */
export interface StepUpAttestation {
  protocol: 'soma-stepup/1';
  /** The challenge this attestation answers. */
  challengeId: string;
  /** Copy of the challenge's action digest — redundant for verifier convenience. */
  actionDigest: string;
  /** DID that approved. */
  subjectDid: string;
  /** Factor that was used. */
  factorType: string;
  /** Factor ID (base64 credential ID or equivalent). */
  factorId: string;
  /** Tier achieved on the deployment's ladder. */
  tierAchieved: number;
  /** Unix ms the factor produced its assertion. */
  assertedAt: number;
  /** Unix ms the heart counter-signed and accepted the attestation. */
  acceptedAt: number;
  /** Heart DID. */
  heartDid: string;
  /** Heart Ed25519 public key, base64. */
  heartPublicKey: string;
  /** Heart Ed25519 signature over canonical JSON. */
  signature: string;
}

// ─── Pluggable Factor Verification ──────────────────────────────────────────

/**
 * Result of verifying a factor-produced assertion.
 *
 * `tierAchieved` is the factor's claim about its own strength (e.g. a
 * WebAuthn verifier reports the tier its platform attestation supports).
 * The final tier may be lowered by the tier-ladder evaluator if the
 * deployment's policy is stricter.
 */
export interface FactorVerificationResult {
  valid: boolean;
  reason?: string;
  tierAchieved?: number;
}

/**
 * A verifier plugin for one factor type. Implementations live outside the
 * heart module (e.g. @soma/stepup-webauthn, @soma/stepup-totp) so this
 * module has no dependencies on WebAuthn libraries or TOTP implementations.
 *
 * The verifier receives the registered factor (public material) and the
 * assertion, plus the challenge it's answering, and decides if the
 * assertion is valid.
 */
export type FactorAssertionVerifier = (input: {
  challenge: StepUpChallenge;
  assertion: FactorAssertion;
  registered: {
    publicMaterial: string;
    attestation: string | null;
    metadata: Record<string, string>;
  };
}) => FactorVerificationResult | Promise<FactorVerificationResult>;

/** Registry mapping factor type → verifier plugin. */
export class FactorVerifierRegistry {
  private readonly verifiers: Map<string, FactorAssertionVerifier> = new Map();

  register(factorType: string, verifier: FactorAssertionVerifier): void {
    this.verifiers.set(factorType, verifier);
  }

  get(factorType: string): FactorAssertionVerifier | null {
    return this.verifiers.get(factorType) ?? null;
  }

  /** Factor types this registry can handle. */
  supported(): string[] {
    return [...this.verifiers.keys()];
  }
}

// ─── Heart-side Step-Up Service ─────────────────────────────────────────────

/**
 * Stateful step-up service running inside a heart. Tracks outstanding
 * challenges, prevents replay, signs attestations on successful
 * submission.
 */
export class StepUpService {
  private readonly outstanding: Map<string, StepUpChallenge> = new Map();
  private readonly consumed: Set<string> = new Set();

  constructor(
    private readonly opts: {
      heartDid: string;
      heartPublicKey: string;
      heartSigningKey: Uint8Array;
      factorRegistry: FactorRegistry;
      verifiers: FactorVerifierRegistry;
      /** Tier ladder evaluator. Receives the verifier's tier, returns the
       *  policy-adjusted tier the deployment grants. */
      evaluateTier?: (input: {
        factorType: string;
        factorTier: number;
        subjectDid: string;
      }) => number;
      /** Defaults to Date.now(). Tests inject a fake clock. */
      now?: () => number;
      /** Default challenge TTL in ms. Overridable per call. */
      defaultTtlMs?: number;
      /** Crypto provider — defaults to getCryptoProvider(). */
      provider?: CryptoProvider;
    },
  ) {}

  /**
   * Create a signed step-up challenge. Caller is responsible for shipping
   * the challenge to the human via a StepUpOracle.
   */
  createChallenge(input: {
    subjectDid: string;
    actionDigest: string;
    minTier: number;
    ttlMs?: number;
  }): StepUpChallenge {
    const p = this.opts.provider ?? getCryptoProvider();
    const now = (this.opts.now ?? Date.now)();
    const ttl = input.ttlMs ?? this.opts.defaultTtlMs ?? 60_000;

    const id = `su-${p.encoding.encodeBase64(p.random.randomBytes(12))}`;
    const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

    const payload = {
      id,
      protocol: 'soma-stepup/1' as const,
      subjectDid: input.subjectDid,
      actionDigest: input.actionDigest,
      minTier: input.minTier,
      issuedAt: now,
      expiresAt: now + ttl,
      nonce,
      heartDid: this.opts.heartDid,
      heartPublicKey: this.opts.heartPublicKey,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = p.signing.sign(signingInput, this.opts.heartSigningKey);

    const challenge: StepUpChallenge = {
      ...payload,
      signature: p.encoding.encodeBase64(signature),
    };

    this.outstanding.set(id, challenge);
    return challenge;
  }

  /**
   * Accept a factor-produced assertion against an outstanding challenge,
   * verify it, and return a signed step-up attestation on success.
   *
   * The outstanding challenge is consumed on success and recorded in the
   * replay-prevention set.
   */
  async submitAttestation(
    assertion: FactorAssertion,
  ): Promise<
    | { ok: true; attestation: StepUpAttestation }
    | { ok: false; reason: string }
  > {
    const p = this.opts.provider ?? getCryptoProvider();
    const now = (this.opts.now ?? Date.now)();

    if (this.consumed.has(assertion.challengeId)) {
      return { ok: false, reason: 'challenge already consumed' };
    }

    const challenge = this.outstanding.get(assertion.challengeId);
    if (!challenge) {
      return { ok: false, reason: 'unknown challenge id' };
    }

    if (now > challenge.expiresAt) {
      this.outstanding.delete(assertion.challengeId);
      return { ok: false, reason: 'challenge expired' };
    }

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

    const rawTier = result.tierAchieved ?? 0;
    const tierAchieved = this.opts.evaluateTier
      ? this.opts.evaluateTier({
          factorType: assertion.factorType,
          factorTier: rawTier,
          subjectDid: challenge.subjectDid,
        })
      : rawTier;

    if (tierAchieved < challenge.minTier) {
      return {
        ok: false,
        reason: `tier achieved ${tierAchieved} < required ${challenge.minTier}`,
      };
    }

    // Passed — mint the signed attestation.
    const payload = {
      protocol: 'soma-stepup/1' as const,
      challengeId: challenge.id,
      actionDigest: challenge.actionDigest,
      subjectDid: challenge.subjectDid,
      factorType: assertion.factorType,
      factorId: assertion.factorId,
      tierAchieved,
      assertedAt: assertion.assertedAt,
      acceptedAt: now,
      heartDid: this.opts.heartDid,
      heartPublicKey: this.opts.heartPublicKey,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = p.signing.sign(signingInput, this.opts.heartSigningKey);

    const attestation: StepUpAttestation = {
      ...payload,
      signature: p.encoding.encodeBase64(signature),
    };

    this.outstanding.delete(challenge.id);
    this.consumed.add(challenge.id);
    this.opts.factorRegistry.markUsed(
      challenge.subjectDid,
      assertion.factorId,
      now,
    );

    return { ok: true, attestation };
  }

  /** Drop challenges that have passed their expiry. Call from a timer. */
  pruneExpired(now: number = (this.opts.now ?? Date.now)()): number {
    let dropped = 0;
    for (const [id, ch] of this.outstanding) {
      if (now > ch.expiresAt) {
        this.outstanding.delete(id);
        dropped += 1;
      }
    }
    return dropped;
  }

  /** Count of challenges still awaiting an attestation. */
  outstandingCount(): number {
    return this.outstanding.size;
  }
}

// ─── Standalone Verification (for downstream verifiers) ─────────────────────

export type StepUpVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a StepUpChallenge's signature against the heart's public key.
 * Doesn't check expiry or consumption — callers do that against their
 * own clock / replay cache.
 */
export function verifyChallengeSignature(
  challenge: StepUpChallenge,
  provider?: CryptoProvider,
): StepUpVerification {
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
 * Verify a StepUpAttestation's heart signature and basic shape. Used by
 * downstream verifiers (SSH guard, API middleware) before trusting the
 * attestation to satisfy a caveat.
 */
export function verifyStepUpAttestation(
  att: StepUpAttestation,
  opts: {
    /** Expected action digest — must match what the verifier is checking. */
    expectedActionDigest: string;
    /** Expected subject — must match the invoker. */
    expectedSubjectDid: string;
    /** Minimum tier the verifier requires. */
    minTier: number;
    /** Maximum freshness in ms — how old the attestation can be. */
    maxAgeMs?: number;
    /** Trusted heart public keys (base64). Empty = accept any. */
    trustedHeartPublicKeys?: string[];
    /** Current time, defaults to Date.now(). */
    now?: number;
    provider?: CryptoProvider;
  },
): StepUpVerification {
  const p = opts.provider ?? getCryptoProvider();
  const now = opts.now ?? Date.now();

  if (att.protocol !== 'soma-stepup/1') {
    return { valid: false, reason: `unsupported protocol ${att.protocol}` };
  }
  if (att.actionDigest !== opts.expectedActionDigest) {
    return { valid: false, reason: 'action digest mismatch' };
  }
  if (att.subjectDid !== opts.expectedSubjectDid) {
    return { valid: false, reason: 'subject mismatch' };
  }
  if (att.tierAchieved < opts.minTier) {
    return {
      valid: false,
      reason: `tier ${att.tierAchieved} below required ${opts.minTier}`,
    };
  }
  if (
    opts.trustedHeartPublicKeys !== undefined &&
    opts.trustedHeartPublicKeys.length > 0 &&
    !opts.trustedHeartPublicKeys.includes(att.heartPublicKey)
  ) {
    return { valid: false, reason: 'heart public key not trusted' };
  }
  if (opts.maxAgeMs !== undefined && now - att.acceptedAt > opts.maxAgeMs) {
    return { valid: false, reason: 'attestation too old' };
  }

  const { signature, ...payload } = att;
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const sigBytes = p.encoding.decodeBase64(signature);
  const pubKey = p.encoding.decodeBase64(att.heartPublicKey);
  if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
    return { valid: false, reason: 'invalid attestation signature' };
  }

  return { valid: true };
}

// ─── Action Digest Helper ───────────────────────────────────────────────────

/**
 * Compute the canonical action digest for an action payload. Any JSON-able
 * object is fine; the hash is over its canonical JSON representation so
 * key order doesn't matter.
 *
 * Verifiers on both sides (challenge creator and challenge consumer) MUST
 * agree on the action shape. A common shape:
 *   { kind: "ssh-exec", host: "...", argv: [...], cwd: "..." }
 */
export function computeActionDigest(
  action: unknown,
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  return p.hashing.hash(canonicalJson(action));
}
