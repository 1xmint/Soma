/**
 * Factor Registry — auth factors bound to a DID for step-up authentication.
 *
 * A subject (typically a human) registers one or more auth factors against
 * their DID. Each registered factor can later produce an assertion that
 * satisfies a `requires-stepup` caveat at delegation use time.
 *
 * Factor types are open-ended strings. The default well-known set covers
 * WebAuthn (platform passkeys like Touch ID / Face ID / Windows Hello,
 * plus roaming authenticators like Yubikey), TOTP (Google Authenticator),
 * email magic link, and native mobile app attestations. Third parties can
 * extend with any string identifier they want — verifiers that don't
 * understand a factor type treat it as unsatisfying, so unknown types
 * fail closed by default.
 *
 * The registry itself is intentionally thin: storage, lookup, revocation.
 * It does NOT verify factor assertions — that's the step-up layer's job.
 * This split keeps the registry usable as a pure data store that can
 * persist via `persistence.ts` without dragging in verifier code.
 *
 * Binding: a factor is bound to exactly one subject DID. The same physical
 * device can be registered under multiple DIDs (different credential IDs),
 * but a given (factorId, subjectDid) pair is unique in the registry.
 */

// ─── Factor Types ───────────────────────────────────────────────────────────

/**
 * Well-known factor type identifiers.
 *
 * The string union is open: any identifier is legal on the wire. These
 * constants exist so call sites can avoid typos when referencing common
 * types. Verifiers that don't recognize a type MUST fail closed.
 */
export const WELL_KNOWN_FACTOR_TYPES = {
  /** WebAuthn platform authenticator: Touch ID, Face ID, Windows Hello, Android biometric. */
  WEBAUTHN_PLATFORM: 'webauthn-platform',
  /** WebAuthn roaming authenticator: Yubikey, Titan, SoloKey, any FIDO2 hardware key. */
  WEBAUTHN_ROAMING: 'webauthn-roaming',
  /** RFC 6238 TOTP: Google Authenticator, Authy, 1Password, etc. */
  TOTP: 'totp',
  /** Email magic link — low-assurance fallback, typically tier 0 only. */
  EMAIL_MAGIC_LINK: 'email-magic-link',
  /** SMS OTP — weak by modern standards, explicitly tier 0. */
  SMS_OTP: 'sms-otp',
  /** Apple App Attest — native iOS app with platform attestation. */
  APPLE_APP_ATTEST: 'apple-app-attest',
  /** Android Key Attestation — native Android app with hardware attestation. */
  ANDROID_KEY_ATTEST: 'android-key-attest',
} as const;

export type FactorType = string;

// ─── Registered Factor ──────────────────────────────────────────────────────

/**
 * A factor registered to a subject DID. Contains whatever material the
 * step-up verifier needs to later check an assertion from this factor.
 */
export interface RegisteredFactor {
  /**
   * Opaque factor identifier, stable across sessions. For WebAuthn this is
   * the credential ID; for TOTP a random label chosen at enrollment; for
   * email the hashed email address.
   */
  factorId: string;
  /** Factor type string — well-known or custom. */
  factorType: FactorType;
  /** DID this factor is bound to. */
  subjectDid: string;
  /**
   * Public verification material, base64-encoded. Meaning depends on type:
   *   - webauthn-*: COSE-encoded public key
   *   - totp: the shared secret (treat as SECRET — see `isSecret`)
   *   - email-magic-link: the hashed email
   *   - app-attest/key-attest: the attested public key
   */
  publicMaterial: string;
  /**
   * Optional attestation the factor produced at enrollment time. Base64.
   * For WebAuthn this is the attestation statement; for Apple/Android it
   * is the platform attestation receipt. Verifiers may inspect this to
   * decide if the factor is hardware-backed for tier-ladder purposes.
   */
  attestation: string | null;
  /**
   * True if `publicMaterial` is actually a shared secret that must be
   * protected at rest. The registry doesn't enforce this; persistence
   * layers should encrypt secrets using the credential vault.
   */
  isSecret: boolean;
  /** Arbitrary metadata (device name, user agent, AAGUID, etc.). */
  metadata: Record<string, string>;
  /** Unix ms of enrollment. */
  registeredAt: number;
  /** Unix ms of most recent successful use, or null if never used. */
  lastUsedAt: number | null;
  /** Unix ms of revocation, or null if still active. */
  revokedAt: number | null;
}

// ─── Registry ───────────────────────────────────────────────────────────────

/**
 * In-memory registry of factors keyed by `(subjectDid, factorId)`.
 *
 * Stateful by design — matches the pattern of `RevocationRegistry` and
 * `AttestationRegistry`. Persistence is external: serialize with
 * `toJSON()` and hand the blob to `persistence.ts`, rehydrate with
 * `fromJSON()`.
 */
export class FactorRegistry {
  private readonly factors: Map<string, RegisteredFactor> = new Map();

  /**
   * Register a new factor for a subject. Throws if `(subjectDid, factorId)`
   * is already present — re-registration must go through `revoke()` first.
   */
  register(
    input: Omit<
      RegisteredFactor,
      'registeredAt' | 'lastUsedAt' | 'revokedAt'
    >,
  ): RegisteredFactor {
    const key = this.key(input.subjectDid, input.factorId);
    if (this.factors.has(key)) {
      throw new Error(`factor already registered: ${key}`);
    }
    const entry: RegisteredFactor = {
      ...input,
      registeredAt: Date.now(),
      lastUsedAt: null,
      revokedAt: null,
    };
    this.factors.set(key, entry);
    return { ...entry };
  }

  /** Fetch a specific factor. Returns null if unknown. */
  get(subjectDid: string, factorId: string): RegisteredFactor | null {
    const f = this.factors.get(this.key(subjectDid, factorId));
    return f ? { ...f } : null;
  }

  /**
   * List all active (non-revoked) factors for a subject. Returns a
   * defensive copy — callers can't mutate the registry through it.
   */
  listActive(subjectDid: string): RegisteredFactor[] {
    return [...this.factors.values()]
      .filter((f) => f.subjectDid === subjectDid && f.revokedAt === null)
      .map((f) => ({ ...f }));
  }

  /**
   * List every factor (including revoked) for a subject. For audit use.
   */
  listAll(subjectDid: string): RegisteredFactor[] {
    return [...this.factors.values()]
      .filter((f) => f.subjectDid === subjectDid)
      .map((f) => ({ ...f }));
  }

  /** Mark a factor as used. No-op if unknown. */
  markUsed(subjectDid: string, factorId: string, at: number = Date.now()): void {
    const f = this.factors.get(this.key(subjectDid, factorId));
    if (f && f.revokedAt === null) {
      f.lastUsedAt = at;
    }
  }

  /**
   * Revoke a factor. Already-revoked factors are not re-revoked (the
   * original `revokedAt` stays put) so audit trails remain stable.
   */
  revoke(subjectDid: string, factorId: string, at: number = Date.now()): void {
    const f = this.factors.get(this.key(subjectDid, factorId));
    if (f && f.revokedAt === null) {
      f.revokedAt = at;
    }
  }

  /** True iff the factor exists and has not been revoked. */
  isActive(subjectDid: string, factorId: string): boolean {
    const f = this.factors.get(this.key(subjectDid, factorId));
    return f !== undefined && f.revokedAt === null;
  }

  /** Count active factors by type for a subject. Drives tier evaluation. */
  countActiveByType(subjectDid: string): Record<FactorType, number> {
    const counts: Record<string, number> = {};
    for (const f of this.listActive(subjectDid)) {
      counts[f.factorType] = (counts[f.factorType] ?? 0) + 1;
    }
    return counts;
  }

  // ─── Serialization ──────────────────────────────────────────────────────

  toJSON(): RegisteredFactor[] {
    return [...this.factors.values()].map((f) => ({ ...f }));
  }

  static fromJSON(entries: RegisteredFactor[]): FactorRegistry {
    const r = new FactorRegistry();
    for (const entry of entries) {
      r.factors.set(r.key(entry.subjectDid, entry.factorId), { ...entry });
    }
    return r;
  }

  private key(did: string, id: string): string {
    return `${did}::${id}`;
  }
}
