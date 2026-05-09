import { describe, it, expect, beforeEach } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { FactorRegistry } from '../../src/heart/factor-registry.js';
import {
  LoginChallengeService,
  LoginFactorVerifierRegistry,
  verifyLoginChallengeSignature,
  verifyLoginVerificationSignature,
  type LoginAssertion,
  type LoginFactorVerifier,
} from '../../src/heart/login-challenge.js';

// ─── Test helpers ───────────────────────────────────────────────────────────

const provider = getCryptoProvider();

function makeKeyPair() {
  return provider.signing.generateKeyPair();
}

function makeService(overrides?: {
  now?: () => number;
  defaultTtlMs?: number;
  evaluateTier?: (input: {
    factorType: string;
    factorTier: number;
    subjectDid: string;
  }) => number;
}) {
  const keyPair = makeKeyPair();
  const heartDid = 'did:key:z6MkheartTest';
  const heartPublicKey = provider.encoding.encodeBase64(keyPair.publicKey);

  const factorRegistry = new FactorRegistry();
  const verifiers = new LoginFactorVerifierRegistry();

  // Register a mock factor for the test subject
  factorRegistry.register({
    factorId: 'factor-1',
    factorType: 'webauthn-platform',
    subjectDid: 'did:key:z6MktestSubject',
    publicMaterial: 'mockPublicKey',
    attestation: null,
    isSecret: false,
    metadata: { device: 'test-device' },
  });

  // Register a mock verifier that always succeeds with tier 1
  const mockVerifier: LoginFactorVerifier = () => ({
    valid: true,
    tierAchieved: 1,
  });
  verifiers.register('webauthn-platform', mockVerifier);

  const service = new LoginChallengeService({
    heartDid,
    heartPublicKey,
    heartSigningKey: keyPair.secretKey,
    factorRegistry,
    verifiers,
    provider,
    now: overrides?.now,
    defaultTtlMs: overrides?.defaultTtlMs,
    evaluateTier: overrides?.evaluateTier,
  });

  return {
    service,
    keyPair,
    heartDid,
    heartPublicKey,
    factorRegistry,
    verifiers,
  };
}

function makeAssertion(
  challengeId: string,
  overrides?: Partial<LoginAssertion>,
): LoginAssertion {
  return {
    challengeId,
    factorId: 'factor-1',
    factorType: 'webauthn-platform',
    rawAssertion: provider.encoding.encodeBase64(
      provider.random.randomBytes(32),
    ),
    assertedAt: Date.now(),
    ...overrides,
  };
}

// ─── LoginChallengeService ──────────────────────────────────────────────────

describe('LoginChallengeService', () => {
  describe('createChallenge', () => {
    it('creates a signed challenge for a subject with active factors', () => {
      const { service } = makeService();

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });

      expect(challenge.protocol).toBe('soma-login/1');
      expect(challenge.subjectDid).toBe('did:key:z6MktestSubject');
      expect(challenge.requestedTier).toBe('L1');
      expect(challenge.id).toMatch(/^login-/);
      expect(challenge.nonce).toBeTruthy();
      expect(challenge.signature).toBeTruthy();
      expect(challenge.expiresAt).toBeGreaterThan(challenge.issuedAt);
    });

    it('uses custom requestedTier', () => {
      const { service } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        requestedTier: 'L2',
      });
      expect(challenge.requestedTier).toBe('L2');
    });

    it('uses custom TTL', () => {
      const now = () => 10_000;
      const { service } = makeService({ now });
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        ttlMs: 30_000,
      });
      expect(challenge.expiresAt).toBe(40_000);
    });

    it('uses default TTL of 2 minutes', () => {
      const now = () => 10_000;
      const { service } = makeService({ now });
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      expect(challenge.expiresAt).toBe(10_000 + 120_000);
    });

    it('challenge signature is verifiable', () => {
      const { service } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const result = verifyLoginChallengeSignature(challenge, provider);
      expect(result.valid).toBe(true);
    });

    it('tracks outstanding challenges', () => {
      const { service } = makeService();
      expect(service.outstandingCount()).toBe(0);
      service.createChallenge({ subjectDid: 'did:key:z6MktestSubject' });
      expect(service.outstandingCount()).toBe(1);
      service.createChallenge({ subjectDid: 'did:key:z6MktestSubject' });
      expect(service.outstandingCount()).toBe(2);
    });

    it('throws if subject has no active factors', () => {
      const { service } = makeService();
      expect(() =>
        service.createChallenge({ subjectDid: 'did:key:z6MknoFactors' }),
      ).toThrow('no active login factors');
    });

    it('throws if subject only has recovery-seed factors', () => {
      const { service, factorRegistry } = makeService();
      factorRegistry.register({
        factorId: 'recovery-1',
        factorType: 'recovery-seed',
        subjectDid: 'did:key:z6MkrecoveryOnly',
        publicMaterial: 'recoveryPubKey',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      expect(() =>
        service.createChallenge({ subjectDid: 'did:key:z6MkrecoveryOnly' }),
      ).toThrow('no active login factors');
    });
  });

  describe('verifyLogin — happy path', () => {
    it('verifies a valid login assertion and returns a signed verification', async () => {
      const nowMs = 100_000;
      const { service, heartDid } = makeService({ now: () => nowMs });

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });

      const assertion = makeAssertion(challenge.id, {
        assertedAt: nowMs,
      });

      const result = await service.verifyLogin(assertion);

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.verification.protocol).toBe('soma-login/1');
      expect(result.verification.challengeId).toBe(challenge.id);
      expect(result.verification.subjectDid).toBe('did:key:z6MktestSubject');
      expect(result.verification.factorType).toBe('webauthn-platform');
      expect(result.verification.factorId).toBe('factor-1');
      expect(result.verification.tierAchieved).toBe('L1');
      expect(result.verification.verifiedAt).toBe(nowMs);
      expect(result.verification.heartDid).toBe(heartDid);
      expect(result.verification.signature).toBeTruthy();
    });

    it('verification signature is valid', async () => {
      const { service, heartPublicKey } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id);
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const sigCheck = verifyLoginVerificationSignature(
        result.verification,
        {
          trustedHeartPublicKeys: [heartPublicKey],
          provider,
        },
      );
      expect(sigCheck.valid).toBe(true);
    });

    it('consumes the challenge (single use)', async () => {
      const { service } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id);

      await service.verifyLogin(assertion);
      expect(service.outstandingCount()).toBe(0);

      const retry = await service.verifyLogin(assertion);
      expect(retry.ok).toBe(false);
      if (!retry.ok) expect(retry.reason).toBe('challenge already consumed');
    });

    it('marks the factor as used', async () => {
      const nowMs = 100_000;
      const { service, factorRegistry } = makeService({ now: () => nowMs });
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, { assertedAt: nowMs });

      await service.verifyLogin(assertion);

      const factor = factorRegistry.get(
        'did:key:z6MktestSubject',
        'factor-1',
      );
      expect(factor!.lastUsedAt).toBe(nowMs);
    });
  });

  describe('verifyLogin — failure cases', () => {
    it('rejects unknown challenge ID', async () => {
      const { service } = makeService();
      const assertion = makeAssertion('nonexistent-id');
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('unknown challenge id');
    });

    it('rejects expired challenge', async () => {
      let nowMs = 10_000;
      const { service } = makeService({ now: () => nowMs });

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        ttlMs: 5_000,
      });

      // Advance past expiry
      nowMs = 20_000;
      const assertion = makeAssertion(challenge.id, { assertedAt: nowMs });
      const result = await service.verifyLogin(assertion);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('challenge expired');
      // Expired challenge is cleaned up
      expect(service.outstandingCount()).toBe(0);
    });

    it('rejects assertion that predates the challenge', async () => {
      const nowMs = 100_000;
      const { service } = makeService({ now: () => nowMs });
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        assertedAt: nowMs - 10_000,
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('assertion predates challenge');
    });

    it('rejects assertion with future timestamp', async () => {
      const nowMs = 100_000;
      const { service } = makeService({ now: () => nowMs });
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        assertedAt: nowMs + 120_000,
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toBe('assertion timestamp is in the future');
    });

    it('rejects factor not registered for subject', async () => {
      const { service } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        factorId: 'unknown-factor',
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toBe('factor not registered for subject');
    });

    it('rejects revoked factor', async () => {
      const { service, factorRegistry } = makeService();
      factorRegistry.revoke('did:key:z6MktestSubject', 'factor-1');

      // Register a second factor so challenge creation succeeds
      factorRegistry.register({
        factorId: 'factor-2',
        factorType: 'webauthn-platform',
        subjectDid: 'did:key:z6MktestSubject',
        publicMaterial: 'mockKey2',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        factorId: 'factor-1',
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('factor is revoked');
    });

    it('rejects factor type mismatch', async () => {
      const { service } = makeService();
      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        factorType: 'totp',
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toBe(
          'factor type mismatch with registered entry',
        );
    });

    it('rejects when no verifier registered for factor type', async () => {
      const { service, factorRegistry, verifiers } = makeService();

      factorRegistry.register({
        factorId: 'totp-1',
        factorType: 'totp',
        subjectDid: 'did:key:z6MktestSubject',
        publicMaterial: 'totpSecret',
        attestation: null,
        isSecret: true,
        metadata: {},
      });
      // No verifier registered for 'totp'

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id, {
        factorId: 'totp-1',
        factorType: 'totp',
      });
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('no verifier registered for factor type');
    });

    it('rejects when factor verifier returns invalid', async () => {
      const { service, verifiers } = makeService();
      verifiers.register('webauthn-platform', () => ({
        valid: false,
        reason: 'signature mismatch',
      }));

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id);
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('signature mismatch');
    });

    it('rejects when tier achieved is below requested', async () => {
      const { service, verifiers } = makeService();
      // Verifier returns tier 0, but challenge requests L1
      verifiers.register('webauthn-platform', () => ({
        valid: true,
        tierAchieved: 0,
      }));

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        requestedTier: 'L1',
      });
      const assertion = makeAssertion(challenge.id);
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('tier achieved L0 < required L1');
    });

    it('applies tier policy evaluator (policy can lower tier)', async () => {
      const { service, verifiers } = makeService({
        evaluateTier: ({ factorTier }) => Math.min(factorTier, 0),
      });
      // Verifier says tier 1, but policy caps at 0
      verifiers.register('webauthn-platform', () => ({
        valid: true,
        tierAchieved: 1,
      }));

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        requestedTier: 'L1',
      });
      const assertion = makeAssertion(challenge.id);
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('tier achieved L0 < required L1');
    });

    it('async verifiers work correctly', async () => {
      const { service, verifiers } = makeService();
      verifiers.register('webauthn-platform', async () => {
        await new Promise((r) => setTimeout(r, 1));
        return { valid: true, tierAchieved: 1 };
      });

      const challenge = service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
      });
      const assertion = makeAssertion(challenge.id);
      const result = await service.verifyLogin(assertion);
      expect(result.ok).toBe(true);
    });
  });

  describe('pruneExpired', () => {
    it('removes expired challenges', () => {
      let nowMs = 10_000;
      const { service } = makeService({ now: () => nowMs });

      service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        ttlMs: 5_000,
      });
      service.createChallenge({
        subjectDid: 'did:key:z6MktestSubject',
        ttlMs: 50_000,
      });

      nowMs = 20_000;
      const pruned = service.pruneExpired(nowMs);
      expect(pruned).toBe(1);
      expect(service.outstandingCount()).toBe(1);
    });
  });
});

// ─── Standalone Verification ────────────────────────────────────────────────

describe('verifyLoginChallengeSignature', () => {
  it('accepts a valid challenge signature', () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    expect(verifyLoginChallengeSignature(challenge, provider).valid).toBe(true);
  });

  it('rejects a tampered challenge', () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const tampered = { ...challenge, subjectDid: 'did:key:z6Mktampered' };
    expect(verifyLoginChallengeSignature(tampered, provider).valid).toBe(false);
  });
});

describe('verifyLoginVerificationSignature', () => {
  it('accepts a valid verification with trusted key', async () => {
    const { service, heartPublicKey } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(makeAssertion(challenge.id));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const check = verifyLoginVerificationSignature(result.verification, {
      trustedHeartPublicKeys: [heartPublicKey],
      provider,
    });
    expect(check.valid).toBe(true);
  });

  it('rejects tampered verification', async () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(makeAssertion(challenge.id));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const tampered = {
      ...result.verification,
      subjectDid: 'did:key:z6Mktampered',
    };
    const check = verifyLoginVerificationSignature(tampered, { provider });
    expect(check.valid).toBe(false);
  });

  it('rejects untrusted heart key', async () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(makeAssertion(challenge.id));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const otherKey = provider.encoding.encodeBase64(
      makeKeyPair().publicKey,
    );
    const check = verifyLoginVerificationSignature(result.verification, {
      trustedHeartPublicKeys: [otherKey],
      provider,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toBe('heart public key not trusted');
  });

  it('rejects when subject mismatch', async () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(makeAssertion(challenge.id));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const check = verifyLoginVerificationSignature(result.verification, {
      expectedSubjectDid: 'did:key:z6Mkwrong',
      provider,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toBe('subject mismatch');
  });

  it('rejects when verification too old', async () => {
    const nowMs = 100_000;
    const { service, heartPublicKey } = makeService({ now: () => nowMs });
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(
      makeAssertion(challenge.id, { assertedAt: nowMs }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const check = verifyLoginVerificationSignature(result.verification, {
      maxAgeMs: 10_000,
      now: nowMs + 20_000,
      trustedHeartPublicKeys: [heartPublicKey],
      provider,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toBe('verification too old');
  });

  it('accepts when no options provided (minimal check)', async () => {
    const { service } = makeService();
    const challenge = service.createChallenge({
      subjectDid: 'did:key:z6MktestSubject',
    });
    const result = await service.verifyLogin(makeAssertion(challenge.id));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const check = verifyLoginVerificationSignature(result.verification, {
      provider,
    });
    expect(check.valid).toBe(true);
  });
});

// ─── LoginFactorVerifierRegistry ────────────────────────────────────────────

describe('LoginFactorVerifierRegistry', () => {
  it('registers and retrieves verifiers', () => {
    const registry = new LoginFactorVerifierRegistry();
    const verifier: LoginFactorVerifier = () => ({ valid: true });
    registry.register('webauthn-platform', verifier);
    expect(registry.get('webauthn-platform')).toBe(verifier);
    expect(registry.get('unknown')).toBeNull();
  });

  it('lists supported factor types', () => {
    const registry = new LoginFactorVerifierRegistry();
    registry.register('webauthn-platform', () => ({ valid: true }));
    registry.register('totp', () => ({ valid: true }));
    expect(registry.supported()).toEqual(
      expect.arrayContaining(['webauthn-platform', 'totp']),
    );
  });
});
