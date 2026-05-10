import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { createGenome, commitGenome } from '../../src/core/genome.js';
import {
  HeartRuntime,
  type HeartConfig,
} from '../../src/heart/runtime.js';
import { FactorRegistry } from '../../src/heart/factor-registry.js';
import {
  LoginChallengeService,
  LoginFactorVerifierRegistry,
  type LoginVerification,
} from '../../src/heart/login-challenge.js';
import type { ProductSession } from '../../src/heart/product-session.js';

const provider = getCryptoProvider();

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeHeartConfig(): HeartConfig {
  const keyPair = provider.signing.generateKeyPair();
  const genome = commitGenome(
    createGenome({
      modelProvider: 'test',
      modelId: 'test-model',
      modelVersion: '1.0',
      systemPrompt: 'Test.',
      toolManifest: '{}',
      runtimeId: 'test-runtime',
    }),
    keyPair,
  );
  return {
    genome,
    signingKeyPair: keyPair,
    modelApiKey: 'sk-test',
    modelBaseUrl: 'https://api.test.com/v1',
    modelId: 'test-model-1',
  };
}

function makeLoginService(
  config: HeartConfig,
  opts?: {
    factorId?: string;
    factorType?: string;
    deviceId?: string;
    tierAchieved?: number;
    hasHardwareAttestation?: boolean;
  },
) {
  const factorRegistry = new FactorRegistry();
  const verifiers = new LoginFactorVerifierRegistry();
  const factorId = opts?.factorId ?? 'webauthn-1';
  const factorType = opts?.factorType ?? 'webauthn-platform';
  const deviceId = opts?.deviceId ?? 'device-1';

  factorRegistry.register({
    factorId,
    factorType,
    subjectDid: 'did:key:z6MktestUser',
    publicMaterial: 'mockKey',
    attestation: null,
    isSecret: false,
    metadata: { deviceId },
  });

  verifiers.register(factorType, () => ({
    valid: true,
    tierAchieved: opts?.tierAchieved ?? 1,
    hasUserVerification: true,
    hasHardwareAttestation: opts?.hasHardwareAttestation ?? false,
  }));

  return { service: new LoginChallengeService({
    heartDid: config.genome.did,
    heartPublicKey: config.genome.publicKey,
    heartSigningKey: config.signingKeyPair.secretKey,
    factorRegistry,
    verifiers,
    provider,
  }), factorRegistry };
}

async function performLogin(
  service: LoginChallengeService,
  opts?: { factorId?: string; factorType?: string },
): Promise<LoginVerification> {
  const challenge = service.createChallenge({
    subjectDid: 'did:key:z6MktestUser',
    requestedTier: 'L0',
  });
  const result = await service.verifyLogin({
    challengeId: challenge.id,
    factorId: opts?.factorId ?? 'webauthn-1',
    factorType: opts?.factorType ?? 'webauthn-platform',
    rawAssertion: provider.encoding.encodeBase64(provider.random.randomBytes(32)),
    assertedAt: Date.now(),
  });
  if (!result.ok) throw new Error(`login failed: ${result.reason}`);
  return result.verification;
}

function issueSomaSession(
  heart: HeartRuntime,
  verification: LoginVerification,
  accountId: string,
): ProductSession {
  const result = heart.issueProductSessionFromLogin(verification, accountId);
  if (!result.ok) throw new Error(`session failed: ${result.reason}`);
  return result.session;
}

function issueAdapterSession(
  heart: HeartRuntime,
  accountId: string,
): ProductSession {
  const result = heart.issueAdapterBridgeSession(accountId);
  if (!result.ok) throw new Error(`adapter session failed: ${result.reason}`);
  return result.session;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('invalidateFactorSessions', () => {
  it('revokes session whose deviceBinding matches the revoked factorId', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');

    expect(session.deviceBinding).not.toBeNull();
    expect(session.deviceBinding!.factorId).toBe('webauthn-1');

    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(1);

    const resolved = heart.resolveProductSession(session.sessionId);
    expect(resolved.ok).toBe(false);
    if (!resolved.ok) {
      expect(resolved.reason).toBe('session is revoked');
    }
  });

  it('does not revoke session bound to a different factor', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');
    expect(session.deviceBinding!.factorId).toBe('webauthn-1');

    // Revoke a completely unrelated factor
    const result = heart.invalidateFactorSessions('totp-99');
    expect(result.sessionsRevoked).toBe(0);

    const resolved = heart.resolveProductSession(session.sessionId);
    expect(resolved.ok).toBe(true);
  });

  it('adapter-bridge sessions (no deviceBinding) are never affected', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);

    const session = issueAdapterSession(heart, 'acct-1');
    expect(session.deviceBinding).toBeNull();

    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(0);

    const resolved = heart.resolveProductSession(session.sessionId);
    expect(resolved.ok).toBe(true);
  });

  it('revokes only the session bound to the matching factor when multiple sessions exist', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);

    // Session 1: soma-direct bound to webauthn-1
    const { service: svc1 } = makeLoginService(config, { factorId: 'webauthn-1' });
    const v1 = await performLogin(svc1, { factorId: 'webauthn-1' });
    const s1 = issueSomaSession(heart, v1, 'acct-1');

    // Session 2: soma-direct bound to webauthn-2
    const { service: svc2 } = makeLoginService(config, {
      factorId: 'webauthn-2',
      deviceId: 'device-2',
    });
    const v2 = await performLogin(svc2, { factorId: 'webauthn-2' });
    const s2 = issueSomaSession(heart, v2, 'acct-2');

    // Session 3: adapter-bridge (no binding)
    const s3 = issueAdapterSession(heart, 'acct-3');

    expect(s1.deviceBinding!.factorId).toBe('webauthn-1');
    expect(s2.deviceBinding!.factorId).toBe('webauthn-2');
    expect(s3.deviceBinding).toBeNull();

    // Revoke factor webauthn-1
    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(1);

    // s1 is revoked
    expect(heart.resolveProductSession(s1.sessionId).ok).toBe(false);
    // s2 is unaffected
    expect(heart.resolveProductSession(s2.sessionId).ok).toBe(true);
    // s3 is unaffected
    expect(heart.resolveProductSession(s3.sessionId).ok).toBe(true);
  });

  it('elevated session whose step-up factor is revoked does not survive', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');

    // Elevate with a different device binding (simulating step-up with a new factor)
    const elevResult = heart.elevateProductSession(session, 2, {
      deviceBinding: {
        factorId: 'yubikey-7',
        factorType: 'webauthn-roaming',
        deviceTrustLevel: 'hardware-attested',
      },
    });
    expect(elevResult.ok).toBe(true);
    if (!elevResult.ok) return;

    expect(elevResult.session.currentAuthorityTier).toBe('L2');
    expect(elevResult.session.deviceBinding!.factorId).toBe('yubikey-7');

    // Revoke the step-up factor — session must not survive
    const result = heart.invalidateFactorSessions('yubikey-7');
    expect(result.sessionsRevoked).toBe(1);

    const resolved = heart.resolveProductSession(elevResult.session.sessionId);
    expect(resolved.ok).toBe(false);
    if (!resolved.ok) {
      expect(resolved.reason).toBe('session is revoked');
    }
  });

  it('revoking original login factor does not affect session after step-up changed deviceBinding', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');
    expect(session.deviceBinding!.factorId).toBe('webauthn-1');

    // Step-up replaces deviceBinding with a different factor
    heart.elevateProductSession(session, 2, {
      deviceBinding: {
        factorId: 'yubikey-7',
        factorType: 'webauthn-roaming',
        deviceTrustLevel: 'hardware-attested',
      },
    });

    // Revoke the ORIGINAL login factor — session's current binding is yubikey-7
    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(0);

    const resolved = heart.resolveProductSession(session.sessionId);
    expect(resolved.ok).toBe(true);
  });

  it('records factor_sessions_invalidated heartbeat', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    issueSomaSession(heart, verification, 'acct-1');

    heart.invalidateFactorSessions('webauthn-1');

    const chain = heart.heartbeats.getChain();
    const beat = chain.find(h => h.eventType === 'factor_sessions_invalidated');
    expect(beat).toBeDefined();
    expect(beat!.eventHash).toBeTruthy();
  });

  it('heartbeat is recorded even when no sessions matched', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);

    const result = heart.invalidateFactorSessions('nonexistent-factor');
    expect(result.sessionsRevoked).toBe(0);

    const chain = heart.heartbeats.getChain();
    const beat = chain.find(h => h.eventType === 'factor_sessions_invalidated');
    expect(beat).toBeDefined();
  });

  it('already-revoked sessions are not double-counted', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');

    // Manually revoke first
    heart.productSessionStore.revoke(session.sessionId);

    // Factor invalidation should find 0 newly-revoked sessions
    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(0);
  });

  it('multiple sessions bound to same factor are all revoked', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    // Two separate logins with the same factor, different accounts
    const v1 = await performLogin(service);
    const s1 = issueSomaSession(heart, v1, 'acct-1');

    const v2 = await performLogin(service);
    const s2 = issueSomaSession(heart, v2, 'acct-2');

    expect(s1.deviceBinding!.factorId).toBe('webauthn-1');
    expect(s2.deviceBinding!.factorId).toBe('webauthn-1');

    const result = heart.invalidateFactorSessions('webauthn-1');
    expect(result.sessionsRevoked).toBe(2);

    expect(heart.resolveProductSession(s1.sessionId).ok).toBe(false);
    expect(heart.resolveProductSession(s2.sessionId).ok).toBe(false);
  });
});

describe('ProductSessionStore.revokeByFactor', () => {
  it('matches on deviceBinding.factorId, not factorType', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);

    const verification = await performLogin(service);
    const session = issueSomaSession(heart, verification, 'acct-1');
    expect(session.deviceBinding!.factorType).toBe('webauthn-platform');

    // Revoke by factorType string should NOT match (it's not a factorId)
    const count = heart.productSessionStore.revokeByFactor('webauthn-platform');
    expect(count).toBe(0);

    // Session still active
    expect(heart.resolveProductSession(session.sessionId).ok).toBe(true);
  });
});
