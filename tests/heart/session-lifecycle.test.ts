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
import { ProductAccountBindingStore } from '../../src/heart/product-account-binding.js';
import {
  deriveProductTokenKey,
  mintProductSessionToken,
} from '../../src/heart/product-session.js';
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

function makeLoginService(config: HeartConfig) {
  const factorRegistry = new FactorRegistry();
  const verifiers = new LoginFactorVerifierRegistry();

  factorRegistry.register({
    factorId: 'webauthn-1',
    factorType: 'webauthn-platform',
    subjectDid: 'did:key:z6MktestUser',
    publicMaterial: 'mockKey',
    attestation: null,
    isSecret: false,
    metadata: { deviceId: 'device-1' },
  });

  verifiers.register('webauthn-platform', () => ({
    valid: true,
    tierAchieved: 1,
    hasUserVerification: true,
    hasHardwareAttestation: false,
  }));

  return new LoginChallengeService({
    heartDid: config.genome.did,
    heartPublicKey: config.genome.publicKey,
    heartSigningKey: config.signingKeyPair.secretKey,
    factorRegistry,
    verifiers,
    provider,
  });
}

async function performLogin(
  service: LoginChallengeService,
): Promise<LoginVerification> {
  const challenge = service.createChallenge({
    subjectDid: 'did:key:z6MktestUser',
    requestedTier: 'L0',
  });
  const result = await service.verifyLogin({
    challengeId: challenge.id,
    factorId: 'webauthn-1',
    factorType: 'webauthn-platform',
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
  opts?: { now?: number; sessionTtlMs?: number },
): ProductSession {
  const result = heart.issueProductSessionFromLogin(verification, accountId, opts);
  if (!result.ok) throw new Error(`session failed: ${result.reason}`);
  return result.session;
}

function mintToken(
  config: HeartConfig,
  session: ProductSession,
  opts?: { now?: number },
): string {
  const tokenKey = deriveProductTokenKey(config.signingKeyPair.secretKey, provider);
  return mintProductSessionToken(session, tokenKey, { ...opts, provider });
}

// ─── resolveProductSession ──────────────────────────────────────────────────

describe('resolveProductSession', () => {
  it('resolves an active session', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);
    const session = issueSomaSession(heart, verification, 'acct-1');

    const result = heart.resolveProductSession(session.sessionId);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.sessionId).toBe(session.sessionId);
    expect(result.session.revocationState).toBe('active');
  });

  it('rejects unknown session ID', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const result = heart.resolveProductSession('nonexistent');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('session not found');
  });

  it('rejects expired session', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);

    const nowMs = Date.now();
    const session = issueSomaSession(heart, verification, 'acct-1', {
      now: nowMs,
      sessionTtlMs: 1000,
    });

    // Before expiry — should succeed
    const before = heart.resolveProductSession(session.sessionId, { now: nowMs + 500 });
    expect(before.ok).toBe(true);

    // After expiry — should fail
    const after = heart.resolveProductSession(session.sessionId, { now: nowMs + 1001 });
    expect(after.ok).toBe(false);
    if (after.ok) return;
    expect(after.reason).toBe('session has expired');
  });

  it('rejects revoked session', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);
    const session = issueSomaSession(heart, verification, 'acct-1');

    heart.productSessionStore.revoke(session.sessionId);

    const result = heart.resolveProductSession(session.sessionId);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('session is revoked');
  });

  it('revoked session is distinguishable from unknown session', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);
    const session = issueSomaSession(heart, verification, 'acct-1');

    heart.productSessionStore.revoke(session.sessionId);

    const revokedResult = heart.resolveProductSession(session.sessionId);
    const unknownResult = heart.resolveProductSession('nonexistent-id');

    expect(revokedResult.ok).toBe(false);
    expect(unknownResult.ok).toBe(false);
    if (revokedResult.ok || unknownResult.ok) return;

    expect(revokedResult.reason).toBe('session is revoked');
    expect(unknownResult.reason).toContain('session not found');
    expect(revokedResult.reason).not.toBe(unknownResult.reason);
  });

  it('applies step-up decay on resolve', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);

    const nowMs = Date.now();
    const session = issueSomaSession(heart, verification, 'acct-1', { now: nowMs });

    // Elevate to L2
    const elevateResult = heart.elevateProductSession(session, 2, {
      now: nowMs + 100,
      windowMs: 5000,
    });
    expect(elevateResult.ok).toBe(true);
    if (!elevateResult.ok) return;

    // Resolve within step-up window — should see L2
    const withinWindow = heart.resolveProductSession(session.sessionId, {
      now: nowMs + 1000,
    });
    expect(withinWindow.ok).toBe(true);
    if (!withinWindow.ok) return;
    expect(withinWindow.session.currentAuthorityTier).toBe('L2');

    // Resolve after step-up window expired — should decay back to L1
    const afterWindow = heart.resolveProductSession(session.sessionId, {
      now: nowMs + 10_000,
    });
    expect(afterWindow.ok).toBe(true);
    if (!afterWindow.ok) return;
    expect(afterWindow.session.currentAuthorityTier).toBe('L1');
    expect(afterWindow.session.baseAuthorityTier).toBe('L1');
  });

  it('decay is persisted to store after resolve', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);

    const nowMs = Date.now();
    const session = issueSomaSession(heart, verification, 'acct-1', { now: nowMs });

    heart.elevateProductSession(session, 2, {
      now: nowMs + 100,
      windowMs: 1000,
    });

    // Resolve after decay window
    heart.resolveProductSession(session.sessionId, { now: nowMs + 5000 });

    // Direct store read should show decayed state
    const stored = heart.productSessionStore.get(session.sessionId);
    expect(stored).toBeDefined();
    expect(stored!.currentAuthorityTier).toBe('L1');
    expect(stored!.stepUpWindowExpiresAt).toBeNull();
  });
});

// ─── resolveProductSessionToken — lifecycle enforcement ─────────────────────

describe('resolveProductSessionToken lifecycle enforcement', () => {
  it('rejects token for expired session', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);

    const nowMs = 1_000_000;
    const session = issueSomaSession(heart, verification, 'acct-1', {
      now: nowMs,
      sessionTtlMs: 5000,
    });

    const token = mintToken(config, session, { now: nowMs });

    // Token validation itself checks expiry
    const result = heart.resolveProductSessionToken(token, {
      now: nowMs + 6000,
    });
    expect(result.ok).toBe(false);
  });

  it('applies decay on token resolution', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const verification = await performLogin(loginService);

    const nowMs = 1_000_000;
    const session = issueSomaSession(heart, verification, 'acct-1', { now: nowMs });
    const token = mintToken(config, session, { now: nowMs });

    // Elevate
    heart.elevateProductSession(session, 2, {
      now: nowMs + 100,
      windowMs: 2000,
    });

    // Resolve after decay
    const result = heart.resolveProductSessionToken(token, { now: nowMs + 5000 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.currentAuthorityTier).toBe('L1');
  });
});

// ─── unbindAccountAndRevokeSessions ─────────────────────────────────────────

describe('unbindAccountAndRevokeSessions', () => {
  it('unbinds and revokes all active sessions for the account', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    // Issue two sessions for the same account
    const v1 = await performLogin(loginService);
    const session1 = issueSomaSession(heart, v1, 'acct-1');
    const v2 = await performLogin(loginService);
    const session2 = issueSomaSession(heart, v2, 'acct-1');

    const result = heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);

    expect(result.unbound).toBe(true);
    expect(result.sessionsRevoked).toBe(2);

    // Binding is dissolved
    expect(bindingStore.getActive('acct-1')).toBeUndefined();

    // Sessions are revoked
    const s1 = heart.productSessionStore.get(session1.sessionId);
    const s2 = heart.productSessionStore.get(session2.sessionId);
    expect(s1!.revocationState).toBe('revoked');
    expect(s2!.revocationState).toBe('revoked');
  });

  it('revoked sessions are distinguishable from unknown sessions after unbind', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(loginService);
    const session = issueSomaSession(heart, v, 'acct-1');

    heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);

    // Resolve the revoked session — should say "revoked", not "not found"
    const revokedResult = heart.resolveProductSession(session.sessionId);
    expect(revokedResult.ok).toBe(false);
    if (revokedResult.ok) return;
    expect(revokedResult.reason).toBe('session is revoked');

    // Unknown session says "not found"
    const unknownResult = heart.resolveProductSession('does-not-exist');
    expect(unknownResult.ok).toBe(false);
    if (unknownResult.ok) return;
    expect(unknownResult.reason).toContain('session not found');
  });

  it('does not revoke sessions for OTHER accounts', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });
    bindingStore.bind({
      accountId: 'acct-2',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v1 = await performLogin(loginService);
    const session1 = issueSomaSession(heart, v1, 'acct-1');
    const v2 = await performLogin(loginService);
    const session2 = issueSomaSession(heart, v2, 'acct-2');

    heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);

    // acct-1 session is revoked
    expect(heart.productSessionStore.get(session1.sessionId)!.revocationState).toBe('revoked');

    // acct-2 session is still active
    expect(heart.productSessionStore.get(session2.sessionId)!.revocationState).toBe('active');
  });

  it('returns unbound=false when no active binding exists', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    const result = heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);
    expect(result.unbound).toBe(false);
    expect(result.sessionsRevoked).toBe(0);
  });

  it('tokens for revoked sessions fail on resolve after unbind', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(loginService);
    const nowMs = 1_000_000;
    const session = issueSomaSession(heart, v, 'acct-1', { now: nowMs });
    const token = mintToken(config, session, { now: nowMs });

    // Token works before unbind
    const before = heart.resolveProductSessionToken(token, { now: nowMs + 100 });
    expect(before.ok).toBe(true);

    // Unbind
    heart.unbindAccountAndRevokeSessions('acct-1', bindingStore, { now: nowMs + 200 });

    // Token fails after unbind
    const after = heart.resolveProductSessionToken(token, { now: nowMs + 300 });
    expect(after.ok).toBe(false);
    if (after.ok) return;
    expect(after.reason).toBe('session is revoked');
  });

  it('records heartbeat event on unbind', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(loginService);
    issueSomaSession(heart, v, 'acct-1');

    heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);

    const heartbeats = heart.heartbeats.getChain();
    const unbindBeat = heartbeats.find(
      (h) => h.eventType === 'account_binding_unbound',
    );
    expect(unbindBeat).toBeDefined();
    expect(unbindBeat!.eventHash).toBeTruthy();
  });

  it('adapter-bridge sessions are also revoked on unbind', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    // Issue an adapter-bridge session for the same account
    const adapterResult = heart.issueAdapterBridgeSession('acct-1', {
      somaIdentityBinding: 'did:key:z6MktestUser',
    });
    expect(adapterResult.ok).toBe(true);
    if (!adapterResult.ok) return;

    heart.unbindAccountAndRevokeSessions('acct-1', bindingStore);

    const stored = heart.productSessionStore.get(adapterResult.session.sessionId);
    expect(stored!.revocationState).toBe('revoked');
  });
});

// ─── Scheduler-free correctness ─────────────────────────────────────────────

describe('scheduler-free lifecycle correctness', () => {
  it('expired sessions are rejected without any sweep', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);

    const nowMs = 1_000_000;
    const v = await performLogin(loginService);
    const session = issueSomaSession(heart, v, 'acct-1', {
      now: nowMs,
      sessionTtlMs: 5000,
    });

    // No prune/sweep called — just resolve at a later time
    const result = heart.resolveProductSession(session.sessionId, {
      now: nowMs + 10_000,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('session has expired');
  });

  it('decayed sessions resolve at correct downgraded authority without sweep', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);

    const nowMs = 1_000_000;
    const v = await performLogin(loginService);
    const session = issueSomaSession(heart, v, 'acct-1', { now: nowMs });

    heart.elevateProductSession(session, 3, {
      now: nowMs + 100,
      windowMs: 2000,
    });

    // No sweep — just resolve after window
    const result = heart.resolveProductSession(session.sessionId, {
      now: nowMs + 5000,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Should be back at login tier (L1), not elevated tier (L3)
    expect(result.session.currentAuthorityTier).toBe('L1');
    expect(result.session.baseAuthorityTier).toBe('L1');
  });

  it('prune is available but not required for correctness', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const loginService = makeLoginService(config);

    const nowMs = 1_000_000;
    const v = await performLogin(loginService);
    issueSomaSession(heart, v, 'acct-1', {
      now: nowMs,
      sessionTtlMs: 1000,
    });

    // Store has the session
    expect(heart.productSessionStore.size).toBe(1);

    // Prune removes expired sessions (optional cleanup)
    const pruned = heart.productSessionStore.prune(nowMs + 5000);
    expect(pruned).toBe(1);
    expect(heart.productSessionStore.size).toBe(0);
  });
});
