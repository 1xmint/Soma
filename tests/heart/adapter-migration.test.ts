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
      systemPrompt: 'You are a test agent.',
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
    publicMaterial: 'mockPublicKey',
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

  const service = new LoginChallengeService({
    heartDid: config.genome.did,
    heartPublicKey: config.genome.publicKey,
    heartSigningKey: config.signingKeyPair.secretKey,
    factorRegistry,
    verifiers,
    provider,
  });

  return { service, factorRegistry, verifiers };
}

async function performLogin(
  service: LoginChallengeService,
  subjectDid: string,
): Promise<LoginVerification> {
  const challenge = service.createChallenge({ subjectDid, requestedTier: 'L0' });
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

function issueAdapterSession(
  heart: HeartRuntime,
  accountId: string,
  opts?: { somaIdentityBinding?: string | null; now?: number },
): ProductSession {
  const result = heart.issueAdapterBridgeSession(accountId, {
    somaIdentityBinding: opts?.somaIdentityBinding ?? null,
    now: opts?.now,
  });
  if (!result.ok) throw new Error(`adapter session failed: ${result.reason}`);
  return result.session;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('migrateAdapterToSomaDirect', () => {
  it('successful migration: new binding, new session, old session revoked', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    expect(adapterSession.authOrigin).toBe('adapter-bridge');

    const verification = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // New session is soma-direct
    expect(result.newSession.authOrigin).toBe('soma-direct');
    expect(result.newSession.accountId).toBe('acct-1');
    expect(result.newSession.somaIdentityBinding).toBe('did:key:z6MktestUser');
    expect(result.newSession.revocationState).toBe('active');

    // Tier is evidence-derived, not adapter-capped
    expect(result.newSession.baseAuthorityTier).toBe('L1');
    expect(result.newSession.currentAuthorityTier).toBe('L1');

    // Device binding is evidence-derived
    expect(result.newSession.deviceBinding).not.toBeNull();
    expect(result.newSession.deviceBinding!.factorType).toBe('webauthn-platform');
    expect(result.newSession.deviceBinding!.deviceTrustLevel).toBe('platform');

    // Binding was created
    expect(result.binding.accountId).toBe('acct-1');
    expect(result.binding.somaIdentityDid).toBe('did:key:z6MktestUser');
    expect(result.binding.bindingType).toBe('primary');

    // Old session is revoked in the store
    expect(result.revokedSessionId).toBe(adapterSession.sessionId);
    const oldStored = heart.productSessionStore.get(adapterSession.sessionId);
    expect(oldStored).toBeDefined();
    expect(oldStored!.revocationState).toBe('revoked');
    expect(oldStored!.authOrigin).toBe('adapter-bridge'); // provenance preserved

    // New session is in the store
    const newStored = heart.productSessionStore.get(result.newSession.sessionId);
    expect(newStored).toBeDefined();
    expect(newStored!.authOrigin).toBe('soma-direct');
  });

  it('migration with pre-existing matching binding succeeds', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    // Pre-bind the account to the same identity
    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.newSession.somaIdentityBinding).toBe('did:key:z6MktestUser');
    // Binding was not changed (pre-existing match)
    expect(bindingStore.activeCount).toBe(1);
  });

  it('rejects when account bound to a different Soma identity', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    // Bind to a DIFFERENT identity
    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MkotherIdentity',
      bindingType: 'primary',
    });

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('already bound to');
    expect(result.reason).toContain('did:key:z6MkotherIdentity');

    // Old session should NOT be revoked on failure
    const oldStored = heart.productSessionStore.get(adapterSession.sessionId);
    expect(oldStored!.revocationState).toBe('active');
  });

  it('rejects when adapter session is already revoked', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    heart.productSessionStore.revoke(adapterSession.sessionId);

    const revokedSession = {
      ...adapterSession,
      revocationState: 'revoked' as const,
    };
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession: revokedSession, verification, bindingStore },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('adapter session is revoked');
  });

  it('rejects when adapter session is expired', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1', {
      now: 1000,
    });
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    // Way past expiry
    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
      { now: adapterSession.expiresAt + 1 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('adapter session has expired');
  });

  it('rejects when session is not adapter-bridge', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    // Issue a soma-direct session (not adapter-bridge)
    const verification1 = await performLogin(service, 'did:key:z6MktestUser');
    const directResult = heart.issueProductSessionFromLogin(
      verification1,
      'acct-1',
    );
    if (!directResult.ok) throw new Error('setup failed');

    const verification2 = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      {
        adapterSession: directResult.session,
        verification: verification2,
        bindingStore,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('session is not adapter-bridge');
  });

  it('rejects when login verification signature is invalid', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    // Create a verification signed by a DIFFERENT heart
    const otherConfig = makeHeartConfig();
    const { service: otherService } = makeLoginService(otherConfig);
    const verification = await performLogin(otherService, 'did:key:z6MktestUser');

    const adapterSession = issueAdapterSession(heart, 'acct-1');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('login verification rejected');
  });

  it('old adapter session token becomes invalid after migration', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');

    // Mint a token for the adapter session
    const {
      deriveProductTokenKey,
      mintProductSessionToken,
      validateProductSessionToken,
      matchTokenToSession,
    } = await import('../../src/heart/product-session.js');

    const tokenKey = deriveProductTokenKey(
      config.signingKeyPair.secretKey,
      provider,
    );
    const token = mintProductSessionToken(adapterSession, tokenKey, { provider });

    // Token is valid before migration
    const preCheck = validateProductSessionToken(token, tokenKey, { provider });
    expect(preCheck.ok).toBe(true);

    // Migrate
    const verification = await performLogin(service, 'did:key:z6MktestUser');
    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );
    expect(result.ok).toBe(true);

    // Token structure is still valid (MAC is fine)
    const postCheck = validateProductSessionToken(token, tokenKey, { provider });
    expect(postCheck.ok).toBe(true);
    if (!postCheck.ok) return;

    // But matching against the store should fail — session is revoked
    const stored = heart.productSessionStore.get(postCheck.claims.sid);
    expect(stored).toBeDefined();
    const matchResult = matchTokenToSession(postCheck.claims, stored!);
    expect(matchResult.ok).toBe(false);
    if (matchResult.ok) return;
    expect(matchResult.reason).toBe('session is revoked');
  });

  it('heartbeat trail records migration event', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    const heartbeats = heart.heartbeats.getChain();
    const migrationBeat = heartbeats.find(
      (h) => h.eventType === 'adapter_migration_completed',
    );
    expect(migrationBeat).toBeDefined();
    expect(migrationBeat!.eventHash).toBeTruthy();
  });

  it('heartbeat trail records denial event on failure', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    // Bind to a different identity to cause failure
    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mkother',
      bindingType: 'primary',
    });

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    const heartbeats = heart.heartbeats.getChain();
    const denialBeat = heartbeats.find(
      (h) => h.eventType === 'adapter_migration_denied',
    );
    expect(denialBeat).toBeDefined();
    expect(denialBeat!.eventHash).toBeTruthy();
  });

  it('new session gets its own sessionId distinct from the old', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const { service } = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    const verification = await performLogin(service, 'did:key:z6MktestUser');

    const result = heart.migrateAdapterToSomaDirect(
      { adapterSession, verification, bindingStore },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.newSession.sessionId).not.toBe(adapterSession.sessionId);
  });

  it('adapter-bridge issuance is unaffected by migration feature', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);

    // Mode B issuance still works as before
    const result = heart.issueAdapterBridgeSession('acct-1', {
      requestedTier: 'L2',
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Still capped at L1
    expect(result.session.currentAuthorityTier).toBe('L1');
    expect(result.session.authOrigin).toBe('adapter-bridge');
    expect(result.session.deviceBinding).toBeNull();
  });
});
