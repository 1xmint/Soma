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
  validateProductSessionToken,
  matchTokenToSession,
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

function makeLoginService(
  config: HeartConfig,
  subjectDid = 'did:key:z6MktestUser',
) {
  const factorRegistry = new FactorRegistry();
  const verifiers = new LoginFactorVerifierRegistry();

  factorRegistry.register({
    factorId: 'webauthn-1',
    factorType: 'webauthn-platform',
    subjectDid,
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
  subjectDid = 'did:key:z6MktestUser',
): Promise<LoginVerification> {
  const challenge = service.createChallenge({
    subjectDid,
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
): ProductSession {
  const result = heart.issueProductSessionFromLogin(verification, accountId);
  if (!result.ok) throw new Error(`session failed: ${result.reason}`);
  return result.session;
}

function issueAdapterSession(
  heart: HeartRuntime,
  accountId: string,
  opts?: { somaIdentityBinding?: string | null },
): ProductSession {
  const result = heart.issueAdapterBridgeSession(accountId, {
    somaIdentityBinding: opts?.somaIdentityBinding ?? null,
  });
  if (!result.ok) throw new Error(`adapter session failed: ${result.reason}`);
  return result.session;
}

function mintToken(config: HeartConfig, session: ProductSession): string {
  const tokenKey = deriveProductTokenKey(config.signingKeyPair.secretKey, provider);
  return mintProductSessionToken(session, tokenKey, { provider });
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('invalidateIdentitySessions', () => {
  it('revokes sessions for all accounts bound to the identity', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    // Bind two accounts to the same identity
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

    const v1 = await performLogin(service);
    const s1 = issueSomaSession(heart, v1, 'acct-1');

    const v2 = await performLogin(service);
    const s2 = issueSomaSession(heart, v2, 'acct-2');

    const result = heart.invalidateIdentitySessions(
      'did:key:z6MktestUser',
      bindingStore,
    );

    expect(result.accountsUnbound).toBe(2);
    expect(result.sessionsRevoked).toBe(2);

    expect(heart.resolveProductSession(s1.sessionId).ok).toBe(false);
    expect(heart.resolveProductSession(s2.sessionId).ok).toBe(false);
  });

  it('does not affect accounts bound to a different identity', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });
    bindingStore.bind({
      accountId: 'acct-other',
      somaIdentityDid: 'did:key:z6MkotherUser',
      bindingType: 'primary',
    });

    const v1 = await performLogin(service);
    const s1 = issueSomaSession(heart, v1, 'acct-1');

    // Issue an adapter session for the other account with a different identity
    const sOther = issueAdapterSession(heart, 'acct-other', {
      somaIdentityBinding: 'did:key:z6MkotherUser',
    });

    const result = heart.invalidateIdentitySessions(
      'did:key:z6MktestUser',
      bindingStore,
    );

    expect(result.accountsUnbound).toBe(1);
    // s1 revoked
    expect(heart.resolveProductSession(s1.sessionId).ok).toBe(false);
    // sOther unaffected — different identity
    expect(heart.resolveProductSession(sOther.sessionId).ok).toBe(true);
    // Other binding still active
    expect(bindingStore.getActive('acct-other')).toBeDefined();
  });

  it('revoked sessions remain distinguishable from unknown sessions', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const s = issueSomaSession(heart, v, 'acct-1');

    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    // Revoked session returns 'session is revoked'
    const revokedResult = heart.resolveProductSession(s.sessionId);
    expect(revokedResult.ok).toBe(false);
    if (!revokedResult.ok) {
      expect(revokedResult.reason).toBe('session is revoked');
    }

    // Unknown session returns 'session not found'
    const unknownResult = heart.resolveProductSession('nonexistent-id');
    expect(unknownResult.ok).toBe(false);
    if (!unknownResult.ok) {
      expect(unknownResult.reason).toContain('session not found');
    }
  });

  it('token resolution fails cleanly after identity-driven invalidation', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const s = issueSomaSession(heart, v, 'acct-1');
    const token = mintToken(config, s);

    // Token works before invalidation
    const tokenKey = deriveProductTokenKey(config.signingKeyPair.secretKey, provider);
    const preCheck = validateProductSessionToken(token, tokenKey, { provider });
    expect(preCheck.ok).toBe(true);

    // Invalidate
    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    // Token structure still valid (MAC is fine)
    const postCheck = validateProductSessionToken(token, tokenKey, { provider });
    expect(postCheck.ok).toBe(true);
    if (!postCheck.ok) return;

    // But session match fails — session is revoked
    const stored = heart.productSessionStore.get(postCheck.claims.sid);
    expect(stored).toBeDefined();
    const matchResult = matchTokenToSession(postCheck.claims, stored!);
    expect(matchResult.ok).toBe(false);
    if (!matchResult.ok) {
      expect(matchResult.reason).toBe('session is revoked');
    }
  });

  it('adapter-bridge sessions with matching somaIdentityBinding are revoked', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    // Adapter session carries a somaIdentityBinding but no formal binding in store
    const adapterSession = issueAdapterSession(heart, 'acct-1', {
      somaIdentityBinding: 'did:key:z6MktestUser',
    });
    expect(adapterSession.authOrigin).toBe('adapter-bridge');
    expect(adapterSession.somaIdentityBinding).toBe('did:key:z6MktestUser');

    const result = heart.invalidateIdentitySessions(
      'did:key:z6MktestUser',
      bindingStore,
    );

    // No bindings to unbind (adapter session has no formal binding)
    expect(result.accountsUnbound).toBe(0);
    // But the session was caught by the belt-and-suspenders revokeByIdentity
    expect(result.sessionsRevoked).toBe(1);

    const resolved = heart.resolveProductSession(adapterSession.sessionId);
    expect(resolved.ok).toBe(false);
  });

  it('adapter-bridge sessions with null somaIdentityBinding are unaffected', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    const adapterSession = issueAdapterSession(heart, 'acct-1');
    expect(adapterSession.somaIdentityBinding).toBeNull();

    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    const resolved = heart.resolveProductSession(adapterSession.sessionId);
    expect(resolved.ok).toBe(true);
  });

  it('authOrigin provenance preserved on revoked sessions', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const s = issueSomaSession(heart, v, 'acct-1');

    // Also issue an adapter session bound to same identity
    const adapterSession = issueAdapterSession(heart, 'acct-adapter', {
      somaIdentityBinding: 'did:key:z6MktestUser',
    });

    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    // Both revoked, but provenance preserved
    const storedDirect = heart.productSessionStore.get(s.sessionId);
    expect(storedDirect!.revocationState).toBe('revoked');
    expect(storedDirect!.authOrigin).toBe('soma-direct');

    const storedAdapter = heart.productSessionStore.get(adapterSession.sessionId);
    expect(storedAdapter!.revocationState).toBe('revoked');
    expect(storedAdapter!.authOrigin).toBe('adapter-bridge');
  });

  it('bindings are dissolved after invalidation', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    issueSomaSession(heart, v, 'acct-1');

    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    // Binding dissolved
    expect(bindingStore.getActive('acct-1')).toBeUndefined();
    // But historical record preserved
    const binding = bindingStore.get('acct-1');
    expect(binding).toBeDefined();
    expect(binding!.unboundAt).not.toBeNull();
  });

  it('records identity_sessions_invalidated heartbeat', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    issueSomaSession(heart, v, 'acct-1');

    heart.invalidateIdentitySessions('did:key:z6MktestUser', bindingStore);

    const chain = heart.heartbeats.getChain();
    const beat = chain.find(h => h.eventType === 'identity_sessions_invalidated');
    expect(beat).toBeDefined();
    expect(beat!.eventHash).toBeTruthy();
  });

  it('heartbeat recorded even when no accounts/sessions matched', () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    const result = heart.invalidateIdentitySessions(
      'did:key:z6MknonexistentUser',
      bindingStore,
    );

    expect(result.accountsUnbound).toBe(0);
    expect(result.sessionsRevoked).toBe(0);

    const chain = heart.heartbeats.getChain();
    const beat = chain.find(h => h.eventType === 'identity_sessions_invalidated');
    expect(beat).toBeDefined();
  });

  it('does not double-count sessions already revoked by account cascade', async () => {
    const config = makeHeartConfig();
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6MktestUser',
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const s = issueSomaSession(heart, v, 'acct-1');
    // Session carries somaIdentityBinding AND is under a bound account
    expect(s.somaIdentityBinding).toBe('did:key:z6MktestUser');

    const result = heart.invalidateIdentitySessions(
      'did:key:z6MktestUser',
      bindingStore,
    );

    // revokeByAccount gets it first; revokeByIdentity sees it's already revoked
    expect(result.sessionsRevoked).toBe(1);
  });
});
