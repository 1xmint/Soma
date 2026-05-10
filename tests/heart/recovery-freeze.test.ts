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
  IdentityRecoveryCoordinator,
  InMemoryRecoveryStore,
} from '../../src/heart/recovery-coordinator.js';
import type { ProductSession } from '../../src/heart/product-session.js';

const provider = getCryptoProvider();
const SUBJECT_DID = 'did:key:z6MktestUser';

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeCoordinator() {
  return new IdentityRecoveryCoordinator(new InMemoryRecoveryStore());
}

function makeHeartConfig(
  coordinator?: IdentityRecoveryCoordinator,
): HeartConfig {
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
    recoveryCoordinator: coordinator,
  };
}

function makeLoginService(
  config: HeartConfig,
  coordinator?: IdentityRecoveryCoordinator,
  subjectDid = SUBJECT_DID,
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
    isFrozen: coordinator
      ? (did) => coordinator.isFrozen(did)
      : undefined,
  });
}

async function performLogin(
  service: LoginChallengeService,
  subjectDid = SUBJECT_DID,
): Promise<LoginVerification> {
  const challenge = service.createChallenge({
    subjectDid,
    requestedTier: 'L0',
  });
  const result = await service.verifyLogin({
    challengeId: challenge.id,
    factorId: 'webauthn-1',
    factorType: 'webauthn-platform',
    rawAssertion: provider.encoding.encodeBase64(
      provider.random.randomBytes(32),
    ),
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

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('freezeIdentity (runtime integration)', () => {
  it('freezes identity: invalidates sessions + records heartbeat', async () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config);
    const bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: SUBJECT_DID,
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const s = issueSomaSession(heart, v, 'acct-1');

    const result = heart.freezeIdentity(SUBJECT_DID, bindingStore);

    expect(result.ceremonyId).toContain('recovery-');
    expect(result.sessionsRevoked).toBeGreaterThanOrEqual(1);
    expect(result.accountsUnbound).toBe(1);

    // Session is revoked
    expect(heart.resolveProductSession(s.sessionId).ok).toBe(false);

    // Heartbeat contains identity_frozen
    const beats = heart.heartbeats.getChain();
    const freezeBeat = beats.find((b) => b.eventType === 'identity_frozen');
    expect(freezeBeat).toBeDefined();
  });

  it('throws if no coordinator is configured', () => {
    const config = makeHeartConfig(); // no coordinator
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    expect(() => heart.freezeIdentity(SUBJECT_DID, bindingStore)).toThrow(
      /not configured with a recovery coordinator/,
    );
  });

  it('throws if identity is already frozen', () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    heart.freezeIdentity(SUBJECT_DID, bindingStore);
    expect(() => heart.freezeIdentity(SUBJECT_DID, bindingStore)).toThrow(
      /already in recovery/,
    );
  });
});

describe('freeze blocks authority-establishing flows', () => {
  let coordinator: IdentityRecoveryCoordinator;
  let config: HeartConfig;
  let heart: HeartRuntime;
  let service: LoginChallengeService;
  let bindingStore: ProductAccountBindingStore;

  async function setupFrozen() {
    coordinator = makeCoordinator();
    config = makeHeartConfig(coordinator);
    heart = new HeartRuntime(config);
    service = makeLoginService(config, coordinator);
    bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: SUBJECT_DID,
      bindingType: 'primary',
    });

    // Freeze the identity
    heart.freezeIdentity(SUBJECT_DID, bindingStore);
    expect(coordinator.isFrozen(SUBJECT_DID)).toBe(true);
  }

  it('blocks issueProductSessionFromLogin', async () => {
    await setupFrozen();

    // Get a verification from before freeze (service without coordinator)
    const serviceNoFreeze = makeLoginService(config);
    const v = await performLogin(serviceNoFreeze);

    const result = heart.issueProductSessionFromLogin(v, 'acct-1');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('frozen');
  });

  it('blocks issueAdapterBridgeSession with somaIdentityBinding', async () => {
    await setupFrozen();

    const result = heart.issueAdapterBridgeSession('acct-1', {
      somaIdentityBinding: SUBJECT_DID,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('frozen');
  });

  it('allows issueAdapterBridgeSession for unrelated account with null binding', async () => {
    await setupFrozen();

    // A genuinely new/unrelated account with null binding is allowed
    const result = heart.issueAdapterBridgeSession('acct-new', {
      somaIdentityBinding: null,
    });
    expect(result.ok).toBe(true);
  });

  it('blocks issueAdapterBridgeSession for previously-bound account with null binding', async () => {
    await setupFrozen();

    // acct-1 was bound to the frozen identity at freeze time.
    // Even with null somaIdentityBinding, the account-level freeze
    // prevents re-entry during recovery.
    const result = heart.issueAdapterBridgeSession('acct-1', {
      somaIdentityBinding: null,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('frozen');
  });

  it('blocks elevateProductSession for frozen identity', async () => {
    // Setup: issue session BEFORE freeze, then try to elevate after
    coordinator = makeCoordinator();
    config = makeHeartConfig(coordinator);
    heart = new HeartRuntime(config);
    service = makeLoginService(config);
    bindingStore = new ProductAccountBindingStore();

    bindingStore.bind({
      accountId: 'acct-1',
      somaIdentityDid: SUBJECT_DID,
      bindingType: 'primary',
    });

    const v = await performLogin(service);
    const session = issueSomaSession(heart, v, 'acct-1');

    // Freeze
    heart.freezeIdentity(SUBJECT_DID, bindingStore);

    // Session was revoked by freeze, but let's try to elevate
    // by constructing a session object directly
    const fakeActiveSession = {
      ...session,
      revocationState: 'active' as const,
      somaIdentityBinding: SUBJECT_DID,
    };
    const result = heart.elevateProductSession(fakeActiveSession, 2);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('frozen');
  });

  it('blocks migrateAdapterToSomaDirect for frozen identity', async () => {
    // Setup: create an adapter session, freeze identity, then try migration
    coordinator = makeCoordinator();
    config = makeHeartConfig(coordinator);
    heart = new HeartRuntime(config);
    service = makeLoginService(config);
    bindingStore = new ProductAccountBindingStore();

    // Adapter session (no identity binding)
    const adapterResult = heart.issueAdapterBridgeSession('acct-1', {
      somaIdentityBinding: null,
    });
    if (!adapterResult.ok) throw new Error('adapter should succeed');
    const adapterSession = adapterResult.session;

    // Freeze the identity
    heart.freezeIdentity(SUBJECT_DID, bindingStore);

    // Get verification from unfrozen service
    const serviceNoFreeze = makeLoginService(config);
    const v = await performLogin(serviceNoFreeze);

    const result = heart.migrateAdapterToSomaDirect(
      {
        adapterSession,
        verification: v,
        bindingStore,
      },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('frozen');
  });

  it('blocks LoginChallengeService.createChallenge when isFrozen is set', async () => {
    await setupFrozen();

    // service was configured with isFrozen callback
    expect(() =>
      service.createChallenge({ subjectDid: SUBJECT_DID }),
    ).toThrow(/frozen.*cannot create login challenge/);
  });

  it('allows LoginChallengeService.createChallenge for unfrozen identity', async () => {
    await setupFrozen();

    const OTHER_DID = 'did:key:z6MkOtherUser';
    const factorRegistry = new FactorRegistry();
    factorRegistry.register({
      factorId: 'webauthn-other',
      factorType: 'webauthn-platform',
      subjectDid: OTHER_DID,
      publicMaterial: 'mockKey',
      attestation: null,
      isSecret: false,
      metadata: {},
    });

    const verifiers = new LoginFactorVerifierRegistry();
    verifiers.register('webauthn-platform', () => ({
      valid: true,
      tierAchieved: 1,
      hasUserVerification: true,
      hasHardwareAttestation: false,
    }));

    const otherService = new LoginChallengeService({
      heartDid: config.genome.did,
      heartPublicKey: config.genome.publicKey,
      heartSigningKey: config.signingKeyPair.secretKey,
      factorRegistry,
      verifiers,
      provider,
      isFrozen: (did) => coordinator.isFrozen(did),
    });

    // Should work for unfrozen identity
    const challenge = otherService.createChallenge({ subjectDid: OTHER_DID });
    expect(challenge).toBeDefined();
    expect(challenge.subjectDid).toBe(OTHER_DID);
  });
});

describe('freeze does not affect unrelated identities', () => {
  it('only blocks the frozen identity, not others', async () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    const OTHER_DID = 'did:key:z6MkOtherUser';

    // Bind one account to frozen DID
    bindingStore.bind({
      accountId: 'acct-frozen',
      somaIdentityDid: SUBJECT_DID,
      bindingType: 'primary',
    });

    // Freeze
    heart.freezeIdentity(SUBJECT_DID, bindingStore);

    // Issue adapter session for OTHER identity — should succeed
    const result = heart.issueAdapterBridgeSession('acct-other', {
      somaIdentityBinding: OTHER_DID,
    });
    expect(result.ok).toBe(true);
  });
});

describe('no arbitrary unfreeze via runtime', () => {
  it('recovery coordinator has no public unfreeze method', () => {
    const coordinator = makeCoordinator();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const c = coordinator as any;
    expect(c.unfreezeIdentity).toBeUndefined();
    expect(c.unfreeze).toBeUndefined();
  });

  it('only recovery completion removes frozen state', () => {
    const coordinator = makeCoordinator();
    coordinator.freezeIdentity(SUBJECT_DID);

    // The only way out is the full ceremony:
    coordinator.initiatePending(SUBJECT_DID, 'recovery-seed', 0);
    coordinator.advanceToVerifying(SUBJECT_DID, { now: Date.now() + 1 });
    coordinator.completeRecovery(SUBJECT_DID);

    expect(coordinator.isFrozen(SUBJECT_DID)).toBe(false);
  });
});

describe('recovery status is queryable', () => {
  it('status reflects ceremony lifecycle', () => {
    const coordinator = makeCoordinator();
    const T0 = 1_700_000_000_000;

    // Nominal
    expect(coordinator.getStatus(SUBJECT_DID)).toBeNull();

    // Frozen
    coordinator.freezeIdentity(SUBJECT_DID, { now: T0 });
    let status = coordinator.getStatus(SUBJECT_DID);
    expect(status).not.toBeNull();
    expect(status!.state).toBe('frozen');
    expect(status!.frozenAt).toBe(T0);

    // Pending
    coordinator.initiatePending(SUBJECT_DID, 'recovery-seed', 1000, { now: T0 + 100 });
    status = coordinator.getStatus(SUBJECT_DID);
    expect(status!.state).toBe('pending');
    expect(status!.evidenceType).toBe('recovery-seed');
    expect(status!.timeLockExpiresAt).toBe(T0 + 1100);

    // Cancelled → back to frozen
    coordinator.cancelRecovery(SUBJECT_DID, { now: T0 + 200 });
    status = coordinator.getStatus(SUBJECT_DID);
    expect(status!.state).toBe('frozen');
    expect(status!.cancelledAt).toBe(T0 + 200);

    // Re-initiate → verify → complete
    coordinator.initiatePending(SUBJECT_DID, 'guardian-quorum', 0, { now: T0 + 300 });
    coordinator.advanceToVerifying(SUBJECT_DID, { now: T0 + 301 });
    status = coordinator.getStatus(SUBJECT_DID);
    expect(status!.state).toBe('verifying');

    coordinator.completeRecovery(SUBJECT_DID, { now: T0 + 400 });
    expect(coordinator.getStatus(SUBJECT_DID)).toBeNull();
  });

  it('status is accessible from runtime via recoveryCoordinator accessor', () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);

    expect(heart.recoveryCoordinator).toBe(coordinator);

    coordinator.freezeIdentity(SUBJECT_DID);
    const status = heart.recoveryCoordinator!.getStatus(SUBJECT_DID);
    expect(status).not.toBeNull();
    expect(status!.state).toBe('frozen');
  });
});

describe('heartbeat events', () => {
  it('freeze produces identity_frozen heartbeat', async () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    heart.freezeIdentity(SUBJECT_DID, bindingStore);

    const beats = heart.heartbeats.getChain();
    const events = beats.map((b) => b.eventType);
    expect(events).toContain('identity_frozen');
  });

  it('blocked issueProductSessionFromLogin produces product_session_denied', async () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const service = makeLoginService(config); // no freeze check on service
    const bindingStore = new ProductAccountBindingStore();

    const v = await performLogin(service);

    heart.freezeIdentity(SUBJECT_DID, bindingStore);
    heart.issueProductSessionFromLogin(v, 'acct-1');

    const beats = heart.heartbeats.getChain();
    const deniedBeat = beats.find(
      (b) => b.eventType === 'product_session_denied',
    );
    expect(deniedBeat).toBeDefined();
  });

  it('blocked adapter session produces adapter_session_denied', async () => {
    const coordinator = makeCoordinator();
    const config = makeHeartConfig(coordinator);
    const heart = new HeartRuntime(config);
    const bindingStore = new ProductAccountBindingStore();

    heart.freezeIdentity(SUBJECT_DID, bindingStore);
    heart.issueAdapterBridgeSession('acct-1', {
      somaIdentityBinding: SUBJECT_DID,
    });

    const beats = heart.heartbeats.getChain();
    const deniedBeat = beats.find(
      (b) => b.eventType === 'adapter_session_denied',
    );
    expect(deniedBeat).toBeDefined();
  });
});
