import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import { FactorRegistry } from '../../src/heart/factor-registry.js';
import {
  StepUpService,
  FactorVerifierRegistry,
  verifyChallengeSignature,
  verifyStepUpAttestation,
  computeActionDigest,
  type FactorAssertion,
  type FactorAssertionVerifier,
} from '../../src/heart/stepup.js';

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function setup(opts: {
  verifierResult?: { valid: boolean; reason?: string; tierAchieved?: number };
  now?: () => number;
} = {}) {
  const heart = makeIdentity();
  const subject = makeIdentity();
  const registry = new FactorRegistry();
  registry.register({
    factorId: 'f-1',
    factorType: 'webauthn-platform',
    subjectDid: subject.did,
    publicMaterial: 'cGs=',
    attestation: null,
    isSecret: false,
    metadata: { deviceId: 'iphone' },
  });

  const verifiers = new FactorVerifierRegistry();
  const verifier: FactorAssertionVerifier = () =>
    opts.verifierResult ?? { valid: true, tierAchieved: 2 };
  verifiers.register('webauthn-platform', verifier);

  const service = new StepUpService({
    heartDid: heart.did,
    heartPublicKey: heart.publicKey,
    heartSigningKey: heart.kp.secretKey,
    factorRegistry: registry,
    verifiers,
    now: opts.now,
    defaultTtlMs: 60_000,
  });

  return { heart, subject, registry, verifiers, service };
}

function assertion(
  challengeId: string,
  overrides: Partial<FactorAssertion> = {},
): FactorAssertion {
  return {
    challengeId,
    factorId: 'f-1',
    factorType: 'webauthn-platform',
    rawAssertion: 'cmF3',
    assertedAt: Date.now(),
    ...overrides,
  };
}

describe('StepUpService — createChallenge', () => {
  it('emits a signed challenge with the expected fields', () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'digest-1',
      minTier: 2,
    });
    expect(ch.protocol).toBe('soma-stepup/1');
    expect(ch.subjectDid).toBe(subject.did);
    expect(ch.actionDigest).toBe('digest-1');
    expect(ch.minTier).toBe(2);
    expect(ch.expiresAt).toBeGreaterThan(ch.issuedAt);
    expect(verifyChallengeSignature(ch).valid).toBe(true);
    expect(service.outstandingCount()).toBe(1);
  });

  it('tampered challenge fails signature check', () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'digest-1',
      minTier: 1,
    });
    const tampered = { ...ch, minTier: 0 };
    expect(verifyChallengeSignature(tampered).valid).toBe(false);
  });
});

describe('StepUpService — submitAttestation happy path', () => {
  it('accepts a valid assertion and mints an attestation', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 2,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.attestation.challengeId).toBe(ch.id);
    expect(res.attestation.tierAchieved).toBe(2);
    expect(res.attestation.subjectDid).toBe(subject.did);
    expect(service.outstandingCount()).toBe(0);
  });

  it('consuming a challenge prevents replay', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const first = await service.submitAttestation(assertion(ch.id));
    expect(first.ok).toBe(true);
    const second = await service.submitAttestation(assertion(ch.id));
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toMatch(/already consumed/);
  });

  it('runs evaluateTier to cap or raise the reported tier', async () => {
    const heart = makeIdentity();
    const subject = makeIdentity();
    const registry = new FactorRegistry();
    registry.register({
      factorId: 'f-1',
      factorType: 'webauthn-platform',
      subjectDid: subject.did,
      publicMaterial: 'cGs=',
      attestation: null,
      isSecret: false,
      metadata: {},
    });
    const verifiers = new FactorVerifierRegistry();
    verifiers.register('webauthn-platform', () => ({ valid: true, tierAchieved: 3 }));
    const service = new StepUpService({
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      factorRegistry: registry,
      verifiers,
      evaluateTier: () => 1, // policy caps to 1
    });
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.attestation.tierAchieved).toBe(1);
  });
});

describe('StepUpService — fail paths', () => {
  it('rejects unknown challenge id', async () => {
    const { service } = setup();
    const res = await service.submitAttestation(assertion('bogus'));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/unknown challenge/);
  });

  it('rejects expired challenge', async () => {
    let t = 1000;
    const { service, subject } = setup({ now: () => t });
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
      ttlMs: 500,
    });
    t = 99999;
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/expired/);
  });

  it('rejects if factor is not registered', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id, { factorId: 'ghost' }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/not registered/);
  });

  it('rejects if factor was revoked', async () => {
    const { service, subject, registry } = setup();
    registry.revoke(subject.did, 'f-1');
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/revoked/);
  });

  it('rejects if assertion factor type mismatches registration', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(
      assertion(ch.id, { factorType: 'totp' }),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/factor type mismatch|no verifier/);
  });

  it('rejects if no verifier is registered for the factor type', async () => {
    const heart = makeIdentity();
    const subject = makeIdentity();
    const registry = new FactorRegistry();
    registry.register({
      factorId: 'f-1',
      factorType: 'exotic-factor',
      subjectDid: subject.did,
      publicMaterial: 'x',
      attestation: null,
      isSecret: false,
      metadata: {},
    });
    const service = new StepUpService({
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      factorRegistry: registry,
      verifiers: new FactorVerifierRegistry(),
    });
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(
      assertion(ch.id, { factorType: 'exotic-factor' }),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/no verifier/);
  });

  it('rejects if the verifier reports invalid', async () => {
    const { service, subject } = setup({
      verifierResult: { valid: false, reason: 'bad signature' },
    });
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/bad signature/);
  });

  it('rejects if tier achieved is below required', async () => {
    const { service, subject } = setup({
      verifierResult: { valid: true, tierAchieved: 1 },
    });
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 3,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/tier achieved/);
  });
});

describe('StepUpService — housekeeping', () => {
  it('pruneExpired drops stale challenges', () => {
    let t = 1000;
    const { service, subject } = setup({ now: () => t });
    service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'a',
      minTier: 1,
      ttlMs: 100,
    });
    service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'b',
      minTier: 1,
      ttlMs: 100_000,
    });
    expect(service.outstandingCount()).toBe(2);
    t = 1000 + 500;
    const dropped = service.pruneExpired();
    expect(dropped).toBe(1);
    expect(service.outstandingCount()).toBe(1);
  });
});

describe('verifyStepUpAttestation', () => {
  it('accepts a round-tripped attestation', async () => {
    const { service, subject, heart } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const v = verifyStepUpAttestation(res.attestation, {
      expectedActionDigest: 'd',
      expectedSubjectDid: subject.did,
      minTier: 1,
      trustedHeartPublicKeys: [heart.publicKey],
    });
    expect(v.valid).toBe(true);
  });

  it('rejects action digest mismatch', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const v = verifyStepUpAttestation(res.attestation, {
      expectedActionDigest: 'OTHER',
      expectedSubjectDid: subject.did,
      minTier: 1,
    });
    expect(v.valid).toBe(false);
    if (!v.valid) expect(v.reason).toMatch(/digest mismatch/);
  });

  it('rejects subject mismatch', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const v = verifyStepUpAttestation(res.attestation, {
      expectedActionDigest: 'd',
      expectedSubjectDid: 'did:key:zOther',
      minTier: 1,
    });
    expect(v.valid).toBe(false);
    if (!v.valid) expect(v.reason).toMatch(/subject mismatch/);
  });

  it('rejects too-old attestations', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const v = verifyStepUpAttestation(res.attestation, {
      expectedActionDigest: 'd',
      expectedSubjectDid: subject.did,
      minTier: 1,
      maxAgeMs: 1,
      now: res.attestation.acceptedAt + 10_000,
    });
    expect(v.valid).toBe(false);
    if (!v.valid) expect(v.reason).toMatch(/too old/);
  });

  it('rejects untrusted heart public key', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const v = verifyStepUpAttestation(res.attestation, {
      expectedActionDigest: 'd',
      expectedSubjectDid: subject.did,
      minTier: 1,
      trustedHeartPublicKeys: ['ZmFrZQ=='],
    });
    expect(v.valid).toBe(false);
    if (!v.valid) expect(v.reason).toMatch(/not trusted/);
  });

  it('rejects tampered attestation', async () => {
    const { service, subject } = setup();
    const ch = service.createChallenge({
      subjectDid: subject.did,
      actionDigest: 'd',
      minTier: 1,
    });
    const res = await service.submitAttestation(assertion(ch.id));
    if (!res.ok) throw new Error('expected ok');
    const tampered = { ...res.attestation, tierAchieved: 99 };
    const v = verifyStepUpAttestation(tampered, {
      expectedActionDigest: 'd',
      expectedSubjectDid: subject.did,
      minTier: 1,
    });
    expect(v.valid).toBe(false);
  });
});

describe('computeActionDigest', () => {
  it('is deterministic regardless of key order', () => {
    const a = computeActionDigest({ host: 'h', argv: ['ls'], cwd: '/tmp' });
    const b = computeActionDigest({ cwd: '/tmp', argv: ['ls'], host: 'h' });
    expect(a).toBe(b);
  });

  it('differs for different actions', () => {
    const a = computeActionDigest({ argv: ['ls'] });
    const b = computeActionDigest({ argv: ['rm', '-rf', '/'] });
    expect(a).not.toBe(b);
  });
});
