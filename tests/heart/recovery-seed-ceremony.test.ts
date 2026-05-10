import { describe, it, expect, beforeEach } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import { domainSigningInput } from '../../src/core/canonicalize.js';
import {
  FactorRegistry,
  WELL_KNOWN_FACTOR_TYPES,
} from '../../src/heart/factor-registry.js';
import {
  IdentityRecoveryCoordinator,
  InMemoryRecoveryStore,
} from '../../src/heart/recovery-coordinator.js';
import {
  RecoverySeedCeremonyService,
  type RecoverySeedEvidence,
  type RecoveryChallenge,
} from '../../src/heart/recovery-seed-ceremony.js';
import { ProductAccountBindingStore } from '../../src/heart/product-account-binding.js';

const crypto = getCryptoProvider();
const MOCK_ROTATION_HASH = 'rotation-event-hash-abc123';

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function signRecoveryEvidence(
  challenge: RecoveryChallenge,
  seedSecretKey: Uint8Array,
): string {
  const { signature: _, ...payload } = challenge;
  const signingInput = domainSigningInput('soma/recovery-evidence/v1', payload);
  const sig = crypto.signing.sign(signingInput, seedSecretKey);
  return crypto.encoding.encodeBase64(sig);
}

function setup(opts: { now?: () => number } = {}) {
  const heart = makeIdentity();
  const identity = makeIdentity();
  const seed = makeIdentity();

  const factorRegistry = new FactorRegistry();
  factorRegistry.register({
    factorId: 'seed-1',
    factorType: WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
    subjectDid: identity.did,
    publicMaterial: seed.publicKey,
    attestation: null,
    isSecret: false,
    metadata: { medium: 'steel-plate' },
  });

  const store = new InMemoryRecoveryStore();
  const coordinator = new IdentityRecoveryCoordinator(store, {
    now: opts.now,
  });

  const events: Array<{ type: string; data: string }> = [];

  const ceremony = new RecoverySeedCeremonyService({
    heartDid: heart.did,
    heartPublicKey: heart.publicKey,
    heartSigningKey: heart.kp.secretKey,
    factorRegistry,
    coordinator,
    now: opts.now,
    provider: crypto,
    onEvent: (type, data) => events.push({ type, data }),
    verifyRotation: () => true,
  });

  return {
    heart,
    identity,
    seed,
    factorRegistry,
    coordinator,
    ceremony,
    events,
  };
}

function makeEvidence(
  challenge: RecoveryChallenge,
  seedSecretKey: Uint8Array,
  overrides: Partial<RecoverySeedEvidence> = {},
): RecoverySeedEvidence {
  return {
    challengeId: challenge.id,
    factorId: 'seed-1',
    factorType: 'recovery-seed',
    rawSignature: signRecoveryEvidence(challenge, seedSecretKey),
    assertedAt: challenge.issuedAt,
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('RecoverySeedCeremonyService', () => {
  // ─── createRecoveryChallenge ──────────────────────────────────────────

  describe('createRecoveryChallenge', () => {
    it('creates a signed challenge for a frozen identity', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);

      expect(ch.protocol).toBe('soma-recovery/1');
      expect(ch.identityDid).toBe(identity.did);
      expect(ch.issuedAt).toBe(T0);
      expect(ch.expiresAt).toBe(T0 + 600_000);
      expect(ch.signature).toBeTruthy();
      expect(ch.nonce).toBeTruthy();
      expect(ch.id).toMatch(/^rc-/);
      expect(ch.heartDid).toBeTruthy();
      expect(ch.heartPublicKey).toBeTruthy();
    });

    it('binds the challenge to the ceremony ID', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      const { ceremonyId } = coordinator.freezeIdentity(identity.did, {
        now: T0,
      });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      expect(ch.ceremonyId).toBe(ceremonyId);
    });

    it('throws if identity is not frozen', () => {
      const { identity, ceremony } = setup();
      expect(() => ceremony.createRecoveryChallenge(identity.did)).toThrow(
        /not in recovery/,
      );
    });

    it('throws if identity is in pending state', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });
      coordinator.initiatePending(identity.did, 'recovery-seed', 60_000, {
        now: T0,
      });

      expect(() => ceremony.createRecoveryChallenge(identity.did)).toThrow(
        /recovery challenge requires 'frozen'/,
      );
    });

    it('throws if identity has no active recovery-seed factor', () => {
      const T0 = 1_700_000_000_000;
      const other = makeIdentity();
      const { coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(other.did, { now: T0 });

      expect(() => ceremony.createRecoveryChallenge(other.did)).toThrow(
        /no active recovery-seed factor/,
      );
    });

    it('uses custom TTL when provided', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did, {
        ttlMs: 30_000,
      });
      expect(ch.expiresAt).toBe(T0 + 30_000);
    });

    it('increments outstanding count', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      expect(ceremony.outstandingCount()).toBe(0);
      ceremony.createRecoveryChallenge(identity.did);
      expect(ceremony.outstandingCount()).toBe(1);
      ceremony.createRecoveryChallenge(identity.did);
      expect(ceremony.outstandingCount()).toBe(2);
    });

    it('challenge signature is verifiable by the heart public key', () => {
      const T0 = 1_700_000_000_000;
      const { identity, heart, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);

      const { signature, ...payload } = ch;
      const signingInput = domainSigningInput(
        'soma/recovery-challenge/v1',
        payload,
      );
      const sigBytes = crypto.encoding.decodeBase64(signature);
      const pubKey = crypto.encoding.decodeBase64(heart.publicKey);
      expect(crypto.signing.verify(signingInput, sigBytes, pubKey)).toBe(true);
    });
  });

  // ─── submitRecoveryEvidence ───────────────────────────────────────────

  describe('submitRecoveryEvidence', () => {
    it('accepts valid seed evidence and advances to pending', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      const evidence = makeEvidence(ch, seed.kp.secretKey);

      const result = ceremony.submitRecoveryEvidence(
        evidence,
        72 * 3600_000,
        { now: T0 },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.ceremony.state).toBe('pending');
        expect(result.ceremony.evidenceType).toBe('recovery-seed');
        expect(result.ceremony.timeLockExpiresAt).toBe(T0 + 72 * 3600_000);
      }

      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');
    });

    it('rejects replayed challenge', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      const evidence = makeEvidence(ch, seed.kp.secretKey);

      ceremony.submitRecoveryEvidence(evidence, 60_000, { now: T0 });
      const replay = ceremony.submitRecoveryEvidence(evidence, 60_000, {
        now: T0,
      });

      expect(replay.ok).toBe(false);
      if (!replay.ok) expect(replay.reason).toContain('already consumed');
    });

    it('rejects unknown challenge ID', () => {
      const T0 = 1_700_000_000_000;
      const { ceremony } = setup({ now: () => T0 });

      const result = ceremony.submitRecoveryEvidence(
        {
          challengeId: 'rc-nonexistent',
          factorId: 'seed-1',
          factorType: 'recovery-seed',
          rawSignature: 'AAAA',
          assertedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('unknown challenge');
    });

    it('rejects expired challenge', () => {
      const T0 = 1_700_000_000_000;
      let now = T0;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => now,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did, {
        ttlMs: 60_000,
      });
      const evidence = makeEvidence(ch, seed.kp.secretKey);

      now = T0 + 120_000;
      const result = ceremony.submitRecoveryEvidence(evidence, 60_000, {
        now,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('expired');
    });

    it('rejects invalid seed signature', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      const wrongKey = makeIdentity();
      const evidence = makeEvidence(ch, wrongKey.kp.secretKey);

      const result = ceremony.submitRecoveryEvidence(evidence, 60_000, {
        now: T0,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('signature verification failed');
    });

    it('rejects unregistered factor ID', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      const evidence = makeEvidence(ch, seed.kp.secretKey, {
        factorId: 'nonexistent-seed',
      });

      const result = ceremony.submitRecoveryEvidence(evidence, 60_000, {
        now: T0,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('not registered');
    });

    it('rejects revoked recovery-seed factor', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });

      // Register a second seed so challenge creation works after revoking the first
      const seed2 = makeIdentity();
      factorRegistry.register({
        factorId: 'seed-2',
        factorType: WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
        subjectDid: identity.did,
        publicMaterial: seed2.publicKey,
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremony.createRecoveryChallenge(identity.did);

      // Revoke seed-1 AFTER challenge creation
      factorRegistry.revoke(identity.did, 'seed-1', T0);

      const evidence = makeEvidence(ch, seed.kp.secretKey);
      const result = ceremony.submitRecoveryEvidence(evidence, 60_000, {
        now: T0,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('revoked');
    });

    it('rejects wrong factor type on registered factor', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony, factorRegistry } = setup({
        now: () => T0,
      });

      // Register a non-seed factor with the same ID pattern
      const otherKey = makeIdentity();
      factorRegistry.register({
        factorId: 'totp-1',
        factorType: WELL_KNOWN_FACTOR_TYPES.TOTP,
        subjectDid: identity.did,
        publicMaterial: otherKey.publicKey,
        attestation: null,
        isSecret: true,
        metadata: {},
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremony.createRecoveryChallenge(identity.did);

      const result = ceremony.submitRecoveryEvidence(
        {
          challengeId: ch.id,
          factorId: 'totp-1',
          factorType: 'recovery-seed',
          rawSignature: 'AAAA',
          assertedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('not a recovery-seed type');
    });

    it('consumes the challenge on success', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      expect(ceremony.outstandingCount()).toBe(1);

      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(ceremony.outstandingCount()).toBe(0);
    });

    it('marks the factor as used', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      expect(factorRegistry.get(identity.did, 'seed-1')?.lastUsedAt).toBeNull();

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(factorRegistry.get(identity.did, 'seed-1')?.lastUsedAt).toBe(T0);
    });

    it('emits recovery_initiated event', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony, events } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        72 * 3600_000,
        { now: T0 },
      );

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_initiated');
      const data = JSON.parse(events[0].data);
      expect(data.identityDid).toBe(identity.did);
      expect(data.evidenceType).toBe('recovery-seed');
      expect(data.timeLockMs).toBe(72 * 3600_000);
      expect(data.factorId).toBe('seed-1');
    });

    it('prevents cross-protocol signature replay (wrong domain)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);

      // Sign under the challenge domain instead of evidence domain
      const { signature: _, ...payload } = ch;
      const wrongDomainInput = domainSigningInput(
        'soma/recovery-challenge/v1',
        payload,
      );
      const wrongSig = crypto.signing.sign(
        wrongDomainInput,
        seed.kp.secretKey,
      );

      const result = ceremony.submitRecoveryEvidence(
        {
          challengeId: ch.id,
          factorId: 'seed-1',
          factorType: 'recovery-seed',
          rawSignature: crypto.encoding.encodeBase64(wrongSig),
          assertedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('signature verification failed');
    });
  });

  // ─── cancelRecovery ───────────────────────────────────────────────────

  describe('cancelRecovery', () => {
    it('cancels a pending recovery and reverts to frozen', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');

      const cancelled = ceremony.cancelRecovery(identity.did, {
        now: T0 + 1000,
      });
      expect(cancelled).toBe(true);
      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');
    });

    it('emits recovery_cancelled event', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony, events } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );
      events.length = 0;

      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_cancelled');
      const data = JSON.parse(events[0].data);
      expect(data.identityDid).toBe(identity.did);
    });

    it('returns false for non-pending identity', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      expect(ceremony.cancelRecovery(identity.did)).toBe(false);
    });

    it('does not emit event when cancellation is a no-op', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony, events } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      ceremony.cancelRecovery(identity.did);
      expect(events).toHaveLength(0);
    });

    it('allows re-challenge after cancellation', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // First attempt
      const ch1 = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch1, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );
      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      // Second attempt — must be able to create a new challenge
      const ch2 = ceremony.createRecoveryChallenge(identity.did);
      expect(ch2.id).not.toBe(ch1.id);

      const result = ceremony.submitRecoveryEvidence(
        makeEvidence(ch2, seed.kp.secretKey),
        0,
        { now: T0 + 2000 },
      );
      expect(result.ok).toBe(true);
    });
  });

  // ─── advanceToVerifying ───────────────────────────────────────────────

  describe('advanceToVerifying', () => {
    it('advances to verifying after time-lock expires', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 60_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        TIME_LOCK,
        { now: T0 },
      );

      const result = ceremony.advanceToVerifying(identity.did, {
        now: T0 + TIME_LOCK + 1,
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.ceremony.state).toBe('verifying');
      }
    });

    it('rejects advancement before time-lock expiry', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 60_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        TIME_LOCK,
        { now: T0 },
      );

      const result = ceremony.advanceToVerifying(identity.did, {
        now: T0 + TIME_LOCK - 1,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('time-lock');
    });

    it('emits recovery_verifying event', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony, events } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      events.length = 0;

      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_verifying');
    });

    it('rejects advancement from frozen state', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const result = ceremony.advanceToVerifying(identity.did, { now: T0 });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain("expected 'pending'");
    });
  });

  // ─── completeRecovery ─────────────────────────────────────────────────

  describe('completeRecovery', () => {
    it('completes recovery when new authenticator is enrolled', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: { deviceId: 'new-iphone' },
      });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.ceremony.completedAt).toBe(T0 + 2);
      }

      expect(coordinator.isFrozen(identity.did)).toBe(false);
    });

    it('rejects completion without non-recovery-seed authenticator', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          'no non-recovery-seed authenticator',
        );

      expect(coordinator.isFrozen(identity.did)).toBe(true);
    });

    it('rejects completion from pending state (not verifying)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        60_000,
        { now: T0 },
      );

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 1,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          "'pending' state, expected 'verifying'",
        );
    });

    it('emits recovery_completed event with rotationEventHash', () => {
      const T0 = 1_700_000_000_000;
      const {
        identity,
        seed,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });
      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });
      events.length = 0;

      ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_completed');
      const data = JSON.parse(events[0].data);
      expect(data.identityDid).toBe(identity.did);
      expect(data.completedAt).toBe(T0 + 2);
      expect(data.rotationEventHash).toBe(MOCK_ROTATION_HASH);
    });

    it('rejects completion for unknown identity', () => {
      const T0 = 1_700_000_000_000;
      const { ceremony } = setup({ now: () => T0 });
      const unknown = makeIdentity();

      const result = ceremony.completeRecovery(unknown.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          'no non-recovery-seed authenticator',
        );
    });

    it('rejects completion without rotation event hash', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: '',
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('credential rotation event hash required');
    });

    it('rejects completion when verifyRotation is not configured', () => {
      const T0 = 1_700_000_000_000;
      const heart = makeIdentity();
      const identity = makeIdentity();
      const seed = makeIdentity();

      const factorRegistry = new FactorRegistry();
      factorRegistry.register({
        factorId: 'seed-1',
        factorType: WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
        subjectDid: identity.did,
        publicMaterial: seed.publicKey,
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const store = new InMemoryRecoveryStore();
      const coordinator = new IdentityRecoveryCoordinator(store, {
        now: () => T0,
      });

      const ceremonyNoVerify = new RecoverySeedCeremonyService({
        heartDid: heart.did,
        heartPublicKey: heart.publicKey,
        heartSigningKey: heart.kp.secretKey,
        factorRegistry,
        coordinator,
        now: () => T0,
        provider: crypto,
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremonyNoVerify.createRecoveryChallenge(identity.did);
      ceremonyNoVerify.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremonyNoVerify.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremonyNoVerify.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('verifyRotation callback not configured');
    });

    it('rejects completion when verifyRotation callback returns false', () => {
      const T0 = 1_700_000_000_000;
      const heart = makeIdentity();
      const identity = makeIdentity();
      const seed = makeIdentity();

      const factorRegistry = new FactorRegistry();
      factorRegistry.register({
        factorId: 'seed-1',
        factorType: WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
        subjectDid: identity.did,
        publicMaterial: seed.publicKey,
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const store = new InMemoryRecoveryStore();
      const coordinator = new IdentityRecoveryCoordinator(store, {
        now: () => T0,
      });

      const ceremonyWithVerify = new RecoverySeedCeremonyService({
        heartDid: heart.did,
        heartPublicKey: heart.publicKey,
        heartSigningKey: heart.kp.secretKey,
        factorRegistry,
        coordinator,
        now: () => T0,
        provider: crypto,
        verifyRotation: () => false,
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremonyWithVerify.createRecoveryChallenge(identity.did);
      ceremonyWithVerify.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremonyWithVerify.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremonyWithVerify.completeRecovery(identity.did, {
        rotationEventHash: 'bad-hash',
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('credential rotation verification failed');
    });

    it('passes completion when verifyRotation callback returns true', () => {
      const T0 = 1_700_000_000_000;
      const heart = makeIdentity();
      const identity = makeIdentity();
      const seed = makeIdentity();

      const factorRegistry = new FactorRegistry();
      factorRegistry.register({
        factorId: 'seed-1',
        factorType: WELL_KNOWN_FACTOR_TYPES.RECOVERY_SEED,
        subjectDid: identity.did,
        publicMaterial: seed.publicKey,
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const store = new InMemoryRecoveryStore();
      const coordinator = new IdentityRecoveryCoordinator(store, {
        now: () => T0,
      });

      let verifiedDid = '';
      let verifiedHash = '';
      const ceremonyWithVerify = new RecoverySeedCeremonyService({
        heartDid: heart.did,
        heartPublicKey: heart.publicKey,
        heartSigningKey: heart.kp.secretKey,
        factorRegistry,
        coordinator,
        now: () => T0,
        provider: crypto,
        verifyRotation: (did, hash) => {
          verifiedDid = did;
          verifiedHash = hash;
          return true;
        },
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremonyWithVerify.createRecoveryChallenge(identity.did);
      ceremonyWithVerify.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremonyWithVerify.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremonyWithVerify.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(result.ok).toBe(true);
      expect(verifiedDid).toBe(identity.did);
      expect(verifiedHash).toBe(MOCK_ROTATION_HASH);
    });
  });

  // ─── Full lifecycle ───────────────────────────────────────────────────

  describe('full lifecycle', () => {
    it('freeze → challenge → evidence → time-lock → verifying → enroll → complete', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 72 * 3600_000;
      let now = T0;
      const {
        identity,
        seed,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => now });

      // 1. Freeze
      coordinator.freezeIdentity(identity.did, { now });
      expect(coordinator.isFrozen(identity.did)).toBe(true);

      // 2. Challenge
      const ch = ceremony.createRecoveryChallenge(identity.did);
      expect(ch.identityDid).toBe(identity.did);

      // 3. Evidence (seed signs the challenge)
      const initResult = ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        TIME_LOCK,
        { now },
      );
      expect(initResult.ok).toBe(true);
      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');

      // 4. Time-lock not yet expired — advance fails
      now = T0 + TIME_LOCK - 1;
      const earlyResult = ceremony.advanceToVerifying(identity.did, { now });
      expect(earlyResult.ok).toBe(false);

      // 5. Time-lock expired — advance succeeds
      now = T0 + TIME_LOCK + 1;
      const verifyResult = ceremony.advanceToVerifying(identity.did, { now });
      expect(verifyResult.ok).toBe(true);
      expect(coordinator.getStatus(identity.did)?.state).toBe('verifying');

      // 6. Cannot complete without new authenticator
      const prematureComplete = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now,
      });
      expect(prematureComplete.ok).toBe(false);

      // 7. Enroll new authenticator
      factorRegistry.register({
        factorId: 'new-passkey',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBhc3NrZXk=',
        attestation: null,
        isSecret: false,
        metadata: { device: 'new-macbook' },
      });

      // 8. Complete recovery
      now += 1000;
      const completeResult = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now,
      });
      expect(completeResult.ok).toBe(true);

      // 9. Identity is nominal again
      expect(coordinator.isFrozen(identity.did)).toBe(false);
      expect(coordinator.getStatus(identity.did)).toBeNull();

      // 10. Events recorded in order
      const eventTypes = events.map(e => e.type);
      expect(eventTypes).toEqual([
        'recovery_initiated',
        'recovery_verifying',
        'recovery_completed',
      ]);
    });

    it('freeze → challenge → evidence → cancel → re-challenge → complete', () => {
      const T0 = 1_700_000_000_000;
      let now = T0;
      const {
        identity,
        seed,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => now });

      coordinator.freezeIdentity(identity.did, { now });

      // First attempt — evidence submitted, then cancelled
      const ch1 = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch1, seed.kp.secretKey),
        60_000,
        { now },
      );
      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');

      ceremony.cancelRecovery(identity.did, { now: now + 1000 });
      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');

      // Second attempt — new challenge needed
      now += 5000;
      const ch2 = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch2, seed.kp.secretKey),
        0,
        { now },
      );

      ceremony.advanceToVerifying(identity.did, { now: now + 1 });
      factorRegistry.register({
        factorId: 'new-auth',
        factorType: WELL_KNOWN_FACTOR_TYPES.TOTP,
        subjectDid: identity.did,
        publicMaterial: 'c2hhcmVkLXNlY3JldA==',
        attestation: null,
        isSecret: true,
        metadata: {},
      });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: now + 2,
      });
      expect(result.ok).toBe(true);
      expect(coordinator.isFrozen(identity.did)).toBe(false);

      const eventTypes = events.map(e => e.type);
      expect(eventTypes).toEqual([
        'recovery_initiated',
        'recovery_cancelled',
        'recovery_initiated',
        'recovery_verifying',
        'recovery_completed',
      ]);
    });

    it('recovery-seed factor stays recovery-scoped (does not grant direct authority)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      // Only a recovery-seed factor is active — completion must fail
      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          'no non-recovery-seed authenticator',
        );
    });
  });

  // ─── Account freeze integration ───────────────────────────────────────

  describe('account freeze integration', () => {
    it('unfreezes accounts after recovery completes', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });

      coordinator.freezeIdentity(identity.did, {
        now: T0,
        accountIds: ['acct-1', 'acct-2'],
      });
      expect(coordinator.isAccountFrozen('acct-1')).toBe(true);
      expect(coordinator.isAccountFrozen('acct-2')).toBe(true);

      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-key',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_ROAMING,
        subjectDid: identity.did,
        publicMaterial: 'eXViaWtleQ==',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(coordinator.isAccountFrozen('acct-1')).toBe(false);
      expect(coordinator.isAccountFrozen('acct-2')).toBe(false);
    });

    it('recovery completion does NOT rebind dissolved product-account bindings', () => {
      const T0 = 1_700_000_000_000;
      const { identity, seed, factorRegistry, coordinator, ceremony } = setup({
        now: () => T0,
      });

      const bindingStore = new ProductAccountBindingStore();
      bindingStore.bind({
        accountId: 'acct-1',
        somaIdentityDid: identity.did,
        bindingType: 'primary',
      }, T0);
      bindingStore.bind({
        accountId: 'acct-2',
        somaIdentityDid: identity.did,
        bindingType: 'primary',
      }, T0);

      // Simulate freeze: dissolve bindings and register frozen accounts
      bindingStore.unbind('acct-1', T0);
      bindingStore.unbind('acct-2', T0);
      coordinator.freezeIdentity(identity.did, {
        now: T0,
        accountIds: ['acct-1', 'acct-2'],
      });

      // Full ceremony: evidence → verifying → enroll → complete
      const ch = ceremony.createRecoveryChallenge(identity.did);
      ceremony.submitRecoveryEvidence(
        makeEvidence(ch, seed.kp.secretKey),
        0,
        { now: T0 },
      );
      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });
      factorRegistry.register({
        factorId: 'new-key',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_ROAMING,
        subjectDid: identity.did,
        publicMaterial: 'eXViaWtleQ==',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });
      expect(result.ok).toBe(true);

      // Accounts are unfrozen (coordinator clears freeze flags)
      expect(coordinator.isAccountFrozen('acct-1')).toBe(false);
      expect(coordinator.isAccountFrozen('acct-2')).toBe(false);

      // But bindings remain dissolved — caller must explicitly rebind
      expect(bindingStore.getActive('acct-1')).toBeUndefined();
      expect(bindingStore.getActive('acct-2')).toBeUndefined();
      expect(bindingStore.get('acct-1')?.unboundAt).toBe(T0);
      expect(bindingStore.get('acct-2')?.unboundAt).toBe(T0);
    });
  });

  // ─── pruneExpired ─────────────────────────────────────────────────────

  describe('pruneExpired', () => {
    it('drops expired outstanding challenges', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      ceremony.createRecoveryChallenge(identity.did, { ttlMs: 60_000 });
      expect(ceremony.outstandingCount()).toBe(1);

      const dropped = ceremony.pruneExpired(T0 + 120_000);
      expect(dropped).toBe(1);
      expect(ceremony.outstandingCount()).toBe(0);
    });

    it('retains non-expired challenges', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      ceremony.createRecoveryChallenge(identity.did, { ttlMs: 600_000 });

      const dropped = ceremony.pruneExpired(T0 + 30_000);
      expect(dropped).toBe(0);
      expect(ceremony.outstandingCount()).toBe(1);
    });
  });

  // ─── Double recovery rejection ────────────────────────────────────────

  describe('double recovery rejection', () => {
    it('rejects second freeze while already in recovery', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      expect(() =>
        coordinator.freezeIdentity(identity.did, { now: T0 + 1 }),
      ).toThrow(/already in recovery/);
    });
  });
});
