import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import { domainSigningInput } from '../../src/core/canonicalize.js';
import {
  FactorRegistry,
  WELL_KNOWN_FACTOR_TYPES,
  type GuardianConfig,
} from '../../src/heart/factor-registry.js';
import {
  IdentityRecoveryCoordinator,
  InMemoryRecoveryStore,
} from '../../src/heart/recovery-coordinator.js';
import {
  GuardianRecoveryCeremonyService,
  type GuardianChallenge,
  type GuardianApproval,
} from '../../src/heart/guardian-recovery-ceremony.js';
import { ProductAccountBindingStore } from '../../src/heart/product-account-binding.js';

const crypto = getCryptoProvider();
const MOCK_ROTATION_HASH = 'rotation-event-hash-guardian-abc123';

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function signGuardianApproval(
  challenge: GuardianChallenge,
  guardianSecretKey: Uint8Array,
): string {
  const { signature: _, ...payload } = challenge;
  const signingInput = domainSigningInput('soma/guardian-approval/v1', payload);
  const sig = crypto.signing.sign(signingInput, guardianSecretKey);
  return crypto.encoding.encodeBase64(sig);
}

function makeApproval(
  challenge: GuardianChallenge,
  guardianSecretKey: Uint8Array,
  overrides: Partial<GuardianApproval> = {},
): GuardianApproval {
  return {
    challengeId: challenge.id,
    guardianDid: challenge.guardianDid,
    rawSignature: signGuardianApproval(challenge, guardianSecretKey),
    approvedAt: challenge.issuedAt,
    ...overrides,
  };
}

interface SetupOpts {
  now?: () => number;
  threshold?: number;
  guardianCount?: number;
  withVerifyRotation?: boolean;
}

function setup(opts: SetupOpts = {}) {
  const heart = makeIdentity();
  const identity = makeIdentity();
  const guardianCount = opts.guardianCount ?? 3;
  const threshold = opts.threshold ?? 2;

  const guardians = Array.from({ length: guardianCount }, () => makeIdentity());

  const factorRegistry = new FactorRegistry();

  const guardianConfig: GuardianConfig = {
    subjectDid: identity.did,
    guardians: guardians.map((g, i) => ({
      guardianDid: g.did,
      label: `guardian-${i}`,
      addedAt: 1_700_000_000_000 - 86_400_000,
      revokedAt: null,
    })),
    threshold,
    updatedAt: 1_700_000_000_000 - 86_400_000,
  };

  const guardianKeyMap = new Map<string, string>();
  for (const g of guardians) {
    guardianKeyMap.set(g.did, g.publicKey);
  }

  const store = new InMemoryRecoveryStore();
  const coordinator = new IdentityRecoveryCoordinator(store, {
    now: opts.now,
  });

  const events: Array<{ type: string; data: string }> = [];

  const ceremony = new GuardianRecoveryCeremonyService({
    heartDid: heart.did,
    heartPublicKey: heart.publicKey,
    heartSigningKey: heart.kp.secretKey,
    factorRegistry,
    coordinator,
    resolveGuardianKey: (did) => guardianKeyMap.get(did) ?? null,
    getGuardianConfig: (did) =>
      did === identity.did ? guardianConfig : null,
    now: opts.now,
    provider: crypto,
    onEvent: (type, data) => events.push({ type, data }),
    verifyRotation: opts.withVerifyRotation === false ? undefined : () => true,
  });

  return {
    heart,
    identity,
    guardians,
    guardianConfig,
    guardianKeyMap,
    factorRegistry,
    coordinator,
    ceremony,
    events,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('GuardianRecoveryCeremonyService', () => {
  // ─── createGuardianChallenge ────────────────────────────────────────────

  describe('createGuardianChallenge', () => {
    it('creates a signed challenge for a frozen identity', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );

      expect(ch.protocol).toBe('soma-guardian-recovery/1');
      expect(ch.identityDid).toBe(identity.did);
      expect(ch.guardianDid).toBe(guardians[0].did);
      expect(ch.issuedAt).toBe(T0);
      expect(ch.expiresAt).toBe(T0 + 600_000);
      expect(ch.signature).toBeTruthy();
      expect(ch.nonce).toBeTruthy();
      expect(ch.id).toMatch(/^gc-/);
    });

    it('binds the challenge to the ceremony ID', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      const { ceremonyId } = coordinator.freezeIdentity(identity.did, {
        now: T0,
      });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      expect(ch.ceremonyId).toBe(ceremonyId);
    });

    it('throws if identity is not frozen', () => {
      const { identity, guardians, ceremony } = setup();
      expect(() =>
        ceremony.createGuardianChallenge(identity.did, guardians[0].did),
      ).toThrow(/not in recovery/);
    });

    it('throws if identity is in pending state', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });
      coordinator.initiatePending(identity.did, 'guardian-quorum', 60_000, {
        now: T0,
      });

      expect(() =>
        ceremony.createGuardianChallenge(identity.did, guardians[0].did),
      ).toThrow(/guardian challenge requires 'frozen'/);
    });

    it('throws if identity has no guardian config', () => {
      const T0 = 1_700_000_000_000;
      const other = makeIdentity();
      const { guardians, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(other.did, { now: T0 });

      expect(() =>
        ceremony.createGuardianChallenge(other.did, guardians[0].did),
      ).toThrow(/no guardian configuration/);
    });

    it('throws if guardian DID is not an active guardian', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const outsider = makeIdentity();
      expect(() =>
        ceremony.createGuardianChallenge(identity.did, outsider.did),
      ).toThrow(/not an active guardian/);
    });

    it('uses custom TTL when provided', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
        { ttlMs: 30_000 },
      );
      expect(ch.expiresAt).toBe(T0 + 30_000);
    });

    it('challenge signature is verifiable by the heart public key', () => {
      const T0 = 1_700_000_000_000;
      const { identity, heart, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );

      const { signature, ...payload } = ch;
      const signingInput = domainSigningInput(
        'soma/guardian-challenge/v1',
        payload,
      );
      const sigBytes = crypto.encoding.decodeBase64(signature);
      const pubKey = crypto.encoding.decodeBase64(heart.publicKey);
      expect(crypto.signing.verify(signingInput, sigBytes, pubKey)).toBe(true);
    });
  });

  // ─── submitGuardianApproval ─────────────────────────────────────────────

  describe('submitGuardianApproval', () => {
    it('accepts valid guardian approval (below quorum)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const approval = makeApproval(ch, guardians[0].kp.secretKey);

      const result = ceremony.submitGuardianApproval(approval, 72 * 3600_000, {
        now: T0,
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.quorumReached).toBe(false);
        expect(result.approvalsReceived).toBe(1);
        expect(result.threshold).toBe(2);
      }

      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');
    });

    it('advances to pending when quorum is reached', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 72 * 3600_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // First guardian
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        TIME_LOCK,
        { now: T0 },
      );

      // Second guardian — quorum reached
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      const result = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        TIME_LOCK,
        { now: T0 },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.quorumReached).toBe(true);
        if (result.quorumReached) {
          expect(result.ceremony.state).toBe('pending');
          expect(result.ceremony.evidenceType).toBe('guardian-quorum');
          expect(result.ceremony.timeLockExpiresAt).toBe(T0 + TIME_LOCK);
        }
      }

      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');
    });

    it('rejects replayed challenge', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const approval = makeApproval(ch, guardians[0].kp.secretKey);

      ceremony.submitGuardianApproval(approval, 60_000, { now: T0 });
      const replay = ceremony.submitGuardianApproval(approval, 60_000, {
        now: T0,
      });

      expect(replay.ok).toBe(false);
      if (!replay.ok) expect(replay.reason).toContain('already consumed');
    });

    it('rejects unknown challenge ID', () => {
      const T0 = 1_700_000_000_000;
      const { guardians, ceremony } = setup({ now: () => T0 });

      const result = ceremony.submitGuardianApproval(
        {
          challengeId: 'gc-nonexistent',
          guardianDid: guardians[0].did,
          rawSignature: 'AAAA',
          approvedAt: T0,
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
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => now,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
        { ttlMs: 60_000 },
      );
      const approval = makeApproval(ch, guardians[0].kp.secretKey);

      now = T0 + 120_000;
      const result = ceremony.submitGuardianApproval(approval, 60_000, {
        now,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('expired');
    });

    it('rejects guardian DID mismatch', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const result = ceremony.submitGuardianApproval(
        {
          challengeId: ch.id,
          guardianDid: guardians[1].did,
          rawSignature: signGuardianApproval(ch, guardians[1].kp.secretKey),
          approvedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('DID mismatch');
    });

    it('rejects invalid guardian signature', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const wrongKey = makeIdentity();
      const result = ceremony.submitGuardianApproval(
        makeApproval(ch, wrongKey.kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('signature verification failed');
    });

    it('rejects unresolvable guardian public key', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, guardianKeyMap, coordinator, ceremony } =
        setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );

      guardianKeyMap.delete(guardians[0].did);

      const result = ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('not resolvable');
    });

    it('rejects duplicate approval from same guardian', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 3,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // First approval
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      // Second challenge for same guardian, different challenge ID
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const result = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toContain('already approved');
    });

    it('consumes the challenge on success', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      expect(ceremony.outstandingCount()).toBe(1);

      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(ceremony.outstandingCount()).toBe(0);
    });

    it('emits guardian_approval_received event', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony, events } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('guardian_approval_received');
      const data = JSON.parse(events[0].data);
      expect(data.identityDid).toBe(identity.did);
      expect(data.guardianDid).toBe(guardians[0].did);
      expect(data.approvalsReceived).toBe(1);
      expect(data.threshold).toBe(2);
    });

    it('emits recovery_initiated when quorum is reached', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony, events } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        72 * 3600_000,
        { now: T0 },
      );

      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        72 * 3600_000,
        { now: T0 },
      );

      const initiated = events.find(e => e.type === 'recovery_initiated');
      expect(initiated).toBeTruthy();
      const data = JSON.parse(initiated!.data);
      expect(data.evidenceType).toBe('guardian-quorum');
      expect(data.guardianCount).toBe(2);
      expect(data.threshold).toBe(2);
      expect(data.guardianDids).toHaveLength(2);
    });

    it('prevents cross-protocol signature replay (wrong domain)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );

      // Sign under the challenge domain instead of approval domain
      const { signature: _, ...payload } = ch;
      const wrongDomainInput = domainSigningInput(
        'soma/guardian-challenge/v1',
        payload,
      );
      const wrongSig = crypto.signing.sign(
        wrongDomainInput,
        guardians[0].kp.secretKey,
      );

      const result = ceremony.submitGuardianApproval(
        {
          challengeId: ch.id,
          guardianDid: guardians[0].did,
          rawSignature: crypto.encoding.encodeBase64(wrongSig),
          approvedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('signature verification failed');
    });

    it('prevents cross-protocol replay with recovery-seed domain', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );

      // Sign under recovery-seed evidence domain
      const { signature: _, ...payload } = ch;
      const seedDomainInput = domainSigningInput(
        'soma/recovery-evidence/v1',
        payload,
      );
      const seedSig = crypto.signing.sign(
        seedDomainInput,
        guardians[0].kp.secretKey,
      );

      const result = ceremony.submitGuardianApproval(
        {
          challengeId: ch.id,
          guardianDid: guardians[0].did,
          rawSignature: crypto.encoding.encodeBase64(seedSig),
          approvedAt: T0,
        },
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain('signature verification failed');
    });
  });

  // ─── getQuorumStatus ────────────────────────────────────────────────────

  describe('getQuorumStatus', () => {
    it('returns null when no approvals submitted', () => {
      const { identity, ceremony } = setup();
      expect(ceremony.getQuorumStatus(identity.did)).toBeNull();
    });

    it('returns current approval state', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 3,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      const status = ceremony.getQuorumStatus(identity.did);
      expect(status).not.toBeNull();
      expect(status!.approvalsReceived).toBe(1);
      expect(status!.threshold).toBe(3);
      expect(status!.guardianDids).toEqual([guardians[0].did]);
    });
  });

  // ─── cancelRecovery ─────────────────────────────────────────────────────

  describe('cancelRecovery', () => {
    it('cancels a pending recovery and reverts to frozen', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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

    it('clears quorum state on cancellation', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(ceremony.getQuorumStatus(identity.did)).not.toBeNull();

      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      expect(ceremony.getQuorumStatus(identity.did)).toBeNull();
    });

    it('emits recovery_cancelled event', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony, events } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );
      events.length = 0;

      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_cancelled');
    });

    it('returns false for non-pending identity', () => {
      const T0 = 1_700_000_000_000;
      const { identity, coordinator, ceremony } = setup({ now: () => T0 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      expect(ceremony.cancelRecovery(identity.did)).toBe(false);
    });

    it('allows re-challenge after cancellation', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // First attempt
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );
      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      // Second attempt
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      expect(ch2.id).not.toBe(ch1.id);

      const result = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        0,
        { now: T0 + 2000 },
      );
      expect(result.ok).toBe(true);
    });

    it('invalidates outstanding challenges on cancellation (stale challenge rejected)', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // Issue challenges to two guardians
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      expect(ceremony.outstandingCount()).toBe(2);

      // Guardian 0 approves, reaching partial quorum
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      // Need quorum to cancel (pending state required)
      // Issue and approve for guardian 1 to reach quorum
      const ch1b = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1b, guardians[1].kp.secretKey),
        60_000,
        { now: T0 },
      );

      // Cancel recovery — reverts to frozen, should invalidate ch2
      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });
      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');

      // ch2 was issued before cancellation — must be rejected
      const staleResult = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        60_000,
        { now: T0 + 2000 },
      );

      expect(staleResult.ok).toBe(false);
      if (!staleResult.ok)
        expect(staleResult.reason).toContain('already consumed');
    });

    it('outstanding count drops to zero after cancellation', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // Issue challenges but don't approve them all
      ceremony.createGuardianChallenge(identity.did, guardians[0].did);
      ceremony.createGuardianChallenge(identity.did, guardians[1].did);

      // Need to reach pending to cancel — approve one (threshold=1)
      const ch3 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[2].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch3, guardians[2].kp.secretKey),
        60_000,
        { now: T0 },
      );

      // Two outstanding remain (guardians 0 and 1)
      expect(ceremony.outstandingCount()).toBe(2);

      ceremony.cancelRecovery(identity.did, { now: T0 + 1000 });

      expect(ceremony.outstandingCount()).toBe(0);
    });
  });

  // ─── advanceToVerifying ─────────────────────────────────────────────────

  describe('advanceToVerifying', () => {
    it('advances to verifying after time-lock expires', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 60_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
      const { identity, guardians, coordinator, ceremony, events } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        0,
        { now: T0 },
      );
      events.length = 0;

      ceremony.advanceToVerifying(identity.did, { now: T0 + 1 });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('recovery_verifying');
    });
  });

  // ─── completeRecovery ───────────────────────────────────────────────────

  describe('completeRecovery', () => {
    it('completes recovery when all gates pass', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
        expect(result.reason).toContain('no non-recovery-seed authenticator');
    });

    it('rejects completion without rotation event hash', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
        expect(result.reason).toContain(
          'credential rotation event hash required',
        );
    });

    it('rejects completion when verifyRotation is not configured', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1, withVerifyRotation: false });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          'verifyRotation callback not configured',
        );
    });

    it('rejects completion when verifyRotation returns false', () => {
      const T0 = 1_700_000_000_000;
      const heart = makeIdentity();
      const identity = makeIdentity();
      const guardians = [makeIdentity(), makeIdentity()];

      const guardianConfig: GuardianConfig = {
        subjectDid: identity.did,
        guardians: guardians.map((g, i) => ({
          guardianDid: g.did,
          label: `g-${i}`,
          addedAt: T0 - 1000,
          revokedAt: null,
        })),
        threshold: 1,
        updatedAt: T0 - 1000,
      };

      const keyMap = new Map(guardians.map(g => [g.did, g.publicKey]));
      const store = new InMemoryRecoveryStore();
      const coordinator = new IdentityRecoveryCoordinator(store, {
        now: () => T0,
      });
      const factorRegistry = new FactorRegistry();

      const ceremonyReject = new GuardianRecoveryCeremonyService({
        heartDid: heart.did,
        heartPublicKey: heart.publicKey,
        heartSigningKey: heart.kp.secretKey,
        factorRegistry,
        coordinator,
        resolveGuardianKey: (did) => keyMap.get(did) ?? null,
        getGuardianConfig: (did) =>
          did === identity.did ? guardianConfig : null,
        now: () => T0,
        provider: crypto,
        verifyRotation: () => false,
      });

      coordinator.freezeIdentity(identity.did, { now: T0 });
      const ch = ceremonyReject.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremonyReject.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        0,
        { now: T0 },
      );
      ceremonyReject.advanceToVerifying(identity.did, { now: T0 + 1 });

      factorRegistry.register({
        factorId: 'new-webauthn',
        factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
        subjectDid: identity.did,
        publicMaterial: 'bmV3LXBr',
        attestation: null,
        isSecret: false,
        metadata: {},
      });

      const result = ceremonyReject.completeRecovery(identity.did, {
        rotationEventHash: 'bad-hash',
        now: T0 + 2,
      });

      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.reason).toContain(
          'credential rotation verification failed',
        );
    });

    it('emits recovery_completed event with rotationEventHash', () => {
      const T0 = 1_700_000_000_000;
      const {
        identity,
        guardians,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => T0, threshold: 1 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
      expect(data.rotationEventHash).toBe(MOCK_ROTATION_HASH);
      expect(data.completedAt).toBe(T0 + 2);
    });

    it('clears quorum state on completion', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1 });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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

      expect(ceremony.getQuorumStatus(identity.did)).not.toBeNull();

      ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now: T0 + 2,
      });

      expect(ceremony.getQuorumStatus(identity.did)).toBeNull();
    });
  });

  // ─── Full lifecycle ─────────────────────────────────────────────────────

  describe('full lifecycle', () => {
    it('freeze → challenges → quorum → time-lock → verifying → enroll → complete', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 72 * 3600_000;
      let now = T0;
      const {
        identity,
        guardians,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => now, threshold: 2 });

      // 1. Freeze
      coordinator.freezeIdentity(identity.did, { now });
      expect(coordinator.isFrozen(identity.did)).toBe(true);

      // 2. First guardian challenge + approval
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const r1 = ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        TIME_LOCK,
        { now },
      );
      expect(r1.ok).toBe(true);
      if (r1.ok) expect(r1.quorumReached).toBe(false);
      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');

      // 3. Second guardian — quorum reached, time-lock starts
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      const r2 = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        TIME_LOCK,
        { now },
      );
      expect(r2.ok).toBe(true);
      if (r2.ok) expect(r2.quorumReached).toBe(true);
      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');

      // 4. Time-lock not yet expired
      now = T0 + TIME_LOCK - 1;
      const earlyResult = ceremony.advanceToVerifying(identity.did, { now });
      expect(earlyResult.ok).toBe(false);

      // 5. Time-lock expired
      now = T0 + TIME_LOCK + 1;
      const verifyResult = ceremony.advanceToVerifying(identity.did, { now });
      expect(verifyResult.ok).toBe(true);
      expect(coordinator.getStatus(identity.did)?.state).toBe('verifying');

      // 6. Cannot complete without new authenticator
      const premature = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now,
      });
      expect(premature.ok).toBe(false);

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
      const result = ceremony.completeRecovery(identity.did, {
        rotationEventHash: MOCK_ROTATION_HASH,
        now,
      });
      expect(result.ok).toBe(true);

      // 9. Identity is nominal
      expect(coordinator.isFrozen(identity.did)).toBe(false);
      expect(coordinator.getStatus(identity.did)).toBeNull();

      // 10. Events recorded in order
      const eventTypes = events.map(e => e.type);
      expect(eventTypes).toEqual([
        'guardian_approval_received',
        'guardian_approval_received',
        'recovery_initiated',
        'recovery_verifying',
        'recovery_completed',
      ]);
    });

    it('freeze → partial quorum → cancel → re-collect → complete', () => {
      const T0 = 1_700_000_000_000;
      let now = T0;
      const {
        identity,
        guardians,
        factorRegistry,
        coordinator,
        ceremony,
        events,
      } = setup({ now: () => now, threshold: 2 });

      coordinator.freezeIdentity(identity.did, { now });

      // First attempt: one approval then cancel
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        60_000,
        { now },
      );

      // Need quorum to advance to pending before cancel works
      const ch1b = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1b, guardians[1].kp.secretKey),
        60_000,
        { now },
      );

      ceremony.cancelRecovery(identity.did, { now: now + 1000 });
      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');

      // Second attempt: fresh quorum
      now += 5000;
      const ch2a = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch2a, guardians[0].kp.secretKey),
        0,
        { now },
      );
      const ch2b = ceremony.createGuardianChallenge(
        identity.did,
        guardians[2].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch2b, guardians[2].kp.secretKey),
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
        'guardian_approval_received',
        'guardian_approval_received',
        'recovery_initiated',
        'recovery_cancelled',
        'guardian_approval_received',
        'guardian_approval_received',
        'recovery_initiated',
        'recovery_verifying',
        'recovery_completed',
      ]);
    });
  });

  // ─── Account freeze integration ─────────────────────────────────────────

  describe('account freeze integration', () => {
    it('unfreezes accounts after recovery completes', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1 });

      coordinator.freezeIdentity(identity.did, {
        now: T0,
        accountIds: ['acct-1', 'acct-2'],
      });
      expect(coordinator.isAccountFrozen('acct-1')).toBe(true);
      expect(coordinator.isAccountFrozen('acct-2')).toBe(true);

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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
      const { identity, guardians, factorRegistry, coordinator, ceremony } =
        setup({ now: () => T0, threshold: 1 });

      const bindingStore = new ProductAccountBindingStore();
      bindingStore.bind(
        {
          accountId: 'acct-1',
          somaIdentityDid: identity.did,
          bindingType: 'primary',
        },
        T0,
      );

      // Simulate freeze dissolving the binding
      bindingStore.unbind('acct-1', T0);
      coordinator.freezeIdentity(identity.did, {
        now: T0,
        accountIds: ['acct-1'],
      });

      // Full ceremony
      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
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

      // Account unfrozen, but binding remains dissolved
      expect(coordinator.isAccountFrozen('acct-1')).toBe(false);
      expect(bindingStore.getActive('acct-1')).toBeUndefined();
      expect(bindingStore.get('acct-1')?.unboundAt).toBe(T0);
    });
  });

  // ─── Quorum edge cases ──────────────────────────────────────────────────

  describe('quorum edge cases', () => {
    it('1-of-1 quorum advances immediately', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 1,
        guardianCount: 1,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      const ch = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      const result = ceremony.submitGuardianApproval(
        makeApproval(ch, guardians[0].kp.secretKey),
        60_000,
        { now: T0 },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.quorumReached).toBe(true);
      }
      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');
    });

    it('3-of-5 quorum requires exactly 3 approvals', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 3,
        guardianCount: 5,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // Approvals 1 and 2: no quorum yet
      for (let i = 0; i < 2; i++) {
        const ch = ceremony.createGuardianChallenge(
          identity.did,
          guardians[i].did,
        );
        const r = ceremony.submitGuardianApproval(
          makeApproval(ch, guardians[i].kp.secretKey),
          60_000,
          { now: T0 },
        );
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.quorumReached).toBe(false);
      }

      expect(coordinator.getStatus(identity.did)?.state).toBe('frozen');

      // Approval 3: quorum
      const ch3 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[2].did,
      );
      const r3 = ceremony.submitGuardianApproval(
        makeApproval(ch3, guardians[2].kp.secretKey),
        60_000,
        { now: T0 },
      );
      expect(r3.ok).toBe(true);
      if (r3.ok) {
        expect(r3.quorumReached).toBe(true);
        expect(r3.approvalsReceived).toBe(3);
      }

      expect(coordinator.getStatus(identity.did)?.state).toBe('pending');
    });

    it('time-lock starts at quorum, not at first approval', () => {
      const T0 = 1_700_000_000_000;
      const TIME_LOCK = 60_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
        threshold: 2,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      // First approval at T0
      const ch1 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[0].did,
      );
      ceremony.submitGuardianApproval(
        makeApproval(ch1, guardians[0].kp.secretKey),
        TIME_LOCK,
        { now: T0 },
      );

      // Second approval at T0 + 30_000 — this triggers quorum
      const ch2 = ceremony.createGuardianChallenge(
        identity.did,
        guardians[1].did,
      );
      const result = ceremony.submitGuardianApproval(
        makeApproval(ch2, guardians[1].kp.secretKey),
        TIME_LOCK,
        { now: T0 + 30_000 },
      );

      expect(result.ok).toBe(true);
      if (result.ok && result.quorumReached) {
        // Time-lock should be T0 + 30_000 + TIME_LOCK, not T0 + TIME_LOCK
        expect(result.ceremony.timeLockExpiresAt).toBe(
          T0 + 30_000 + TIME_LOCK,
        );
      }
    });
  });

  // ─── pruneExpired ───────────────────────────────────────────────────────

  describe('pruneExpired', () => {
    it('drops expired outstanding challenges', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      ceremony.createGuardianChallenge(identity.did, guardians[0].did, {
        ttlMs: 60_000,
      });
      expect(ceremony.outstandingCount()).toBe(1);

      const dropped = ceremony.pruneExpired(T0 + 120_000);
      expect(dropped).toBe(1);
      expect(ceremony.outstandingCount()).toBe(0);
    });

    it('retains non-expired challenges', () => {
      const T0 = 1_700_000_000_000;
      const { identity, guardians, coordinator, ceremony } = setup({
        now: () => T0,
      });
      coordinator.freezeIdentity(identity.did, { now: T0 });

      ceremony.createGuardianChallenge(identity.did, guardians[0].did, {
        ttlMs: 600_000,
      });

      const dropped = ceremony.pruneExpired(T0 + 30_000);
      expect(dropped).toBe(0);
      expect(ceremony.outstandingCount()).toBe(1);
    });
  });
});
