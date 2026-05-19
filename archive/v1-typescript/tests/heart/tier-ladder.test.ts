import { describe, it, expect } from 'vitest';
import {
  checkPredicate,
  evaluateLadder,
  evaluateLadderDetailed,
  DEFAULT_LADDER,
  PARANOID_LADDER,
  type TierEvalInput,
  type TierPredicate,
} from '../../src/heart/tier-ladder.js';

function input(overrides: Partial<TierEvalInput> = {}): TierEvalInput {
  return {
    factorType: 'webauthn-platform',
    factorTier: 1,
    subjectDid: 'did:key:zAlice',
    hasUserVerification: true,
    hasHardwareAttestation: false,
    registeredActive: [
      {
        factorType: 'webauthn-platform',
        factorId: 'f-1',
        metadata: { deviceId: 'iphone' },
      },
    ],
    ...overrides,
  };
}

describe('checkPredicate — leaf predicates', () => {
  it('factor-type matches when in set', () => {
    const pred: TierPredicate = {
      kind: 'factor-type',
      types: ['webauthn-platform', 'totp'],
    };
    expect(checkPredicate(pred, input())).toBe(true);
    expect(checkPredicate(pred, input({ factorType: 'sms-otp' }))).toBe(false);
  });

  it('min-factor-tier compares numerically', () => {
    const pred: TierPredicate = { kind: 'min-factor-tier', tier: 2 };
    expect(checkPredicate(pred, input({ factorTier: 2 }))).toBe(true);
    expect(checkPredicate(pred, input({ factorTier: 1 }))).toBe(false);
  });

  it('user-verification reflects the input flag', () => {
    const pred: TierPredicate = { kind: 'user-verification' };
    expect(checkPredicate(pred, input({ hasUserVerification: true }))).toBe(true);
    expect(checkPredicate(pred, input({ hasUserVerification: false }))).toBe(false);
  });

  it('hardware-attested reflects the input flag', () => {
    const pred: TierPredicate = { kind: 'hardware-attested' };
    expect(checkPredicate(pred, input({ hasHardwareAttestation: true }))).toBe(true);
    expect(checkPredicate(pred, input({ hasHardwareAttestation: false }))).toBe(false);
  });

  it('registered-count counts all types by default', () => {
    const pred: TierPredicate = { kind: 'registered-count', count: 2 };
    const i = input({
      registeredActive: [
        { factorType: 'webauthn-platform', factorId: 'a', metadata: {} },
        { factorType: 'totp', factorId: 'b', metadata: {} },
      ],
    });
    expect(checkPredicate(pred, i)).toBe(true);
  });

  it('registered-count filters by factorType when specified', () => {
    const pred: TierPredicate = {
      kind: 'registered-count',
      count: 2,
      factorType: 'webauthn-platform',
    };
    const i = input({
      registeredActive: [
        { factorType: 'webauthn-platform', factorId: 'a', metadata: {} },
        { factorType: 'totp', factorId: 'b', metadata: {} },
      ],
    });
    expect(checkPredicate(pred, i)).toBe(false);
  });

  it('distinct-device-count uses metadata.deviceId if present', () => {
    const pred: TierPredicate = { kind: 'distinct-device-count', count: 2 };
    const i = input({
      registeredActive: [
        { factorType: 'x', factorId: 'a', metadata: { deviceId: 'iphone' } },
        { factorType: 'x', factorId: 'b', metadata: { deviceId: 'iphone' } },
        { factorType: 'x', factorId: 'c', metadata: { deviceId: 'laptop' } },
      ],
    });
    expect(checkPredicate(pred, i)).toBe(true);
  });

  it('distinct-device-count falls back to factorId when deviceId missing', () => {
    const pred: TierPredicate = { kind: 'distinct-device-count', count: 3 };
    const i = input({
      registeredActive: [
        { factorType: 'x', factorId: 'a', metadata: {} },
        { factorType: 'x', factorId: 'b', metadata: {} },
        { factorType: 'x', factorId: 'c', metadata: {} },
      ],
    });
    expect(checkPredicate(pred, i)).toBe(true);
  });
});

describe('checkPredicate — combinators', () => {
  const yes: TierPredicate = { kind: 'min-factor-tier', tier: 0 };
  const no: TierPredicate = { kind: 'min-factor-tier', tier: 99 };

  it('and requires all', () => {
    expect(checkPredicate({ kind: 'and', of: [yes, yes] }, input())).toBe(true);
    expect(checkPredicate({ kind: 'and', of: [yes, no] }, input())).toBe(false);
  });

  it('or requires at least one', () => {
    expect(checkPredicate({ kind: 'or', of: [no, yes] }, input())).toBe(true);
    expect(checkPredicate({ kind: 'or', of: [no, no] }, input())).toBe(false);
  });

  it('not inverts', () => {
    expect(checkPredicate({ kind: 'not', of: no }, input())).toBe(true);
    expect(checkPredicate({ kind: 'not', of: yes }, input())).toBe(false);
  });
});

describe('evaluateLadder', () => {
  it('returns the highest tier whose predicate passes', () => {
    const tier = evaluateLadder(DEFAULT_LADDER, input({
      factorType: 'webauthn-platform',
      hasUserVerification: true,
      hasHardwareAttestation: false,
    }));
    expect(tier).toBe(1);
  });

  it('grants tier 2 for two distinct devices with UV', () => {
    const tier = evaluateLadder(DEFAULT_LADDER, input({
      hasUserVerification: true,
      registeredActive: [
        { factorType: 'webauthn-platform', factorId: 'a', metadata: { deviceId: 'iphone' } },
        { factorType: 'webauthn-platform', factorId: 'b', metadata: { deviceId: 'laptop' } },
      ],
    }));
    expect(tier).toBe(2);
  });

  it('grants tier 2 for hardware-attested UV even from one device', () => {
    const tier = evaluateLadder(DEFAULT_LADDER, input({
      factorType: 'webauthn-roaming',
      hasUserVerification: true,
      hasHardwareAttestation: true,
    }));
    expect(tier).toBe(2);
  });

  it('grants tier 3 for hardware + UV + two devices', () => {
    const tier = evaluateLadder(DEFAULT_LADDER, input({
      factorType: 'webauthn-roaming',
      hasUserVerification: true,
      hasHardwareAttestation: true,
      registeredActive: [
        { factorType: 'webauthn-roaming', factorId: 'a', metadata: { deviceId: 'yubi-1' } },
        { factorType: 'webauthn-roaming', factorId: 'b', metadata: { deviceId: 'yubi-2' } },
      ],
    }));
    expect(tier).toBe(3);
  });

  it('returns 0 when nothing matches (no UV)', () => {
    const tier = evaluateLadder(DEFAULT_LADDER, input({
      hasUserVerification: false,
    }));
    expect(tier).toBe(0);
  });

  it('evaluateLadderDetailed returns label of matching rule', () => {
    const detail = evaluateLadderDetailed(DEFAULT_LADDER, input({
      hasUserVerification: true,
    }));
    expect(detail.tier).toBe(1);
    expect(detail.rule?.label).toBe('webauthn-uv');
  });
});

describe('PARANOID_LADDER', () => {
  it('denies platform passkey without hardware attestation', () => {
    const tier = evaluateLadder(PARANOID_LADDER, input({
      factorType: 'webauthn-platform',
      hasUserVerification: true,
      hasHardwareAttestation: false,
    }));
    expect(tier).toBe(0);
  });

  it('grants tier 1 only for hardware + UV', () => {
    const tier = evaluateLadder(PARANOID_LADDER, input({
      factorType: 'webauthn-roaming',
      hasUserVerification: true,
      hasHardwareAttestation: true,
    }));
    expect(tier).toBe(1);
  });

  it('requires three distinct devices for tier 3', () => {
    const tier = evaluateLadder(PARANOID_LADDER, input({
      factorType: 'webauthn-roaming',
      hasUserVerification: true,
      hasHardwareAttestation: true,
      registeredActive: [
        { factorType: 'webauthn-roaming', factorId: 'a', metadata: { deviceId: 'y1' } },
        { factorType: 'webauthn-roaming', factorId: 'b', metadata: { deviceId: 'y2' } },
        { factorType: 'webauthn-roaming', factorId: 'c', metadata: { deviceId: 'y3' } },
      ],
    }));
    expect(tier).toBe(3);
  });
});
