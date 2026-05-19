import { describe, it, expect } from 'vitest';
import {
  FactorRegistry,
  WELL_KNOWN_FACTOR_TYPES,
  type RegisteredFactor,
} from '../../src/heart/factor-registry.js';

function makeFactor(
  overrides: Partial<
    Omit<RegisteredFactor, 'registeredAt' | 'lastUsedAt' | 'revokedAt'>
  > = {},
): Omit<RegisteredFactor, 'registeredAt' | 'lastUsedAt' | 'revokedAt'> {
  return {
    factorId: 'f-1',
    factorType: WELL_KNOWN_FACTOR_TYPES.WEBAUTHN_PLATFORM,
    subjectDid: 'did:key:zAlice',
    publicMaterial: 'cG9ja2V5',
    attestation: null,
    isSecret: false,
    metadata: {},
    ...overrides,
  };
}

describe('FactorRegistry — basic lifecycle', () => {
  it('registers a factor and returns a copy', () => {
    const r = new FactorRegistry();
    const entry = r.register(makeFactor());
    expect(entry.factorId).toBe('f-1');
    expect(entry.revokedAt).toBeNull();
    expect(entry.registeredAt).toBeGreaterThan(0);
  });

  it('rejects duplicate (subjectDid, factorId)', () => {
    const r = new FactorRegistry();
    r.register(makeFactor());
    expect(() => r.register(makeFactor())).toThrow(/already registered/);
  });

  it('allows same factorId under different subjects', () => {
    const r = new FactorRegistry();
    r.register(makeFactor({ subjectDid: 'did:key:zAlice' }));
    r.register(makeFactor({ subjectDid: 'did:key:zBob' }));
    expect(r.listAll('did:key:zAlice').length).toBe(1);
    expect(r.listAll('did:key:zBob').length).toBe(1);
  });

  it('marks factor used without changing revocation state', () => {
    const r = new FactorRegistry();
    r.register(makeFactor());
    r.markUsed('did:key:zAlice', 'f-1', 12345);
    const f = r.get('did:key:zAlice', 'f-1');
    expect(f?.lastUsedAt).toBe(12345);
    expect(f?.revokedAt).toBeNull();
  });

  it('revokes a factor and stops counting it as active', () => {
    const r = new FactorRegistry();
    r.register(makeFactor());
    expect(r.isActive('did:key:zAlice', 'f-1')).toBe(true);
    r.revoke('did:key:zAlice', 'f-1');
    expect(r.isActive('did:key:zAlice', 'f-1')).toBe(false);
    expect(r.listActive('did:key:zAlice').length).toBe(0);
    expect(r.listAll('did:key:zAlice').length).toBe(1);
  });

  it('ignores double-revoke (preserves original revokedAt)', () => {
    const r = new FactorRegistry();
    r.register(makeFactor());
    r.revoke('did:key:zAlice', 'f-1', 1000);
    r.revoke('did:key:zAlice', 'f-1', 2000);
    const f = r.get('did:key:zAlice', 'f-1');
    expect(f?.revokedAt).toBe(1000);
  });
});

describe('FactorRegistry — counts and snapshots', () => {
  it('counts active factors by type', () => {
    const r = new FactorRegistry();
    r.register(makeFactor({ factorId: 'a', factorType: 'webauthn-platform' }));
    r.register(makeFactor({ factorId: 'b', factorType: 'webauthn-platform' }));
    r.register(makeFactor({ factorId: 'c', factorType: 'webauthn-roaming' }));
    r.register(makeFactor({ factorId: 'd', factorType: 'totp' }));
    r.revoke('did:key:zAlice', 'b');

    const counts = r.countActiveByType('did:key:zAlice');
    expect(counts['webauthn-platform']).toBe(1);
    expect(counts['webauthn-roaming']).toBe(1);
    expect(counts['totp']).toBe(1);
  });

  it('returns defensive copies — registry state cannot be mutated via get', () => {
    const r = new FactorRegistry();
    r.register(makeFactor());
    const f = r.get('did:key:zAlice', 'f-1');
    if (f) f.revokedAt = 999;
    expect(r.isActive('did:key:zAlice', 'f-1')).toBe(true);
  });
});

describe('FactorRegistry — serialization', () => {
  it('round-trips through toJSON / fromJSON', () => {
    const r = new FactorRegistry();
    r.register(makeFactor({ factorId: 'a' }));
    r.register(makeFactor({ factorId: 'b', factorType: 'totp' }));
    r.revoke('did:key:zAlice', 'b');

    const snapshot = r.toJSON();
    const r2 = FactorRegistry.fromJSON(snapshot);
    expect(r2.isActive('did:key:zAlice', 'a')).toBe(true);
    expect(r2.isActive('did:key:zAlice', 'b')).toBe(false);
    expect(r2.listAll('did:key:zAlice').length).toBe(2);
  });
});
