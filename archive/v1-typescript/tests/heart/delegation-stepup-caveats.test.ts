import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import {
  createDelegation,
  checkCaveats,
  type Caveat,
} from '../../src/heart/delegation.js';

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function makeDelegation(caveats: Caveat[]) {
  const issuer = makeIdentity();
  const subject = makeIdentity();
  return {
    subject,
    d: createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ['ssh:exec'],
      caveats,
    }),
  };
}

describe('Caveat: requires-stepup', () => {
  it('rejects when no stepUpAttestation is supplied (fail-closed)', () => {
    const { subject, d } = makeDelegation([
      { kind: 'requires-stepup', minTier: 2 },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/fail-closed/);
  });

  it('accepts when attestation matches invoker and clears the tier', () => {
    const { subject, d } = makeDelegation([
      { kind: 'requires-stepup', minTier: 2 },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      stepUpAttestation: {
        subjectDid: subject.did,
        tierAchieved: 2,
        acceptedAt: Date.now(),
      },
    });
    expect(check.valid).toBe(true);
  });

  it('rejects when attestation subject does not match invoker', () => {
    const { subject, d } = makeDelegation([
      { kind: 'requires-stepup', minTier: 1 },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      stepUpAttestation: {
        subjectDid: 'did:key:zSomeoneElse',
        tierAchieved: 3,
        acceptedAt: Date.now(),
      },
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/subject/);
  });

  it('rejects when tier achieved is below minimum', () => {
    const { subject, d } = makeDelegation([
      { kind: 'requires-stepup', minTier: 3 },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      stepUpAttestation: {
        subjectDid: subject.did,
        tierAchieved: 1,
        acceptedAt: Date.now(),
      },
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/below required/);
  });

  it('rejects stale attestation when maxAgeMs is set', () => {
    const { subject, d } = makeDelegation([
      { kind: 'requires-stepup', minTier: 1, maxAgeMs: 1000 },
    ]);
    const now = 1_000_000;
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      now,
      stepUpAttestation: {
        subjectDid: subject.did,
        tierAchieved: 2,
        acceptedAt: now - 5000,
      },
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/too old/);
  });
});

describe('Caveat: host-allowlist', () => {
  it('rejects when ctx.host is missing (fail-closed)', () => {
    const { subject, d } = makeDelegation([
      { kind: 'host-allowlist', hosts: ['prod.example.com'] },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/fail-closed/);
  });

  it('accepts when host is in the allowlist', () => {
    const { subject, d } = makeDelegation([
      { kind: 'host-allowlist', hosts: ['prod.example.com', 'staging.example.com'] },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      host: 'staging.example.com',
    });
    expect(check.valid).toBe(true);
  });

  it('rejects when host is not in the allowlist', () => {
    const { subject, d } = makeDelegation([
      { kind: 'host-allowlist', hosts: ['prod.example.com'] },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      host: 'evil.example.com',
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/not in allowlist/);
  });
});

describe('Caveat: command-allowlist', () => {
  it('rejects when ctx.commandArgv is missing (fail-closed)', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ exact: ['ls', '-la'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/fail-closed/);
  });

  it('accepts exact argv match', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ exact: ['ls', '-la'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      commandArgv: ['ls', '-la'],
    });
    expect(check.valid).toBe(true);
  });

  it('rejects exact pattern when argv length differs', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ exact: ['ls'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      commandArgv: ['ls', '-la'],
    });
    expect(check.valid).toBe(false);
  });

  it('accepts prefix match even with extra trailing argv', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ prefix: ['git', 'log'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      commandArgv: ['git', 'log', '--oneline', '-n', '10'],
    });
    expect(check.valid).toBe(true);
  });

  it('rejects prefix when argv is shorter than prefix', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ prefix: ['git', 'log'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      commandArgv: ['git'],
    });
    expect(check.valid).toBe(false);
  });

  it('does not perform shell interpolation — literal match only', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'command-allowlist',
        patterns: [{ exact: ['echo', 'hello'] }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      commandArgv: ['echo', 'hello; rm -rf /'],
    });
    expect(check.valid).toBe(false);
  });
});

describe('Caveat: time-window', () => {
  // Build a fixed "now" at 14:30 UTC on a known day.
  const fixedNoon = Date.UTC(2026, 3, 15, 14, 30, 0);

  it('accepts when current hour falls inside a simple window', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'time-window',
        windows: [{ startHourUtc: 9, endHourUtc: 17 }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      now: fixedNoon,
    });
    expect(check.valid).toBe(true);
  });

  it('rejects when current hour is outside all windows', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'time-window',
        windows: [{ startHourUtc: 0, endHourUtc: 6 }],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      now: fixedNoon,
    });
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toMatch(/not in any allowed/);
  });

  it('handles windows that wrap midnight (start > end)', () => {
    // 22:00 UTC → 06:00 UTC overnight window
    const lateNight = Date.UTC(2026, 3, 15, 23, 0, 0);
    const earlyMorning = Date.UTC(2026, 3, 15, 3, 0, 0);
    const { subject: s1, d: d1 } = makeDelegation([
      {
        kind: 'time-window',
        windows: [{ startHourUtc: 22, endHourUtc: 6 }],
      },
    ]);
    const { subject: s2, d: d2 } = makeDelegation([
      {
        kind: 'time-window',
        windows: [{ startHourUtc: 22, endHourUtc: 6 }],
      },
    ]);
    expect(
      checkCaveats(d1, {
        invokerDid: s1.did,
        capability: 'ssh:exec',
        now: lateNight,
      }).valid,
    ).toBe(true);
    expect(
      checkCaveats(d2, {
        invokerDid: s2.did,
        capability: 'ssh:exec',
        now: earlyMorning,
      }).valid,
    ).toBe(true);
  });

  it('rejects just outside a wrapping window', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'time-window',
        windows: [{ startHourUtc: 22, endHourUtc: 6 }],
      },
    ]);
    const midday = Date.UTC(2026, 3, 15, 12, 0, 0);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      now: midday,
    });
    expect(check.valid).toBe(false);
  });

  it('accepts if any window in the list matches', () => {
    const { subject, d } = makeDelegation([
      {
        kind: 'time-window',
        windows: [
          { startHourUtc: 0, endHourUtc: 6 },
          { startHourUtc: 14, endHourUtc: 15 },
        ],
      },
    ]);
    const check = checkCaveats(d, {
      invokerDid: subject.did,
      capability: 'ssh:exec',
      now: fixedNoon,
    });
    expect(check.valid).toBe(true);
  });
});
