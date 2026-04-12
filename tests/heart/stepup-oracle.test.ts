import { describe, it, expect } from 'vitest';
import {
  BaseStepUpOracle,
  CliPromptOracle,
  OracleChain,
  type DeliveryResult,
} from '../../src/heart/stepup-oracle.js';
import type {
  FactorAssertion,
  StepUpChallenge,
} from '../../src/heart/stepup.js';

function fakeChallenge(id = 'ch-1'): StepUpChallenge {
  return {
    id,
    protocol: 'soma-stepup/1',
    subjectDid: 'did:key:zAlice',
    actionDigest: 'digest',
    minTier: 2,
    issuedAt: 1000,
    expiresAt: 2000,
    nonce: 'nonce',
    heartDid: 'did:key:zHeart',
    heartPublicKey: 'aGVhcnQ=',
    signature: 'c2ln',
  };
}

function fakeAssertion(challengeId = 'ch-1'): FactorAssertion {
  return {
    challengeId,
    factorId: 'f-1',
    factorType: 'webauthn-platform',
    rawAssertion: 'cmF3',
    assertedAt: 1500,
  };
}

describe('CliPromptOracle', () => {
  it('delivers pending and emits assertion via autoAssertion callback', async () => {
    const oracle = new CliPromptOracle({
      autoAssertion: (ch) => fakeAssertion(ch.id),
    });
    const received: FactorAssertion[] = [];
    oracle.onAssertion((a) => {
      received.push(a);
    });
    const result = await oracle.deliver(fakeChallenge('ch-A'));
    expect(result.status).toBe('pending');
    // queueMicrotask: flush microtask queue
    await Promise.resolve();
    await Promise.resolve();
    expect(received).toHaveLength(1);
    expect(received[0]?.challengeId).toBe('ch-A');
  });

  it('returns failed when autoAssertion returns null', async () => {
    const oracle = new CliPromptOracle({
      autoAssertion: () => null,
    });
    const result = await oracle.deliver(fakeChallenge());
    expect(result.status).toBe('failed');
  });

  it('returns pending without autoAssertion and supports injectAssertion', async () => {
    const oracle = new CliPromptOracle();
    const received: FactorAssertion[] = [];
    oracle.onAssertion((a) => {
      received.push(a);
    });
    const result = await oracle.deliver(fakeChallenge('ch-B'));
    expect(result.status).toBe('pending');
    await oracle.injectAssertion(fakeAssertion('ch-B'));
    expect(received).toHaveLength(1);
  });

  it('writes challenge details to the log hook', async () => {
    const lines: string[] = [];
    const oracle = new CliPromptOracle({ log: (l) => lines.push(l) });
    await oracle.deliver(fakeChallenge('ch-LOG'));
    expect(lines.some((l) => l.includes('ch-LOG'))).toBe(true);
    expect(lines.some((l) => l.includes('minTier'))).toBe(true);
  });
});

class UnsupportedOracle extends BaseStepUpOracle {
  readonly name = 'unsupported';
  deliver(_challenge: StepUpChallenge): Promise<DeliveryResult> {
    return Promise.resolve({ status: 'unsupported', reason: 'no channel' });
  }
}

class DeliveringOracle extends BaseStepUpOracle {
  readonly name: string;
  delivered = 0;
  constructor(name: string) {
    super();
    this.name = name;
  }
  deliver(_challenge: StepUpChallenge): Promise<DeliveryResult> {
    this.delivered += 1;
    return Promise.resolve({ status: 'delivered', deliveryId: 'd' });
  }
}

describe('OracleChain', () => {
  it('falls through unsupported oracles to the first supporting one', async () => {
    const primary = new UnsupportedOracle();
    const fallback = new DeliveringOracle('fallback');
    const chain = new OracleChain([primary, fallback]);
    const result = await chain.deliver(fakeChallenge());
    expect(result.status).toBe('delivered');
    expect(fallback.delivered).toBe(1);
  });

  it('returns unsupported when every child is unsupported', async () => {
    const chain = new OracleChain([
      new UnsupportedOracle(),
      new UnsupportedOracle(),
    ]);
    const result = await chain.deliver(fakeChallenge());
    expect(result.status).toBe('unsupported');
  });

  it('short-circuits on first non-unsupported result', async () => {
    const first = new DeliveringOracle('first');
    const second = new DeliveringOracle('second');
    const chain = new OracleChain([first, second]);
    await chain.deliver(fakeChallenge());
    expect(first.delivered).toBe(1);
    expect(second.delivered).toBe(0);
  });

  it('fans child assertions out to chain listeners', async () => {
    const child = new CliPromptOracle();
    const chain = new OracleChain([child]);
    const received: FactorAssertion[] = [];
    chain.onAssertion((a) => {
      received.push(a);
    });
    await child.injectAssertion(fakeAssertion('ch-FAN'));
    expect(received).toHaveLength(1);
    expect(received[0]?.challengeId).toBe('ch-FAN');
  });

  it('exposes a composite name listing children', () => {
    const chain = new OracleChain([
      new UnsupportedOracle(),
      new DeliveringOracle('push'),
    ]);
    expect(chain.name).toContain('unsupported');
    expect(chain.name).toContain('push');
  });
});
