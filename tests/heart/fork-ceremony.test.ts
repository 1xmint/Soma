import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { createGenome, commitGenome } from '../../src/core/genome.js';
import { forkCeremony, type ForkCeremonyOptions } from '../../src/heart/fork-ceremony.js';
import {
  loadHeartState, serializeHeart, signKeyPairToJson,
  type HeartState,
} from '../../src/heart/persistence.js';
import { verifyLineageChain, effectiveCapabilities, type HeartLineage } from '../../src/heart/lineage.js';

const FAST_SCRYPT = { N: 1024, r: 1, p: 1 };

function createTestHeart(secret: string, provider = getCryptoProvider()) {
  const kp = provider.signing.generateKeyPair();
  const genome = createGenome({
    modelProvider: 'test',
    modelId: 'test-model',
    modelVersion: '1',
    systemPrompt: 'test',
    toolManifest: '[]',
    runtimeId: 'test',
  }, provider);
  const commitment = commitGenome(genome, kp, provider);
  const state: HeartState = {
    version: 1,
    genome: commitment,
    signingKey: signKeyPairToJson(kp, provider),
    modelId: 'test-model',
    modelBaseUrl: 'http://localhost',
    dataSources: [],
    credentials: [],
    heartbeats: [],
    revocations: [],
    savedAt: Date.now(),
  };
  const blob = serializeHeart(state, secret, { scrypt: FAST_SCRYPT, provider });
  return { blob, secret, state, kp, commitment };
}

describe('Fork Ceremony', () => {
  it('happy path — parent + child, verifiable chain', () => {
    const parent = createTestHeart('parent-pw');
    const child = createTestHeart('child-pw');

    const result = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'parent-pw',
      childBlob: child.blob,
      childSecret: 'child-pw',
      scryptParams: FAST_SCRYPT,
    });

    expect(result.parentDid).toBe(parent.commitment.did);
    expect(result.childDid).toBe(child.commitment.did);
    expect(result.chainLength).toBe(1);
    expect(result.rootDid).toBe(parent.commitment.did);

    const patchedState = loadHeartState(result.childBlob, 'child-pw');
    expect(patchedState.lineageChain).toHaveLength(1);
    expect(patchedState.lineageRootDid).toBe(parent.commitment.did);

    const lineage: HeartLineage = {
      did: child.commitment.did,
      rootDid: result.rootDid,
      chain: patchedState.lineageChain!,
    };
    expect(verifyLineageChain(lineage).valid).toBe(true);
  });

  it('re-ceremony — different certificateId, same DIDs', () => {
    const parent = createTestHeart('p');
    const child = createTestHeart('c');

    const r1 = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childBlob: child.blob,
      childSecret: 'c',
      scryptParams: FAST_SCRYPT,
    });
    const r2 = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childBlob: child.blob,
      childSecret: 'c',
      scryptParams: FAST_SCRYPT,
    });

    expect(r1.certificateId).not.toBe(r2.certificateId);
    expect(r1.parentDid).toBe(r2.parentDid);
    expect(r1.childDid).toBe(r2.childDid);
  });

  it('multi-level — A→B→C, chain length 2, root is A', () => {
    const a = createTestHeart('a');
    const b = createTestHeart('b');
    const c = createTestHeart('c');

    const ab = forkCeremony({
      parentBlob: a.blob,
      parentSecret: 'a',
      childBlob: b.blob,
      childSecret: 'b',
      scryptParams: FAST_SCRYPT,
    });

    const bc = forkCeremony({
      parentBlob: ab.childBlob,
      parentSecret: 'b',
      childBlob: c.blob,
      childSecret: 'c',
      scryptParams: FAST_SCRYPT,
    });

    expect(bc.chainLength).toBe(2);
    expect(bc.rootDid).toBe(a.commitment.did);

    const cState = loadHeartState(bc.childBlob, 'c');
    const lineage: HeartLineage = {
      did: c.commitment.did,
      rootDid: bc.rootDid,
      chain: cState.lineageChain!,
    };
    expect(verifyLineageChain(lineage).valid).toBe(true);
  });

  it('capability attenuation — granted capabilities carry through', () => {
    const parent = createTestHeart('p');
    const child = createTestHeart('c');

    const result = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childBlob: child.blob,
      childSecret: 'c',
      capabilities: ['tool:search', 'tool:db'],
      scryptParams: FAST_SCRYPT,
    });

    const cState = loadHeartState(result.childBlob, 'c');
    expect(cState.lineageChain![0].capabilities).toEqual(['tool:search', 'tool:db']);

    const lineage: HeartLineage = {
      did: child.commitment.did,
      rootDid: result.rootDid,
      chain: cState.lineageChain!,
    };
    const caps = effectiveCapabilities(lineage);
    expect(caps).toEqual(['tool:search', 'tool:db']);
  });

  it('no child blob — creates fresh child heart', () => {
    const parent = createTestHeart('p');

    const result = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childSecret: 'fresh-child',
      scryptParams: FAST_SCRYPT,
    });

    expect(result.childDid).toBeTruthy();
    expect(result.childDid).not.toBe(result.parentDid);
    expect(result.chainLength).toBe(1);

    const cState = loadHeartState(result.childBlob, 'fresh-child');
    expect(cState.lineageChain).toHaveLength(1);
    expect(cState.lineageRootDid).toBe(parent.commitment.did);
    expect(cState.genome.did).toBe(result.childDid);

    const lineage: HeartLineage = {
      did: result.childDid,
      rootDid: result.rootDid,
      chain: cState.lineageChain!,
    };
    expect(verifyLineageChain(lineage).valid).toBe(true);
  });

  it('error — wrong parent password', () => {
    const parent = createTestHeart('correct');

    expect(() =>
      forkCeremony({
        parentBlob: parent.blob,
        parentSecret: 'wrong',
        childSecret: 'c',
        scryptParams: FAST_SCRYPT,
      }),
    ).toThrow(/decryption failed|wrong password/);
  });

  it('error — tampered parent blob', () => {
    const parent = createTestHeart('p');
    const tampered = parent.blob.slice(0, -10) + 'XXXXXXXXXX';

    expect(() =>
      forkCeremony({
        parentBlob: tampered,
        parentSecret: 'p',
        childSecret: 'c',
        scryptParams: FAST_SCRYPT,
      }),
    ).toThrow();
  });

  it('idempotency — same inputs produce same child DID but different certificateId', () => {
    const parent = createTestHeart('p');
    const child = createTestHeart('c');

    const r1 = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childBlob: child.blob,
      childSecret: 'c',
      scryptParams: FAST_SCRYPT,
    });
    const r2 = forkCeremony({
      parentBlob: parent.blob,
      parentSecret: 'p',
      childBlob: child.blob,
      childSecret: 'c',
      scryptParams: FAST_SCRYPT,
    });

    expect(r1.childDid).toBe(r2.childDid);
    expect(r1.parentDid).toBe(r2.parentDid);
    expect(r1.certificateId).not.toBe(r2.certificateId);
  });
});
