/**
 * Historical-credential lookup (SOMA-ROTATION-SPEC.md §4.8 / §15 item 8;
 * SOMA-DELEGATION-SPEC.md §Rotation Interaction's Slice D code contract).
 *
 * Pins the contract end-to-end:
 *
 *   1. Unknown identity → typed `unknown-identity` miss.
 *   2. Known identity + unknown credential → typed
 *      `credential-not-in-chain` miss.
 *   3. Pending/anchored genesis → credential is visible but
 *      `effectiveFrom = null` — delegation verifier fails closed.
 *   4. Effective genesis → `effectiveFrom = witness-time`,
 *      `effectiveUntil = null`.
 *   5. After a full rotation both events effective:
 *      - the genesis credential's `effectiveUntil` equals the new
 *        event's `effectiveAt` (witness time of the new event),
 *        NOT the old event's or new event's `timestamp` (§4.8);
 *      - the new credential's `effectiveFrom` equals that same
 *        witness time; its `effectiveUntil` is `null`.
 *   6. Rotation staged+anchored-but-not-witnessed:
 *      - the genesis credential's `effectiveUntil` is `null` (the
 *        superseding event has not reached `effective`);
 *      - the new credential is visible with `effectiveFrom = null`.
 *   7. `publicKey` lookup: byte-exact match succeeds, length mismatch
 *      misses, one-byte difference misses.
 *   8. Identity-scoped: a credential under `alice` is invisible when
 *      looked up under `bob`, even by `publicKey`.
 *   9. Pure read: a sequence of lookups does not mutate controller
 *      state (event statuses, `effectiveAt` timestamps, and snapshot
 *      digests stay byte-identical).
 *  10. Accepted-pool independence: a credential that is still in the
 *      `accepted` grace pool after rotation still reports the
 *      **historical** effective window, not a live-grace proxy.
 *  11. Timestamp vs. effectiveAt: when stage time and witness time
 *      are pinned to distinct values, `effectiveFrom`/`effectiveUntil`
 *      follow witness time, not stage time. This is the load-bearing
 *      property from §4.8 — using `timestamp` as a proxy would admit
 *      delegations the delegation verifier must reject.
 */

import { describe, it, expect } from 'vitest';

import {
  CredentialRotationController,
  DEFAULT_POLICY,
  MockCredentialBackend,
  type ControllerPolicy,
} from '../../../src/heart/credential-rotation/index.js';

function makePolicy(): ControllerPolicy {
  return { ...DEFAULT_POLICY, backendAllowlist: ['mock-a'] };
}

async function fullyEffective(
  controller: CredentialRotationController,
  identityId: string,
  eventHash: string,
  clockRef: { t: number },
  witnessAt?: number,
) {
  controller.anchorEvent(identityId, eventHash, `pulse-${eventHash.slice(0, 6)}`);
  if (witnessAt !== undefined) clockRef.t = witnessAt;
  controller.witnessEvent(identityId, eventHash);
}

function makeHarness(): {
  controller: CredentialRotationController;
  backend: MockCredentialBackend;
  clockRef: { t: number };
} {
  const clockRef = { t: 1_700_000_000_000 };
  const controller = new CredentialRotationController({
    policy: makePolicy(),
    clock: () => clockRef.t,
  });
  const backend = new MockCredentialBackend({ backendId: 'mock-a' });
  controller.registerBackend(backend);
  return { controller, backend, clockRef };
}

describe('lookupHistoricalCredential — typed misses', () => {
  it('returns unknown-identity for an identity that was never inceptioned', () => {
    const { controller } = makeHarness();
    const result = controller.lookupHistoricalCredential('nobody', {
      kind: 'credentialId',
      credentialId: 'anything',
    });
    expect(result).toEqual({ found: false, reason: 'unknown-identity' });
  });

  it('returns credential-not-in-chain for a known identity + unknown credential id', async () => {
    const { controller, clockRef } = makeHarness();
    const { event } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', event.hash, clockRef);

    const result = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: 'nonexistent-id',
    });
    expect(result).toEqual({ found: false, reason: 'credential-not-in-chain' });
  });

  it('returns credential-not-in-chain for a known identity + unknown publicKey', async () => {
    const { controller, clockRef } = makeHarness();
    const { event } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', event.hash, clockRef);

    const stranger = new Uint8Array(32).fill(0xaa);
    const result = controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: stranger,
    });
    expect(result).toEqual({ found: false, reason: 'credential-not-in-chain' });
  });
});

describe('lookupHistoricalCredential — single-event chain', () => {
  it('pending genesis: credential visible, effectiveFrom=null, effectiveUntil=null', async () => {
    const { controller } = makeHarness();
    const { credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    // No anchor, no witness — event is still `pending`.
    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: credential.credentialId,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.credential.credentialId).toBe(credential.credentialId);
    expect(hit.effectiveFrom).toBeNull();
    expect(hit.effectiveUntil).toBeNull();
  });

  it('anchored-not-witnessed genesis: effectiveFrom still null', async () => {
    const { controller } = makeHarness();
    const { event, credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', event.hash, 'pulse-root-0');
    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: credential.credentialId,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.effectiveFrom).toBeNull();
  });

  it('effective genesis: effectiveFrom = witness clock, effectiveUntil = null', async () => {
    const { controller, clockRef } = makeHarness();
    clockRef.t = 1_700_000_000_000;
    const { event, credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', event.hash, 'pulse-root-0');
    clockRef.t = 1_700_000_005_000; // advance clock before witness
    controller.witnessEvent('alice', event.hash);

    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: credential.credentialId,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.effectiveFrom).toBe(1_700_000_005_000);
    expect(hit.effectiveUntil).toBeNull();
  });
});

describe('lookupHistoricalCredential — multi-event chain', () => {
  it('both events effective: effectiveUntil of old = effectiveAt of new', async () => {
    const { controller, clockRef } = makeHarness();
    clockRef.t = 1_700_000_000_000;
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'root-0');
    clockRef.t = 1_700_000_001_000;
    controller.witnessEvent('alice', e0.hash);

    clockRef.t = 1_700_000_010_000;
    const { event: e1, credential: c1 } = await controller.rotate('alice');
    controller.anchorEvent('alice', e1.hash, 'root-1');
    clockRef.t = 1_700_000_011_500;
    controller.witnessEvent('alice', e1.hash);

    const hitOld = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    expect(hitOld.found).toBe(true);
    if (!hitOld.found) return;
    expect(hitOld.effectiveFrom).toBe(1_700_000_001_000);
    expect(hitOld.effectiveUntil).toBe(1_700_000_011_500);

    const hitNew = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c1.credentialId,
    });
    expect(hitNew.found).toBe(true);
    if (!hitNew.found) return;
    expect(hitNew.effectiveFrom).toBe(1_700_000_011_500);
    expect(hitNew.effectiveUntil).toBeNull();
  });

  it('rotation anchored-but-not-witnessed: old window still open, new has effectiveFrom=null', async () => {
    const { controller, clockRef } = makeHarness();
    clockRef.t = 1_700_000_000_000;
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'root-0');
    clockRef.t = 1_700_000_001_000;
    controller.witnessEvent('alice', e0.hash);

    clockRef.t = 1_700_000_010_000;
    const { event: e1, credential: c1 } = await controller.rotate('alice');
    controller.anchorEvent('alice', e1.hash, 'root-1');
    // NO witness call — e1 stays `anchored`.

    const hitOld = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    expect(hitOld.found).toBe(true);
    if (!hitOld.found) return;
    expect(hitOld.effectiveFrom).toBe(1_700_000_001_000);
    // Superseding event has effectiveAt = null, so the window stays open.
    expect(hitOld.effectiveUntil).toBeNull();

    const hitNew = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c1.credentialId,
    });
    expect(hitNew.found).toBe(true);
    if (!hitNew.found) return;
    expect(hitNew.effectiveFrom).toBeNull();
    expect(hitNew.effectiveUntil).toBeNull();
  });

  it('effectiveFrom/Until follow witness time, not stage time (§4.8 load-bearing)', async () => {
    // If the controller used `event.timestamp` (stage time) as a proxy
    // for the window, `effectiveFrom` would equal 1_700_000_010_000
    // here and the delegation verifier's "effective at issued_at"
    // check would admit a delegation issued at 1_700_000_010_500 —
    // which is inside the L3 unwitnessed window and MUST be rejected.
    // Pinning witness time 1500 ms later proves the lookup uses
    // `effectiveAt` per §4.8.
    const { controller, clockRef } = makeHarness();
    clockRef.t = 1_700_000_000_000;
    const { event: e0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'root-0');
    clockRef.t = 1_700_000_000_500;
    controller.witnessEvent('alice', e0.hash);

    clockRef.t = 1_700_000_010_000; // stage time of the rotation
    const { event: e1, credential: c1 } = await controller.rotate('alice');
    // e1.timestamp now equals 1_700_000_010_000.
    expect(e1.timestamp).toBe(1_700_000_010_000);

    controller.anchorEvent('alice', e1.hash, 'root-1');
    clockRef.t = 1_700_000_011_500; // witness time, strictly later
    controller.witnessEvent('alice', e1.hash);

    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c1.credentialId,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.effectiveFrom).toBe(1_700_000_011_500);
    expect(hit.effectiveFrom).not.toBe(e1.timestamp);
  });
});

describe('lookupHistoricalCredential — publicKey matching', () => {
  it('byte-exact publicKey lookup finds the credential', async () => {
    const { controller, clockRef } = makeHarness();
    const { event, credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', event.hash, clockRef);

    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: credential.publicKey,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.credential.credentialId).toBe(credential.credentialId);
  });

  it('length-mismatched publicKey is a miss', async () => {
    const { controller, clockRef } = makeHarness();
    const { event } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', event.hash, clockRef);

    const wrongLen = new Uint8Array(16).fill(0x42);
    const miss = controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: wrongLen,
    });
    expect(miss).toEqual({ found: false, reason: 'credential-not-in-chain' });
  });

  it('one-byte-different publicKey is a miss', async () => {
    const { controller, clockRef } = makeHarness();
    const { event, credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', event.hash, clockRef);

    const tampered = new Uint8Array(credential.publicKey);
    tampered[tampered.length - 1] = tampered[tampered.length - 1] ^ 0x01;
    const miss = controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: tampered,
    });
    expect(miss).toEqual({ found: false, reason: 'credential-not-in-chain' });
  });
});

describe('lookupHistoricalCredential — identity scoping', () => {
  it('alice credential is invisible under bob, even by publicKey', async () => {
    const { controller, clockRef } = makeHarness();
    const { event: ea, credential: ca } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'alice', ea.hash, clockRef);

    clockRef.t += 1000;
    const { event: eb } = await controller.incept({
      identityId: 'bob',
      backendId: 'mock-a',
    });
    await fullyEffective(controller, 'bob', eb.hash, clockRef);

    const missUnderBob = controller.lookupHistoricalCredential('bob', {
      kind: 'credentialId',
      credentialId: ca.credentialId,
    });
    expect(missUnderBob).toEqual({
      found: false,
      reason: 'credential-not-in-chain',
    });
    const missUnderBobByKey = controller.lookupHistoricalCredential('bob', {
      kind: 'publicKey',
      publicKey: ca.publicKey,
    });
    expect(missUnderBobByKey).toEqual({
      found: false,
      reason: 'credential-not-in-chain',
    });
  });
});

describe('lookupHistoricalCredential — pure read and pool independence', () => {
  it('lookups do not mutate event-chain state or effectiveAt values', async () => {
    const { controller, clockRef } = makeHarness();
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'root-0');
    clockRef.t = 1_700_000_001_000;
    controller.witnessEvent('alice', e0.hash);
    clockRef.t = 1_700_000_010_000;
    const { event: e1, credential: c1 } = await controller.rotate('alice');
    controller.anchorEvent('alice', e1.hash, 'root-1');
    clockRef.t = 1_700_000_011_500;
    controller.witnessEvent('alice', e1.hash);

    const beforeSnap = JSON.stringify(controller.snapshot());

    controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c1.credentialId,
    });
    controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: c0.publicKey,
    });
    controller.lookupHistoricalCredential('alice', {
      kind: 'publicKey',
      publicKey: c1.publicKey,
    });
    controller.lookupHistoricalCredential('bob', {
      kind: 'credentialId',
      credentialId: 'whatever',
    });

    const afterSnap = JSON.stringify(controller.snapshot());
    expect(afterSnap).toBe(beforeSnap);
  });

  it('accepted-pool membership does not alter the historical window', async () => {
    const { controller, clockRef } = makeHarness();
    clockRef.t = 1_700_000_000_000;
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'root-0');
    clockRef.t = 1_700_000_001_000;
    controller.witnessEvent('alice', e0.hash);

    clockRef.t = 1_700_000_010_000;
    const { event: e1 } = await controller.rotate('alice');
    controller.anchorEvent('alice', e1.hash, 'root-1');
    clockRef.t = 1_700_000_011_500;
    controller.witnessEvent('alice', e1.hash);

    // After rotation, c0 is in the accepted pool (grace window).
    // The lookup MUST still report the historical window computed
    // from the event chain's `effectiveAt` values, NOT anything
    // derived from the live accepted-pool grace.
    const hit = controller.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    expect(hit.found).toBe(true);
    if (!hit.found) return;
    expect(hit.effectiveFrom).toBe(1_700_000_001_000);
    expect(hit.effectiveUntil).toBe(1_700_000_011_500);
  });
});
