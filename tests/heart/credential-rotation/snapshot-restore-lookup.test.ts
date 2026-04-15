/**
 * Snapshot / restore × event-chain retention × historical lookup
 * (SOMA-ROTATION-SPEC.md §4.7 / §10.1 / §10.2 / §15 item 8;
 * SOMA-DELEGATION-SPEC.md §Rotation Interaction's Slice D code contract).
 *
 * The §10.2 snapshot completeness rule now explicitly requires that
 * a restored controller answer the historical-credential lookup with
 * the same results as the live controller. This file pins that
 * property across several shapes:
 *
 *   1. A long effective-only chain (K=5 rotations). Every
 *      credential's lookup result on the restored controller is
 *      byte-identical to the live controller's, proving §4.7 event
 *      retention survives the snapshot round-trip and §10.2's
 *      `effectiveAt` preservation works.
 *   2. A chain with a trailing anchored-but-not-witnessed event.
 *      Both the still-open supersession (null `effectiveUntil` for
 *      the prior credential) and the not-yet-effective new credential
 *      (null `effectiveFrom`) round-trip correctly.
 *   3. `SNAPSHOT_VERSION` fail-closed: a forged v=1 snapshot is
 *      rejected by `restore()` with a clear error citing §10.1.
 *   4. `SNAPSHOT_VERSION` fail-closed: a forged v=99 snapshot is
 *      rejected the same way.
 *   5. Multi-identity scoping: when both alice and bob have event
 *      chains, a restored controller honours identity-scoped lookups
 *      without cross-bleed.
 *
 * The live/restored comparison uses structural equality on the
 * result shape (`found`, `credential.credentialId`, `effectiveFrom`,
 * `effectiveUntil`), not object identity — restored credentials are
 * fresh objects but their field values must match bit-for-bit.
 */

import { describe, it, expect } from 'vitest';

import {
  CredentialRotationController,
  DEFAULT_POLICY,
  MockCredentialBackend,
  SNAPSHOT_VERSION,
  type ControllerPolicy,
  type ControllerSnapshot,
  type Credential,
  type HistoricalCredentialLookupResult,
} from '../../../src/heart/credential-rotation/index.js';

function makePolicy(): ControllerPolicy {
  return { ...DEFAULT_POLICY, backendAllowlist: ['mock-a'] };
}

function makeHarness(startClock = 1_700_000_000_000): {
  controller: CredentialRotationController;
  backend: MockCredentialBackend;
  clockRef: { t: number };
} {
  const clockRef = { t: startClock };
  const controller = new CredentialRotationController({
    policy: makePolicy(),
    clock: () => clockRef.t,
  });
  const backend = new MockCredentialBackend({ backendId: 'mock-a' });
  controller.registerBackend(backend);
  return { controller, backend, clockRef };
}

/**
 * Structural comparator — strips the `Credential` object to just its
 * identifying fields so two controllers holding distinct-but-equivalent
 * credential objects compare equal.
 */
function stripResult(result: HistoricalCredentialLookupResult): unknown {
  if (!result.found) return result;
  return {
    found: true,
    credentialId: result.credential.credentialId,
    effectiveFrom: result.effectiveFrom,
    effectiveUntil: result.effectiveUntil,
  };
}

async function rotateAndEffect(
  controller: CredentialRotationController,
  identityId: string,
  clockRef: { t: number },
  label: string,
  witnessDelta = 1500,
): Promise<Credential> {
  const { event, credential } = await controller.rotate(identityId);
  controller.anchorEvent(identityId, event.hash, `pulse-${label}`);
  clockRef.t += witnessDelta;
  controller.witnessEvent(identityId, event.hash);
  return credential;
}

describe('snapshot/restore — long effective chain retention (§4.7, §10.2)', () => {
  it('round-trips a 6-credential chain with identical lookup results', async () => {
    const { controller, backend, clockRef } = makeHarness();
    // Incept + 5 rotations.
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'pulse-0');
    clockRef.t += 1000;
    controller.witnessEvent('alice', e0.hash);

    const credentials: Credential[] = [c0];
    for (let i = 1; i <= 5; i++) {
      clockRef.t += 10_000;
      credentials.push(
        await rotateAndEffect(controller, 'alice', clockRef, `r${i}`),
      );
    }

    expect(controller.getEvents('alice').length).toBe(6);

    const snap = controller.snapshot();
    expect(snap.version).toBe(SNAPSHOT_VERSION);

    const restored = CredentialRotationController.restore(snap, {
      backends: [backend],
      clock: () => clockRef.t,
    });

    for (const cred of credentials) {
      const live = controller.lookupHistoricalCredential('alice', {
        kind: 'credentialId',
        credentialId: cred.credentialId,
      });
      const rest = restored.lookupHistoricalCredential('alice', {
        kind: 'credentialId',
        credentialId: cred.credentialId,
      });
      expect(stripResult(rest)).toEqual(stripResult(live));
      // And by publicKey.
      const liveByKey = controller.lookupHistoricalCredential('alice', {
        kind: 'publicKey',
        publicKey: cred.publicKey,
      });
      const restByKey = restored.lookupHistoricalCredential('alice', {
        kind: 'publicKey',
        publicKey: cred.publicKey,
      });
      expect(stripResult(restByKey)).toEqual(stripResult(liveByKey));
    }

    // Ancient (first) credential still reachable — §4.7 retention
    // survived the round-trip.
    const ancient = restored.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    expect(ancient.found).toBe(true);
    if (ancient.found) {
      expect(ancient.effectiveFrom).not.toBeNull();
      expect(ancient.effectiveUntil).not.toBeNull();
    }
  });
});

describe('snapshot/restore — trailing anchored-not-witnessed event', () => {
  it('preserves effectiveFrom=null and the still-open supersession', async () => {
    const { controller, backend, clockRef } = makeHarness();
    const { event: e0, credential: c0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'pulse-0');
    clockRef.t = 1_700_000_001_000;
    controller.witnessEvent('alice', e0.hash);

    clockRef.t = 1_700_000_010_000;
    const { event: e1, credential: c1 } = await controller.rotate('alice');
    controller.anchorEvent('alice', e1.hash, 'pulse-1');
    // NO witness — e1 stays `anchored`.

    const snap = controller.snapshot();
    const restored = CredentialRotationController.restore(snap, {
      backends: [backend],
      clock: () => clockRef.t,
    });

    const restOld = restored.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c0.credentialId,
    });
    expect(restOld.found).toBe(true);
    if (!restOld.found) return;
    expect(restOld.effectiveFrom).toBe(1_700_000_001_000);
    expect(restOld.effectiveUntil).toBeNull();

    const restNew = restored.lookupHistoricalCredential('alice', {
      kind: 'credentialId',
      credentialId: c1.credentialId,
    });
    expect(restNew.found).toBe(true);
    if (!restNew.found) return;
    expect(restNew.effectiveFrom).toBeNull();
    expect(restNew.effectiveUntil).toBeNull();
  });
});

describe('snapshot/restore — SNAPSHOT_VERSION fail-closed (§10.1)', () => {
  it('rejects a forged v=1 snapshot with a clear error', async () => {
    const { controller, backend, clockRef } = makeHarness();
    const { event: e0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'pulse-0');
    clockRef.t += 1000;
    controller.witnessEvent('alice', e0.hash);

    const snap = controller.snapshot();
    const forged = {
      ...snap,
      version: 1 as unknown as typeof SNAPSHOT_VERSION,
    };
    expect(() =>
      CredentialRotationController.restore(forged as ControllerSnapshot, {
        backends: [backend],
      }),
    ).toThrow(/unsupported snapshot version 1/);
  });

  it('rejects a forged future v=99 snapshot', async () => {
    const { controller, backend, clockRef } = makeHarness();
    const { event: e0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'pulse-0');
    clockRef.t += 1000;
    controller.witnessEvent('alice', e0.hash);

    const snap = controller.snapshot();
    const forged = {
      ...snap,
      version: 99 as unknown as typeof SNAPSHOT_VERSION,
    };
    expect(() =>
      CredentialRotationController.restore(forged as ControllerSnapshot, {
        backends: [backend],
      }),
    ).toThrow(/unsupported snapshot version 99/);
  });

  it('the fail-closed error cites §10.1', async () => {
    const { controller, backend, clockRef } = makeHarness();
    const { event: e0 } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', e0.hash, 'pulse-0');
    clockRef.t += 1000;
    controller.witnessEvent('alice', e0.hash);
    const snap = controller.snapshot();
    const forged = {
      ...snap,
      version: 1 as unknown as typeof SNAPSHOT_VERSION,
    };
    let thrown: unknown;
    try {
      CredentialRotationController.restore(forged as ControllerSnapshot, {
        backends: [backend],
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(String((thrown as Error).message)).toContain('§10.1');
  });
});

describe('snapshot/restore — multi-identity scoping', () => {
  it('restored controller preserves identity scoping for lookups', async () => {
    const { controller, backend, clockRef } = makeHarness();
    const { event: ea, credential: ca } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', ea.hash, 'pulse-a');
    clockRef.t += 1000;
    controller.witnessEvent('alice', ea.hash);

    clockRef.t += 1000;
    const { event: eb, credential: cb } = await controller.incept({
      identityId: 'bob',
      backendId: 'mock-a',
    });
    controller.anchorEvent('bob', eb.hash, 'pulse-b');
    clockRef.t += 1000;
    controller.witnessEvent('bob', eb.hash);

    const snap = controller.snapshot();
    const restored = CredentialRotationController.restore(snap, {
      backends: [backend],
      clock: () => clockRef.t,
    });

    // Each credential is visible under its own identity.
    expect(
      restored.lookupHistoricalCredential('alice', {
        kind: 'credentialId',
        credentialId: ca.credentialId,
      }).found,
    ).toBe(true);
    expect(
      restored.lookupHistoricalCredential('bob', {
        kind: 'credentialId',
        credentialId: cb.credentialId,
      }).found,
    ).toBe(true);

    // Cross-lookups miss even by publicKey bytes.
    expect(
      restored.lookupHistoricalCredential('bob', {
        kind: 'publicKey',
        publicKey: ca.publicKey,
      }),
    ).toEqual({ found: false, reason: 'credential-not-in-chain' });
    expect(
      restored.lookupHistoricalCredential('alice', {
        kind: 'publicKey',
        publicKey: cb.publicKey,
      }),
    ).toEqual({ found: false, reason: 'credential-not-in-chain' });
  });
});
