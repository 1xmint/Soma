/**
 * Package-surface pin for Gate 6 (ADR-0004).
 *
 * Guards that the top-level `src/heart/index.ts` barrel — the module
 * that becomes `soma-heart`'s main entry — re-exports the
 * credential-rotation names that Slice D / Slice E promoted to the
 * public surface:
 *
 *   - `SNAPSHOT_VERSION` (value, for durable persistence consumers)
 *   - `ControllerSnapshot` (type)
 *   - `HistoricalCredentialLookupHit/Key/Miss/Result` (types)
 *
 * The `./credential-rotation` subpath already exports all of these;
 * this file pins the `.` entry so consumers importing from the package
 * root don't regress.
 *
 * Value-level check uses `SNAPSHOT_VERSION === 2` to both exercise the
 * runtime re-export and cross-check that the value agrees with the
 * snapshot.ts source of truth. Type-level checks use `satisfies` so a
 * broken re-export fails at typecheck time, not just at runtime.
 */

import { describe, it, expect } from 'vitest';

import {
  SNAPSHOT_VERSION,
  CredentialRotationController,
  MockCredentialBackend,
  DEFAULT_POLICY,
  type ControllerSnapshot,
  type HistoricalCredentialLookupHit,
  type HistoricalCredentialLookupKey,
  type HistoricalCredentialLookupMiss,
  type HistoricalCredentialLookupResult,
} from '../../src/heart/index.js';

describe('Gate 6 package surface — top-level heart entry', () => {
  it('re-exports SNAPSHOT_VERSION as the current v2 value', () => {
    expect(SNAPSHOT_VERSION).toBe(2);
  });

  it('re-exports ControllerSnapshot as a usable type alias', async () => {
    const clockRef = { t: 1_700_000_000_000 };
    const controller = new CredentialRotationController({
      policy: { ...DEFAULT_POLICY, backendAllowlist: ['mock-a'] },
      clock: () => clockRef.t,
    });
    const backend = new MockCredentialBackend({ backendId: 'mock-a' });
    controller.registerBackend(backend);
    const { event } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', event.hash, 'pulse-0');
    clockRef.t += 100;
    controller.witnessEvent('alice', event.hash);

    const snap: ControllerSnapshot = controller.snapshot();
    expect(snap.version).toBe(SNAPSHOT_VERSION);
  });

  it('re-exports HistoricalCredentialLookup* types as usable aliases', async () => {
    const clockRef = { t: 1_700_000_000_000 };
    const controller = new CredentialRotationController({
      policy: { ...DEFAULT_POLICY, backendAllowlist: ['mock-a'] },
      clock: () => clockRef.t,
    });
    const backend = new MockCredentialBackend({ backendId: 'mock-a' });
    controller.registerBackend(backend);
    const { event, credential } = await controller.incept({
      identityId: 'alice',
      backendId: 'mock-a',
    });
    controller.anchorEvent('alice', event.hash, 'pulse-0');
    clockRef.t += 100;
    controller.witnessEvent('alice', event.hash);

    const hitKey: HistoricalCredentialLookupKey = {
      kind: 'credentialId',
      credentialId: credential.credentialId,
    };
    const missKey: HistoricalCredentialLookupKey = {
      kind: 'credentialId',
      credentialId: 'does-not-exist',
    };

    const hit: HistoricalCredentialLookupResult =
      controller.lookupHistoricalCredential('alice', hitKey);
    const miss: HistoricalCredentialLookupResult =
      controller.lookupHistoricalCredential('alice', missKey);

    expect(hit.found).toBe(true);
    if (hit.found) {
      const narrowed: HistoricalCredentialLookupHit = hit;
      expect(narrowed.credential.credentialId).toBe(credential.credentialId);
      expect(narrowed.effectiveFrom).not.toBeNull();
    }

    expect(miss.found).toBe(false);
    if (!miss.found) {
      const narrowed: HistoricalCredentialLookupMiss = miss;
      expect(narrowed.reason).toBe('credential-not-in-chain');
    }
  });
});
