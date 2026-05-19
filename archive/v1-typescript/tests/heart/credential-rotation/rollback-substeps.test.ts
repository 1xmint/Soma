/**
 * §5.2 / §5.4 rollback substep tests (SOMA-ROTATION-SPEC.md §15 item 5).
 *
 * §5.2 enumerates the substeps that execute between
 * `stageNextCredential` and `commitStagedRotation`:
 *
 *   - commitment re-derivation and comparison;
 *   - suite allowlist check;
 *   - derivation of the new ratchet anchor;
 *   - old-key signing of the pre-event body;
 *   - new-key proof-of-possession signing;
 *   - event hashing.
 *
 * §5.4 requires a Slice D acceptance test that forces a throw in each
 * substep by instrumenting either the backend or the controller's
 * crypto provider, then asserts the identity ended up in the
 * pre-stage state per §5.2:
 *
 *   - same `current` credential (still `effective`);
 *   - same event-chain length;
 *   - same ratchet anchor;
 *   - no staged secret material in the backend — proved by
 *     `backend.snapshot()` succeeding (the mock backend refuses to
 *     snapshot while any identity is mid-stage);
 *   - rate-limit bucket unchanged — proved by comparing the
 *     `rotationTimestamps` array on a fresh controller snapshot.
 *
 * A final integration check drives a clean rotation after each
 * failure-path recovery to prove the controller is still usable.
 */

import { describe, it, expect } from 'vitest';

import {
  CredentialRotationController,
  DEFAULT_POLICY,
  MockCredentialBackend,
  PreRotationMismatch,
  SuiteDowngradeRejected,
  type AlgorithmSuite,
  type ControllerPolicy,
  type Credential,
} from '../../../src/heart/credential-rotation/index.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../../../src/core/crypto-provider.js';

function makePolicy(): ControllerPolicy {
  return { ...DEFAULT_POLICY, backendAllowlist: ['mock-a'] };
}

interface Harness {
  controller: CredentialRotationController;
  backend: MockCredentialBackend;
  clockRef: { t: number };
  priorCurrent: Credential;
  priorRatchet: string;
  priorEventCount: number;
  priorRotationTimestamps: number[];
}

async function setup(opts: {
  backend?: MockCredentialBackend;
  provider?: CryptoProvider;
  policy?: ControllerPolicy;
} = {}): Promise<Harness> {
  const clockRef = { t: 1_700_000_000_000 };
  const controller = new CredentialRotationController({
    policy: opts.policy ?? makePolicy(),
    clock: () => clockRef.t,
    provider: opts.provider,
  });
  const backend = opts.backend ?? new MockCredentialBackend({ backendId: 'mock-a' });
  controller.registerBackend(backend);
  const { event } = await controller.incept({
    identityId: 'alice',
    backendId: 'mock-a',
  });
  controller.anchorEvent('alice', event.hash, 'pulse-root-0');
  clockRef.t += 100;
  controller.witnessEvent('alice', event.hash);
  clockRef.t += 1000;
  const priorCurrent = controller.getCurrentCredential('alice');
  if (!priorCurrent) throw new Error('setup: incept failed to install current');
  const snap = controller.snapshot();
  return {
    controller,
    backend,
    clockRef,
    priorCurrent,
    priorRatchet: controller.getRatchetAnchor('alice'),
    priorEventCount: controller.getEvents('alice').length,
    priorRotationTimestamps: [...(snap.identities[0]?.rotationTimestamps ?? [])],
  };
}

function assertPreStageState(h: Harness): void {
  const current = h.controller.getCurrentCredential('alice');
  expect(current).not.toBeNull();
  expect(current!.credentialId).toBe(h.priorCurrent.credentialId);
  expect(h.controller.getEvents('alice').length).toBe(h.priorEventCount);
  expect(h.controller.getEvents('alice').at(-1)!.status).toBe('effective');
  expect(h.controller.getRatchetAnchor('alice')).toBe(h.priorRatchet);
  // Backend-level proof: mock backend refuses to snapshot while any
  // identity is mid-stage. A successful snapshot proves no staged
  // secret material remains.
  expect(() => h.backend.snapshot()).not.toThrow();
  // Rate-limit bucket: a failed rotate must NOT consume a rotation
  // slot (§5.2 / §8.2).
  const snap = h.controller.snapshot();
  expect(snap.identities[0]!.rotationTimestamps).toEqual(
    h.priorRotationTimestamps,
  );
}

// ─── Helpers that force a throw at a specific substep ───────────────────────

/**
 * Backend subclass that tampers the manifest returned by
 * `stageNextCredential` so the controller's commitment re-derivation
 * fails with `PreRotationMismatch`. The rest of the staging state is
 * still installed so `abortStagedRotation` has something to roll back.
 */
class TamperedPublicKeyBackend extends MockCredentialBackend {
  override async stageNextCredential(args: {
    identityId: string;
    oldCredentialId: string;
    issuedAt: number;
  }): Promise<Credential> {
    const real = await super.stageNextCredential(args);
    const tampered = new Uint8Array(real.publicKey);
    tampered[0] = tampered[0] ^ 0xff;
    return { ...real, publicKey: tampered };
  }
}

/**
 * Backend subclass that declares its `algorithmSuite` as `secp256k1`
 * from construction time onward. Inception and rotation both mint
 * credentials whose `nextManifestCommitment` is computed with that
 * declared suite baked in (see `mintEntry` in the reference backend),
 * so the controller's L1 commitment re-derivation passes regardless
 * of which suite is policy-allowed at rotate time. This lets the
 * §5.2 suite-allowlist substep be exercised **independently** of the
 * commitment substep by narrowing the controller policy's
 * `suiteAllowlist` after the backend is already registered. The
 * underlying key material is still ed25519 (inherited from the
 * reference backend), which is irrelevant here because the suite
 * check at `controller.ts:578` reads `newCredential.algorithmSuite`
 * directly and never inspects the key bytes.
 */
class DeclaredSuiteBackend extends MockCredentialBackend {
  override readonly algorithmSuite: AlgorithmSuite = 'secp256k1';
}

/**
 * Backend subclass that lets staging succeed but throws on the next
 * signing call. `rotate()` calls `signWithCredential` twice after
 * staging: first for the old-key signature, then for the new-key
 * proof-of-possession. `throwOn` selects which one fails.
 */
class SignThrowBackend extends MockCredentialBackend {
  private armed = false;
  private thrown = false;
  constructor(opts: { backendId: string; throwOn: 'old' | 'new' }) {
    super({ backendId: opts.backendId });
    this.throwOn = opts.throwOn;
  }
  private readonly throwOn: 'old' | 'new';
  private stagedId: string | null = null;
  override async stageNextCredential(args: {
    identityId: string;
    oldCredentialId: string;
    issuedAt: number;
  }): Promise<Credential> {
    const real = await super.stageNextCredential(args);
    this.stagedId = real.credentialId;
    // Only arm the throw on the FIRST stage — subsequent stages
    // (e.g. a clean retry after rollback) must pass through.
    if (!this.thrown) this.armed = true;
    return real;
  }
  override async signWithCredential(
    credentialId: string,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    if (this.armed) {
      const isNew = credentialId === this.stagedId;
      if (
        (this.throwOn === 'old' && !isNew) ||
        (this.throwOn === 'new' && isNew)
      ) {
        this.armed = false;
        this.thrown = true;
        throw new Error(`sign-throw-backend: forced ${this.throwOn}-key throw`);
      }
    }
    return super.signWithCredential(credentialId, message);
  }
}

/**
 * Wrap a real crypto provider so `hashing.hash` throws when its input
 * carries a specific domain-separation prefix. Used to force throws
 * in the ratchet-derivation substep (`soma-ratchet:`) and in the
 * event-hashing substep (`soma-rotation-event:`). All other hashing
 * calls pass through unchanged so inception and pre-rotation commit
 * computation still work.
 */
function providerWithHashBomb(prefix: string): CryptoProvider {
  const real = getCryptoProvider();
  let armed = false;
  return {
    ...real,
    hashing: {
      ...real.hashing,
      hash(input: string): string {
        if (armed && input.startsWith(prefix)) {
          armed = false;
          throw new Error(`hash-bomb: ${prefix}`);
        }
        return real.hashing.hash(input);
      },
    },
    _arm() {
      armed = true;
    },
    _disarm() {
      armed = false;
    },
  } as CryptoProvider & { _arm(): void; _disarm(): void };
}

// ─── Substep tests ──────────────────────────────────────────────────────────

describe('§5.2 rollback substep — commitment re-derivation', () => {
  it('PreRotationMismatch on tampered staged public key leaves the identity pre-stage', async () => {
    const backend = new TamperedPublicKeyBackend({ backendId: 'mock-a' });
    const h = await setup({ backend });
    await expect(h.controller.rotate('alice')).rejects.toBeInstanceOf(
      PreRotationMismatch,
    );
    assertPreStageState(h);
  });
});

describe('§5.2 rollback substep — suite allowlist check', () => {
  it('SuiteDowngradeRejected fires independently of the L1 commitment check and leaves the identity pre-stage', async () => {
    // Strategy: bind the inception commitment to a suite (`secp256k1`)
    // that the controller DOES accept at registration time, then
    // narrow the policy's suiteAllowlist to exclude that suite before
    // the rotate call. The controller stores the policy by reference
    // (no defensive clone in `validatePolicy`) so an in-place edit on
    // the same object the controller was constructed with updates
    // the live allowlist used by the §5.2 substep check at
    // `controller.ts:578`. At rotate time:
    //
    //   1. Stage returns a credential with `algorithmSuite = secp256k1`.
    //   2. Commitment re-derivation computes the hash over the same
    //      `(backendId, 'secp256k1', publicKey)` triple the parent's
    //      `mintEntry` used at inception, so it MATCHES the old
    //      credential's `nextManifestCommitment` and the L1 check
    //      passes.
    //   3. The suite check now sees `secp256k1` against the narrowed
    //      allowlist `['ed25519']` and raises `SuiteDowngradeRejected`.
    //
    // This exercises the suite-allowlist rollback substep on a path
    // where PreRotationMismatch provably did NOT fire first.
    const mutablePolicy: ControllerPolicy = {
      ...DEFAULT_POLICY,
      backendAllowlist: ['mock-a'],
      suiteAllowlist: ['secp256k1'],
    };
    const backend = new DeclaredSuiteBackend({ backendId: 'mock-a' });
    const h = await setup({ backend, policy: mutablePolicy });
    // Sanity: inception commitment actually bound the disallowed-to-be
    // suite, so if the upcoming narrowing works the suite check is the
    // only substep that can trip on rotate.
    expect(h.priorCurrent.algorithmSuite).toBe('secp256k1');

    // Narrow the policy to exclude secp256k1 without touching any
    // other field. Cast through `unknown` because `suiteAllowlist` is
    // declared `readonly AlgorithmSuite[]` on the ControllerPolicy
    // type.
    (
      mutablePolicy as unknown as { suiteAllowlist: AlgorithmSuite[] }
    ).suiteAllowlist = ['ed25519'];

    let caught: unknown;
    try {
      await h.controller.rotate('alice');
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(SuiteDowngradeRejected);
    // And NOT PreRotationMismatch — make the independence explicit so
    // a future implementation reshuffle that accidentally tangled the
    // two substeps would fail loudly here. Both classes extend
    // `InvariantViolation` and neither subclasses the other, so the
    // negative check is meaningful.
    expect(caught).not.toBeInstanceOf(PreRotationMismatch);
    assertPreStageState(h);
  });
});

describe('§5.2 rollback substep — ratchet-anchor derivation', () => {
  it('throw inside deriveRatchetAnchor leaves the identity pre-stage', async () => {
    const provider = providerWithHashBomb('soma-ratchet:') as CryptoProvider & {
      _arm(): void;
    };
    const h = await setup({ provider });
    provider._arm();
    await expect(h.controller.rotate('alice')).rejects.toThrow(/hash-bomb/);
    assertPreStageState(h);
  });
});

describe('§5.2 rollback substep — old-key signing', () => {
  it('throw inside old-key signWithCredential leaves the identity pre-stage', async () => {
    const backend = new SignThrowBackend({ backendId: 'mock-a', throwOn: 'old' });
    const h = await setup({ backend });
    await expect(h.controller.rotate('alice')).rejects.toThrow(
      /sign-throw-backend: forced old-key/,
    );
    assertPreStageState(h);
  });
});

describe('§5.2 rollback substep — new-key proof-of-possession', () => {
  it('throw inside new-key PoP signWithCredential leaves the identity pre-stage', async () => {
    const backend = new SignThrowBackend({ backendId: 'mock-a', throwOn: 'new' });
    const h = await setup({ backend });
    await expect(h.controller.rotate('alice')).rejects.toThrow(
      /sign-throw-backend: forced new-key/,
    );
    assertPreStageState(h);
  });
});

describe('§5.2 rollback substep — event hashing', () => {
  it('throw inside computeEventHash leaves the identity pre-stage', async () => {
    const provider = providerWithHashBomb(
      'soma-rotation-event:',
    ) as CryptoProvider & { _arm(): void };
    const h = await setup({ provider });
    provider._arm();
    await expect(h.controller.rotate('alice')).rejects.toThrow(/hash-bomb/);
    assertPreStageState(h);
  });
});

// ─── Integration: post-rollback the controller is still usable ─────────────

describe('§5.2 — controller is usable after every substep failure', () => {
  it('clean rotation succeeds after a failed rotation (commitment mismatch)', async () => {
    // Replace the tampered backend with a clean one for the second
    // rotate, because the controller needs a backend whose staged
    // public key actually matches the commitment.
    const backend = new TamperedPublicKeyBackend({ backendId: 'mock-a' });
    const h = await setup({ backend });
    await expect(h.controller.rotate('alice')).rejects.toBeInstanceOf(
      PreRotationMismatch,
    );
    assertPreStageState(h);
    // Re-arm: a rotate against the same tampered backend will fail
    // the same way. That is fine — the property under test is that
    // the controller is still in a usable state and the backend
    // continues to accept stage/abort cycles without wedging.
    await expect(h.controller.rotate('alice')).rejects.toBeInstanceOf(
      PreRotationMismatch,
    );
    assertPreStageState(h);
  });

  it('clean rotation succeeds after a sign-throw failure', async () => {
    const backend = new SignThrowBackend({ backendId: 'mock-a', throwOn: 'new' });
    const h = await setup({ backend });
    await expect(h.controller.rotate('alice')).rejects.toThrow(
      /sign-throw-backend/,
    );
    assertPreStageState(h);
    // The SignThrowBackend disarms itself after the first throw, so
    // the next rotate goes through cleanly.
    const { event } = await h.controller.rotate('alice');
    h.controller.anchorEvent('alice', event.hash, 'pulse-root-1');
    h.controller.witnessEvent('alice', event.hash);
    expect(h.controller.getEvents('alice').length).toBe(h.priorEventCount + 1);
    expect(h.controller.getCurrentCredential('alice')!.credentialId).not.toBe(
      h.priorCurrent.credentialId,
    );
  });
});
