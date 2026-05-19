/**
 * Credential-rotation fuzz / property tests.
 *
 * Drives the controller through long random sequences of
 * incept / rotate / anchor / witness / ack / snapshot+restore and
 * asserts the chain invariants hold after every step:
 *
 *   P1. Monotonic sequence: every event has sequence === index.
 *   P2. Chain linkage: each event's previousEventHash matches the
 *       prior event's hash (genesis for inception).
 *   P3. Ratchet derivation: verifyRotationChain passes.
 *   P4. Current pointer: if any event is `effective`, the controller's
 *       current credential matches the tip's newCredential.
 *   P5. Round-trip identity: snapshot → restore produces a controller
 *       that agrees on every identity's events and current credential.
 *   P6. Post-restore rotation still chains off the restored tail.
 *
 * A seeded mulberry32 PRNG picks the action sequence so failures are
 * reproducible from the printed seed.
 */

import { describe, it, expect } from 'vitest';
import {
  CredentialRotationController,
  MockCredentialBackend,
  DEFAULT_POLICY,
  verifyRotationChain,
  type ControllerPolicy,
  type RotationEvent,
} from '../../src/heart/credential-rotation/index.js';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';

const crypto = getCryptoProvider();

// ─── PRNG ────────────────────────────────────────────────────────────────────

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rnd: () => number, items: readonly T[]): T {
  return items[Math.floor(rnd() * items.length)]!;
}

// ─── Harness ─────────────────────────────────────────────────────────────────

function makePolicy(): ControllerPolicy {
  return {
    ...DEFAULT_POLICY,
    backendAllowlist: ['fuzz-backend'],
    // Loosen the rate limit so long runs don't starve on D3 rejections;
    // the limit itself is covered by a dedicated test.
    maxRotationsPerHour: 1000,
    rotationBurst: 100,
  };
}

interface Harness {
  controller: CredentialRotationController;
  backend: MockCredentialBackend;
  clock: { t: number };
  pending: Map<string, string[]>; // identity -> pending event hashes
  anchored: Map<string, string[]>; // identity -> anchored (awaiting witness)
  accepted: Map<string, string[]>; // identity -> accepted credentialIds
  identities: string[];
  nextIdentityId: number;
}

function makeHarness(): Harness {
  const clock = { t: 1_700_000_000_000 };
  const controller = new CredentialRotationController({
    policy: makePolicy(),
    clock: () => clock.t,
  });
  const backend = new MockCredentialBackend({ backendId: 'fuzz-backend' });
  controller.registerBackend(backend);
  return {
    controller,
    backend,
    clock,
    pending: new Map(),
    anchored: new Map(),
    accepted: new Map(),
    identities: [],
    nextIdentityId: 0,
  };
}

// ─── Invariant checker ──────────────────────────────────────────────────────

function assertChainInvariants(h: Harness, label: string): void {
  for (const identityId of h.identities) {
    const events = h.controller.getEvents(identityId);
    // P1 + P2: sequence + linkage, checked alongside P3 by verifyRotationChain
    // plus explicit per-index assertions for clearer failure messages.
    for (let i = 0; i < events.length; i++) {
      const e = events[i]!;
      expect(
        e.sequence,
        `${label}: identity ${identityId} event ${i} sequence`,
      ).toBe(i);
      if (i > 0) {
        expect(
          e.previousEventHash,
          `${label}: identity ${identityId} event ${i} link`,
        ).toBe(events[i - 1]!.hash);
      }
    }
    // P3: ratchet + hash recomputation
    const verdict = verifyRotationChain(events, crypto);
    expect(verdict, `${label}: verifyRotationChain for ${identityId}`).toEqual({
      valid: true,
    });

    // P4: current pointer consistency with last effective event
    const current = h.controller.getCurrentCredential(identityId);
    const lastEffective = [...events]
      .reverse()
      .find((e: RotationEvent) => e.status === 'effective');
    if (current !== null) {
      expect(
        current.credentialId,
        `${label}: current matches last effective for ${identityId}`,
      ).toBe(lastEffective?.newCredential.credentialId);
    } else {
      expect(
        lastEffective,
        `${label}: no current yet for ${identityId}`,
      ).toBeUndefined();
    }
  }
}

// ─── Random actions ─────────────────────────────────────────────────────────

async function stepIncept(h: Harness, rnd: () => number): Promise<void> {
  // Small cap on identity count to keep runs bounded.
  if (h.identities.length >= 4) return;
  const id = `id-${h.nextIdentityId++}`;
  const { event } = await h.controller.incept({
    identityId: id,
    backendId: 'fuzz-backend',
  });
  h.identities.push(id);
  h.pending.set(id, [event.hash]);
  h.anchored.set(id, []);
  h.accepted.set(id, []);
  void rnd; // consume no extra entropy; deterministic either way
}

async function stepRotate(h: Harness, rnd: () => number): Promise<void> {
  // Only identities whose tip event is effective can rotate — this matches
  // the "one rotation in-flight per identity" invariant enforced by the
  // controller (prior rotation must be anchored + witnessed first).
  const eligible = h.identities.filter(id => {
    if (h.controller.getCurrentCredential(id) === null) return false;
    const events = h.controller.getEvents(id);
    return events[events.length - 1]!.status === 'effective';
  });
  if (eligible.length === 0) return;
  const id = pick(rnd, eligible);
  const before = h.controller.getCurrentCredential(id)!.credentialId;
  h.clock.t += 1 + Math.floor(rnd() * 1000);
  const { event } = await h.controller.rotate(id);
  h.pending.get(id)!.push(event.hash);
  h.accepted.get(id)!.push(before);
}

function stepAnchor(h: Harness, rnd: () => number): void {
  const eligible = h.identities.filter(id => (h.pending.get(id) ?? []).length > 0);
  if (eligible.length === 0) return;
  const id = pick(rnd, eligible);
  const pending = h.pending.get(id)!;
  const hash = pending.shift()!;
  h.controller.anchorEvent(id, hash, `pulse-root-${hash.slice(0, 8)}`);
  h.anchored.get(id)!.push(hash);
}

function stepWitness(h: Harness, rnd: () => number): void {
  const eligible = h.identities.filter(
    id => (h.anchored.get(id) ?? []).length > 0,
  );
  if (eligible.length === 0) return;
  const id = pick(rnd, eligible);
  const anchored = h.anchored.get(id)!;
  const hash = anchored.shift()!;
  h.controller.witnessEvent(id, hash);
}

async function stepAck(h: Harness, rnd: () => number): Promise<void> {
  const eligible = h.identities.filter(id => (h.accepted.get(id) ?? []).length > 0);
  if (eligible.length === 0) return;
  const id = pick(rnd, eligible);
  const accepted = h.accepted.get(id)!;
  const credId = accepted.shift()!;
  await h.controller.ackPropagation(id, credId);
}

async function stepAdvanceTime(h: Harness, rnd: () => number): Promise<void> {
  h.clock.t += Math.floor(rnd() * 30_000);
}

async function stepSnapshotRestore(h: Harness, rnd: () => number): Promise<void> {
  // Only snapshot when no rotations are mid-flight (no staged rotations).
  // The harness never leaves one staged — rotate either commits or throws.
  // Drain pending-anchor and anchored-witness lists before snapshotting is
  // NOT required; status fields travel in the snapshot.
  const snapController = h.controller.snapshot();
  const snapBackend = h.backend.snapshot();

  const restoredBackend = MockCredentialBackend.restore(snapBackend);
  const restoredController = CredentialRotationController.restore(
    snapController,
    { backends: [restoredBackend], clock: () => h.clock.t },
  );

  // P5: events + current match on every identity
  for (const id of h.identities) {
    const before = h.controller.getEvents(id);
    const after = restoredController.getEvents(id);
    expect(after.length).toBe(before.length);
    for (let i = 0; i < before.length; i++) {
      expect(after[i]!.hash).toBe(before[i]!.hash);
      expect(after[i]!.status).toBe(before[i]!.status);
      expect(after[i]!.sequence).toBe(before[i]!.sequence);
    }
    const cBefore = h.controller.getCurrentCredential(id);
    const cAfter = restoredController.getCurrentCredential(id);
    expect(cAfter?.credentialId).toBe(cBefore?.credentialId);
  }

  // Swap harness to the restored stack so subsequent actions go through
  // the restored objects — this exercises post-restore continuity (P6).
  h.controller = restoredController;
  h.backend = restoredBackend;
  void rnd;
}

// ─── Runner ──────────────────────────────────────────────────────────────────

type Step = (h: Harness, rnd: () => number) => Promise<void> | void;

const STEPS: { name: string; weight: number; run: Step }[] = [
  { name: 'incept', weight: 2, run: stepIncept },
  { name: 'rotate', weight: 5, run: stepRotate },
  { name: 'anchor', weight: 4, run: stepAnchor },
  { name: 'witness', weight: 4, run: stepWitness },
  { name: 'ack', weight: 2, run: stepAck },
  { name: 'advanceTime', weight: 1, run: stepAdvanceTime },
  { name: 'snapshotRestore', weight: 1, run: stepSnapshotRestore },
];

function pickStep(rnd: () => number) {
  const total = STEPS.reduce((s, x) => s + x.weight, 0);
  let r = rnd() * total;
  for (const step of STEPS) {
    r -= step.weight;
    if (r <= 0) return step;
  }
  return STEPS[STEPS.length - 1]!;
}

async function runFuzz(seed: number, steps: number): Promise<void> {
  const rnd = mulberry32(seed);
  const h = makeHarness();
  for (let i = 0; i < steps; i++) {
    const step = pickStep(rnd);
    try {
      await step.run(h, rnd);
    } catch (err) {
      throw new Error(
        `fuzz seed=${seed} step=${i} action=${step.name} threw: ${(err as Error).message}`,
      );
    }
    assertChainInvariants(h, `seed=${seed} step=${i} action=${step.name}`);
  }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('CredentialRotationController — fuzz / property', () => {
  // Pinned seeds so failures are reproducible. Add more if a specific
  // failure seed comes up — the harness prints the seed in any error.
  const seeds = [1, 2, 3, 42, 1337, 0xdeadbeef, 0xfeedface];

  for (const seed of seeds) {
    it(`survives 200 random actions (seed=${seed})`, async () => {
      await runFuzz(seed, 200);
    });
  }

  it(
    'survives a long 1000-action run on a single seed',
    { timeout: 30_000 },
    async () => {
      await runFuzz(0xc0ffee, 1000);
    },
  );
});
