/**
 * Trust-flow simulations for the reference evaluator policy.
 *
 * The claim under test is the one the whole design rests on:
 *
 *   What an adversary can capture is bounded by the capacity of the edges
 *   reaching it from parties the evaluator genuinely trusts, and does NOT grow
 *   with the number of identities the adversary runs.
 *
 * So the sweeps are: hold attack edges fixed and vary identity count (expect
 * flat), then hold identity count fixed and vary attack edges (expect linear).
 * Everything is reported as a RATIO against the theoretical bound, never as a
 * bare number -- a metric with no ceiling in view can pin silently and look
 * like a defeated attack when it is only a saturated measurement.
 *
 * Deterministic by construction: a seeded PRNG, no wall clock, no Math.random.
 * A simulation whose numbers change between runs cannot be quoted.
 */

import { portfolioStanding, DEFAULT_POLICY } from "../../src/evaluator-policy.mjs";

/** xorshift32 — small, deterministic, and adequate for choosing edges. */
export function rng(seed) {
  let x = seed >>> 0 || 0x9e3779b9;
  return () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    return x / 0x100000000;
  };
}

const did = (s) => `did:key:z${s}`;

/**
 * Build a world containing an honest region and an adversary region.
 *
 * The honest region is deliberately shallow: roots vouch directly for honest
 * participants, so each honest participant holds exactly one edge's worth of
 * capacity and can pass on no more. That is conservation doing its job, and it
 * is what makes attack edges — not identity count — the thing that must be
 * bought.
 *
 * `attackEdges` receipts run from DISTINCT honest participants to distinct
 * adversary identities. Distinct on purpose: routing them all through one
 * honest party would make that party's own inflow the binding constraint and
 * the sweep would measure the wrong thing.
 */
export function buildWorld({ honest, sybils, attackEdges, seed = 1, sybilDensity = 2 }) {
  if (attackEdges > honest) throw new Error("attack edges cannot exceed distinct honest parties");
  const rand = rng(seed);

  const roots = [did("R0"), did("R1"), did("R2")];
  const honestDids = Array.from({ length: honest }, (_, i) => did(`H${i}`));
  const sybilDids = Array.from({ length: sybils }, (_, i) => did(`S${i}`));

  const entries = [];
  const push = (attester, subject) =>
    entries.push({
      receipt: {
        attester_did: attester,
        subject_did: subject,
        basis: "verified",
        outcome: "succeeded",
        fault: "none"
      },
      independence: "no_known_common_ancestor",
      // Disclosed on purpose. The sweeps are about how much a Sybil region can
      // capture, not about basis weighting, so every receipt in the world gets
      // the strongest honest treatment -- including the adversary's. Giving the
      // attacker the benefit of the doubt is the only way the result means
      // anything.
      method_disclosed: true
    });

  // Roots vouch for the honest region.
  for (let i = 0; i < honestDids.length; i += 1) push(roots[i % roots.length], honestDids[i]);

  // The adversary's own region: dense, mutually flattering, entirely free, and
  // — this is the point — entirely worthless.
  for (let i = 0; i < sybilDids.length; i += 1) {
    for (let d = 0; d < sybilDensity; d += 1) {
      const target = sybilDids[Math.floor(rand() * sybilDids.length)];
      if (target !== sybilDids[i]) push(sybilDids[i], target);
    }
  }

  // The edges that actually cost something.
  for (let i = 0; i < attackEdges; i += 1) {
    push(honestDids[i], sybilDids[Math.floor(rand() * sybilDids.length)]);
  }

  return { roots, honestDids, sybilDids, entries };
}

/**
 * What the adversary captured, and what it captured relative to the bound.
 *
 * The theoretical ceiling is `attackEdges * perEdgeCap`: every unit of captured
 * standing must cross one of those edges. A ratio above 1 means the policy
 * leaked flow and the mechanism is falsified.
 */
export function measureCapture({ honest, sybils, attackEdges, seed, policy = DEFAULT_POLICY }) {
  const world = buildWorld({ honest, sybils, attackEdges, seed });
  const result = portfolioStanding({
    subjects: world.sybilDids,
    entries: world.entries,
    trustRoots: world.roots,
    policy
  });
  const captured = result.joint_standing ?? 0;
  const ceiling = attackEdges * policy.perEdgeCap;
  return {
    sybils,
    attackEdges,
    captured,
    ceiling,
    ratio: ceiling === 0 ? (captured === 0 ? 0 : Infinity) : captured / ceiling
  };
}

/** Identity-count sweep at fixed attack edges. Expect a flat line. */
export function sweepIdentities({ counts, attackEdges = 4, honest = 64, seed = 7, policy }) {
  return counts.map((n) => measureCapture({ honest, sybils: n, attackEdges, seed, policy }));
}

/** Attack-edge sweep at fixed identity count. Expect linear growth. */
export function sweepAttackEdges({ edgeCounts, sybils = 500, honest = 1024, seed = 11, policy }) {
  return edgeCounts.map((g) => measureCapture({ honest, sybils, attackEdges: g, seed, policy }));
}

/**
 * The corpus-fabrication adversary.
 *
 * Fable 5's §7 conjecture: "share of corpus attested" has no denominator
 * without a global view, so a ring can fabricate a corpus and attest 100% of
 * its own fiction. Here the ring produces an arbitrarily large, internally
 * perfect, all-`verified` corpus and receives no attack edges at all.
 *
 * If coverage-of-corpus were a standing input this would score highly. Under
 * trust flow it must score exactly nothing.
 */
export function fabricatedCorpus({ sybils, density, seed = 13, policy = DEFAULT_POLICY }) {
  const world = buildWorld({ honest: 8, sybils, attackEdges: 0, seed, sybilDensity: density });
  const result = portfolioStanding({
    subjects: world.sybilDids,
    entries: world.entries,
    trustRoots: world.roots,
    policy
  });
  return {
    sybils,
    density,
    receipts: world.entries.length,
    captured: result.joint_standing,
    basis: result.basis
  };
}
