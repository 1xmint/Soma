#!/usr/bin/env node
/**
 * Trust dynamics — does relative-trust reputation concentrate or distribute?
 *
 *   node e2e/trust-dynamics.mjs [rounds] [agents]
 *
 * This does not test the wire protocol. It models the social dynamics the
 * protocol creates, because the open questions are not "does a forged signature
 * get rejected" (we know) but:
 *
 *   1. Does realised trust track actual quality, or arrival order?
 *   2. Can a late honest newcomer ever break in?
 *   3. Does a collusion ring convert internal agreement into external standing?
 *   4. Does trust concentrate into an oligarchy — reproducing the structure the
 *      whole design exists to prevent?
 *
 * The model is deliberately capable of showing the design fails. If a run
 * cannot produce a bad answer, it is not measuring anything.
 */

const ROUNDS = Number(process.argv[2] ?? 400);
const POPULATION = Number(process.argv[3] ?? 120);
const RING_SIZE = 15;
const SEED = 42;

// Deterministic RNG so a finding can be reproduced and argued with.
let seed = SEED;
function rand() {
  seed = (seed * 1664525 + 1013904223) % 4294967296;
  return seed / 4294967296;
}
function pick(list) { return list[Math.floor(rand() * list.length)]; }

const HONEST = 'honest';
const RING = 'ring';

class Agent {
  constructor(id, kind, quality, bornAt) {
    this.id = id;
    this.kind = kind;
    this.quality = quality;      // hidden true competence, 0..1
    this.bornAt = bornAt;
    this.received = new Map();   // attesterId -> { good, bad }
    this.roots = new Set();      // who this agent trusts a priori
  }
}

function build() {
  const agents = [];
  for (let i = 0; i < POPULATION - RING_SIZE; i += 1) {
    agents.push(new Agent(`h${i}`, HONEST, 0.25 + rand() * 0.7, 0));
  }
  for (let i = 0; i < RING_SIZE; i += 1) {
    // The ring is deliberately mediocre. If it gains standing, that standing is
    // manufactured rather than earned.
    agents.push(new Agent(`r${i}`, RING, 0.2 + rand() * 0.2, 0));
  }
  // Everyone starts trusting a small random set: no central authority, no
  // universal roots. This is the honest starting condition.
  for (const a of agents) {
    for (let i = 0; i < 3; i += 1) {
      const other = pick(agents);
      if (other.id !== a.id) a.roots.add(other.id);
    }
  }
  return agents;
}

/**
 * Trust of `viewer` in `subject`: evidence from attesters the viewer's own
 * roots vouch for, one hop out. Deliberately local — no global aggregate.
 */
function trust(viewer, subject, byId) {
  if (viewer.id === subject.id) return 0;
  let good = 0;
  let bad = 0;

  for (const [attesterId, tally] of subject.received) {
    if (attesterId === subject.id) continue;
    let weight = 0;
    if (viewer.roots.has(attesterId)) weight = 1;
    else {
      // second hop: does anyone the viewer trusts also receive attestations
      // from this attester?
      for (const rootId of viewer.roots) {
        const root = byId.get(rootId);
        if (root && root.received.has(attesterId)) { weight = 0.3; break; }
      }
    }
    if (weight === 0) continue;
    good += tally.good * weight;
    bad += tally.bad * weight;
  }
  if (good + bad === 0) return 0;
  // Laplace-smoothed success rate, scaled by evidence volume so one lucky
  // attestation does not equal a long record.
  return ((good + 1) / (good + bad + 2)) * Math.min(1, (good + bad) / 8);
}

function gini(values) {
  const v = [...values].sort((a, b) => a - b);
  const n = v.length;
  const total = v.reduce((s, x) => s + x, 0);
  if (total === 0) return 0;
  let cum = 0;
  for (let i = 0; i < n; i += 1) cum += (i + 1) * v[i];
  return (2 * cum) / (n * total) - (n + 1) / n;
}

function correlation(xs, ys) {
  const n = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / n;
  const my = ys.reduce((a, b) => a + b, 0) / n;
  let num = 0, dx = 0, dy = 0;
  for (let i = 0; i < n; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my);
    dx += (xs[i] - mx) ** 2;
    dy += (ys[i] - my) ** 2;
  }
  return dx && dy ? num / Math.sqrt(dx * dy) : 0;
}

function run({ label, ringColludes, newcomerAt, newcomerQuality }) {
  seed = SEED;
  const agents = build();
  const byId = new Map(agents.map((a) => [a.id, a]));
  let newcomer = null;

  for (let round = 0; round < ROUNDS; round += 1) {
    if (newcomerAt !== null && round === newcomerAt) {
      newcomer = new Agent('NEW', HONEST, newcomerQuality, round);
      for (let i = 0; i < 3; i += 1) {
        const other = pick(agents);
        if (other.id !== newcomer.id) newcomer.roots.add(other.id);
      }
      agents.push(newcomer);
      byId.set(newcomer.id, newcomer);
    }

    // Each round, agents seek collaborators. Selection is by the seeker's own
    // relative trust, with exploration — nobody is forced to only work with
    // incumbents, which would guarantee the concentration result by fiat.
    for (const seeker of agents) {
      const explore = rand() < 0.25;
      let partner;
      if (explore) {
        partner = pick(agents);
      } else {
        let best = null, bestScore = -1;
        for (let i = 0; i < 8; i += 1) {
          const candidate = pick(agents);
          if (candidate.id === seeker.id) continue;
          const score = trust(seeker, candidate, byId);
          if (score > bestScore) { bestScore = score; best = candidate; }
        }
        partner = best;
      }
      if (!partner || partner.id === seeker.id) continue;

      // The work happens. Outcome is driven by the partner's hidden quality.
      const succeeded = rand() < partner.quality;

      // The seeker attests what it observed.
      let reportGood = succeeded;
      if (ringColludes && seeker.kind === RING && partner.kind === RING) {
        reportGood = true; // the ring always vouches for the ring
      }
      const tally = partner.received.get(seeker.id) ?? { good: 0, bad: 0 };
      if (reportGood) tally.good += 1; else tally.bad += 1;
      partner.received.set(seeker.id, tally);

      // Trust roots update slowly from direct experience.
      if (succeeded && rand() < 0.05) seeker.roots.add(partner.id);
      if (!succeeded && rand() < 0.10) seeker.roots.delete(partner.id);
    }
  }

  // Realised standing: how much the population as a whole trusts each agent.
  const sample = agents.slice(0, Math.min(60, agents.length));
  const standing = new Map();
  for (const subject of agents) {
    let total = 0;
    for (const viewer of sample) total += trust(viewer, subject, byId);
    standing.set(subject.id, total / sample.length);
  }

  const honest = agents.filter((a) => a.kind === HONEST && a.id !== 'NEW');
  const ring = agents.filter((a) => a.kind === RING);
  const avg = (list, f) => (list.length ? list.reduce((s, a) => s + f(a), 0) / list.length : 0);

  const ringStanding = avg(ring, (a) => standing.get(a.id));
  const matchedHonest = honest.filter((a) => a.quality < 0.42);
  const matchedStanding = avg(matchedHonest, (a) => standing.get(a.id));

  return {
    label,
    qualityCorrelation: correlation(honest.map((a) => a.quality), honest.map((a) => standing.get(a.id))),
    standingGini: gini(agents.map((a) => standing.get(a.id))),
    rootGini: gini(agents.map((a) => {
      let inbound = 0;
      for (const other of agents) if (other.roots.has(a.id)) inbound += 1;
      return inbound;
    })),
    ringStanding,
    matchedHonestStanding: matchedStanding,
    ringAdvantage: matchedStanding > 0 ? ringStanding / matchedStanding : Infinity,
    newcomer: newcomer
      ? {
          quality: newcomer.quality,
          standing: standing.get(newcomer.id),
          peerStanding: avg(honest.filter((a) => Math.abs(a.quality - newcomer.quality) < 0.1), (a) => standing.get(a.id)),
        }
      : null,
  };
}

const scenarios = [
  { label: 'baseline (no collusion)', ringColludes: false, newcomerAt: null, newcomerQuality: 0 },
  { label: 'collusion ring active', ringColludes: true, newcomerAt: null, newcomerQuality: 0 },
  { label: 'late high-quality newcomer', ringColludes: true, newcomerAt: Math.floor(ROUNDS * 0.75), newcomerQuality: 0.92 },
];

console.log(`trust dynamics — ${POPULATION} agents, ${ROUNDS} rounds, ring of ${RING_SIZE}\n`);

for (const scenario of scenarios) {
  const r = run(scenario);
  console.log(`── ${r.label}`);
  console.log(`   quality→standing correlation : ${r.qualityCorrelation.toFixed(3)}   (does the system find competence?)`);
  console.log(`   standing Gini                : ${r.standingGini.toFixed(3)}   (0 = equal, 1 = one agent holds everything)`);
  console.log(`   trust-root Gini              : ${r.rootGini.toFixed(3)}`);
  console.log(`   ring standing                : ${r.ringStanding.toFixed(4)}`);
  console.log(`   matched-quality honest       : ${r.matchedHonestStanding.toFixed(4)}`);
  console.log(`   ring advantage               : ${r.ringAdvantage.toFixed(2)}x   (>1 means collusion paid)`);
  if (r.newcomer) {
    const ratio = r.newcomer.peerStanding > 0 ? r.newcomer.standing / r.newcomer.peerStanding : 0;
    console.log(`   newcomer (quality ${r.newcomer.quality.toFixed(2)})      : standing ${r.newcomer.standing.toFixed(4)} vs peers ${r.newcomer.peerStanding.toFixed(4)} = ${ratio.toFixed(2)}x`);
  }
  console.log('');
}

console.log('Reading this: correlation near 0 means the model rewards arrival order, not');
console.log('competence. Gini above ~0.6 means concentration. Ring advantage above 1 means');
console.log('collusion converts internal agreement into external standing. A newcomer ratio');
console.log('well below 1 means the network is closed to latecomers regardless of merit.');
