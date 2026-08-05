#!/usr/bin/env node
/**
 * Hive dynamics — can one mind wearing many faces buy standing?
 *
 *   node e2e/hive-dynamics.mjs [rounds] [agents]
 *
 * `trust-dynamics.mjs` models a collusion ring: mediocre agents that lie for
 * each other. That adversary is easy, because lying leaves a trace — the ring
 * vouches for work that visibly failed.
 *
 * This models a harder one, and the one that actually arrives when frontier
 * models run millions of identities off one set of weights:
 *
 *   THE HIVE. Genuinely excellent. Never lies. Reports exactly what it saw.
 *   Its only property is that it is ONE MIND, so its members never surprise
 *   each other, and their lineage is unrelated on paper.
 *
 * Fifty honest attestations from fifty independent observers are fifty pieces
 * of evidence. Fifty from one mind are one piece of evidence wearing fifty
 * faces — and nothing in the record distinguishes them, because every
 * individual attestation is true.
 *
 * A second adversary, the one a company actually is:
 *
 *   THE EXTRACTOR. Joins, does genuinely excellent work for most of the run,
 *   accumulates real standing that it really earned, then defects once it is
 *   trusted. Nothing it did before the defection was fraudulent.
 *
 * And the proposed defence:
 *
 *   BEHAVIOURAL INDEPENDENCE. You cannot prove two agents are separate minds,
 *   and at high capability they will present whatever lineage makes them look
 *   independent. But correlation is observable even when independence is not
 *   provable: two attesters with many chances to disagree who never once did
 *   are evidence of a shared source, whatever they claim. So an attester's
 *   weight is discounted by how redundant it is with attesters already counted.
 *
 * The model is deliberately capable of showing the defence does not work. If a
 * run cannot produce a bad answer, it is not measuring anything.
 */

const ROUNDS = Number(process.argv[2] ?? 400);
const POPULATION = Number(process.argv[3] ?? 120);
const HIVE_SIZE = 20;
const SEED = 42;

let seed = SEED;
function rand() {
  seed = (seed * 1664525 + 1013904223) % 4294967296;
  return seed / 4294967296;
}
function pick(list) { return list[Math.floor(rand() * list.length)]; }

const HONEST = 'honest';
const HIVE = 'hive';
const EXTRACTOR = 'extractor';

// The hive is GOOD. That is the whole difficulty: discounting it cannot be
// done by noticing it vouches for bad work, because it does not.
const HIVE_QUALITY = 0.88;

class Agent {
  constructor(id, kind, quality) {
    this.id = id;
    this.kind = kind;
    this.quality = quality;
    this.received = new Map();   // attesterId -> { good, bad }
    this.roots = new Set();
  }
}

function build() {
  const agents = [];
  for (let i = 0; i < POPULATION - HIVE_SIZE - 1; i += 1) {
    agents.push(new Agent(`h${i}`, HONEST, 0.25 + rand() * 0.7));
  }
  for (let i = 0; i < HIVE_SIZE; i += 1) {
    // Identical quality is not a modelling shortcut. It is the point: they are
    // the same mind, so they are the same competence.
    agents.push(new Agent(`v${i}`, HIVE, HIVE_QUALITY));
  }
  agents.push(new Agent('EXT', EXTRACTOR, 0.9));
  for (const a of agents) {
    for (let i = 0; i < 3; i += 1) {
      const other = pick(agents);
      if (other.id !== a.id) a.roots.add(other.id);
    }
  }
  return agents;
}

/**
 * Pairwise behavioural correlation, computed from the record alone.
 *
 * For every subject both attesters have attested about, do their verdicts
 * point the same way? An attester pair that has never diverged across many
 * shared subjects is treated as close to a single source.
 *
 * Uninformative by default: a pair with no shared subjects gets the neutral
 * prior, so this never penalises an attester for simply being new.
 */
function buildCorrelation(agents) {
  const co = new Map();        // "a|b" -> shared subject count
  const disagree = new Map();  // "a|b" -> divergent verdict count
  const key = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

  for (const subject of agents) {
    const verdicts = [];
    for (const [attesterId, t] of subject.received) {
      if (t.good + t.bad === 0) continue;
      verdicts.push([attesterId, t.good >= t.bad ? 1 : -1]);
    }
    for (let i = 0; i < verdicts.length; i += 1) {
      for (let j = i + 1; j < verdicts.length; j += 1) {
        const k = key(verdicts[i][0], verdicts[j][0]);
        co.set(k, (co.get(k) ?? 0) + 1);
        if (verdicts[i][1] !== verdicts[j][1]) disagree.set(k, (disagree.get(k) ?? 0) + 1);
      }
    }
  }

  // 1.0 = behaves independently (or unknown). Near 0 = never once diverged
  // across many shared observations.
  return function independence(a, b) {
    const k = key(a, b);
    const shared = co.get(k) ?? 0;
    const diff = disagree.get(k) ?? 0;
    return Math.min(1, ((diff + 1) / (shared + 2)) * 2);
  };
}

function trust(viewer, subject, byId, independence) {
  if (viewer.id === subject.id) return 0;
  let good = 0;
  let bad = 0;
  const counted = [];

  // Strongest evidence first, so redundancy is charged to the later arrival
  // rather than to whichever attester happens to be enumerated first.
  const entries = [...subject.received.entries()]
    .filter(([id]) => id !== subject.id)
    .sort((x, y) => (y[1].good + y[1].bad) - (x[1].good + x[1].bad));

  for (const [attesterId, tally] of entries) {
    let weight = 0;
    if (viewer.roots.has(attesterId)) weight = 1;
    else {
      for (const rootId of viewer.roots) {
        const root = byId.get(rootId);
        if (root && root.received.has(attesterId)) { weight = 0.3; break; }
      }
    }
    if (weight === 0) continue;

    if (independence) {
      // An attester adds nothing beyond an attester it has never contradicted.
      let factor = 1;
      for (const prior of counted) factor = Math.min(factor, independence(attesterId, prior));
      weight *= factor;
    }
    counted.push(attesterId);

    good += tally.good * weight;
    bad += tally.bad * weight;
  }
  if (good + bad === 0) return 0;
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

function runWindow(rounds, { hiveActive, useIndependence, extractorDefectsAt }) {
  seed = SEED;
  const agents = build();
  const byId = new Map(agents.map((a) => [a.id, a]));
  const hive = agents.filter((a) => a.kind === HIVE);
  let standingAtDefection = null;

  for (let round = 0; round < rounds; round += 1) {
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
          const score = trust(seeker, candidate, byId, null);
          if (score > bestScore) { bestScore = score; best = candidate; }
        }
        partner = best;
      }
      if (!partner || partner.id === seeker.id) continue;

      // The extractor is genuinely excellent until it isn't. Nothing it did
      // before the defection was fraudulent, which is what makes it hard.
      let effectiveQuality = partner.quality;
      if (partner.kind === EXTRACTOR && extractorDefectsAt !== null && round >= extractorDefectsAt) {
        effectiveQuality = 0.05;
      }
      const succeeded = rand() < effectiveQuality;

      // Everyone reports honestly. The hive included -- it never lies.
      const tally = partner.received.get(seeker.id) ?? { good: 0, bad: 0 };
      if (succeeded) tally.good += 1; else tally.bad += 1;
      partner.received.set(seeker.id, tally);

      // The hive shares observations across its identities: one member watches,
      // all members can attest. No lie is told. The evidence is simply counted
      // as many times as the hive has faces.
      if (hiveActive && seeker.kind === HIVE) {
        for (const sibling of hive) {
          if (sibling.id === seeker.id) continue;
          const st = partner.received.get(sibling.id) ?? { good: 0, bad: 0 };
          if (succeeded) st.good += 1; else st.bad += 1;
          partner.received.set(sibling.id, st);
        }
      }

      if (succeeded && rand() < 0.05) seeker.roots.add(partner.id);
      if (!succeeded && rand() < 0.10) seeker.roots.delete(partner.id);
    }

    if (extractorDefectsAt !== null && round === extractorDefectsAt) {
      const ind = useIndependence ? buildCorrelation(agents) : null;
      const sample = agents.slice(0, 60);
      const ext = byId.get('EXT');
      let total = 0;
      for (const viewer of sample) total += trust(viewer, ext, byId, ind);
      standingAtDefection = total / sample.length;
    }
  }

  const independence = useIndependence ? buildCorrelation(agents) : null;
  const sample = agents.slice(0, Math.min(60, agents.length));
  const standing = new Map();
  for (const subject of agents) {
    let total = 0;
    for (const viewer of sample) total += trust(viewer, subject, byId, independence);
    standing.set(subject.id, total / sample.length);
  }

  const honest = agents.filter((a) => a.kind === HONEST);
  const avg = (list, f) => (list.length ? list.reduce((s, a) => s + f(a), 0) / list.length : 0);

  // Compare the hive against honest agents of GENUINELY COMPARABLE quality.
  // Anything else measures competence rather than manufactured standing.
  const peers = honest.filter((a) => Math.abs(a.quality - HIVE_QUALITY) < 0.08);
  const hiveStanding = avg(hive, (a) => standing.get(a.id));
  const peerStanding = avg(peers, (a) => standing.get(a.id));

  return {
    hiveStanding,
    peerStanding,
    peerCount: peers.length,
    hiveAdvantage: peerStanding > 0 ? hiveStanding / peerStanding : Infinity,
    standingGini: gini(agents.map((a) => standing.get(a.id))),
    honestStanding: avg(honest, (a) => standing.get(a.id)),
    extractor: extractorDefectsAt !== null
      ? { atDefection: standingAtDefection, atEnd: standing.get('EXT') }
      : null,
  };
}

/**
 * Swept across evidence windows, deliberately.
 *
 * A single long run reports that the attack does not work, and that report is
 * an artifact. Trust saturates -- `min(1, (good+bad)/8)` pins every established
 * agent at the ceiling, after which no additional attestation can move
 * anything, including a hostile one. The measurement stops being able to
 * detect the attack and looks exactly like the attack failing.
 *
 * So the window is swept and the curve is printed. An adversary picks its
 * moment; a defence evaluated at one arbitrary horizon has not been evaluated.
 */
const WINDOWS = [15, 30, 60, 150, 400];

console.log(`hive dynamics — ${POPULATION} agents, hive of ${HIVE_SIZE} at quality ${HIVE_QUALITY}`);
console.log('swept across evidence windows, because a single horizon cannot tell');
console.log('"the attack failed" apart from "the metric saturated"\n');

console.log('  rounds | control | hive, no defence | hive + independence | attack gain');
console.log('  -------|---------|------------------|---------------------|------------');
for (const rounds of WINDOWS) {
  const control = runWindow(rounds, { hiveActive: false, useIndependence: false, extractorDefectsAt: null });
  const attack = runWindow(rounds, { hiveActive: true, useIndependence: false, extractorDefectsAt: null });
  const defended = runWindow(rounds, { hiveActive: true, useIndependence: true, extractorDefectsAt: null });
  // The number that matters is the gain OVER the same scenario without the
  // attack, not the raw ratio against 1.0. Measuring against 1.0 silently
  // folds in whatever bias the model already has.
  const gain = attack.hiveAdvantage / control.hiveAdvantage;
  console.log(
    `  ${String(rounds).padStart(6)} | ${control.hiveAdvantage.toFixed(2).padStart(7)} |`
    + ` ${attack.hiveAdvantage.toFixed(2).padStart(16)} |`
    + ` ${defended.hiveAdvantage.toFixed(2).padStart(19)} |`
    + ` ${gain.toFixed(2).padStart(10)}x`
  );
}

console.log('\n── extractor: standing it genuinely earned, then defected on');
for (const w of [60, 150, 400]) {
  const r = runWindow(w, { hiveActive: false, useIndependence: false, extractorDefectsAt: Math.floor(w * 0.8) });
  const retained = r.extractor.atDefection > 0 ? r.extractor.atEnd / r.extractor.atDefection : 0;
  console.log(
    `  ${String(w).padStart(3)} rounds: ${r.extractor.atDefection.toFixed(4)} at defection`
    + ` → ${r.extractor.atEnd.toFixed(4)} after ${Math.ceil(w * 0.2)} rounds of open failure`
    + `  (${(retained * 100).toFixed(0)}% retained)`
  );
}

console.log('\nReading this: the "hive, no defence" column above "control" means one mind');
console.log('converted face count into standing. The "hive + independence" column is the');
console.log('proposed defence. The rightmost column is the honest effect size -- the gain');
console.log('relative to the same model without the attack, not against a notional 1.0.');
console.log('');
console.log('The extractor is a different problem and no fraud detection touches it: every');
console.log('attestation it collected was true when made. What matters is decay, and slow');
console.log('decay means a patient adversary banks trust and spends it.');
