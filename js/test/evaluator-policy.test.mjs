import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_POLICY,
  receiptContribution,
  edgeCapacities,
  standingOf,
  portfolioStanding,
  burnBound
} from "../src/evaluator-policy.mjs";

/**
 * The evaluator policy consumes receipts that have ALREADY been verified by
 * receipt.mjs. It is policy over established attribution, not a second
 * verifier, and it is tested here with plain objects for that reason.
 */

const did = (name) => `did:key:z${name}`;
const E = did("Evaluator");
const ROOT = did("Root");

function receipt(attester, subject, opts = {}) {
  return {
    attester_did: attester,
    subject_did: subject,
    basis: opts.basis ?? "verified",
    outcome: opts.outcome ?? "succeeded",
    fault: opts.fault ?? "none"
  };
}

// method_disclosed defaults to true here so these fixtures mean what they say:
// a `verified` receipt whose method nobody disclosed is deliberately weighed as
// `witnessed` by the reference policy, which is tested explicitly below.
const entry = (attester, subject, opts = {}) => ({
  receipt: receipt(attester, subject, opts),
  independence: opts.independence ?? "no_known_common_ancestor",
  method_disclosed: opts.method_disclosed ?? true
});

test("a stranger gets insufficient basis, which is not a score of zero", () => {
  const result = standingOf({
    subject: did("Stranger"),
    entries: [],
    trustRoots: [ROOT]
  });
  assert.equal(result.basis, "insufficient");
  assert.equal(result.standing, null, "insufficient must not be rendered as 0");
});

test("standing may not be computed without trust roots the evaluator chose", () => {
  assert.throws(
    () => standingOf({ subject: did("Anyone"), entries: [], trustRoots: [] }),
    /trust roots/
  );
});

test("a million manufactured attesters move nothing for an evaluator who trusts none of them", () => {
  // The adversary builds a dense clique: every Sybil attests for the target and
  // for every other Sybil, all verified, all successful. This is the best graph
  // free identity can buy.
  const target = did("Target");
  const sybils = Array.from({ length: 200 }, (_, i) => did(`Sybil${i}`));
  const entries = [];
  for (const s of sybils) entries.push(entry(s, target));
  for (let i = 0; i < sybils.length; i += 1) {
    entries.push(entry(sybils[i], sybils[(i + 1) % sybils.length]));
  }

  const result = standingOf({ subject: target, entries, trustRoots: [ROOT] });
  assert.equal(result.basis, "insufficient");
  assert.equal(result.standing, null, "manufactured attesters produced standing from nothing");
});

test("conservation: an attester cannot pass on more trust than it received", () => {
  // ROOT vouches for BROKER once. BROKER then vouches for ten subjects at full
  // capacity. Each subject individually can receive at most what BROKER holds.
  const broker = did("Broker");
  const subjects = Array.from({ length: 10 }, (_, i) => did(`Sub${i}`));
  const entries = [entry(ROOT, broker), ...subjects.map((s) => entry(broker, s))];

  for (const s of subjects) {
    const r = standingOf({ subject: s, entries, trustRoots: [ROOT] });
    assert.ok(
      r.standing <= DEFAULT_POLICY.perEdgeCap + 1e-9,
      `${s} received ${r.standing}, more than the broker could hold`
    );
  }
});

test("summing per-subject standing is NOT a bound — the joint figure is", () => {
  // This is the amplification the per-subject view hides, and the reason
  // portfolioStanding exists. One attack edge, five identities behind it.
  const broker = did("Broker");
  const subjects = Array.from({ length: 5 }, (_, i) => did(`Sub${i}`));
  const entries = [entry(ROOT, broker), ...subjects.map((s) => entry(broker, s))];

  const individual = subjects.map(
    (s) => standingOf({ subject: s, entries, trustRoots: [ROOT] }).standing
  );
  const summed = individual.reduce((a, b) => a + b, 0);
  const joint = portfolioStanding({ subjects, entries, trustRoots: [ROOT] }).joint_standing;

  assert.ok(summed > joint, "the sum should exceed the joint bound, or this test proves nothing");
  assert.ok(
    Math.abs(joint - DEFAULT_POLICY.perEdgeCap) < 1e-9,
    `joint standing should be limited by the single attack edge, got ${joint}`
  );
  assert.ok(summed >= 4.9, `expected the naive sum to be ~5x the truth, got ${summed}`);
});

test("joint standing does not grow when the adversary adds identities", () => {
  const broker = did("Broker");
  const jointFor = (n) => {
    const subjects = Array.from({ length: n }, (_, i) => did(`Sub${i}`));
    const entries = [entry(ROOT, broker), ...subjects.map((s) => entry(broker, s))];
    return portfolioStanding({ subjects, entries, trustRoots: [ROOT] }).joint_standing;
  };
  const small = jointFor(5);
  const large = jointFor(500);
  assert.equal(small, large, "adding identities multiplied the bound instead of dividing it");
});

test("joint standing grows with attack edges, which is what must be bought", () => {
  const subjects = [did("SubA"), did("SubB")];
  const withBrokers = (g) => {
    const entries = [];
    for (let i = 0; i < g; i += 1) {
      const broker = did(`Broker${i}`);
      entries.push(entry(ROOT, broker));
      for (const s of subjects) entries.push(entry(broker, s));
    }
    return portfolioStanding({ subjects, entries, trustRoots: [ROOT] }).joint_standing;
  };
  // One root of capacity 1.0 caps the total no matter how many brokers it
  // vouches for -- conservation again, one level up.
  assert.ok(withBrokers(3) <= DEFAULT_POLICY.rootCapacity + 1e-9);
  assert.ok(withBrokers(1) > 0);
});

test("a failure attributed to the subject reduces the edge; one attributed upstream does not", () => {
  const s = did("Worker");
  const base = edgeCapacities([entry(ROOT, s)], DEFAULT_POLICY).edges[0].capacity;

  const blamed = edgeCapacities(
    [entry(ROOT, s), entry(ROOT, s, { outcome: "failed", fault: "subject" })],
    DEFAULT_POLICY
  ).edges[0].capacity;

  const upstream = edgeCapacities(
    [entry(ROOT, s), entry(ROOT, s, { outcome: "failed", fault: "upstream_tool" })],
    DEFAULT_POLICY
  ).edges[0].capacity;

  assert.ok(blamed < base, "a failure blamed on the subject must reduce its edge");
  assert.equal(upstream, base, "a broken upstream tool must not be charged to the subject");
});

test("an unattributed failure is not read as evidence against the subject", () => {
  const s = did("Worker");
  const base = edgeCapacities([entry(ROOT, s)], DEFAULT_POLICY).edges[0].capacity;
  const unattributed = edgeCapacities(
    [entry(ROOT, s), entry(ROOT, s, { outcome: "failed", fault: "unattributed" })],
    DEFAULT_POLICY
  ).edges[0].capacity;
  assert.equal(unattributed, base, "'I cannot say whose fault it was' must not become 'the subject's'");
});

test("adverse evidence is reported rather than silently floored away", () => {
  const s = did("Worker");
  const { edges, adverse } = edgeCapacities(
    [entry(ROOT, s, { outcome: "failed", fault: "subject" })],
    DEFAULT_POLICY
  );
  assert.equal(edges[0].capacity, 0, "a negative edge cannot carry flow");
  assert.equal(adverse.length, 1, "the negative evidence must still be surfaced");
  assert.ok(adverse[0].net < 0);
});

test("basis is ordered: verified outweighs witnessed outweighs party", () => {
  const s = did("Worker");
  const cap = (basis) => edgeCapacities([entry(ROOT, s, { basis })], DEFAULT_POLICY).edges[0].capacity;
  assert.ok(cap("verified") > cap("witnessed"));
  assert.ok(cap("witnessed") > cap("party"));
});

test("a verified claim nobody can re-run is weighed as an opinion", () => {
  const s = did("Worker");
  const disclosed = edgeCapacities(
    [entry(ROOT, s, { basis: "verified", method_disclosed: true })],
    DEFAULT_POLICY
  ).edges[0].capacity;
  const undisclosed = edgeCapacities(
    [entry(ROOT, s, { basis: "verified", method_disclosed: false })],
    DEFAULT_POLICY
  ).edges[0].capacity;
  const witnessed = edgeCapacities(
    [entry(ROOT, s, { basis: "witnessed", method_disclosed: false })],
    DEFAULT_POLICY
  ).edges[0].capacity;

  assert.ok(undisclosed < disclosed, "an unfalsifiable 'verified' must not be worth a falsifiable one");
  assert.equal(undisclosed, witnessed, "it should be weighed exactly as what it actually is: witnessed");
});

test("the downgrade can be turned off, and that is a choice with a name", () => {
  const s = did("Worker");
  const lenient = { ...DEFAULT_POLICY, requireDisclosedMethod: false };
  const undisclosed = edgeCapacities(
    [entry(ROOT, s, { basis: "verified", method_disclosed: false })],
    lenient
  ).edges[0].capacity;
  assert.equal(undisclosed, DEFAULT_POLICY.basisWeight.verified);
});

test("shared lineage is discounted but not discarded", () => {
  const s = did("Child");
  const shared = edgeCapacities([entry(ROOT, s, { independence: "shared_lineage" })], DEFAULT_POLICY)
    .edges[0].capacity;
  const stranger = edgeCapacities(
    [entry(ROOT, s, { independence: "no_known_common_ancestor" })],
    DEFAULT_POLICY
  ).edges[0].capacity;
  assert.ok(shared > 0, "a parent's knowledge of its child is real information");
  assert.ok(shared < stranger, "it is not independent, and must not count as though it were");
});

test("one relationship cannot exceed the per-edge cap however many receipts it carries", () => {
  const s = did("Worker");
  const many = Array.from({ length: 100 }, () => entry(ROOT, s));
  const { edges } = edgeCapacities(many, DEFAULT_POLICY);
  assert.ok(edges[0].capacity <= DEFAULT_POLICY.perEdgeCap + 1e-9, "per-edge cap did not hold");
});

test("a self-receipt is refused rather than scored", () => {
  const s = did("Self");
  assert.throws(() => edgeCapacities([entry(s, s)], DEFAULT_POLICY), /attester and subject/);
});

test("asking about your own trust root returns a statement, not a measurement", () => {
  const r = standingOf({ subject: ROOT, entries: [], trustRoots: [ROOT] });
  assert.equal(r.basis, "own_trust_root");
  assert.equal(r.standing, null);
});

test("the cut names the relationships that would have to be corrupted", () => {
  const broker = did("Broker");
  const s = did("Worker");
  const entries = [entry(ROOT, broker), entry(broker, s)];
  const r = standingOf({ subject: s, entries, trustRoots: [ROOT] });
  assert.ok(r.standing > 0);
  assert.ok(r.cut_edges.length > 0, "a bound with no explanation is not an answer");
  for (const e of r.cut_edges) {
    assert.ok(["root_allocation", "relationship"].includes(e.kind));
    assert.ok(typeof e.to === "string");
    if (e.kind === "relationship") assert.ok(typeof e.from === "string");
  }
});

test("the cut names a relationship when the relationship is what binds", () => {
  // Raise the root allocation so the binding constraint is the broker edge
  // rather than the evaluator's own generosity.
  const broker = did("Broker");
  const s = did("Worker");
  const entries = [entry(ROOT, broker), entry(broker, s)];
  const r = standingOf({
    subject: s,
    entries,
    trustRoots: [ROOT],
    policy: { ...DEFAULT_POLICY, rootCapacity: 10 }
  });
  const relationships = r.cut_edges.filter((e) => e.kind === "relationship");
  assert.ok(relationships.length > 0, "the binding relationship should be named");
});

test("decay is applied when the evaluator supplies one", () => {
  const s = did("Worker");
  const fresh = edgeCapacities([entry(ROOT, s)], DEFAULT_POLICY).edges[0].capacity;
  const stale = edgeCapacities([entry(ROOT, s)], { ...DEFAULT_POLICY, decay: () => 0.25 })
    .edges[0].capacity;
  assert.ok(stale < fresh);
  assert.ok(Math.abs(stale - fresh * 0.25) < 1e-9);
});

test("a decay function outside [0,1] is refused rather than trusted", () => {
  const s = did("Worker");
  assert.throws(
    () => edgeCapacities([entry(ROOT, s)], { ...DEFAULT_POLICY, decay: () => 2 }),
    /between 0 and 1/
  );
});

test("the burn bound is what may be extended, and insufficient standing extends nothing", () => {
  assert.equal(burnBound(null), 0, "an unknown party must not be extended value");
  assert.equal(burnBound(2.5), 2.5);
  assert.equal(burnBound(2.5, { safetyFactor: 0.5 }), 1.25);
});

test("no output carries a global score", () => {
  const broker = did("Broker");
  const s = did("Worker");
  const entries = [entry(ROOT, broker), entry(broker, s)];
  const r = standingOf({ subject: s, entries, trustRoots: [ROOT] });
  const text = JSON.stringify(r).toLowerCase();
  for (const forbidden of ["rank", "tier", "rating", "percentile", "\"score\""]) {
    assert.ok(!text.includes(forbidden), `output leaked a global aggregate: ${forbidden}`);
  }
  assert.ok(r.truth_claim.includes("not_a_global_score"));
});

// Unused import guard: E is the evaluator in the narrative above and is
// deliberately never a node in the graph. The evaluator is the source, not a
// participant, and if it ever appears as one the model has drifted.
void E;
