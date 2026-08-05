import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { DEFAULT_POLICY, portfolioNetwork, portfolioStanding } from "../src/evaluator-policy.mjs";
import {
  buildWorld,
  sweepIdentities,
  sweepAttackEdges,
  fabricatedCorpus
} from "./sim/trust-flow-sim.mjs";

/**
 * The claim: captured standing is flat in the adversary's identity count and
 * linear in the number of edges reaching it from genuinely trusted parties.
 *
 * Results are asserted as ratios against the theoretical ceiling rather than as
 * absolute numbers, so a metric that pins cannot be mistaken for a defeated
 * attack.
 */

test("captured standing is flat in the adversary's identity count", () => {
  const counts = [10, 100, 1000, 10_000];
  const results = sweepIdentities({ counts, attackEdges: 4, honest: 64 });

  const first = results[0].captured;
  for (const r of results) {
    assert.ok(
      Math.abs(r.captured - first) < 1e-9,
      `capture moved with identity count: ${r.sybils} identities captured ${r.captured}, ` +
        `but ${results[0].sybils} captured ${first}`
    );
  }
  // A flat line at zero would pass the above while proving nothing.
  assert.ok(first > 0, "the adversary should capture something, or the sweep is vacuous");
});

test("a thousandfold increase in identities buys nothing", () => {
  const small = sweepIdentities({ counts: [10], attackEdges: 3, honest: 32 })[0];
  const large = sweepIdentities({ counts: [10_000], attackEdges: 3, honest: 32 })[0];
  assert.equal(large.captured, small.captured);
  assert.equal(large.attackEdges, small.attackEdges);
});

test("captured standing never exceeds the capacity of the attack edges", () => {
  const results = [
    ...sweepIdentities({ counts: [50, 500, 5000], attackEdges: 6, honest: 64 }),
    ...sweepAttackEdges({ edgeCounts: [1, 2, 4, 8, 16, 32], sybils: 300, honest: 512 })
  ];
  for (const r of results) {
    assert.ok(
      r.ratio <= 1 + 1e-9,
      `capture/ceiling was ${r.ratio} at g=${r.attackEdges}, n=${r.sybils} — flow leaked`
    );
  }
});

test("the evaluator's own root allocation is itself a ceiling", () => {
  // Three roots at the default capacity of 1.0 can deliver at most 3.0 in
  // total, however many attack edges exist below them. This is conservation one
  // level up, and it is a feature: an evaluator's total exposure is bounded by
  // its own declared generosity, not by the adversary's effort.
  const results = sweepAttackEdges({ edgeCounts: [4, 16, 64], sybils: 300, honest: 512 });
  const rootCeiling = 3 * DEFAULT_POLICY.rootCapacity;
  for (const r of results) {
    assert.ok(
      r.captured <= rootCeiling + 1e-9,
      `captured ${r.captured} above the total root allocation ${rootCeiling}`
    );
  }
  assert.ok(
    Math.abs(results[2].captured - rootCeiling) < 1e-9,
    "with plenty of attack edges the root allocation should be the binding constraint"
  );
});

test("captured standing grows linearly in attack edges, which is what must be bought", () => {
  // Root capacity is raised out of the way so that attack edges — not the
  // evaluator's own generosity — are the binding constraint. Otherwise this
  // measures the ceiling tested above and says nothing about g.
  const policy = { ...DEFAULT_POLICY, rootCapacity: 10_000 };
  const edgeCounts = [1, 2, 4, 8, 16, 32];
  const results = sweepAttackEdges({ edgeCounts, sybils: 300, honest: 512, policy });

  for (const r of results) {
    assert.ok(
      Math.abs(r.captured - r.attackEdges * policy.perEdgeCap) < 1e-6,
      `expected ${r.attackEdges} edges to yield ${r.attackEdges * policy.perEdgeCap}, got ${r.captured}`
    );
  }

  // Doubling the edges doubles the capture: the cost is per edge, and edges are
  // the thing that cannot be manufactured.
  for (let i = 1; i < results.length; i += 1) {
    const factor = results[i].captured / results[i - 1].captured;
    const expected = results[i].attackEdges / results[i - 1].attackEdges;
    assert.ok(Math.abs(factor - expected) < 1e-6, `slope broke at g=${results[i].attackEdges}`);
  }
});

test("a fabricated corpus of any size captures exactly nothing", () => {
  // The §7 conjecture: coverage-of-corpus has no denominator without a global
  // view, so a ring attests 100% of its own fiction. Under trust flow that is
  // worth nothing, because none of it crosses the cut.
  for (const [sybils, density] of [[50, 2], [200, 4], [500, 8]]) {
    const r = fabricatedCorpus({ sybils, density });
    assert.equal(r.captured, null, `${r.receipts} fabricated receipts produced standing`);
    assert.equal(r.basis, "insufficient");
    assert.ok(r.receipts > sybils, "the fabricated corpus should actually be large");
  }
});

test("one genuine relationship outweighs a hundred thousand manufactured ones", () => {
  const honestWorld = buildWorld({ honest: 8, sybils: 1, attackEdges: 1, seed: 3 });
  const honestResult = portfolioStanding({
    subjects: honestWorld.sybilDids,
    entries: honestWorld.entries,
    trustRoots: honestWorld.roots
  });

  const sybilWorld = buildWorld({ honest: 8, sybils: 100_000, attackEdges: 0, seed: 3 });
  const sybilResult = portfolioStanding({
    subjects: sybilWorld.sybilDids,
    entries: sybilWorld.entries,
    trustRoots: sybilWorld.roots
  });

  assert.ok(honestResult.joint_standing > 0);
  assert.equal(sybilResult.joint_standing, null);
});

test("the flow computation agrees with an independently enumerated minimum cut", () => {
  // The falsifier implements no flow algorithm at all: it enumerates every
  // partition separating source from sink and takes the smallest crossing
  // capacity, which is the definition of a minimum cut. Agreement between a
  // flow solver and a definition is worth something; agreement between two
  // flow solvers would not be.
  const cases = [];
  const scenarios = [
    { name: "one attack edge", honest: 3, sybils: 2, attackEdges: 1, seed: 1 },
    { name: "two attack edges", honest: 3, sybils: 3, attackEdges: 2, seed: 2 },
    { name: "no attack edge", honest: 3, sybils: 3, attackEdges: 0, seed: 3 },
    { name: "saturated honest region", honest: 4, sybils: 2, attackEdges: 3, seed: 4 }
  ];

  for (const s of scenarios) {
    const world = buildWorld(s);
    const args = {
      subjects: world.sybilDids,
      entries: world.entries,
      trustRoots: world.roots,
      policy: DEFAULT_POLICY
    };
    const net = portfolioNetwork(args);
    const standing = portfolioStanding(args);
    const flow = Math.round((standing.joint_standing ?? 0) * net.scale);

    assert.ok(net.nodeCount <= 18, `${s.name} is too large to enumerate: ${net.nodeCount} nodes`);
    cases.push({
      name: s.name,
      node_count: net.nodeCount,
      source: net.source,
      sink: net.sink,
      edges: net.edges,
      flow,
      max_nodes: 18
    });
  }

  const dir = mkdtempSync(join(tmpdir(), "somavera-mincut-"));
  const file = join(dir, "network.json");
  writeFileSync(file, JSON.stringify({ cases }, null, 2), "utf8");

  const script = new URL("./sim/mincut-falsifier.py", import.meta.url);
  const proc = spawnSync("python", [script.pathname.replace(/^\/([A-Za-z]:)/, "$1"), file], {
    encoding: "utf8"
  });

  if (proc.error || proc.status === null) {
    // A missing Python is a missing check, and a missing check must be loud.
    assert.fail(`the independent falsifier could not be run: ${proc.error?.message ?? "no exit status"}`);
  }
  assert.equal(proc.status, 0, `falsifier rejected the evaluator:\n${proc.stdout}\n${proc.stderr}`);
  assert.match(proc.stdout, /0 failure\(s\)/);

  // "0 failures" is also what a run that skipped everything prints. Require one
  // confirmed comparison per case, or this check is checking nothing.
  const confirmed = (proc.stdout.match(/^ok /gm) ?? []).length;
  assert.equal(
    confirmed,
    cases.length,
    `expected ${cases.length} enumerated comparisons, saw ${confirmed}:\n${proc.stdout}`
  );
  assert.ok(!/SKIP/.test(proc.stdout), `a case was skipped rather than checked:\n${proc.stdout}`);

  // Negative control: a falsifier that cannot reject anything is decoration.
  // Feed it a flow one unit above the truth and require it to say so.
  const tampered = JSON.parse(JSON.stringify({ cases }));
  tampered.cases[0].flow += 1;
  const badFile = join(dir, "tampered.json");
  writeFileSync(badFile, JSON.stringify(tampered, null, 2), "utf8");

  const rejected = spawnSync("python", [script.pathname.replace(/^\/([A-Za-z]:)/, "$1"), badFile], {
    encoding: "utf8"
  });
  assert.equal(rejected.status, 1, "the falsifier accepted a flow above the minimum cut");
  assert.match(rejected.stdout, /FAIL/);
});
