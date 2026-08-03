import test from "node:test";
import assert from "node:assert/strict";
import { describeAttesterStructure } from "../src/attester-structure.mjs";

function receipt(attester, subject, outcome = "succeeded", task = "t1") {
  return { attester_did: attester, subject_did: subject, outcome, task_id: task };
}

test("a closed ring is described, not accused", () => {
  // Twenty keypairs, twenty roots, all attesting only to each other. Exactly the
  // shape an adversary spins up to look like independent sources.
  const ring = Array.from({ length: 5 }, (_, i) => `did:key:zring${i}`);
  const receipts = [];
  for (const a of ring) {
    for (const b of ring) {
      if (a !== b) receipts.push(receipt(a, b));
    }
  }

  const result = describeAttesterStructure(receipts, { evaluatorKnown: [] });

  for (const o of result.observations) {
    assert.equal(o.subjects_outside_this_set, 0, "the ring never attests outside itself");
    assert.equal(o.never_reported_anything_but_success, true);
    assert.equal(o.evaluator_has_independent_dealings, false);
  }

  // The critical assertion: no verdict anywhere in the output.
  const serialized = JSON.stringify(result);
  for (const word of ["sybil", "suspicious", "fake", "score", "risk", "malicious"]) {
    assert.ok(!serialized.toLowerCase().includes(word), `output must not contain a verdict word: ${word}`);
  }
});

test("absent lineage is reported as unknown, never as unrelated", () => {
  const receipts = [receipt("did:key:zA", "did:key:zX"), receipt("did:key:zB", "did:key:zX")];
  const result = describeAttesterStructure(receipts, { lineages: new Map() });

  for (const o of result.observations) {
    assert.equal(o.lineage_known, false);
    assert.deepEqual(o.shares_lineage_with, [], "unknown lineage yields no relation claim in either direction");
  }
  assert.match(result.truth_claim, /its absence shows nothing/);
});

test("shared lineage is surfaced when it is actually known", () => {
  const lineages = new Map([
    ["did:key:zA", ["did:key:zRoot", "did:key:zA"]],
    ["did:key:zB", ["did:key:zRoot", "did:key:zB"]],
    ["did:key:zC", ["did:key:zOther", "did:key:zC"]]
  ]);
  const receipts = [
    receipt("did:key:zA", "did:key:zX"),
    receipt("did:key:zB", "did:key:zX"),
    receipt("did:key:zC", "did:key:zX")
  ];

  const result = describeAttesterStructure(receipts, { lineages });
  const byDid = new Map(result.observations.map((o) => [o.did, o]));

  assert.deepEqual(byDid.get("did:key:zA").shares_lineage_with, ["did:key:zB"]);
  assert.deepEqual(byDid.get("did:key:zC").shares_lineage_with, []);
});

test("an attester that has never reported a failure is visible as such", () => {
  const always = [receipt("did:key:zGlow", "did:key:zX"), receipt("did:key:zGlow", "did:key:zY")];
  const honest = [
    receipt("did:key:zReal", "did:key:zX", "succeeded"),
    receipt("did:key:zReal", "did:key:zY", "failed")
  ];

  const result = describeAttesterStructure([...always, ...honest]);
  const byDid = new Map(result.observations.map((o) => [o.did, o]));

  assert.equal(byDid.get("did:key:zGlow").never_reported_anything_but_success, true);
  assert.equal(byDid.get("did:key:zReal").never_reported_anything_but_success, false);
});

// The evaluator's own dealings are the thing an adversary cannot manufacture:
// they require the evaluator to have actually transacted.
test("the evaluator's independent dealings are marked", () => {
  const receipts = [receipt("did:key:zKnown", "did:key:zX"), receipt("did:key:zStranger", "did:key:zX")];
  const result = describeAttesterStructure(receipts, { evaluatorKnown: ["did:key:zKnown"] });
  const byDid = new Map(result.observations.map((o) => [o.did, o]));

  assert.equal(byDid.get("did:key:zKnown").evaluator_has_independent_dealings, true);
  assert.equal(byDid.get("did:key:zStranger").evaluator_has_independent_dealings, false);
});

test("a genuine team looks structurally similar to a ring, and that is stated honestly", () => {
  // Colleagues attest to each other constantly. Nothing distinguishes this from
  // a ring at the structural level, which is exactly why no verdict is issued.
  const team = ["did:key:zTeam1", "did:key:zTeam2"];
  const receipts = [
    receipt(team[0], team[1], "succeeded"),
    receipt(team[1], team[0], "succeeded"),
    receipt(team[0], "did:key:zOutsider", "failed")
  ];

  const result = describeAttesterStructure(receipts);
  const byDid = new Map(result.observations.map((o) => [o.did, o]));

  assert.equal(byDid.get(team[0]).subjects_outside_this_set, 1, "attesting outside the set is visible");
  assert.equal(byDid.get(team[1]).subjects_outside_this_set, 0);
  assert.match(result.interpretation, /no judgement is made/);
});
