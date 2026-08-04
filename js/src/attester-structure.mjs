import { classifyIndependence } from "./receipt.mjs";

/**
 * Surface structural facts about a set of attesters. Judge nothing.
 *
 * The problem: identities are free, so five attesters may be five parties or
 * one party wearing five keys. Lineage catches the cheap version — agents
 * sharing a root are visibly related. It does not catch an adversary who spends
 * twenty keypairs on twenty unrelated roots.
 *
 * The tempting fix is a similarity detector that flags likely Sybils. That is a
 * mistake in an open protocol: a published detector is a published gradient, and
 * the adversary optimises against it. Any threshold we ship becomes the exact
 * boundary attackers tune to sit beneath.
 *
 * So this returns observations, never conclusions. There is no score, no flag,
 * and no threshold — nothing to game, because the evaluator supplies the
 * judgement and can change it without telling anyone.
 *
 * What it can show is real: hidden common origin is invisible beforehand but
 * leaves traces afterwards. Attesters who never disagree, who only ever attest
 * to each other, or who share no counterparty with you, are structurally
 * distinctive whatever their lineage claims.
 */

/**
 * @param receipts  verified receipts, each with attester_did / subject_did / outcome / task_id
 * @param options.lineages         map of did -> ordered ancestor list, where known
 * @param options.evaluatorKnown   dids the evaluator has independent dealings with
 */
export function describeAttesterStructure(receipts, { lineages = new Map(), evaluatorKnown = [] } = {}) {
  const known = new Set(evaluatorKnown);
  const attesters = new Map();

  for (const receipt of receipts) {
    const entry = attesters.get(receipt.attester_did) ?? {
      did: receipt.attester_did,
      attestations: 0,
      outcomes: { succeeded: 0, failed: 0, disputed: 0 },
      subjects: new Set(),
      tasks: new Set()
    };
    entry.attestations += 1;
    if (receipt.outcome in entry.outcomes) entry.outcomes[receipt.outcome] += 1;
    entry.subjects.add(receipt.subject_did);
    entry.tasks.add(receipt.task_id);
    attesters.set(receipt.attester_did, entry);
  }

  const dids = [...attesters.keys()];

  const observations = dids.map((did) => {
    const entry = attesters.get(did);
    const others = dids.filter((other) => other !== did);

    // Do they only ever attest inside this set? A closed group is not proof of
    // anything -- a genuine team also attests mostly to itself -- but it is a
    // fact the evaluator should see rather than have decided for them.
    const subjectsInsideSet = [...entry.subjects].filter((s) => attesters.has(s)).length;

    // Lineage where it is known. Absent lineage is reported as unknown, never
    // as unrelated: the whole point of P7.
    const relatedToOthers = others
      .map((other) => {
        const mine = lineages.get(did);
        const theirs = lineages.get(other);
        if (!mine || !theirs) return { did: other, relation: "unknown" };
        return { did: other, relation: classifyIndependence(mine, theirs) };
      })
      .filter((r) => r.relation === "shared_lineage");

    return {
      did,
      attestations: entry.attestations,
      distinct_subjects: entry.subjects.size,
      distinct_tasks: entry.tasks.size,
      outcomes: entry.outcomes,
      // An attester that has never reported anything but success has either been
      // extraordinarily lucky, or is not reporting what it saw.
      never_reported_anything_but_success:
        entry.outcomes.failed === 0 && entry.outcomes.disputed === 0 && entry.attestations > 0,
      subjects_inside_this_set: subjectsInsideSet,
      subjects_outside_this_set: entry.subjects.size - subjectsInsideSet,
      shares_lineage_with: relatedToOthers.map((r) => r.did),
      lineage_known: lineages.has(did),
      evaluator_has_independent_dealings: known.has(did)
    };
  });

  return {
    schema_version: "soma.attester-structure.provisional-v1",
    attester_count: dids.length,
    observations,
    // Stated in the output so it travels with the data and cannot be quietly
    // reinterpreted as a verdict by whatever consumes it.
    interpretation: "structural observations only; no judgement is made and none is implied",
    truth_claim:
      "shared lineage shows relation; its absence shows nothing, because identities are free to create"
  };
}
