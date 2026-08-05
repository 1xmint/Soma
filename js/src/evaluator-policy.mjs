import { SomaError } from "./errors.mjs";

/**
 * The reference evaluator policy: standing as bounded trust flow.
 *
 * This is the piece the rest of the system has been missing. The protocol makes
 * evidence legible; it deliberately renders no verdict and computes no score.
 * Something still has to answer "how much should I trust this party?", and
 * whatever answers it is where the Sybil economics actually live. A sound
 * evidence layer with a naive evaluator on top is Sybil-food: an evaluator that
 * adds up receipts is defeated by manufacturing receipts, and manufacturing is
 * free.
 *
 * So state the thing plainly, because it relocates the whole problem:
 *
 *   SYBIL PRICING IS NOT A PROTOCOL PROPERTY. It is an evaluator-policy
 *   property over protocol-legible inputs.
 *
 * Which is why this ships with safe defaults rather than as an example. The
 * evaluator that ships becomes the one people use, and therefore the de facto
 * protocol. Shipping a lazy one and calling it illustrative would put the
 * inflatable aggregate back exactly where P3 removed it.
 *
 * WHAT IT COMPUTES
 *
 * Standing of subject S, relative to evaluator E, is the MAXIMUM FLOW from E's
 * own trust roots to S across the counter-signed receipt graph, where a receipt
 * from A about B is an edge A->B whose capacity is set by this policy.
 *
 * The single rule that does the work is conservation: no party may pass on more
 * trust than it received. Max-flow enforces that at every intermediate node by
 * construction, and the consequence is the entire point:
 *
 *   An adversary running a million identities that attest for one another has
 *   manufactured a million edges of capacity nothing. No flow enters that
 *   region except across the edges reaching it from parties E genuinely trusts,
 *   so by max-flow/min-cut the total standing it can obtain is bounded by the
 *   capacity of those few edges -- and the number of identities appears nowhere
 *   in that bound.
 *
 * Faking standing therefore costs what earning it costs: either genuinely
 * serving someone E trusts, or corrupting them, at a price attributable to them
 * and forfeitable by them. That is Sybil PRICING. Nothing here detects a Sybil,
 * nothing here decides who is honest, and no global quantity is produced.
 *
 * WHAT IT DOES NOT DO -- read this before relying on it:
 *
 *   It does not make uniqueness provable. Identity is free and one actor with N
 *   keys stays observationally identical to N actors. That is not solved here
 *   and cannot be solved under this identity model. It is priced instead.
 *
 *   It does not defeat betrayal by the genuinely trusted. Collusion among
 *   parties E really does trust is not a Sybil attack at all -- it is betrayal,
 *   priced at exactly the colluders' standing, and no system prices it lower.
 *   The floor on any evaluator's security is the cost of corrupting its
 *   cheapest meaningful trust path, which is equally true of every human
 *   institution. Per-edge caps are the lever; there is no cure.
 *
 *   It does not detect a patient adversary. An identity that does years of
 *   genuine work earns genuine standing, because it did genuine work. What
 *   bounds it is the spend, not the accrual: see `burnBound` below.
 *
 *   It produces no number comparable across evaluators. Standing is denominated
 *   in this evaluator's own root capacity and means nothing outside it. Two
 *   evaluators will and should disagree.
 *
 * Nothing here is frozen. This is policy, above the protocol. Every signature
 * still verifies if you replace the whole file.
 */

/** Fixed-point scale for capacities. */
const SCALE = 1_000_000;

/**
 * Safe defaults, on by default.
 *
 * Every number here is somebody's judgement and none is frozen. They are chosen
 * to be defensible rather than optimal, and an evaluator with real data should
 * replace them.
 */
export const DEFAULT_POLICY = Object.freeze({
  /**
   * How much an attester's claim is worth by how they claim to know.
   *
   * Only `verified` is falsifiable -- it asserts something reality can
   * contradict, and anyone can redo the check. `party` is an interested
   * opinion. Treating them alike is treating an opinion as a measurement.
   */
  basisWeight: Object.freeze({ verified: 1.0, witnessed: 0.4, party: 0.15 }),

  /**
   * Failure costs more than success earns.
   *
   * Symmetric weighting lets an adversary farm standing by doing a great many
   * cheap things adequately and a few expensive things badly. The asymmetry is
   * the standard fix and it is not subtle: it is why one public failure hurts
   * more than one public success helps, everywhere else in life too.
   */
  failurePenalty: 2.0,
  disputedPenalty: 0.5,

  /**
   * Whose failure it was changes everything, and conflating outcome with fault
   * destroys the evidence exactly where it matters most. Agents are composed:
   * a subject calls models, tools and delegates it does not control. An agent
   * that correctly reported a broken upstream API must not be scored like one
   * that broke it.
   *
   * `unattributed` carries no penalty on purpose. It means "a failure happened
   * and I cannot say whose it was", and reading an explicit statement of
   * ignorance as evidence against the subject is precisely what P7 forbids.
   * This is safe because *the attester* chooses the label, not the subject: an
   * honest attester who knows it was the subject's fault says so, and the
   * subject cannot relabel its own failures.
   */
  faultAttribution: Object.freeze({
    subject: 1.0,
    delegate: 0.5,
    upstream_tool: 0.0,
    environment: 0.0,
    unattributed: 0.0,
    none: 0.0
  }),

  /**
   * Lineage is labelled, never rejected.
   *
   * A parent attesting to its child is genuinely informative -- the parent has
   * the most direct knowledge of what the child did. What it is not is
   * independent, and the failure mode is counting it as though it came from a
   * stranger.
   *
   * `no_known_common_ancestor` is not called independent and is not treated as
   * such. Roots are free, so absence of a known common ancestor is absence of
   * evidence of relation, not evidence of independence -- which is why it does
   * not get a bonus over `unknown` so much as `unknown` gets a penalty for
   * being unverifiable.
   */
  lineageDiscount: Object.freeze({
    no_known_common_ancestor: 1.0,
    unknown: 0.5,
    shared_lineage: 0.25,
    self: 0.0
  }),

  /**
   * The cap on any single relationship, and the lever that prices anchor
   * compromise. Without it, one corrupted trusted party is an unbounded hole;
   * with it, the adversary must corrupt proportionally many.
   */
  perEdgeCap: 1.0,

  /**
   * What one trust root is worth. Finite on purpose: an infinite root makes the
   * min-cut depend only on the attack edges, which is elegant in the theorem
   * and reckless in practice, because a single corrupted root then has
   * unlimited reach.
   */
  rootCapacity: 1.0,

  /**
   * Standing lapses. Evidence is permanent; what it says about competence *now*
   * is not. Supply a function of a receipt returning a factor in [0,1] --
   * wiring `currentWeight` from depth-clock.mjs is the intended use. The
   * default does not decay, and an evaluator that leaves it there is choosing
   * to let a patient adversary bank standing indefinitely.
   */
  decay: null
});

const BASIS = ["party", "witnessed", "verified"];
const OUTCOMES = ["succeeded", "failed", "disputed"];

function requirePolicy(policy) {
  const p = { ...DEFAULT_POLICY, ...(policy ?? {}) };
  if (!(p.perEdgeCap > 0) || !Number.isFinite(p.perEdgeCap)) {
    throw new SomaError("perEdgeCap must be a positive finite number", 2, "EVALUATOR_POLICY_INVALID");
  }
  if (!(p.rootCapacity > 0) || !Number.isFinite(p.rootCapacity)) {
    throw new SomaError("rootCapacity must be a positive finite number", 2, "EVALUATOR_POLICY_INVALID");
  }
  if (p.decay !== null && typeof p.decay !== "function") {
    throw new SomaError("decay must be null or a function of a receipt", 2, "EVALUATOR_POLICY_INVALID");
  }
  return p;
}

/**
 * The signed contribution one receipt makes to the capacity of its edge.
 *
 * Positive for a success, negative for a failure the attester attributed to the
 * subject. Returned signed rather than clamped so that a party's failures can
 * cancel its successes on the same edge instead of being silently dropped --
 * dropping them would mean an attester's bad news about a subject counted for
 * nothing while its good news counted fully, which is how a reputation system
 * becomes a marketing channel.
 */
export function receiptContribution(receipt, independence, policy) {
  const p = requirePolicy(policy);

  if (!receipt || typeof receipt !== "object") {
    throw new SomaError("receipt must be an object", 2, "EVALUATOR_RECEIPT_INVALID");
  }
  if (!BASIS.includes(receipt.basis)) {
    throw new SomaError("receipt basis must be party, witnessed or verified", 2, "EVALUATOR_RECEIPT_INVALID");
  }
  if (!OUTCOMES.includes(receipt.outcome)) {
    throw new SomaError("receipt outcome must be succeeded, failed or disputed", 2, "EVALUATOR_RECEIPT_INVALID");
  }
  const lineage = p.lineageDiscount[independence];
  if (lineage === undefined) {
    throw new SomaError(`unknown independence label: ${independence}`, 2, "EVALUATOR_RECEIPT_INVALID");
  }

  const decay = p.decay ? p.decay(receipt) : 1;
  if (!(decay >= 0 && decay <= 1)) {
    throw new SomaError("decay must return a factor between 0 and 1", 2, "EVALUATOR_POLICY_INVALID");
  }

  const base = p.basisWeight[receipt.basis] * lineage * decay;

  if (receipt.outcome === "succeeded") return base;
  if (receipt.outcome === "disputed") return -base * p.disputedPenalty;

  const blame = p.faultAttribution[receipt.fault] ?? 0;
  return -base * p.failurePenalty * blame;
}

/**
 * Collapse a set of receipts into directed edge capacities.
 *
 * `entries` are `{ receipt, independence }`. Capacity is the net contribution
 * of every receipt on that edge, floored at zero and capped at `perEdgeCap`.
 *
 * Flooring at zero is a property of flow networks, not a judgement: a capacity
 * cannot be negative. Adverse evidence that pushed an edge below zero is
 * therefore reported separately rather than thrown away, because "this edge
 * carries no trust" and "this attester says the subject failed repeatedly" are
 * very different facts and an evaluator should see the second one.
 */
export function edgeCapacities(entries, policy) {
  const p = requirePolicy(policy);
  const net = new Map();
  const adverse = [];

  for (const entry of entries) {
    const { receipt, independence = "unknown" } = entry ?? {};
    if (!receipt || typeof receipt.attester_did !== "string" || typeof receipt.subject_did !== "string") {
      throw new SomaError("each entry must carry a receipt with attester and subject", 2, "EVALUATOR_RECEIPT_INVALID");
    }
    if (receipt.attester_did === receipt.subject_did) {
      // A self-receipt is malformed, not merely unhelpful. The receipt layer
      // already refuses it; refusing it again here means a policy fed raw input
      // cannot be talked into scoring one.
      throw new SomaError("a receipt cannot name the same identity as attester and subject", 2, "EVALUATOR_SELF_RECEIPT");
    }
    const key = `${receipt.attester_did} ${receipt.subject_did}`;
    const contribution = receiptContribution(receipt, independence, p);
    net.set(key, (net.get(key) ?? 0) + contribution);
  }

  const edges = [];
  for (const [key, value] of net) {
    const [from, to] = key.split(" ");
    if (value < 0) adverse.push({ from, to, net: value });
    edges.push({ from, to, capacity: Math.min(Math.max(value, 0), p.perEdgeCap) });
  }
  return { edges, adverse };
}

/**
 * Dinic's algorithm over integer capacities.
 *
 * Integers, not floats: capacities are scaled to fixed point before entry.
 * Augmenting-path methods on floating point can fail to terminate and can
 * return answers that differ by platform, and an evaluator whose result depends
 * on rounding order is one that two honest parties will disagree about for no
 * reason.
 */
function maxFlowInteger(nodeCount, rawEdges, source, sink) {
  const head = [];
  const next = [];
  const cap = [];
  const first = new Array(nodeCount).fill(-1);

  const addEdge = (u, v, c) => {
    head.push(v); cap.push(c); next.push(first[u]); first[u] = head.length - 1;
    head.push(u); cap.push(0); next.push(first[v]); first[v] = head.length - 1;
  };
  for (const e of rawEdges) addEdge(e.u, e.v, e.c);

  const level = new Array(nodeCount);
  const iter = new Array(nodeCount);

  const bfs = () => {
    level.fill(-1);
    const queue = [source];
    level[source] = 0;
    for (let qi = 0; qi < queue.length; qi += 1) {
      const u = queue[qi];
      for (let e = first[u]; e !== -1; e = next[e]) {
        if (cap[e] > 0 && level[head[e]] < 0) {
          level[head[e]] = level[u] + 1;
          queue.push(head[e]);
        }
      }
    }
    return level[sink] >= 0;
  };

  // Advance/retreat rather than recursion. A recursive blocking-flow search
  // costs one stack frame per node on the augmenting path, and an adversary
  // region is free to be a long chain -- which is a graph an attacker chooses,
  // so the depth is the attacker's to pick. Overflowing the stack on a crafted
  // graph would turn an evaluation into a crash.
  let flow = 0;
  while (bfs()) {
    for (let i = 0; i < nodeCount; i += 1) iter[i] = first[i];
    const path = [];
    let u = source;
    for (;;) {
      if (u === sink) {
        let pushed = Number.MAX_SAFE_INTEGER;
        for (const e of path) pushed = Math.min(pushed, cap[e]);
        for (const e of path) { cap[e] -= pushed; cap[e ^ 1] += pushed; }
        flow += pushed;
        // Retreat to just before the first edge this augmentation saturated.
        let idx = 0;
        while (idx < path.length && cap[path[idx]] > 0) idx += 1;
        path.length = idx;
        u = idx === 0 ? source : head[path[idx - 1]];
        continue;
      }
      let advanced = false;
      for (; iter[u] !== -1; iter[u] = next[iter[u]]) {
        const e = iter[u];
        const v = head[e];
        if (cap[e] > 0 && level[v] === level[u] + 1) { path.push(e); u = v; advanced = true; break; }
      }
      if (advanced) continue;
      if (u === source) break;
      level[u] = -1; // dead end in this phase
      const e = path.pop();
      u = head[e ^ 1];
      iter[u] = next[iter[u]];
    }
  }

  // Everything still reachable from the source in the residual graph is the
  // source side of a minimum cut. Reporting it is what turns a number into an
  // answer: these are the relationships that would have to be corrupted.
  const reachable = new Set([source]);
  const stack = [source];
  while (stack.length > 0) {
    const u = stack.pop();
    for (let e = first[u]; e !== -1; e = next[e]) {
      if (cap[e] > 0 && !reachable.has(head[e])) { reachable.add(head[e]); stack.push(head[e]); }
    }
  }
  return { flow, reachable };
}

/**
 * Standing of `subject`, relative to this evaluator's trust roots.
 *
 * `trustRoots` is required and may not be empty. There is deliberately no
 * global default, for the same reason depth-clock refuses one: counting over
 * everybody is precisely the inflatable global aggregate that free identity
 * makes meaningless, and an optional parameter is an invitation to supply one.
 *
 * Returns `basis: "insufficient"` with `standing: null` when no flow reaches
 * the subject. That is not a score of zero and must not be rendered as one. The
 * honest answer to "should I trust this stranger, knowing nobody who knows
 * them?" is that the system cannot tell you -- and a newcomer is in exactly
 * that position without having done anything wrong.
 */
export function standingOf({ subject, entries, trustRoots, policy }) {
  const p = requirePolicy(policy);

  if (typeof subject !== "string" || !subject.startsWith("did:key:")) {
    throw new SomaError("subject must be a did:key identifier", 2, "EVALUATOR_SUBJECT_INVALID");
  }
  const roots = trustRoots instanceof Set ? trustRoots : new Set(trustRoots ?? []);
  if (roots.size === 0) {
    throw new SomaError(
      "standing must be computed over a non-empty set of trust roots this evaluator chose",
      2,
      "EVALUATOR_TRUST_ROOTS_REQUIRED"
    );
  }
  if (roots.has(subject)) {
    // Asking how much you trust one of your own roots is a question about your
    // roots, not about the evidence. Answering it with a flow number would
    // invent a measurement out of an axiom.
    return {
      schema_version: "soma.standing.provisional-v1",
      subject,
      standing: null,
      basis: "own_trust_root",
      cut_edges: [],
      adverse: [],
      truth_claim: "standing_is_relative_to_this_evaluator_and_is_not_a_global_score"
    };
  }

  const { edges, adverse } = edgeCapacities(entries ?? [], p);

  const index = new Map();
  const idOf = (did) => {
    if (!index.has(did)) index.set(did, index.size + 1); // 0 is the virtual source
    return index.get(did);
  };
  const SOURCE = 0;
  idOf(subject);
  for (const root of roots) idOf(root);

  const raw = [];
  for (const root of roots) {
    raw.push({ u: SOURCE, v: idOf(root), c: Math.round(p.rootCapacity * SCALE) });
  }
  for (const e of edges) {
    if (e.capacity <= 0) continue;
    raw.push({ u: idOf(e.from), v: idOf(e.to), c: Math.round(e.capacity * SCALE) });
  }

  const sink = idOf(subject);
  const { flow, reachable } = maxFlowInteger(index.size + 1, raw, SOURCE, sink);

  // The cut: edges from the source side to the sink side. These are what would
  // have to be bought, and naming them is more useful than the number, because
  // a number cannot be inspected.
  //
  // Source edges are included and labelled rather than skipped. When the
  // binding constraint is the evaluator's own root allocation -- which is the
  // common case for a well-connected subject -- every edge in the cut is a
  // source edge, and skipping them returned a bound with no explanation at all.
  // "You are limited by how much you trust your own roots, not by anything
  // about this subject" is an answer, and a useful one.
  const didOf = new Map([...index].map(([did, id]) => [id, did]));
  const cutEdges = [];
  for (const e of raw) {
    if (reachable.has(e.u) && !reachable.has(e.v)) {
      cutEdges.push(
        e.u === SOURCE
          ? { kind: "root_allocation", from: null, to: didOf.get(e.v), capacity: e.c / SCALE }
          : { kind: "relationship", from: didOf.get(e.u), to: didOf.get(e.v), capacity: e.c / SCALE }
      );
    }
  }

  const standing = flow / SCALE;
  return {
    schema_version: "soma.standing.provisional-v1",
    subject,
    standing: flow > 0 ? standing : null,
    basis: flow > 0 ? "evaluator_trust_flow" : "insufficient",
    cut_edges: cutEdges,
    adverse,
    truth_claim: "standing_is_relative_to_this_evaluator_and_is_not_a_global_score"
  };
}

/**
 * The joint bound across many subjects at once -- and the trap it closes.
 *
 * `standingOf` answers "how much do I trust this one party", and the max-flow
 * bound it returns is correct for that question. It is NOT correct for the
 * question a relying party actually faces, and the difference is where a Sybil
 * adversary lives:
 *
 *   One attack edge of capacity c reaches an adversary region holding N
 *   identities. Evaluated ONE AT A TIME, every one of those N identities has
 *   standing c, because each computation gets the whole edge to itself. Extend
 *   V <= c to each and total exposure is N*c. N is back, and the bound is gone.
 *
 * The identities are not independent; they share an inflow, and evaluating them
 * separately double-counts the same trust once per identity. So:
 *
 *   SUMMING PER-SUBJECT STANDING IS NOT A BOUND. It is the amplification.
 *
 * This function computes the honest quantity: maximum flow from the evaluator's
 * roots to all subjects jointly, which is what conservation actually limits. It
 * is the total value that may be outstanding across the whole portfolio at one
 * time, and it does not grow when the adversary adds identities -- adding them
 * divides the same flow rather than multiplying it.
 *
 * An evaluator that extends credit to more than one party must use this. The
 * per-subject figure is for ranking and for explaining a single decision.
 */
export function portfolioNetwork({ subjects, entries, trustRoots, policy }) {
  const p = requirePolicy(policy);
  const subjectList = [...new Set(subjects ?? [])];
  if (subjectList.length === 0) {
    throw new SomaError("portfolio standing needs at least one subject", 2, "EVALUATOR_SUBJECT_INVALID");
  }
  const roots = trustRoots instanceof Set ? trustRoots : new Set(trustRoots ?? []);
  if (roots.size === 0) {
    throw new SomaError(
      "standing must be computed over a non-empty set of trust roots this evaluator chose",
      2,
      "EVALUATOR_TRUST_ROOTS_REQUIRED"
    );
  }

  const { edges, adverse } = edgeCapacities(entries ?? [], p);

  const index = new Map();
  const idOf = (did) => {
    if (!index.has(did)) index.set(did, index.size + 1);
    return index.get(did);
  };
  const SOURCE = 0;
  for (const root of roots) idOf(root);
  for (const s of subjectList) idOf(s);

  const raw = [];
  let totalCapacity = 0;
  for (const root of roots) {
    const c = Math.round(p.rootCapacity * SCALE);
    raw.push({ u: SOURCE, v: idOf(root), c });
    totalCapacity += c;
  }
  for (const e of edges) {
    if (e.capacity <= 0) continue;
    const c = Math.round(e.capacity * SCALE);
    raw.push({ u: idOf(e.from), v: idOf(e.to), c });
    totalCapacity += c;
  }

  // The sink edges must not themselves constrain the answer, so they are given
  // more capacity than the whole network can deliver.
  const SINK = index.size + 1;
  for (const s of subjectList) raw.push({ u: idOf(s), v: SINK, c: totalCapacity + 1 });

  return { edges: raw, source: SOURCE, sink: SINK, nodeCount: SINK + 1, scale: SCALE, adverse, subjectList };
}

export function portfolioStanding({ subjects, entries, trustRoots, policy }) {
  const { edges: raw, source, sink, nodeCount, adverse, subjectList } =
    portfolioNetwork({ subjects, entries, trustRoots, policy });

  const { flow } = maxFlowInteger(nodeCount, raw, source, sink);
  return {
    schema_version: "soma.portfolio-standing.provisional-v1",
    subjects: subjectList,
    joint_standing: flow > 0 ? flow / SCALE : null,
    basis: flow > 0 ? "evaluator_trust_flow" : "insufficient",
    adverse,
    truth_claim: "joint_capacity_across_subjects_not_the_sum_of_their_individual_standings"
  };
}

/**
 * The burn bound: never extend more value than would burn if you were betrayed.
 *
 *     V <= B
 *
 * Where more than one subject is involved, B must come from `portfolioStanding`
 * and not from summing `standingOf` -- see the trap documented there.
 *
 * This is the rule that makes the whole arrangement price an attack rather than
 * try to detect one, and it is the relying party's rule, not the protocol's.
 *
 * The patient adversary is the case that matters. An identity that spends years
 * doing genuine work accrues genuine standing, and nothing should try to tell
 * it apart from an honest participant, because until the moment it defects it
 * *is* one -- and a system that could tell them apart would be the surveillance
 * machine this project exists to refuse. What the design controls is not the
 * accrual but the spend: hold every extension at or below what the subject
 * would forfeit, and coordinated defection extracts at most what it destroys.
 * One shot, break-even at best.
 *
 * Bounded, not detected. Do not write it up as detection.
 */
export function burnBound(standing, { safetyFactor = 1.0 } = {}) {
  if (standing === null || standing === undefined) return 0;
  if (!(standing >= 0) || !Number.isFinite(standing)) {
    throw new SomaError("standing must be a non-negative finite number or null", 2, "EVALUATOR_STANDING_INVALID");
  }
  if (!(safetyFactor > 0) || !Number.isFinite(safetyFactor)) {
    throw new SomaError("safetyFactor must be a positive finite number", 2, "EVALUATOR_POLICY_INVALID");
  }
  return standing * safetyFactor;
}
