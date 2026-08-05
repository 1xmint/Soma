import { canonicalize } from "./canonicalize.mjs";
import { sha256 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";

/**
 * Time as depth, not as a reading.
 *
 * The protocol has no clock, deliberately: an external ordering service is the
 * infrastructure dependence this system exists to avoid. But `issued_at` is a
 * string the signer chooses, so anything resting on how old a record is rests
 * on nothing — and standing that cannot lapse can be banked by a patient
 * adversary and spent later.
 *
 * The way out is to stop asking what time it is and ask how much of the
 * network has happened since. When parties publish heads that reference the
 * heads they have seen from others, the references form a DAG, and a record's
 * age becomes the number of DISTINCT SIGNERS whose later heads transitively
 * reach it. That is not wall-clock time. It is better suited to the purpose:
 *
 *   - It cannot be fast-forwarded by lying, because a reference must be made
 *     by somebody else's key. Depth is spent by others, not claimed by you.
 *   - Backdating requires everyone who referenced you to have lied
 *     consistently, and their heads are hash-chained and self-signed, so
 *     inconsistency is already an equivocation proof.
 *   - It needs no shared clock, no leap seconds, no timezone, and no server
 *     anyone must keep running.
 *
 * This is the same shape as certificate transparency logs cross-signing each
 * other, and the same shape as block height.
 *
 * WHAT IT DOES NOT DO -- read this before relying on it:
 *
 *   A clique can cross-reference itself all day and manufacture enormous depth
 *   among its own members. Depth is therefore MEANINGLESS IN THE ABSOLUTE and
 *   is only ever counted over signers the evaluator already has reason to
 *   trust. Like every other quantity here, it is relative to the evaluator,
 *   and a global "depth score" would be inflatable exactly the way a global
 *   reputation score is.
 *
 *   It also proves elapsed PARTICIPATION, not elapsed duration. An adversary
 *   who genuinely waits accrues genuine depth. This does not defeat the
 *   aged-identity attack and is not offered as a defence against it. What it
 *   provides is the ordering that makes standing perishable, which is a
 *   different and smaller claim.
 *
 * Nothing here is frozen. It is evaluator policy, and two evaluators may count
 * depth differently while every signature still verifies.
 */

const REFERENCE_DOMAIN = "soma:depth-reference:provisional-v1";
const HASH = /^[a-f0-9]{64}$/;

/**
 * The commitment a party makes when it says "I saw these heads".
 *
 * Hashed under its own domain so a reference set cannot be replayed as any
 * other kind of record.
 */
export function referenceCommitment(observedHeadHashes) {
  if (!Array.isArray(observedHeadHashes)) {
    throw new SomaError("observed head hashes must be an array", 2, "DEPTH_REFERENCE_INVALID");
  }
  for (const h of observedHeadHashes) {
    if (typeof h !== "string" || !HASH.test(h)) {
      throw new SomaError("observed head hash must be 64 lowercase hex characters", 2, "DEPTH_REFERENCE_INVALID");
    }
  }
  // Sorted and de-duplicated: the set is what is being committed to, and two
  // parties who saw the same heads in a different order must commit
  // identically or the commitment measures arrival order instead of knowledge.
  const unique = [...new Set(observedHeadHashes)].sort();
  return sha256(Buffer.from(`${REFERENCE_DOMAIN}\n${canonicalize(unique)}`, "utf8"));
}

/**
 * Build the reference graph from a corpus of heads.
 *
 * Each head is `{ head_hash, signer_did, observed_head_hashes }`. Heads that
 * reference a hash nobody in the corpus published are kept -- absence of the
 * referenced head is not evidence that it never existed (P7), it usually just
 * means an incomplete view.
 */
function buildGraph(heads) {
  const byHash = new Map();
  for (const head of heads) {
    if (!head || typeof head !== "object") {
      throw new SomaError("head must be an object", 2, "DEPTH_HEAD_INVALID");
    }
    if (typeof head.head_hash !== "string" || !HASH.test(head.head_hash)) {
      throw new SomaError("head_hash must be 64 lowercase hex characters", 2, "DEPTH_HEAD_INVALID");
    }
    if (typeof head.signer_did !== "string" || !head.signer_did.startsWith("did:key:")) {
      throw new SomaError("signer_did must be a did:key identifier", 2, "DEPTH_HEAD_INVALID");
    }
    if (byHash.has(head.head_hash)) {
      // Two different heads cannot share a hash unless one is a forgery or the
      // hash was not derived from the contents. Either way it is not a merge
      // to paper over.
      throw new SomaError("duplicate head hash in corpus", 2, "DEPTH_HEAD_DUPLICATE");
    }
    byHash.set(head.head_hash, {
      hash: head.head_hash,
      signer: head.signer_did,
      refs: Array.isArray(head.observed_head_hashes) ? head.observed_head_hashes : []
    });
  }
  return byHash;
}

/**
 * Which distinct signers' heads transitively reach `targetHash`?
 *
 * A signer counts once no matter how many heads it published, because
 * otherwise depth is bought by publishing frequently -- which is free.
 *
 * The target's own signer never counts toward its own depth. Self-reference is
 * the thing this exists to rule out: an agent cannot age itself.
 */
export function witnessesOf(targetHash, heads) {
  const byHash = buildGraph(heads);
  const target = byHash.get(targetHash);
  const targetSigner = target ? target.signer : null;

  const witnesses = new Set();
  for (const head of byHash.values()) {
    if (head.hash === targetHash) continue;
    if (head.signer === targetSigner) continue;

    // Walk this head's reference closure looking for the target.
    const seen = new Set();
    const stack = [...head.refs];
    while (stack.length > 0) {
      const next = stack.pop();
      if (seen.has(next)) continue;
      seen.add(next);
      if (next === targetHash) { witnesses.add(head.signer); break; }
      const node = byHash.get(next);
      if (node) {
        // Only follow references through heads by OTHER signers. A chain of
        // self-references cannot be used to launder a path to the target.
        if (node.signer === head.signer || node.signer !== targetSigner) stack.push(...node.refs);
      }
    }
  }
  return witnesses;
}

/**
 * How far apart are two signers' views of the network?
 *
 * Counting distinct signers treats one operator's thousand hosts as a thousand
 * witnesses. Count is free: an organisation large enough can run a billion
 * identities, have them do genuine work, and reference whatever it likes. Any
 * measure whose unit is "how many" is bought outright at that scale.
 *
 * What is not free is *seeing differently*. Two genuinely separate observers
 * are on different networks, with different peers and different latency, so
 * they never hold quite the same view — each has referenced something the
 * other never did. Hosts driven by one operator converge, because there is one
 * view behind them.
 *
 * Returns 0 for identical viewpoints and 1 for wholly disjoint ones, or `null`
 * when there is not enough history to say. `null` means unknown and must not
 * be read as a middling correlation — absence of evidence is not evidence
 * (P7). A new host that has said little yet is not thereby suspicious, and a
 * numeric "neutral" here would quietly penalise every newcomer.
 */
export function viewDivergence(signerA, signerB, heads, minimumEvidence = 4) {
  const refsOf = (signer) => {
    const refs = new Set();
    for (const head of heads) {
      if (head.signer_did !== signer) continue;
      for (const r of head.observed_head_hashes ?? []) refs.add(r);
    }
    return refs;
  };
  const a = refsOf(signerA);
  const b = refsOf(signerB);
  if (a.size < minimumEvidence || b.size < minimumEvidence) return null;

  let shared = 0;
  for (const r of a) if (b.has(r)) shared += 1;
  const union = a.size + b.size - shared;
  return union === 0 ? null : 1 - shared / union;
}

/**
 * Depth of a record, counted over signers this evaluator trusts and discounted
 * by how much they merely echo one another.
 *
 * `trustedSigners` is required rather than optional. There is no sensible
 * global default: counting over everyone is precisely the inflatable global
 * aggregate that the identity model makes meaningless, and making it optional
 * invites an implementation to supply one.
 *
 * The discount is what makes this resist scale. A signer contributes at most
 * as much as its divergence from every signer already counted, so a bloc of a
 * thousand hosts sharing one view contributes roughly what one host does. The
 * adversary's advantage was count, and count is now worth nothing by itself.
 *
 * That does not make the attack impossible; it makes it expensive in the
 * currency being attacked. To appear independent, a bloc must genuinely see
 * differently — separate infrastructure, separate peers — which costs per
 * identity rather than per bloc, while an honest participant pays nothing to
 * be what it already is.
 */
export function depthOf(targetHash, heads, trustedSigners, { discountCorrelated = true } = {}) {
  if (!(trustedSigners instanceof Set) || trustedSigners.size === 0) {
    throw new SomaError(
      "depth must be counted over a non-empty set of signers the evaluator trusts",
      2,
      "DEPTH_TRUST_SET_REQUIRED"
    );
  }
  const witnesses = [...witnessesOf(targetHash, heads)].filter((s) => trustedSigners.has(s));
  if (!discountCorrelated) return witnesses.length;

  // Most-divergent first, so redundancy is charged to the echo rather than to
  // whichever signer happens to be enumerated first.
  const spread = new Map();
  for (const s of witnesses) {
    let total = 0;
    for (const other of witnesses) {
      if (other === s) continue;
      const d = viewDivergence(s, other, heads);
      total += d === null ? 1 : d;
    }
    spread.set(s, total);
  }
  witnesses.sort((x, y) => spread.get(y) - spread.get(x));

  let depth = 0;
  const counted = [];
  for (const signer of witnesses) {
    let factor = 1;
    for (const prior of counted) {
      const d = viewDivergence(signer, prior, heads);
      // Unknown means unknown. Only measured redundancy discounts anything.
      if (d !== null) factor = Math.min(factor, d);
    }
    depth += factor;
    counted.push(signer);
  }
  return depth;
}

/**
 * Does `earlierHash` provably precede `laterHash`?
 *
 * True only when the later head's reference closure reaches the earlier one.
 * Returns false for "unknown" as well as for "no" -- the caller must not read
 * a false as evidence of the reverse ordering. Concurrency is the normal case
 * in a DAG, and most pairs are genuinely unordered.
 */
export function precedes(earlierHash, laterHash, heads) {
  const byHash = buildGraph(heads);
  const later = byHash.get(laterHash);
  if (!later) return false;

  const seen = new Set();
  const stack = [...later.refs];
  while (stack.length > 0) {
    const next = stack.pop();
    if (seen.has(next)) continue;
    seen.add(next);
    if (next === earlierHash) return true;
    const node = byHash.get(next);
    if (node) stack.push(...node.refs);
  }
  return false;
}

/**
 * Standing that lapses.
 *
 * Evidence is permanent; standing is not. A receipt stays true forever, but
 * what it says about a party's competence *now* weakens as the network moves
 * on without it. Without this, trust can be accumulated and banked, and an
 * adversary who contributes genuinely and then defects keeps almost everything
 * it earned.
 *
 * `halfLife` is expressed in depth, not seconds, and is deliberately a
 * parameter with no default. It is somebody's policy -- a fast-moving domain
 * should forget faster than a slow one -- and no tunable number may be frozen.
 */
export function currentWeight({ evidenceHeadHash, heads, trustedSigners, halfLife }) {
  if (typeof halfLife !== "number" || !Number.isFinite(halfLife) || halfLife <= 0) {
    throw new SomaError("halfLife must be a positive finite number of depth units", 2, "DECAY_HALF_LIFE_INVALID");
  }
  const depth = depthOf(evidenceHeadHash, heads, trustedSigners);
  return Math.pow(0.5, depth / halfLife);
}
