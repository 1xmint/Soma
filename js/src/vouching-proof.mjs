import { canonicalize } from "./canonicalize.mjs";
import { sha256 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { verifyReceipt } from "./receipt.mjs";
import { verifyEquivocationProof } from "./equivocation.mjs";

/**
 * Vouching, made collectable.
 *
 * RECEIPT-SPEC already carries the load-bearing sentence: "attestation
 * transfers stake, it does not manufacture truth." The stake was rhetorical.
 * Nothing could ever collect it, so vouching was free, and a bond nobody can
 * call is not a bond.
 *
 * The collection mechanism was already in the repository and nobody had noticed
 * what it was for. An equivocation proof is two contradictory signatures in one
 * hand: complete, offline-checkable by a stranger, needing no clock, no
 * adjudicator and no trusted party. Compose it with a receipt in which some
 * attester vouched for the equivocator, and the pair is a third artifact with
 * exactly the same properties:
 *
 *     A vouched for S.  S is proven to equivocate.
 *
 * That composite carries no signature of its own, and it must not. Both halves
 * are already self-authenticating, so a signature would add a signer whose
 * honesty mattered -- and the moment anyone must be trusted for a proof to
 * count, an adjudicator exists, and an adjudicator is an owner. Anybody may
 * assemble one. Nobody may be believed about it.
 *
 * WHY THIS IS THE STAKE THE CONSTRAINTS ALLOWED
 *
 * The project refuses a fee, a stake, or a bond "in any ISSUED asset", because
 * an issuer is an owner and a ledger is a capture target. Standing is not
 * issued: nobody grants it, no ledger holds it, and every evaluator recomputes
 * it from evidence. Putting standing at risk is therefore a bond with no
 * issuer, no ledger, and no holder class, denominated in precisely the thing an
 * attacker is trying to counterfeit. To buy a false vouch, an adversary must
 * pay for the attester's future standing; buying many from one attester does
 * not scale, because conservation already caps what one attester can pass on.
 *
 * WHAT IT DOES NOT PROVE -- and this is the part that will be overstated:
 *
 *   Not that the attester lied. Not that the attester knew. Not even that the
 *   attester vouched *after* the equivocation happened -- there is no clock, so
 *   ordering is not established here at all.
 *
 * An honest attester can be deceived, and this composite will name them. That
 * is correct and it is the point: if only provable malice cost anything, the
 * stake would be uncollectable, because malice is exactly what cannot be
 * proven. Being wrong costs something regardless of intent, which is what makes
 * vouching a considered act rather than a free one.
 *
 * An evaluator therefore DISCOUNTS the attester's edge. It does not punish, it
 * does not ban, and it renders no verdict -- consistent with a protocol that
 * never renders one.
 *
 * THE KEY-BINDING GAP -- read this before believing this mechanism bites today.
 *
 * A composite only binds when the receipt's `subject_did` is the SAME DID that
 * signed the equivocating heads. Exact equality, no indirection. That is not a
 * simplification; it is the only binding that keeps the composite checkable by
 * a stranger holding nothing but the bytes.
 *
 * Today's default artifacts do not satisfy it. `evidence.mjs` signs heads with
 * `controller_signing`, while receipts conventionally name the party's
 * `agent_did`, and those are different keys with different DIDs. So against
 * stock artifacts this composes to null, and a mechanism that never fires is
 * worth exactly nothing however elegant it reads.
 *
 * The obvious repair is worse than the gap. The public identity document does
 * carry both `controller_did` and `agent_did` -- and it is UNSIGNED,
 * self-asserted. Binding through it would let anyone forge a document pairing
 * an honest party's agent DID with an equivocator's controller key, and the
 * result would be a tool for destroying honest attesters rather than a bond.
 * An unsigned document must never be load-bearing in a proof.
 *
 * Two honest ways to close it, neither done here:
 *
 *   1. Sign the identity document, so the controller/agent binding is the
 *      party's own attributable statement rather than anyone's assertion. This
 *      is the smaller change and probably the right one.
 *   2. Have receipts name the DID that actually signs the evidence.
 *
 * Until one of those lands, this composes only for parties whose receipts name
 * their signing DID. Recorded here so the limitation is not mistaken for an
 * oversight, and so nobody reports this as working when it is waiting.
 */

export const VOUCHING_PROOF_DOMAIN = "somavera:soma-vouching-contradicted:v1";
export const VOUCHING_PROOF_SCHEMA = "soma.vouching-contradicted.provisional-v1";

/** Contradiction kinds, and how strong each one actually is. */
export const CONTRADICTION_KINDS = Object.freeze({
  /**
   * The vouched-for party is proven to have signed two different heads at one
   * sequence. Fully self-authenticating: checkable offline, forever, by a
   * stranger holding nothing but the bytes.
   */
  SUBJECT_EQUIVOCATION: "subject_equivocation"
});

function didOfKeyId(keyId) {
  const hash = keyId.indexOf("#");
  return hash === -1 ? keyId : keyId.slice(0, hash);
}

/**
 * Derive the identifier of a composite from its own contents.
 *
 * Derived, never asserted, matching every other identifier in this
 * implementation: an assembler cannot choose it, so it cannot be used as a
 * covert channel or collided on purpose.
 */
export function deriveVouchingProofId(core) {
  return sha256(Buffer.from(`${VOUCHING_PROOF_DOMAIN}\n${canonicalize(core)}`, "utf8"));
}

/**
 * Compose a receipt and an equivocation proof into a contradicted vouch.
 *
 * Returns null rather than throwing when the two simply do not compose -- a
 * receipt about a different subject, or a receipt that vouched for nothing. A
 * pair that does not compose is not an accusation and must not be reported as a
 * weaker one.
 */
export function composeVouchingContradiction({ receipt, equivocationProof }) {
  // Both halves are re-verified from scratch. Taking either on faith would make
  // the composite only as good as whoever handed it over, which is the property
  // this whole construction exists to avoid.
  const verifiedReceipt = verifyReceipt(receipt);
  const verifiedEquivocation = verifyEquivocationProof(equivocationProof);

  // Only a positive attestation is a vouch. A `failed` receipt about a party
  // who later turns out to equivocate is the attester having been RIGHT, and
  // charging them for it would invert the incentive exactly.
  if (receipt.outcome !== "succeeded") return null;

  const equivocatorDid = didOfKeyId(verifiedEquivocation.signer_key_id);
  if (equivocatorDid !== receipt.subject_did) return null;

  // An attester cannot be charged for vouching for itself, because a
  // self-receipt is refused upstream and can never exist. Checked anyway: this
  // composite is assembled by strangers from bytes they were handed.
  if (receipt.attester_did === receipt.subject_did) {
    throw new SomaError("a receipt cannot name one identity as attester and subject", 7, "VOUCHING_PROOF_INVALID");
  }

  const core = {
    schema_version: VOUCHING_PROOF_SCHEMA,
    kind: CONTRADICTION_KINDS.SUBJECT_EQUIVOCATION,
    attester_did: receipt.attester_did,
    subject_did: receipt.subject_did,
    receipt_id: verifiedReceipt.receipt_id ?? receipt.receipt_id,
    equivocation: {
      signer_key_id: verifiedEquivocation.signer_key_id,
      sequence: verifiedEquivocation.sequence,
      head_hashes: verifiedEquivocation.head_hashes
    }
  };

  return {
    ...core,
    proof_id: deriveVouchingProofId(core),
    receipt,
    equivocation_proof: equivocationProof,
    claim: "this attester vouched for a party that is proven to equivocate",
    truth_claim:
      "both halves are self-authenticating; this establishes neither the attester's knowledge nor any ordering between the vouch and the equivocation"
  };
}

/**
 * Re-check a composite from scratch, taking nothing on faith from its bearer.
 *
 * Throws rather than returning false. A proof that does not hold is not a
 * weaker proof; it is an accusation against a named party, and repeating it
 * would do the damage the proof was supposed to justify.
 */
export function verifyVouchingContradiction(proof) {
  if (proof === null || typeof proof !== "object" || proof.schema_version !== VOUCHING_PROOF_SCHEMA) {
    throw new SomaError("vouching contradiction shape is invalid", 2, "VOUCHING_PROOF_INVALID");
  }
  if (proof.kind !== CONTRADICTION_KINDS.SUBJECT_EQUIVOCATION) {
    throw new SomaError("unknown contradiction kind", 2, "VOUCHING_PROOF_INVALID");
  }

  const rebuilt = composeVouchingContradiction({
    receipt: proof.receipt,
    equivocationProof: proof.equivocation_proof
  });
  if (rebuilt === null) {
    throw new SomaError("the cited receipt and proof do not compose", 7, "VOUCHING_PROOF_UNPROVEN");
  }
  if (rebuilt.proof_id !== proof.proof_id) {
    throw new SomaError("the composite misstates what its parts show", 7, "VOUCHING_PROOF_INVALID");
  }
  if (rebuilt.attester_did !== proof.attester_did || rebuilt.subject_did !== proof.subject_did) {
    throw new SomaError("the composite misnames its parties", 7, "VOUCHING_PROOF_INVALID");
  }

  return {
    attester_did: rebuilt.attester_did,
    subject_did: rebuilt.subject_did,
    receipt_id: rebuilt.receipt_id,
    kind: rebuilt.kind,
    truth_claim: rebuilt.truth_claim
  };
}

/**
 * Turn verified contradictions into the discount an evaluator applies.
 *
 * Returned as a multiplier per attester rather than applied here, because
 * applying it is the evaluator's business and this module renders no verdict.
 *
 * The discount compounds per contradiction: one is a mistake anybody could
 * make, and being wrong repeatedly is the thing that should cost. `floor`
 * exists because driving an attester to exactly zero is indistinguishable from
 * never having heard of them, and those are different facts -- an evaluator
 * should be able to tell "unknown" from "known to have been wrong."
 */
export function vouchingDiscounts(proofs, { perContradiction = 0.5, floor = 0.01 } = {}) {
  if (!(perContradiction > 0 && perContradiction < 1)) {
    throw new SomaError("perContradiction must be between 0 and 1 exclusive", 2, "VOUCHING_DISCOUNT_INVALID");
  }
  if (!(floor >= 0 && floor < 1)) {
    throw new SomaError("floor must be between 0 and 1", 2, "VOUCHING_DISCOUNT_INVALID");
  }

  const counts = new Map();
  const seen = new Set();
  for (const proof of proofs) {
    const verified = verifyVouchingContradiction(proof);
    // One contradiction counts once however many times it is presented.
    // Otherwise an adversary destroys an honest attester by replaying a single
    // genuine proof, which would make this a weapon rather than a bond.
    if (seen.has(proof.proof_id)) continue;
    seen.add(proof.proof_id);
    counts.set(verified.attester_did, (counts.get(verified.attester_did) ?? 0) + 1);
  }

  const discounts = new Map();
  for (const [did, n] of counts) {
    discounts.set(did, Math.max(floor, Math.pow(perContradiction, n)));
  }
  return discounts;
}
