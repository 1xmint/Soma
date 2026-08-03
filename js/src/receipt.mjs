import { canonicalize } from "./canonicalize.mjs";
import { sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";

// Separate domains for the identifier and the signature, matching every other
// signing context in this implementation. Sharing one domain would let a
// receipt identifier be presented as a signature preimage.
export const RECEIPT_ID_DOMAIN = "somavera:soma-work-receipt:v1";
export const RECEIPT_SIGNATURE_DOMAIN = "somavera:soma-work-receipt-signature:v1";

export const RECEIPT_SCHEMA = "soma.work-receipt.provisional-v1";

const CORE_FIELDS = [
  "attester_did",
  "capability",
  "claim_hash",
  "basis",
  "domain",
  "fault",
  "issued_at",
  "observed_at",
  "outcome",
  "schema_version",
  "subject_did",
  "task_id"
];

const RECEIPT_FIELDS = [...CORE_FIELDS, "receipt_id", "signature"].sort();

// failed and disputed exist deliberately. A system that can only record success
// produces reputation that is meaningless by construction, because a missing
// receipt cannot be distinguished from work that went badly.
const OUTCOMES = new Set(["succeeded", "failed", "disputed"]);

// Outcome says what happened. Fault says who it is attributable to, and the two
// are not the same question.
//
// Agents are composed: a subject calls models, tools and delegates it does not
// control. Without this separation every upstream flake is recorded as subject
// failure, and the evidence turns to noise exactly where composed work matters
// most. An agent that correctly reported a broken upstream API did its job.
//
// Fault is the attester's judgement, not an established fact. It records who
// one named party believes is answerable, which is worth exactly as much as
// that party's own standing.
const FAULTS = new Set(["none", "subject", "delegate", "upstream_tool", "environment", "unattributed"]);

// How the attester came to know what it is claiming. This is not decoration:
// the three carry entirely different evidential weight.
//
//   party      the attester took part. Subjective, and interested -- it may be
//              lying and nobody can check.
//   witnessed  the attester saw it happen without taking part. Less interested,
//              still not reproducible.
//   verified   the attester independently checked the claim against something
//              else, and anyone can redo that check.
//
// Only `verified` is falsifiable. A verified claim makes an assertion reality
// can contradict; the other two cannot be wrong in any checkable sense. An
// evaluator that cannot tell them apart is treating an opinion as a measurement.
const BASES = new Set(["party", "witnessed", "verified"]);

// A signature names the suite that produced it. Verifiers decide which suites
// they accept; there is no handshake and therefore no downgrade attack, because
// there is nothing to negotiate. Records are verified asynchronously by
// strangers years later, so negotiation -- the standard answer to crypto
// agility -- is the wrong shape for this problem.
//
// New suites are added. Old labels are never removed, or every record signed
// under them becomes unverifiable, which is the one irreversible mistake
// available here.
const SUITES = new Set(["Ed25519-v1"]);

const HASH = /^[a-f0-9]{64}$/;
const NAME = /^[a-z][a-z0-9-]{0,63}$/;
const DID = /^did:[a-z0-9]+:[A-Za-z0-9._:-]{1,512}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const DID_KEY_PREFIX = "did:key:";

/**
 * Recover the attester's public key from its DID.
 *
 * Soma DIDs are `did:key:z…`, where the fingerprint is the multibase-encoded
 * public key. The identifier *is* the key commitment, so verification needs no
 * network, no registry and no key distribution.
 *
 * This is why the key is never a parameter. Accepting one would let a caller
 * verify a receipt naming one attester against a different attester's key, and
 * attribution — the only thing a receipt actually establishes — would depend on
 * the caller passing the right key. Here it cannot be got wrong.
 */
export function attesterKeyFromDid(did) {
  if (typeof did !== "string" || !did.startsWith(DID_KEY_PREFIX)) {
    throw new SomaError(
      "receipts require a self-certifying did:key attester; no other method resolves offline",
      2,
      "RECEIPT_DID_UNSUPPORTED"
    );
  }
  const fingerprint = did.slice(DID_KEY_PREFIX.length);
  if (!/^z[1-9A-HJ-NP-Za-km-z]{40,120}$/.test(fingerprint)) {
    throw new SomaError("attester DID does not carry a valid multibase key", 2, "RECEIPT_DID_INVALID");
  }
  return fingerprint;
}

function exactObject(value, fields, code, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SomaError(`${label} must be an object`, 2, code);
  }
  const present = Object.keys(value).sort();
  if (present.length !== fields.length || present.some((key, index) => key !== fields[index])) {
    throw new SomaError(
      `${label} must carry exactly [${fields.join(", ")}]`,
      2,
      code,
      { received: present }
    );
  }
}

function receiptCore(receipt) {
  const core = {};
  for (const field of CORE_FIELDS) core[field] = receipt[field];
  return core;
}

/** Derived, never asserted. A submitter cannot choose it, so it cannot be
 *  collided deliberately or used as a covert channel. */
export function deriveReceiptId(core) {
  return sha256(Buffer.from(`${RECEIPT_ID_DOMAIN}\n${canonicalize(core)}`, "utf8"));
}

function signaturePreimage(receiptId) {
  return Buffer.concat([
    Buffer.from(`${RECEIPT_SIGNATURE_DOMAIN}\n`, "utf8"),
    Buffer.from(receiptId, "hex")
  ]);
}

function validateCore(core) {
  exactObject(core, [...CORE_FIELDS].sort(), "RECEIPT_SHAPE_INVALID", "receipt core");

  if (core.schema_version !== RECEIPT_SCHEMA) {
    throw new SomaError("unsupported receipt schema version", 2, "RECEIPT_VERSION_UNSUPPORTED");
  }
  if (!DID.test(core.attester_did) || !DID.test(core.subject_did)) {
    throw new SomaError("receipt DIDs are invalid", 2, "RECEIPT_DID_INVALID");
  }

  // Checked before any signature work. A receipt about yourself is malformed,
  // not merely unauthorized: there is no key that could make it valid, so
  // rejecting it early costs nothing and states the reason precisely.
  if (core.attester_did === core.subject_did) {
    throw new SomaError(
      "a receipt cannot attest to its own attester; self-signed claims are evidence, not receipts",
      7,
      "RECEIPT_SELF_ATTESTED"
    );
  }

  if (!OUTCOMES.has(core.outcome)) {
    throw new SomaError("receipt outcome is not one of succeeded, failed, disputed", 2, "RECEIPT_OUTCOME_INVALID");
  }
  if (!BASES.has(core.basis)) {
    throw new SomaError(
      "receipt basis is not one of party, witnessed, verified",
      2,
      "RECEIPT_BASIS_INVALID"
    );
  }
  if (!FAULTS.has(core.fault)) {
    throw new SomaError(
      "receipt fault is not one of none, subject, delegate, upstream_tool, environment, unattributed",
      2,
      "RECEIPT_FAULT_INVALID"
    );
  }

  // Outcome and fault must agree about whether anything went wrong. Allowing
  // "succeeded" beside a blamed party, or "failed" beside no fault at all, would
  // make the pair unreadable — and an evaluator reading one field without the
  // other would draw the opposite conclusion from the one the attester meant.
  if (core.outcome === "succeeded" && core.fault !== "none") {
    throw new SomaError("a succeeded receipt cannot attribute fault", 2, "RECEIPT_FAULT_INCONSISTENT");
  }
  if (core.outcome !== "succeeded" && core.fault === "none") {
    throw new SomaError(
      "a failed or disputed receipt must attribute fault, using unattributed where the attester cannot say",
      2,
      "RECEIPT_FAULT_INCONSISTENT"
    );
  }
  if (typeof core.task_id !== "string" || core.task_id.length < 1 || core.task_id.length > 256) {
    throw new SomaError("receipt task_id is invalid", 2, "RECEIPT_FIELD_INVALID");
  }
  if (!NAME.test(core.capability) || !NAME.test(core.domain)) {
    throw new SomaError("receipt capability or domain is invalid", 2, "RECEIPT_FIELD_INVALID");
  }
  if (!HASH.test(core.claim_hash)) {
    throw new SomaError("receipt claim_hash is invalid", 2, "RECEIPT_FIELD_INVALID");
  }
  if (!ISO.test(core.issued_at) || !ISO.test(core.observed_at)) {
    throw new SomaError("receipt timestamps must be RFC 3339 UTC with second precision", 2, "RECEIPT_FIELD_INVALID");
  }
  if (Date.parse(core.observed_at) > Date.parse(core.issued_at)) {
    throw new SomaError("receipt cannot be observed after it was issued", 2, "RECEIPT_FIELD_INVALID");
  }
}

/**
 * Build and sign a receipt as the attester.
 *
 * The attester's private key signs a derived identifier, not the raw core, so
 * the signature and the identifier cannot be confused for one another.
 */
export function createReceipt(core, attesterPrivateKeyBase64) {
  validateCore(core);
  const receipt_id = deriveReceiptId(core);
  return {
    ...core,
    receipt_id,
    signature: {
      suite: "Ed25519-v1",
      value: signEd25519(attesterPrivateKeyBase64, signaturePreimage(receipt_id))
    }
  };
}

/**
 * Verify a receipt.
 *
 * The attester's key is derived from `attester_did` and is deliberately not a
 * parameter: see attesterKeyFromDid. A receipt therefore cannot be verified
 * against anyone but the party it names.
 *
 * Returns the parsed receipt. Throws on any failure — there is no partial
 * success, and no boolean that a caller can accidentally ignore.
 */
export function verifyReceipt(receipt) {
  exactObject(receipt, RECEIPT_FIELDS, "RECEIPT_SHAPE_INVALID", "receipt");

  const core = receiptCore(receipt);
  validateCore(core);

  // Recomputed from the parsed receipt, never trusted from input.
  const expectedId = deriveReceiptId(core);
  if (receipt.receipt_id !== expectedId) {
    throw new SomaError("receipt_id does not match its contents", 7, "RECEIPT_ID_MISMATCH");
  }

  const signature = receipt.signature;
  if (signature === null || typeof signature !== "object" || Array.isArray(signature)) {
    throw new SomaError("receipt signature must name its suite", 2, "RECEIPT_SIGNATURE_SHAPE_INVALID");
  }
  const signatureKeys = Object.keys(signature).sort();
  if (signatureKeys.length !== 2 || signatureKeys[0] !== "suite" || signatureKeys[1] !== "value") {
    throw new SomaError("receipt signature must carry exactly [suite, value]", 2, "RECEIPT_SIGNATURE_SHAPE_INVALID");
  }
  // An unrecognised suite is refused, never assumed compatible. Guessing would
  // mean verifying under an algorithm the signer did not choose.
  if (!SUITES.has(signature.suite)) {
    throw new SomaError(
      `receipt signature suite ${signature.suite} is not accepted by this verifier`,
      7,
      "RECEIPT_SUITE_UNSUPPORTED"
    );
  }
  if (!verifyEd25519(attesterKeyFromDid(core.attester_did), signaturePreimage(expectedId), signature.value)) {
    throw new SomaError("receipt signature does not verify against the attester key", 7, "RECEIPT_SIGNATURE_INVALID");
  }

  return receipt;
}

/**
 * Classify how related an attester and a subject are.
 *
 * Computed from lineage, never read from input. Each lineage is the ordered
 * list of ancestor DIDs from root to the identity itself.
 *
 * The `no_known_common_ancestor` label is deliberately not called
 * "independent". Root identities are free to create, so the absence of a known
 * common ancestor is not evidence of independence — only the absence of
 * evidence of relation. Calling it independence would launder an unknown into a
 * guarantee, which is the failure this whole design exists to prevent.
 */
export function classifyIndependence(attesterLineage, subjectLineage) {
  const attester = [...attesterLineage];
  const subject = [...subjectLineage];

  if (attester.length === 0 || subject.length === 0) {
    throw new SomaError("lineage must include at least the identity itself", 2, "RECEIPT_LINEAGE_INVALID");
  }

  const attesterDid = attester[attester.length - 1];
  const subjectDid = subject[subject.length - 1];
  if (attesterDid === subjectDid) return "self";

  const attesterSet = new Set(attester);
  for (const ancestor of subject) {
    if (attesterSet.has(ancestor)) return "shared_lineage";
  }
  return "no_known_common_ancestor";
}

/**
 * Summarise a set of verified receipts for one subject.
 *
 * Independence is computed here from the lineages supplied alongside each
 * receipt, never read from a caller-supplied label. A label that could be
 * passed in is a label that can be wrong, and the one thing it would be worth
 * lying about is whether an attester is related to the subject.
 *
 * Where lineage is unavailable the label is `unknown` — this implementation has
 * no lineage store, so that is the honest answer rather than an optimistic one.
 *
 * Returns counts by label and outcome, and nothing else. There is deliberately
 * no score, tier or rank: identities are free, so any global aggregate can be
 * inflated by manufacturing attesters. Combining these into a judgement is the
 * evaluator's policy, not the protocol's.
 *
 * `basis` is `insufficient` when nothing survives from an attester the evaluator
 * already trusts. That is not a zero score: it is the honest answer that the
 * system cannot tell them.
 */
export function summariseReceipts(entries, trustedAttesterDids = []) {
  const trusted = new Set(trustedAttesterDids);
  const summary = {
    schema_version: "soma.receipt-summary.provisional-v1",
    by_independence: { self: 0, shared_lineage: 0, no_known_common_ancestor: 0, unknown: 0 },
    by_outcome: { succeeded: 0, failed: 0, disputed: 0 },
    by_fault: { none: 0, subject: 0, delegate: 0, upstream_tool: 0, environment: 0, unattributed: 0 },
    by_basis: { party: 0, witnessed: 0, verified: 0 },
    from_trusted_attesters: 0,
    distinct_attesters: 0,
    basis: "insufficient",
    score: null,
    truth_claim: "receipts_record_attribution_by_a_named_party_not_truth"
  };

  const attesters = new Set();
  for (const entry of entries) {
    const receipt = entry.receipt;
    if (!receipt || typeof receipt.attester_did !== "string") {
      throw new SomaError("each entry must carry a receipt", 2, "RECEIPT_SUMMARY_ENTRY_INVALID");
    }
    if (!(receipt.outcome in summary.by_outcome)) {
      throw new SomaError("receipt outcome is not one of succeeded, failed, disputed", 2, "RECEIPT_OUTCOME_INVALID");
    }

    const label = entry.attester_lineage && entry.subject_lineage
      ? classifyIndependence(entry.attester_lineage, entry.subject_lineage)
      : "unknown";

    summary.by_independence[label] += 1;
    summary.by_outcome[receipt.outcome] += 1;
    if (receipt.fault in summary.by_fault) summary.by_fault[receipt.fault] += 1;
    if (receipt.basis in summary.by_basis) summary.by_basis[receipt.basis] += 1;
    attesters.add(receipt.attester_did);
    if (trusted.has(receipt.attester_did)) summary.from_trusted_attesters += 1;
  }

  summary.distinct_attesters = attesters.size;
  if (summary.from_trusted_attesters > 0) summary.basis = "evaluator_trusted_attesters";
  return summary;
}
