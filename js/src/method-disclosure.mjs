import { canonicalize } from "./canonicalize.mjs";
import { sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { attesterKeyFromDid } from "./receipt.mjs";

/**
 * What "verified" actually promised, and how to make it collectable.
 *
 * RECEIPT-SPEC says only `verified` is falsifiable: it asserts something
 * reality can contradict, and anyone can redo the check. That sentence is the
 * hinge of the whole design, because it is what lets verification SUBSTITUTE
 * for trust -- where a claim can be independently re-run, no standing is
 * required at all, and in a network of millions almost nobody has a trust path
 * to almost anybody. Shrinking the set of interactions that need trust is worth
 * more than making trust reach further.
 *
 * Except a stranger could not redo any check, because the receipt never said
 * which one was run. `verified` was an unfalsifiable claim about
 * falsifiability, and it cost exactly as much to write as `party`. The gap was
 * recorded as deliberately deferred; it is on the critical path, because it
 * gates the newcomer's on-ramp and it sets what fraction of the corpus can be
 * collateral at all.
 *
 * WHY A COMPANION RECORD RATHER THAN A FIELD
 *
 * `receipt_core` is a closed field set and `receipt_id` is derived from its
 * canonical bytes, so adding a field changes the identifier of every receipt
 * and makes existing ones unverifiable -- the one irreversible mistake
 * available here. A separate record signed by the same attester and bound to
 * `receipt_id` costs nothing to existing evidence and can be published later
 * than the receipt, which matters because a method is often only worth naming
 * once someone asks.
 *
 * That does mean an attester could re-run the check, see it fail, and simply
 * never disclose. Good: an undisclosed method is not a loophole, it is the
 * absence of the thing being claimed. An evaluator that cannot re-run a check
 * has been handed an opinion, and should weigh it as one -- which is what
 * `requireDisclosedMethod` does in the reference policy. Disclosure is
 * therefore voluntary and valuable rather than mandatory and gameable, and the
 * pressure lands where it should: on making work checkable.
 *
 * WHAT A DISCLOSURE IS NOT
 *
 * It is not proof the method was run, and not proof the method is any good. It
 * commits the attester to a specific, named, re-runnable procedure and to the
 * result they say it produced. Its whole value is that it can be shown wrong.
 */

export const DISCLOSURE_ID_DOMAIN = "somavera:soma-method-disclosure:v1";
export const DISCLOSURE_SIGNATURE_DOMAIN = "somavera:soma-method-disclosure-signature:v1";
export const DISCLOSURE_SCHEMA = "soma.method-disclosure.provisional-v1";

const CORE_FIELDS = ["attester_did", "inputs_hash", "method", "receipt_id", "result_hash", "schema_version"];
const FULL_FIELDS = [...CORE_FIELDS, "disclosure_id", "signature"].sort();
const SUITES = new Set(["Ed25519-v1"]);
const HASH = /^[a-f0-9]{64}$/;

/**
 * Method names are constrained to a flat, lowercase vocabulary.
 *
 * Deliberately not an enumeration. A frozen vocabulary would have to be right
 * about every future kind of checking, and a bad vocabulary baked into the
 * record is worse than none -- which is the reason this was deferred in the
 * first place. A shape rather than a list lets methods accumulate as
 * conventions, and lets an evaluator refuse ones it does not recognise, which
 * is the same posture the signature suites take.
 */
const METHOD = /^[a-z][a-z0-9-]{0,63}$/;

function exactObject(value, fields, code, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SomaError(`${label} must be an object`, 2, code);
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== fields.length || keys.some((k, i) => k !== fields[i])) {
    throw new SomaError(`${label} must carry exactly [${fields.join(", ")}]`, 2, code);
  }
}

function validateCore(core) {
  exactObject(core, CORE_FIELDS, "METHOD_DISCLOSURE_SHAPE_INVALID", "method disclosure");
  if (core.schema_version !== DISCLOSURE_SCHEMA) {
    throw new SomaError("method disclosure schema_version is not recognised", 2, "METHOD_DISCLOSURE_SHAPE_INVALID");
  }
  if (typeof core.method !== "string" || !METHOD.test(core.method)) {
    throw new SomaError("method must be a lowercase dash-separated name", 2, "METHOD_DISCLOSURE_SHAPE_INVALID");
  }
  for (const field of ["receipt_id", "inputs_hash", "result_hash"]) {
    if (!HASH.test(core[field] ?? "")) {
      throw new SomaError(`${field} must be 64 lowercase hex characters`, 2, "METHOD_DISCLOSURE_SHAPE_INVALID");
    }
  }
  if (typeof core.attester_did !== "string" || !core.attester_did.startsWith("did:key:")) {
    throw new SomaError("attester_did must be a did:key identifier", 2, "METHOD_DISCLOSURE_SHAPE_INVALID");
  }
}

const disclosureCore = (d) => {
  const { disclosure_id: _id, signature: _sig, ...core } = d;
  return core;
};

export function deriveDisclosureId(core) {
  return sha256(Buffer.from(`${DISCLOSURE_ID_DOMAIN}\n${canonicalize(core)}`, "utf8"));
}

const signaturePreimage = (id) =>
  Buffer.concat([Buffer.from(`${DISCLOSURE_SIGNATURE_DOMAIN}\n`, "utf8"), Buffer.from(id, "hex")]);

export function createMethodDisclosure(core, attesterPrivateKeyBase64) {
  validateCore(core);
  const disclosure_id = deriveDisclosureId(core);
  return {
    ...core,
    disclosure_id,
    signature: {
      suite: "Ed25519-v1",
      value: signEd25519(attesterPrivateKeyBase64, signaturePreimage(disclosure_id))
    }
  };
}

/**
 * Verify a disclosure. The attester's key comes from `attester_did` and is
 * never a parameter, for the same reason it never is on a receipt: a caller
 * supplying the key means attribution depends on the caller getting it right.
 */
export function verifyMethodDisclosure(disclosure) {
  exactObject(disclosure, FULL_FIELDS, "METHOD_DISCLOSURE_SHAPE_INVALID", "method disclosure");
  const core = disclosureCore(disclosure);
  validateCore(core);

  const expectedId = deriveDisclosureId(core);
  if (expectedId !== disclosure.disclosure_id) {
    throw new SomaError("method disclosure id does not match its contents", 7, "METHOD_DISCLOSURE_INVALID");
  }
  const { signature } = disclosure;
  const keys = Object.keys(signature ?? {}).sort();
  if (keys.length !== 2 || keys[0] !== "suite" || keys[1] !== "value") {
    throw new SomaError("method disclosure signature must carry exactly [suite, value]", 2, "METHOD_DISCLOSURE_SHAPE_INVALID");
  }
  if (!SUITES.has(signature.suite)) {
    throw new SomaError(
      `method disclosure suite ${signature.suite} is not accepted by this verifier`,
      7,
      "METHOD_DISCLOSURE_SUITE_UNSUPPORTED"
    );
  }
  if (!verifyEd25519(attesterKeyFromDid(core.attester_did), signaturePreimage(expectedId), signature.value)) {
    throw new SomaError("method disclosure signature does not verify", 7, "METHOD_DISCLOSURE_SIGNATURE_INVALID");
  }
  return disclosure;
}

/**
 * Index verified disclosures by the receipt they describe.
 *
 * A disclosure only speaks for a receipt whose attester signed it. Without that
 * check anyone could publish a flattering method for someone else's receipt, or
 * a damning one, and the record would say whatever its loudest reader wanted.
 */
export function disclosureIndex(disclosures, receiptsById = new Map()) {
  const index = new Map();
  for (const disclosure of disclosures) {
    const verified = verifyMethodDisclosure(disclosure);
    const receipt = receiptsById.get(verified.receipt_id);
    if (receipt && receipt.attester_did !== verified.attester_did) {
      throw new SomaError(
        "a method disclosure was signed by someone other than the receipt's attester",
        7,
        "METHOD_DISCLOSURE_ATTESTER_MISMATCH"
      );
    }
    index.set(verified.receipt_id, verified);
  }
  return index;
}

/**
 * Does a re-run contradict what the attester committed to?
 *
 * Honest about its own strength, because this is weaker than an equivocation
 * proof and the difference matters: an equivocation proof is self-authenticating
 * and settles offline forever, whereas this is REPRODUCIBLE -- it requires
 * somebody to actually re-run the named method on the named inputs. Two
 * different standards of evidence, and conflating them would overstate what the
 * system can settle without anyone doing any work.
 */
export function methodContradicted(disclosure, observedResultHash) {
  const verified = verifyMethodDisclosure(disclosure);
  if (!HASH.test(observedResultHash ?? "")) {
    throw new SomaError("observed result hash must be 64 lowercase hex characters", 2, "METHOD_DISCLOSURE_INVALID");
  }
  if (observedResultHash === verified.result_hash) return null;
  return {
    schema_version: "soma.method-contradicted.provisional-v1",
    attester_did: verified.attester_did,
    receipt_id: verified.receipt_id,
    method: verified.method,
    inputs_hash: verified.inputs_hash,
    committed_result_hash: verified.result_hash,
    observed_result_hash: observedResultHash,
    truth_claim:
      "reproducible rather than self-authenticating: this holds only for whoever re-runs the named method on the named inputs"
  };
}
