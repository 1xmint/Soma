import { canonicalize } from "./canonicalize.mjs";
import { sha256, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";

/**
 * Equivocation detection for evidence heads.
 *
 * A hash-chained, self-signed ledger gives tamper-evidence *within* one view.
 * It gives nothing across views: an owner can maintain two divergent histories
 * and present a different one to each counterparty. Alice sees head A at
 * sequence 7, Bob sees head B at sequence 7, both signatures are valid, and
 * neither can tell.
 *
 * No global clock is needed to fix this, and none should be introduced — an
 * external ordering service is exactly the infrastructure dependence this
 * system exists to avoid. Two heads signed by the same key, at the same
 * sequence, with different contents are already a complete proof of
 * equivocation. The subject signed both. Nobody has to be trusted to say so.
 *
 * That makes this a detection problem rather than a prevention problem, and
 * detection distributes: anyone who has seen two conflicting heads can produce
 * a proof that anyone else can check offline.
 */

const HEAD_ID_DOMAIN = "soma:evidence-head:provisional-v1";
const HEAD_SIGNATURE_DOMAIN = "soma:evidence-head:signature:provisional-v1";
const PROOF_SCHEMA = "soma.equivocation-proof.provisional-v1";
const HASH = /^[a-f0-9]{64}$/;

function headCore(head) {
  const { head_hash: ignoredHash, signature: ignoredSignature, ...core } = head;
  return core;
}

/** Recompute a head's identifier from its own contents. */
function deriveHeadHash(head) {
  return sha256(Buffer.from(`${HEAD_ID_DOMAIN}\n${canonicalize(headCore(head))}`, "utf8"));
}

function signaturePreimage(headHash) {
  return Buffer.concat([
    Buffer.from(`${HEAD_SIGNATURE_DOMAIN}\n`, "utf8"),
    Buffer.from(headHash, "hex")
  ]);
}

/**
 * Check that a head is internally consistent and signed by the key it names.
 *
 * Deliberately narrower than the ledger's own head verification: it takes no
 * identity document and no key history, because an equivocation proof must be
 * checkable by a stranger who holds neither. The signing key is taken from the
 * head's own `signer_key_id`, which is exactly what makes the proof
 * self-authenticating — the subject named the key, and the subject signed.
 */
export function verifyHeadStandalone(head) {
  if (head === null || typeof head !== "object" || Array.isArray(head)) {
    throw new SomaError("evidence head must be an object", 2, "EQUIVOCATION_HEAD_INVALID");
  }
  if (typeof head.signer_key_id !== "string" || !head.signer_key_id.includes("#")) {
    throw new SomaError("evidence head signer_key_id is invalid", 2, "EQUIVOCATION_HEAD_INVALID");
  }
  if (!HASH.test(head.head_hash ?? "")) {
    throw new SomaError("evidence head hash is invalid", 2, "EQUIVOCATION_HEAD_INVALID");
  }
  if (!head.signature || typeof head.signature.value !== "string") {
    throw new SomaError("evidence head signature is missing", 2, "EQUIVOCATION_HEAD_INVALID");
  }
  if (head.signature.key_id !== head.signer_key_id) {
    throw new SomaError("evidence head signer key mismatch", 7, "EQUIVOCATION_HEAD_INVALID");
  }

  const derived = deriveHeadHash(head);
  if (derived !== head.head_hash) {
    throw new SomaError("evidence head hash does not match its contents", 7, "EQUIVOCATION_HEAD_INVALID");
  }

  // did:key:zABC#zABC — the fingerprint after the fragment is the key itself,
  // so verification needs no registry and no identity document.
  const fingerprint = head.signer_key_id.slice(head.signer_key_id.indexOf("#") + 1);
  if (!verifyEd25519(fingerprint, signaturePreimage(derived), head.signature.value)) {
    throw new SomaError("evidence head signature does not verify", 7, "EQUIVOCATION_HEAD_INVALID");
  }
  return derived;
}

/**
 * Produce a proof if two heads equivocate, or null if they do not.
 *
 * Equivocation is: the same signer, at the same sequence, having signed two
 * different heads. Everything else is legitimate — a repeated head is a repeat,
 * different sequences are ordinary progress, and different signers are
 * different agents.
 */
export function detectEquivocation(headA, headB) {
  const hashA = verifyHeadStandalone(headA);
  const hashB = verifyHeadStandalone(headB);

  if (headA.signer_key_id !== headB.signer_key_id) return null;
  if (headA.sequence !== headB.sequence) return null;
  if (hashA === hashB) return null;

  // Order the pair deterministically so the same conflict always yields the
  // same proof, whoever assembles it and in whichever order they saw them.
  const [first, second] = hashA < hashB ? [headA, headB] : [headB, headA];

  return {
    schema_version: PROOF_SCHEMA,
    signer_key_id: first.signer_key_id,
    sequence: first.sequence,
    heads: [first, second],
    claim: "one key signed two different heads at one sequence",
    truth_claim: "the subject signed both; no third party is trusted by this proof"
  };
}

/**
 * Re-check a proof from scratch. Takes nothing on faith from whoever built it.
 *
 * Throws rather than returning false: a proof that does not hold is not a
 * weaker proof, it is an accusation that must not be repeated.
 */
export function verifyEquivocationProof(proof) {
  if (proof === null || typeof proof !== "object" || proof.schema_version !== PROOF_SCHEMA) {
    throw new SomaError("equivocation proof shape is invalid", 2, "EQUIVOCATION_PROOF_INVALID");
  }
  if (!Array.isArray(proof.heads) || proof.heads.length !== 2) {
    throw new SomaError("an equivocation proof carries exactly two heads", 2, "EQUIVOCATION_PROOF_INVALID");
  }

  const [a, b] = proof.heads;
  const found = detectEquivocation(a, b);
  if (found === null) {
    throw new SomaError("the cited heads do not equivocate", 7, "EQUIVOCATION_PROOF_UNPROVEN");
  }
  if (found.signer_key_id !== proof.signer_key_id || found.sequence !== proof.sequence) {
    throw new SomaError("the proof misstates what its heads show", 7, "EQUIVOCATION_PROOF_INVALID");
  }
  return {
    signer_key_id: found.signer_key_id,
    sequence: found.sequence,
    head_hashes: found.heads.map((head) => head.head_hash),
    truth_claim: "the named key signed both heads; this says nothing about which history is real"
  };
}
