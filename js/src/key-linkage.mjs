import { canonicalize } from "./canonicalize.mjs";
import { sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";

/**
 * Two keys, each vouching that the other is its own.
 *
 * One identity holds several keys with different jobs -- a controller key that
 * signs evidence heads, an agent key that does work and is named by receipts.
 * They are different keys, so they are different DIDs, and nothing offline
 * connected them. That gap made the vouching composite inert: a receipt naming
 * an agent DID could never be bound to an equivocation proof naming a
 * controller key, so a mechanism that reads as a bond fired against nothing.
 *
 * The public identity document does carry both, and it is UNSIGNED. Binding
 * through it would let anyone forge a document pairing an honest party's agent
 * DID with an equivocator's controller key, turning the bond into a weapon for
 * destroying honest attesters. An unsigned document must never be load-bearing
 * in a proof, and the fix is not to sign that document -- it is to make the
 * claim mutual.
 *
 * WHY MUTUALITY IS THE WHOLE MECHANISM
 *
 * A one-way statement is a land grab. If a controller key alone could declare
 * "agent A is mine", anyone could point at a stranger's agent and inherit its
 * standing, or attach their own misbehaviour to it. So both keys sign the same
 * bytes:
 *
 *     controller says "this pair is mine"   AND   agent says "this pair is mine"
 *
 * Forging the pairing requires BOTH private keys -- and an adversary holding
 * both private keys is not forging anything, because at that point the two keys
 * genuinely are controlled by one party, which is exactly what the record
 * claims. **The forgery and the truth are the same event.** That is what makes
 * this self-authenticating with no issuer, no registry and no document anyone
 * has to be trusted about.
 *
 * WHAT IT DOES NOT SAY
 *
 * Not that the two keys belong to a person, an organisation, or anything in the
 * world. Not that they always did, and not that they still do -- there is no
 * clock here, so this establishes no interval. It says: whoever held these two
 * private keys at the moment of signing asserted they were the same party. An
 * evaluator that wants more than that needs evidence this record does not
 * contain.
 *
 * Revocation is deliberately absent, for the same reason receipts have none:
 * withdrawing a statement needs a distribution mechanism, and inventing one
 * here would smuggle in the network layer this design does not have. A party
 * that wishes to disown a key rotates it, which the controller-rotation
 * machinery already handles and already makes visible.
 */

export const LINKAGE_ID_DOMAIN = "somavera:soma-key-linkage:v1";
export const LINKAGE_SIGNATURE_DOMAIN = "somavera:soma-key-linkage-signature:v1";
export const LINKAGE_SCHEMA = "soma.key-linkage.provisional-v1";

const SUITES = new Set(["Ed25519-v1"]);
const HASH = /^[a-f0-9]{64}$/;

/** `did:key:zABC#zABC` — the fragment after the hash is the key itself. */
function fingerprintOf(keyId) {
  const at = keyId.indexOf("#");
  if (at === -1) throw new SomaError("key id must carry a key fragment", 2, "KEY_LINKAGE_INVALID");
  return keyId.slice(at + 1);
}

export function didOfKeyId(keyId) {
  const at = keyId.indexOf("#");
  return at === -1 ? keyId : keyId.slice(0, at);
}

function validateKeyId(keyId, label) {
  if (typeof keyId !== "string" || !keyId.startsWith("did:key:") || !keyId.includes("#")) {
    throw new SomaError(`${label} must be a did:key identifier with a key fragment`, 2, "KEY_LINKAGE_INVALID");
  }
}

/**
 * The bytes both parties sign.
 *
 * Key ids are sorted, so the same pair always produces the same record whoever
 * assembles it and in whichever order. Without that, one pairing would have two
 * identifiers and an evaluator counting distinct linkages could be made to see
 * two relationships where there is one.
 */
export function linkageCore(keyIdA, keyIdB) {
  validateKeyId(keyIdA, "key id");
  validateKeyId(keyIdB, "key id");
  if (keyIdA === keyIdB) {
    throw new SomaError("a key cannot be linked to itself", 2, "KEY_LINKAGE_SELF");
  }
  return {
    schema_version: LINKAGE_SCHEMA,
    key_ids: [keyIdA, keyIdB].sort()
  };
}

export function deriveLinkageId(core) {
  return sha256(Buffer.from(`${LINKAGE_ID_DOMAIN}\n${canonicalize(core)}`, "utf8"));
}

const signaturePreimage = (id) =>
  Buffer.concat([Buffer.from(`${LINKAGE_SIGNATURE_DOMAIN}\n`, "utf8"), Buffer.from(id, "hex")]);

/**
 * Build a linkage. Requires both private keys, which is the point.
 */
export function createKeyLinkage({ keyIdA, privateKeyA, keyIdB, privateKeyB }) {
  const core = linkageCore(keyIdA, keyIdB);
  const linkage_id = deriveLinkageId(core);
  const preimage = signaturePreimage(linkage_id);

  const byKeyId = new Map([
    [keyIdA, privateKeyA],
    [keyIdB, privateKeyB]
  ]);

  return {
    ...core,
    linkage_id,
    // Ordered to match key_ids, so the record reads in one direction only.
    signatures: core.key_ids.map((keyId) => ({
      key_id: keyId,
      suite: "Ed25519-v1",
      value: signEd25519(byKeyId.get(keyId), preimage)
    }))
  };
}

/**
 * Re-check a linkage from scratch. Both signatures, or it is not a linkage.
 *
 * Throws rather than returning false. A half-signed pairing is not a weaker
 * claim -- it is one key asserting ownership of another party's key, which is
 * the attack this record exists to make impossible.
 */
export function verifyKeyLinkage(linkage) {
  if (linkage === null || typeof linkage !== "object" || linkage.schema_version !== LINKAGE_SCHEMA) {
    throw new SomaError("key linkage shape is invalid", 2, "KEY_LINKAGE_INVALID");
  }
  if (!Array.isArray(linkage.key_ids) || linkage.key_ids.length !== 2) {
    throw new SomaError("a key linkage carries exactly two key ids", 2, "KEY_LINKAGE_INVALID");
  }

  const core = linkageCore(linkage.key_ids[0], linkage.key_ids[1]);
  if (core.key_ids[0] !== linkage.key_ids[0] || core.key_ids[1] !== linkage.key_ids[1]) {
    throw new SomaError("key linkage key ids are not in canonical order", 2, "KEY_LINKAGE_INVALID");
  }

  const expectedId = deriveLinkageId(core);
  if (!HASH.test(linkage.linkage_id ?? "") || expectedId !== linkage.linkage_id) {
    throw new SomaError("key linkage id does not match its contents", 7, "KEY_LINKAGE_INVALID");
  }

  if (!Array.isArray(linkage.signatures) || linkage.signatures.length !== 2) {
    throw new SomaError("a key linkage requires a signature from each key", 7, "KEY_LINKAGE_UNSIGNED");
  }

  const preimage = signaturePreimage(expectedId);
  const signed = new Set();
  for (const signature of linkage.signatures) {
    const keys = Object.keys(signature ?? {}).sort();
    if (keys.length !== 3 || keys[0] !== "key_id" || keys[1] !== "suite" || keys[2] !== "value") {
      throw new SomaError("key linkage signature must carry exactly [key_id, suite, value]", 2, "KEY_LINKAGE_INVALID");
    }
    if (!core.key_ids.includes(signature.key_id)) {
      throw new SomaError("key linkage signed by a key it does not name", 7, "KEY_LINKAGE_INVALID");
    }
    if (!SUITES.has(signature.suite)) {
      throw new SomaError(
        `key linkage suite ${signature.suite} is not accepted by this verifier`,
        7,
        "KEY_LINKAGE_SUITE_UNSUPPORTED"
      );
    }
    if (!verifyEd25519(fingerprintOf(signature.key_id), preimage, signature.value)) {
      throw new SomaError("key linkage signature does not verify", 7, "KEY_LINKAGE_SIGNATURE_INVALID");
    }
    signed.add(signature.key_id);
  }

  // Both, not merely two. Two signatures from one key would otherwise pass a
  // naive count while proving nothing about the other party at all.
  if (signed.size !== 2) {
    throw new SomaError("a key linkage requires a signature from each of its two keys", 7, "KEY_LINKAGE_UNSIGNED");
  }

  return {
    linkage_id: expectedId,
    key_ids: core.key_ids,
    dids: core.key_ids.map(didOfKeyId),
    truth_claim:
      "whoever held both private keys asserted these keys are one party; this establishes no interval and nothing about the world"
  };
}

/**
 * Do these verified linkages put two DIDs under one party?
 *
 * Transitive on purpose: an identity with a controller, an agent and an
 * observer key links them pairwise, and a chain of mutual assertions is as
 * strong as its weakest link -- which is still "both private keys", because
 * every hop required both.
 */
export function sameParty(didA, didB, linkages) {
  if (didA === didB) return true;

  const adjacency = new Map();
  for (const linkage of linkages) {
    const [x, y] = verifyKeyLinkage(linkage).dids;
    if (!adjacency.has(x)) adjacency.set(x, new Set());
    if (!adjacency.has(y)) adjacency.set(y, new Set());
    adjacency.get(x).add(y);
    adjacency.get(y).add(x);
  }

  const seen = new Set([didA]);
  const stack = [didA];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === didB) return true;
    for (const next of adjacency.get(current) ?? []) {
      if (!seen.has(next)) { seen.add(next); stack.push(next); }
    }
  }
  return false;
}
