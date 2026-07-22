import { canonicalize } from "../src/canonicalize.mjs";
import { sha256, signEd25519 } from "../src/crypto.mjs";

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  let output = "";
  while (value > 0n) {
    output = alphabet[Number(value % 58n)] + output;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    output = `1${output}`;
  }
  return output || "1";
}

const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const publicKey = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]).toString("base64");
const fingerprint = `z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), publicKey]))}`;
const did = `did:key:${fingerprint}`;
const keyId = `${did}#${fingerprint}`;
const issuedAt = "2026-07-16T12:00:01.000Z";
const eventCore = {
  schema_version: "soma.local-evidence-event.provisional-v1",
  context_id: `soma:local-context:v1:${sha256(Buffer.from(`soma:local-evidence-context:v1\n${did}`, "utf8"))}`,
  kind: "execution",
  subject_did: did,
  issuer_did: did,
  task_id: "vector-task-001",
  capability: "code.review",
  domain: "software.security",
  claim_hash: sha256(Buffer.from("fixed non-secret vector claim", "utf8")),
  artifact_hashes: [],
  receipt_ids: [],
  occurred_at: "2026-07-16T12:00:00.000Z",
  issued_at: issuedAt,
  supersedes: null,
  assurance: "self_signed_attribution_only"
};
const evidenceId = sha256(Buffer.from(`soma:local-evidence:provisional-v1\n${canonicalize(eventCore)}`, "utf8"));
const evidenceEvent = {
  ...eventCore,
  evidence_id: evidenceId,
  signature: {
    suite: "Ed25519-v1",
    key_id: keyId,
    value: signEd25519(pkcs8, Buffer.concat([Buffer.from("soma:local-evidence:provisional-v1:signature\n"), Buffer.from(evidenceId, "hex")]))
  }
};
const entryCore = {
  schema_version: "soma.local-evidence-entry.provisional-v1",
  sequence: 0,
  previous_entry_hash: "0".repeat(64),
  evidence_event: evidenceEvent,
  recorded_at: issuedAt,
  signer_key_id: keyId
};
const entryHash = sha256(Buffer.from(`soma:local-evidence-entry:v1\n${canonicalize(entryCore)}`, "utf8"));
const entry = {
  ...entryCore,
  entry_hash: entryHash,
  signature: {
    suite: "Ed25519-v1",
    key_id: keyId,
    value: signEd25519(pkcs8, Buffer.concat([Buffer.from("soma:local-evidence-entry:signature:v1\n"), Buffer.from(entryHash, "hex")]))
  }
};
console.log(JSON.stringify({
  vector_version: "soma.local-evidence-entry.provisional-v1",
  status: "provisional_not_ratified",
  public_key_multibase: fingerprint,
  key_id: keyId,
  canonical_event: canonicalize(evidenceEvent),
  evidence_id: evidenceId,
  evidence_signature_base64: evidenceEvent.signature.value,
  canonical_entry: canonicalize(entry),
  entry_hash: entryHash,
  entry_signature_base64: entry.signature.value
}, null, 2));
