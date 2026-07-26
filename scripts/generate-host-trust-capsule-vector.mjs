import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const HISTORY_DOMAIN = "somavera:soma-host-trust-history-chain:v1\n";
const CURRENT_SET_DOMAIN = "somavera:soma-host-trust-current-set:v1\n";
const OBJECT_SET_DOMAIN = "somavera:soma-host-trust-object-set:v1\n";
const CAPSULE_DOMAIN = "somavera:soma-host-trust-capsule:v1\n";
const SIGNATURE_DOMAIN = "somavera:soma-host-trust-capsule-signature:v1\n";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let value = BigInt("0x" + Buffer.from(bytes).toString("hex")), result = "";
  while (value > 0n) { result = BASE58[Number(value % 58n)] + result; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = "1" + result; }
  return result || "1";
}
const objectCore = ({ canonical_json_base64, ...core }) => core;
const capsuleCore = ({ $schema, capsule_id, signature, ...core }) => core;

const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const seed = Buffer.from("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f", "hex");
const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
const publicRaw = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" })).subarray(-32);
const controllerDid = "did:key:example-soma-capsule-controller";
const controllerKeyId = controllerDid + "#controller-1";
const publicKeyMultibase = "z" + base58(Buffer.concat([Buffer.from([0xed, 0x01]), publicRaw]));

const hostDid = "did:key:example-vera-host";
const hostToken = "1".repeat(64);
const pinId = "a".repeat(64);
const descriptorId = "b".repeat(64);
const transitionId = "c".repeat(64);
const confirmationId = "d".repeat(64);
const payloads = [
  {
    path: `hosts/${hostToken}.json`,
    kind: "current_pin",
    value: { schema_version: "soma.host-pin.provisional-v2", pin_id: pinId, descriptor: { descriptor_id: descriptorId, descriptor_sequence: 8, host_did: hostDid }, predecessor_pin_id: "e".repeat(64), confirmation_id: confirmationId }
  },
  {
    path: `hosts/history/${hostToken}/${confirmationId}.json`,
    kind: "history_transition",
    value: { schema_version: "soma.host-succession-transition.provisional-v1", transition_id: transitionId, confirmation_id: confirmationId, successor_pin_id: pinId, host_did: hostDid }
  }
];
const objects = payloads.map((entry) => {
  const bytes = Buffer.from(canonicalize(entry.value) + "\n");
  return { path: entry.path, kind: entry.kind, byte_length: bytes.length, sha256: sha256(bytes), canonical_json_base64: bytes.toString("base64") };
}).sort((a, b) => a.path.localeCompare(b.path));
const hosts = [{
  host_did: hostDid,
  current_pin_id: pinId,
  current_descriptor_id: descriptorId,
  current_descriptor_sequence: 8,
  transition_ids: [transitionId],
  history_chain_root: sha256(HISTORY_DOMAIN + canonicalize([transitionId]))
}];
const capsule = {
  $schema: "../schemas/soma-host-trust-capsule.schema.json",
  schema_version: "somavera.soma-host-trust-capsule.v1",
  profile_status: "freeze_blocking_draft",
  capsule_id: "0".repeat(64),
  created_at: "2027-01-01T13:00:00Z",
  controller: { did: controllerDid, signing_key_id: controllerKeyId, public_key_multibase: publicKeyMultibase, public_key_sha256: sha256(publicRaw) },
  source: { origin_capsule_hash: "8cb60c8ce3199aa35c101657834eece86e8823e9d6aa8eb47a9e23db89582431", reference_release_manifest_hash: "f".repeat(64), reference_release_version: "0.1.0" },
  host_count: hosts.length,
  transition_count: 1,
  current_set_root: sha256(CURRENT_SET_DOMAIN + canonicalize(hosts)),
  object_set_root: sha256(OBJECT_SET_DOMAIN + canonicalize(objects.map(objectCore))),
  hosts,
  objects,
  claims: { complete_host_trust_state: true, contains_managed_secrets: false, external_anchor_created: false, rollback_detection_without_separately_preserved_capsule: false, authorizes_restore: false, authorizes_connection: false, authorizes_consent: false, authorizes_disclosure: false, authorizes_send: false, authorizes_emergency_recovery: false },
  authority: "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority",
  signature: {}
};
capsule.capsule_id = sha256(CAPSULE_DOMAIN + canonicalize(capsuleCore(capsule)));
capsule.signature = { suite: "Ed25519-v1", key_id: controllerKeyId, value: sign(null, Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(capsule.capsule_id, "hex")]), privateKey).toString("base64") };

const vector = {
  vector_version: "somavera.soma-host-trust-capsule.v1",
  expected_controller_did: controllerDid,
  expected_controller_signing_key_id: controllerKeyId,
  controller_public_key_base64: publicRaw.toString("base64"),
  domains: { history_chain: HISTORY_DOMAIN.slice(0, -1), current_set: CURRENT_SET_DOMAIN.slice(0, -1), object_set: OBJECT_SET_DOMAIN.slice(0, -1), capsule_id: CAPSULE_DOMAIN.slice(0, -1), capsule_signature: SIGNATURE_DOMAIN.slice(0, -1) },
  expected: { current_set_root: capsule.current_set_root, object_set_root: capsule.object_set_root, capsule_core_jcs: canonicalize(capsuleCore(capsule)), capsule_id: capsule.capsule_id, signature_message_hex: Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(capsule.capsule_id, "hex")]).toString("hex"), result: "accept_portable_copy_not_external_anchor" },
  capsule
};
const invalid = {
  vector_version: "somavera.soma-host-trust-capsule-invalid.v1",
  base_vector: "host-trust-capsule-v1.json",
  cases: [
    { name: "object_bytes_mutated", mutation: "object_bytes_mutated", expected_error: "CAPSULE_OBJECT_HASH_INVALID" },
    { name: "object_size_mutated", mutation: "object_size_mutated", expected_error: "CAPSULE_OBJECT_SIZE_INVALID" },
    { name: "object_order_reversed", mutation: "object_order_reversed", expected_error: "CAPSULE_OBJECT_ORDER_INVALID" },
    { name: "object_path_duplicated", mutation: "object_path_duplicated", expected_error: "CAPSULE_OBJECT_PATH_INVALID" },
    { name: "host_order_duplicated", mutation: "host_order_duplicated", expected_error: "CAPSULE_HOST_ORDER_INVALID" },
    { name: "history_root_mutated", mutation: "history_root_mutated", expected_error: "CAPSULE_HISTORY_ROOT_INVALID" },
    { name: "current_set_root_mutated", mutation: "current_set_root_mutated", expected_error: "CAPSULE_CURRENT_SET_ROOT_INVALID" },
    { name: "object_set_root_mutated", mutation: "object_set_root_mutated", expected_error: "CAPSULE_OBJECT_SET_ROOT_INVALID" },
    { name: "host_count_mutated", mutation: "host_count_mutated", expected_error: "CAPSULE_COUNT_INVALID" },
    { name: "transition_count_mutated", mutation: "transition_count_mutated", expected_error: "CAPSULE_COUNT_INVALID" },
    { name: "controller_did_substituted", mutation: "controller_did_substituted", expected_error: "CAPSULE_CONTROLLER_INVALID" },
    { name: "controller_key_hash_mutated", mutation: "controller_key_hash_mutated", expected_error: "CAPSULE_CONTROLLER_KEY_INVALID" },
    { name: "external_anchor_claim_escalated", mutation: "external_anchor_claim_escalated", expected_error: "CAPSULE_CLAIMS_INVALID" },
    { name: "restore_claim_escalated", mutation: "restore_claim_escalated", expected_error: "CAPSULE_CLAIMS_INVALID" },
    { name: "capsule_id_mutated", mutation: "capsule_id_mutated", expected_error: "CAPSULE_ID_INVALID" },
    { name: "signature_corrupted", mutation: "signature_corrupted", expected_error: "CAPSULE_SIGNATURE_INVALID" }
  ]
};

await writeFile(path.join(root, "examples", "soma-host-trust-capsule.example.json"), JSON.stringify(capsule, null, 2) + "\n");
await writeFile(path.join(root, "conformance", "host-trust-capsule-v1.json"), JSON.stringify(vector, null, 2) + "\n");
await writeFile(path.join(root, "conformance", "host-trust-capsule-invalid-v1.json"), JSON.stringify(invalid, null, 2) + "\n");
console.log("Generated portable Soma host-trust capsule example and vectors.");
