import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const HISTORY_DOMAIN = "somavera:soma-host-trust-history-chain:v1\n";
const CURRENT_SET_DOMAIN = "somavera:soma-host-trust-current-set:v1\n";
const OBJECT_SET_DOMAIN = "somavera:soma-host-trust-object-set:v1\n";
const CAPSULE_DOMAIN = "somavera:soma-host-trust-capsule:v1\n";
const SIGNATURE_DOMAIN = "somavera:soma-host-trust-capsule-signature:v1\n";
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const objectCore = ({ canonical_json_base64, ...core }) => core;
const capsuleCore = ({ $schema, capsule_id, signature, ...core }) => core;
const corrupt = (value) => (value[0] === "A" ? "B" : "A") + value.slice(1);

function base58(bytes) {
  let value = BigInt("0x" + Buffer.from(bytes).toString("hex")), result = "";
  while (value > 0n) { result = BASE58[Number(value % 58n)] + result; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = "1" + result; }
  return result || "1";
}
const multibase = (raw) => "z" + base58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
function publicKey(raw) { return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" }); }
function validate(capsule, vector) {
  const errors = [];
  const raw = Buffer.from(vector.controller_public_key_base64, "base64");
  if (capsule.controller?.did !== vector.expected_controller_did || capsule.controller?.signing_key_id !== vector.expected_controller_signing_key_id) errors.push("CAPSULE_CONTROLLER_INVALID");
  if (capsule.controller?.public_key_sha256 !== sha256(raw) || capsule.controller?.public_key_multibase !== multibase(raw)) errors.push("CAPSULE_CONTROLLER_KEY_INVALID");
  const paths = capsule.objects?.map((entry) => entry.path) || [];
  if (new Set(paths).size !== paths.length || canonicalize(paths) !== canonicalize([...paths].sort())) errors.push("CAPSULE_OBJECT_ORDER_INVALID", "CAPSULE_OBJECT_PATH_INVALID");
  for (const object of capsule.objects || []) {
    const bytes = Buffer.from(object.canonical_json_base64 || "", "base64");
    if (bytes.length !== object.byte_length) errors.push("CAPSULE_OBJECT_SIZE_INVALID");
    if (sha256(bytes) !== object.sha256) errors.push("CAPSULE_OBJECT_HASH_INVALID");
  }
  const hosts = capsule.hosts || [];
  const hostDids = hosts.map((entry) => entry.host_did);
  if (new Set(hostDids).size !== hostDids.length || canonicalize(hostDids) !== canonicalize([...hostDids].sort())) errors.push("CAPSULE_HOST_ORDER_INVALID");
  for (const host of hosts) {
    if (new Set(host.transition_ids || []).size !== (host.transition_ids || []).length || sha256(HISTORY_DOMAIN + canonicalize(host.transition_ids || [])) !== host.history_chain_root) errors.push("CAPSULE_HISTORY_ROOT_INVALID");
  }
  const transitionCount = hosts.reduce((sum, host) => sum + (host.transition_ids?.length || 0), 0);
  if (capsule.host_count !== hosts.length || capsule.transition_count !== transitionCount) errors.push("CAPSULE_COUNT_INVALID");
  if (sha256(CURRENT_SET_DOMAIN + canonicalize(hosts)) !== capsule.current_set_root) errors.push("CAPSULE_CURRENT_SET_ROOT_INVALID");
  if (sha256(OBJECT_SET_DOMAIN + canonicalize((capsule.objects || []).map(objectCore))) !== capsule.object_set_root) errors.push("CAPSULE_OBJECT_SET_ROOT_INVALID");
  const claims = capsule.claims || {};
  if (claims.complete_host_trust_state !== true || claims.contains_managed_secrets !== false || claims.external_anchor_created !== false || claims.rollback_detection_without_separately_preserved_capsule !== false || claims.authorizes_restore !== false || claims.authorizes_connection !== false || claims.authorizes_consent !== false || claims.authorizes_disclosure !== false || claims.authorizes_send !== false || claims.authorizes_emergency_recovery !== false || capsule.authority !== "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority") errors.push("CAPSULE_CLAIMS_INVALID");
  if (sha256(CAPSULE_DOMAIN + canonicalize(capsuleCore(capsule))) !== capsule.capsule_id) errors.push("CAPSULE_ID_INVALID");
  let validSignature = false;
  try { validSignature = capsule.signature?.suite === "Ed25519-v1" && capsule.signature?.key_id === capsule.controller?.signing_key_id && verify(null, Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(capsule.capsule_id || "", "hex")]), publicKey(raw), Buffer.from(capsule.signature?.value || "", "base64")); } catch {}
  if (!validSignature) errors.push("CAPSULE_SIGNATURE_INVALID");
  return [...new Set(errors)];
}
function mutate(capsule, name) {
  if (name === "object_bytes_mutated") { const bytes = Buffer.from(capsule.objects[0].canonical_json_base64, "base64"); bytes[0] ^= 1; capsule.objects[0].canonical_json_base64 = bytes.toString("base64"); }
  if (name === "object_size_mutated") capsule.objects[0].byte_length += 1;
  if (name === "object_order_reversed") capsule.objects.reverse();
  if (name === "object_path_duplicated") capsule.objects[1].path = capsule.objects[0].path;
  if (name === "host_order_duplicated") capsule.hosts.push(structuredClone(capsule.hosts[0]));
  if (name === "history_root_mutated") capsule.hosts[0].history_chain_root = "1".repeat(64);
  if (name === "current_set_root_mutated") capsule.current_set_root = "2".repeat(64);
  if (name === "object_set_root_mutated") capsule.object_set_root = "3".repeat(64);
  if (name === "host_count_mutated") capsule.host_count += 1;
  if (name === "transition_count_mutated") capsule.transition_count += 1;
  if (name === "controller_did_substituted") capsule.controller.did = "did:key:attacker";
  if (name === "controller_key_hash_mutated") capsule.controller.public_key_sha256 = "4".repeat(64);
  if (name === "external_anchor_claim_escalated") capsule.claims.external_anchor_created = true;
  if (name === "restore_claim_escalated") capsule.claims.authorizes_restore = true;
  if (name === "capsule_id_mutated") capsule.capsule_id = "5".repeat(64);
  if (name === "signature_corrupted") capsule.signature.value = corrupt(capsule.signature.value);
}
function assert(value, message) { if (!value) throw new Error("host trust capsule conformance failed: " + message); }
const json = async (relative) => JSON.parse(await readFile(path.join(root, relative), "utf8"));
const vector = await json("conformance/host-trust-capsule-v1.json");
const capsule = vector.capsule;
assert(canonicalize(capsuleCore(capsule)) === vector.expected.capsule_core_jcs, "capsule core differs");
assert(capsule.current_set_root === vector.expected.current_set_root, "current set root differs");
assert(capsule.object_set_root === vector.expected.object_set_root, "object set root differs");
assert(capsule.capsule_id === vector.expected.capsule_id, "capsule ID differs");
assert(Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(capsule.capsule_id, "hex")]).toString("hex") === vector.expected.signature_message_hex, "signature message differs");
assert(validate(capsule, vector).length === 0, "valid capsule rejected: " + validate(capsule, vector).join(", "));
let checks = 1;
const invalid = await json("conformance/host-trust-capsule-invalid-v1.json");
for (const test of invalid.cases) {
  const candidate = structuredClone(capsule);
  mutate(candidate, test.mutation);
  const errors = validate(candidate, vector);
  assert(errors.includes(test.expected_error), `${test.name} did not produce ${test.expected_error}; got ${errors.join(", ")}`);
  checks += 1;
}
console.log(`Portable host-trust capsule conformance checks passed: ${checks}`);
console.log("A capsule is complete signed portable bytes, not an external anchor or restore authority; rollback detection requires a separately preserved prior capsule or hash.");
