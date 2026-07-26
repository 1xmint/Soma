import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const D = Object.freeze({
  history: "somavera:soma-host-trust-history-chain:v2\n",
  controllerHistory: "somavera:soma-controller-history-chain:v2\n",
  currentSet: "somavera:soma-host-trust-current-set:v2\n",
  objectSet: "somavera:soma-host-trust-object-set:v2\n",
  capsule: "somavera:soma-host-trust-capsule:v2\n",
  capsuleSignature: "somavera:soma-host-trust-capsule-signature:v2\n",
  rotation: "somavera:soma-controller-key-rotation:v1\n",
  priorSignature: "somavera:soma-controller-key-rotation-prior-signature:v1\n",
  successorSignature: "somavera:soma-controller-key-rotation-successor-signature:v1\n"
});
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const objectCore = ({ canonical_json_base64, ...core }) => core;
const capsuleCore = ({ $schema, capsule_id, signature, ...core }) => core;
const rotationCore = ({ $schema, rotation_id, signatures, ...core }) => core;
const corrupt = (value) => (value[0] === "A" ? "B" : "A") + value.slice(1);

function base58Decode(value) {
  let number = 0n;
  for (const character of value) {
    const index = BASE58.indexOf(character);
    if (index < 0) throw new Error("invalid base58");
    number = number * 58n + BigInt(index);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let zeroes = 0;
  for (const character of value) {
    if (character !== "1") break;
    zeroes += 1;
  }
  if (zeroes) bytes = Buffer.concat([Buffer.alloc(zeroes), bytes]);
  return bytes;
}

function rawKey(multibase) {
  if (typeof multibase !== "string" || !multibase.startsWith("z")) throw new Error("invalid multibase");
  const decoded = base58Decode(multibase.slice(1));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error("invalid Ed25519 multicodec");
  return decoded.subarray(2);
}

function publicKey(multibase) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawKey(multibase)]),
    format: "der",
    type: "spki"
  });
}

function signatureValid(signature, key, domain, id) {
  try {
    return signature?.suite === "Ed25519-v1" &&
      signature.key_id === key.key_id &&
      verify(
        null,
        Buffer.concat([Buffer.from(domain), Buffer.from(id, "hex")]),
        publicKey(key.public_key_multibase),
        Buffer.from(signature.value, "base64")
      );
  } catch {
    return false;
  }
}

function validate(capsule, vector) {
  const errors = [];
  const controller = capsule.controller || {};
  let initialRaw = null;
  try { initialRaw = rawKey(controller.initial_key?.public_key_multibase); } catch {}
  if (controller.did !== vector.expected_controller_did) errors.push("CAPSULE_CONTROLLER_INVALID");
  if (!initialRaw ||
      controller.initial_key.public_key_sha256 !== sha256(initialRaw) ||
      controller.initial_key.public_key_sha256 !== vector.expected_initial_controller_key_sha256) {
    errors.push("CAPSULE_CONTROLLER_INITIAL_KEY_INVALID");
  }

  const paths = (capsule.objects || []).map((entry) => entry.path);
  if (new Set(paths).size !== paths.length || canonicalize(paths) !== canonicalize([...paths].sort())) {
    errors.push("CAPSULE_OBJECT_ORDER_INVALID", "CAPSULE_OBJECT_PATH_INVALID");
  }
  const rotations = [];
  for (const object of capsule.objects || []) {
    const bytes = Buffer.from(object.canonical_json_base64 || "", "base64");
    if (bytes.length !== object.byte_length) errors.push("CAPSULE_OBJECT_SIZE_INVALID");
    if (sha256(bytes) !== object.sha256) errors.push("CAPSULE_OBJECT_HASH_INVALID");
    if (object.kind === "controller_rotation") {
      try { rotations.push({ object, record: JSON.parse(bytes.toString("utf8")) }); }
      catch { errors.push("CAPSULE_CONTROLLER_HISTORY_INCOMPLETE"); }
    }
  }

  const ids = controller.rotation_ids || [];
  if (new Set(ids).size !== ids.length || ids.length !== controller.rotation_sequence) {
    errors.push("CAPSULE_CONTROLLER_HISTORY_ORDER_INVALID");
  }
  let current = controller.initial_key;
  let head = null;
  for (let index = 0; index < rotations.length; index += 1) {
    const { object, record } = rotations[index];
    const expectedPath = `identity/rotations/${String(index + 1).padStart(12, "0")}-${record.rotation_id}.json`;
    if (object.path !== expectedPath ||
        record.rotation_sequence !== index + 1 ||
        record.previous_rotation_id !== head ||
        ids[index] !== record.rotation_id ||
        record.prior_key?.key_id !== current?.key_id ||
        record.prior_key?.public_key_multibase !== current?.public_key_multibase ||
        sha256(D.rotation + canonicalize(rotationCore(record))) !== record.rotation_id) {
      errors.push("CAPSULE_CONTROLLER_HISTORY_ORDER_INVALID");
    }
    if (!signatureValid(record.signatures?.prior, record.prior_key, D.priorSignature, record.rotation_id) ||
        !signatureValid(record.signatures?.successor, record.successor_key, D.successorSignature, record.rotation_id)) {
      errors.push("CAPSULE_CONTROLLER_HISTORY_SIGNATURE_INVALID");
    }
    current = record.successor_key;
    head = record.rotation_id;
  }
  if (rotations.length !== ids.length) errors.push("CAPSULE_CONTROLLER_HISTORY_INCOMPLETE");
  if (controller.rotation_head !== head) errors.push("CAPSULE_CONTROLLER_HISTORY_HEAD_INVALID");
  if (controller.active_signing_key_id !== current?.key_id) errors.push("CAPSULE_CONTROLLER_ACTIVE_KEY_INVALID");
  if (capsule.controller_rotation_count !== rotations.length ||
      capsule.controller_rotation_count !== controller.rotation_sequence) errors.push("CAPSULE_COUNT_INVALID");
  if (sha256(D.controllerHistory + canonicalize(ids)) !== capsule.controller_history_root) {
    errors.push("CAPSULE_CONTROLLER_HISTORY_ROOT_INVALID");
  }

  const hosts = capsule.hosts || [];
  const hostDids = hosts.map((entry) => entry.host_did);
  if (new Set(hostDids).size !== hostDids.length ||
      canonicalize(hostDids) !== canonicalize([...hostDids].sort())) errors.push("CAPSULE_HOST_ORDER_INVALID");
  for (const host of hosts) {
    if (new Set(host.transition_ids || []).size !== (host.transition_ids || []).length ||
        sha256(D.history + canonicalize(host.transition_ids || [])) !== host.history_chain_root) {
      errors.push("CAPSULE_HISTORY_ROOT_INVALID");
    }
  }
  const transitionCount = hosts.reduce((sum, host) => sum + (host.transition_ids?.length || 0), 0);
  if (capsule.host_count !== hosts.length || capsule.transition_count !== transitionCount) errors.push("CAPSULE_COUNT_INVALID");
  if (sha256(D.currentSet + canonicalize(hosts)) !== capsule.current_set_root) errors.push("CAPSULE_CURRENT_SET_ROOT_INVALID");
  if (sha256(D.objectSet + canonicalize((capsule.objects || []).map(objectCore))) !== capsule.object_set_root) {
    errors.push("CAPSULE_OBJECT_SET_ROOT_INVALID");
  }
  const claims = capsule.claims || {};
  if (claims.complete_host_trust_state !== true ||
      claims.complete_controller_rotation_history !== true ||
      claims.contains_managed_secrets !== false ||
      claims.external_anchor_created !== false ||
      claims.rollback_detection_without_separately_preserved_capsule !== false ||
      claims.authorizes_restore !== false ||
      claims.authorizes_connection !== false ||
      claims.authorizes_consent !== false ||
      claims.authorizes_disclosure !== false ||
      claims.authorizes_send !== false ||
      claims.authorizes_emergency_recovery !== false ||
      capsule.authority !== "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority") {
    errors.push("CAPSULE_CLAIMS_INVALID");
  }
  if (sha256(D.capsule + canonicalize(capsuleCore(capsule))) !== capsule.capsule_id) errors.push("CAPSULE_ID_INVALID");
  if (!signatureValid(capsule.signature, current, D.capsuleSignature, capsule.capsule_id)) {
    errors.push("CAPSULE_SIGNATURE_INVALID");
  }
  return [...new Set(errors)];
}

function replaceRotation(capsule, mutate) {
  const object = capsule.objects.find((entry) => entry.kind === "controller_rotation");
  const record = JSON.parse(Buffer.from(object.canonical_json_base64, "base64").toString("utf8"));
  mutate(record);
  const bytes = Buffer.from(canonicalize(record) + "\n");
  Object.assign(object, {
    byte_length: bytes.length,
    sha256: sha256(bytes),
    canonical_json_base64: bytes.toString("base64")
  });
}

function mutate(capsule, name) {
  if (name === "initial_key_substituted") capsule.controller.initial_key.public_key_sha256 = "1".repeat(64);
  if (name === "rotation_object_removed") capsule.objects = capsule.objects.filter((entry) => entry.kind !== "controller_rotation");
  if (name === "rotation_object_reordered") capsule.controller.rotation_ids.push(capsule.controller.rotation_ids[0]);
  if (name === "rotation_prior_signature_corrupted") replaceRotation(capsule, (record) => { record.signatures.prior.value = corrupt(record.signatures.prior.value); });
  if (name === "rotation_successor_signature_corrupted") replaceRotation(capsule, (record) => { record.signatures.successor.value = corrupt(record.signatures.successor.value); });
  if (name === "rotation_head_mutated") capsule.controller.rotation_head = "2".repeat(64);
  if (name === "rotation_count_mutated") capsule.controller_rotation_count += 1;
  if (name === "controller_history_root_mutated") capsule.controller_history_root = "3".repeat(64);
  if (name === "active_key_substituted") capsule.controller.active_signing_key_id = "did:key:attacker#key";
  if (name === "controller_history_claim_escalated") capsule.claims.complete_controller_rotation_history = false;
  if (name === "capsule_signature_corrupted") capsule.signature.value = corrupt(capsule.signature.value);
}

function assert(value, message) {
  if (!value) throw new Error("host trust capsule v2 conformance failed: " + message);
}

const json = async (relative) => JSON.parse(await readFile(path.join(root, relative), "utf8"));
const vector = await json("conformance/host-trust-capsule-v2.json");
const capsule = vector.capsule;
assert(canonicalize(capsuleCore(capsule)) === vector.expected.capsule_core_jcs, "capsule core differs");
assert(capsule.current_set_root === vector.expected.current_set_root, "current set root differs");
assert(capsule.controller_history_root === vector.expected.controller_history_root, "controller history root differs");
assert(capsule.object_set_root === vector.expected.object_set_root, "object set root differs");
assert(capsule.capsule_id === vector.expected.capsule_id, "capsule ID differs");
assert(validate(capsule, vector).length === 0, "valid capsule rejected: " + validate(capsule, vector).join(", "));
let checks = 1;
const invalid = await json("conformance/host-trust-capsule-invalid-v2.json");
for (const test of invalid.cases) {
  const candidate = structuredClone(capsule);
  mutate(candidate, test.mutation);
  const errors = validate(candidate, vector);
  assert(errors.includes(test.expected_error), `${test.name} did not produce ${test.expected_error}; got ${errors.join(", ")}`);
  checks += 1;
}
console.log(`Controller-history-capable host-trust capsule v2 conformance checks passed: ${checks}`);
