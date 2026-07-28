import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const HISTORY_DOMAIN = "somavera:soma-host-trust-history-chain:v2\n";
const CONTROLLER_HISTORY_DOMAIN = "somavera:soma-controller-history-chain:v2\n";
const CURRENT_SET_DOMAIN = "somavera:soma-host-trust-current-set:v2\n";
const OBJECT_SET_DOMAIN = "somavera:soma-host-trust-object-set:v2\n";
const CAPSULE_DOMAIN = "somavera:soma-host-trust-capsule:v2\n";
const SIGNATURE_DOMAIN = "somavera:soma-host-trust-capsule-signature:v2\n";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const objectCore = ({ canonical_json_base64, ...core }) => core;
const capsuleCore = ({ $schema, capsule_id, signature, ...core }) => core;

const controllerVector = JSON.parse(
  await readFile(path.join(root, "conformance", "controller-key-rotation-v1.json"), "utf8")
);
const rotation = controllerVector.rotation;
const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const successorSeed = Buffer.from(
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  "hex"
);
const successorPrivateKey = createPrivateKey({
  key: Buffer.concat([prefix, successorSeed]),
  format: "der",
  type: "pkcs8"
});

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
    value: {
      schema_version: "soma.host-pin.provisional-v2",
      pin_id: pinId,
      descriptor: {
        descriptor_id: descriptorId,
        descriptor_sequence: 8,
        host_did: hostDid
      },
      predecessor_pin_id: "e".repeat(64),
      confirmation_id: confirmationId
    }
  },
  {
    path: `hosts/history/${hostToken}/${confirmationId}.json`,
    kind: "history_transition",
    value: {
      schema_version: "soma.host-succession-transition.provisional-v1",
      transition_id: transitionId,
      confirmation_id: confirmationId,
      successor_pin_id: pinId,
      host_did: hostDid
    }
  },
  {
    path: `identity/rotations/${String(rotation.rotation_sequence).padStart(12, "0")}-${rotation.rotation_id}.json`,
    kind: "controller_rotation",
    value: rotation
  }
];
const objects = payloads.map((entry) => {
  const bytes = Buffer.from(canonicalize(entry.value) + "\n");
  return {
    path: entry.path,
    kind: entry.kind,
    byte_length: bytes.length,
    sha256: sha256(bytes),
    canonical_json_base64: bytes.toString("base64")
  };
}).sort((left, right) => left.path.localeCompare(right.path));
const hosts = [{
  host_did: hostDid,
  current_pin_id: pinId,
  current_descriptor_id: descriptorId,
  current_descriptor_sequence: 8,
  transition_ids: [transitionId],
  history_chain_root: sha256(HISTORY_DOMAIN + canonicalize([transitionId]))
}];
const rotationIds = [rotation.rotation_id];
const capsule = {
  $schema: "../schemas/soma-host-trust-capsule-v2.schema.json",
  schema_version: "somavera.soma-host-trust-capsule.v2",
  profile_status: "freeze_blocking_draft",
  capsule_id: "0".repeat(64),
  created_at: "2027-01-01T13:00:00.000Z",
  controller: {
    did: rotation.controller_did,
    initial_key: {
      key_id: rotation.prior_key.key_id,
      public_key_multibase: rotation.prior_key.public_key_multibase,
      public_key_sha256: rotation.prior_key.public_key_sha256,
      valid_from: rotation.prior_key.valid_from
    },
    active_signing_key_id: rotation.successor_key.key_id,
    rotation_sequence: 1,
    rotation_head: rotation.rotation_id,
    rotation_ids: rotationIds
  },
  source: {
    origin_capsule_hash: "9f711a3a8e53502c464efd2798266067adc2d42995246acb3b496c05ef948fb0",
    reference_release_manifest_hash: "f".repeat(64),
    reference_release_version: "0.2.0"
  },
  host_count: hosts.length,
  transition_count: 1,
  controller_rotation_count: 1,
  current_set_root: sha256(CURRENT_SET_DOMAIN + canonicalize(hosts)),
  controller_history_root: sha256(CONTROLLER_HISTORY_DOMAIN + canonicalize(rotationIds)),
  object_set_root: sha256(OBJECT_SET_DOMAIN + canonicalize(objects.map(objectCore))),
  hosts,
  objects,
  claims: {
    complete_host_trust_state: true,
    complete_controller_rotation_history: true,
    contains_managed_secrets: false,
    external_anchor_created: false,
    rollback_detection_without_separately_preserved_capsule: false,
    authorizes_restore: false,
    authorizes_connection: false,
    authorizes_consent: false,
    authorizes_disclosure: false,
    authorizes_send: false,
    authorizes_emergency_recovery: false
  },
  authority: "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority",
  signature: {}
};
capsule.capsule_id = sha256(CAPSULE_DOMAIN + canonicalize(capsuleCore(capsule)));
capsule.signature = {
  suite: "Ed25519-v1",
  key_id: rotation.successor_key.key_id,
  value: sign(
    null,
    Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(capsule.capsule_id, "hex")]),
    successorPrivateKey
  ).toString("base64")
};

const vector = {
  vector_version: "somavera.soma-host-trust-capsule.v2",
  expected_controller_did: rotation.controller_did,
  expected_initial_controller_key_sha256: rotation.prior_key.public_key_sha256,
  domains: {
    history_chain: HISTORY_DOMAIN.slice(0, -1),
    controller_history_chain: CONTROLLER_HISTORY_DOMAIN.slice(0, -1),
    current_set: CURRENT_SET_DOMAIN.slice(0, -1),
    object_set: OBJECT_SET_DOMAIN.slice(0, -1),
    capsule_id: CAPSULE_DOMAIN.slice(0, -1),
    capsule_signature: SIGNATURE_DOMAIN.slice(0, -1)
  },
  expected: {
    current_set_root: capsule.current_set_root,
    controller_history_root: capsule.controller_history_root,
    object_set_root: capsule.object_set_root,
    capsule_core_jcs: canonicalize(capsuleCore(capsule)),
    capsule_id: capsule.capsule_id,
    signature_message_hex: Buffer.concat([
      Buffer.from(SIGNATURE_DOMAIN),
      Buffer.from(capsule.capsule_id, "hex")
    ]).toString("hex"),
    result: "accept_complete_controller_chain_portable_copy_not_external_anchor"
  },
  capsule
};
const invalid = {
  vector_version: "somavera.soma-host-trust-capsule-invalid.v2",
  base_vector: "host-trust-capsule-v2.json",
  cases: [
    { name: "initial_key_substituted", mutation: "initial_key_substituted", expected_error: "CAPSULE_CONTROLLER_INITIAL_KEY_INVALID" },
    { name: "rotation_object_removed", mutation: "rotation_object_removed", expected_error: "CAPSULE_CONTROLLER_HISTORY_INCOMPLETE" },
    { name: "rotation_object_reordered", mutation: "rotation_object_reordered", expected_error: "CAPSULE_CONTROLLER_HISTORY_ORDER_INVALID" },
    { name: "rotation_prior_signature_corrupted", mutation: "rotation_prior_signature_corrupted", expected_error: "CAPSULE_CONTROLLER_HISTORY_SIGNATURE_INVALID" },
    { name: "rotation_successor_signature_corrupted", mutation: "rotation_successor_signature_corrupted", expected_error: "CAPSULE_CONTROLLER_HISTORY_SIGNATURE_INVALID" },
    { name: "rotation_head_mutated", mutation: "rotation_head_mutated", expected_error: "CAPSULE_CONTROLLER_HISTORY_HEAD_INVALID" },
    { name: "rotation_count_mutated", mutation: "rotation_count_mutated", expected_error: "CAPSULE_COUNT_INVALID" },
    { name: "controller_history_root_mutated", mutation: "controller_history_root_mutated", expected_error: "CAPSULE_CONTROLLER_HISTORY_ROOT_INVALID" },
    { name: "active_key_substituted", mutation: "active_key_substituted", expected_error: "CAPSULE_CONTROLLER_ACTIVE_KEY_INVALID" },
    { name: "controller_history_claim_escalated", mutation: "controller_history_claim_escalated", expected_error: "CAPSULE_CLAIMS_INVALID" },
    { name: "capsule_signature_corrupted", mutation: "capsule_signature_corrupted", expected_error: "CAPSULE_SIGNATURE_INVALID" }
  ]
};

await writeFile(
  path.join(root, "examples", "soma-host-trust-capsule-v2.example.json"),
  JSON.stringify(capsule, null, 2) + "\n"
);
await writeFile(
  path.join(root, "conformance", "host-trust-capsule-v2.json"),
  JSON.stringify(vector, null, 2) + "\n"
);
await writeFile(
  path.join(root, "conformance", "host-trust-capsule-invalid-v2.json"),
  JSON.stringify(invalid, null, 2) + "\n"
);
console.log("Generated controller-history-capable Soma host-trust capsule v2 vectors.");
