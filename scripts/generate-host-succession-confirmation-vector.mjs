import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const source = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
const examplePath = path.join(root, "examples", "soma-host-succession-confirmation.example.json");
const vectorPath = path.join(root, "conformance", "host-succession-confirmation-v1.json");
const invalidPath = path.join(root, "conformance", "host-succession-confirmation-invalid-v1.json");

const SUBJECT_ID_DOMAIN = "somavera:soma-host-succession-confirmation-subject:v1\n";
const CONFIRMATION_ID_DOMAIN = "somavera:soma-host-succession-confirmation:v1\n";
const SIGNATURE_DOMAIN = "somavera:soma-host-succession-confirmation-signature:v1\n";

function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function controllerFromSeed(seedHex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { privateKey, publicKeyBase64: Buffer.from(publicDer).subarray(-32).toString("base64") };
}
function keyById(keys, id) { return keys.find((key) => key.key_id === id); }
function subjectCore(value) {
  return {
    network_lineage_id: value.network_lineage_id,
    execution_context_id: value.execution_context_id,
    host_did: value.host_did,
    origin: value.origin,
    prior_descriptor_id: value.prior_descriptor_id,
    prior_descriptor_sequence: value.prior_descriptor_sequence,
    successor_descriptor_id: value.successor_descriptor_id,
    successor_descriptor_sequence: value.successor_descriptor_sequence,
    succession_id: value.succession_id,
    change_scope: value.change_scope,
    successor_active_host_signing_key_id: value.successor_active_host_signing_key_id,
    successor_active_host_signing_key_sha256: value.successor_active_host_signing_key_sha256,
    successor_active_ingestion_key_id: value.successor_active_ingestion_key_id,
    successor_active_ingestion_key_sha256: value.successor_active_ingestion_key_sha256
  };
}
function confirmationCore(value) {
  const { $schema, confirmation_id, signature, ...core } = value;
  return core;
}

const prior = source.prior_descriptor;
const successor = source.successor_descriptor;
const proof = source.succession_proof;
const signing = keyById(successor.host_signing_keys, successor.active_host_signing_key_id);
const ingestion = keyById(successor.ingestion_encryption_keys, successor.active_ingestion_key_id);
const controller = controllerFromSeed("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
const controllerDid = "did:key:example-soma-controller";
const controllerKeyId = controllerDid + "#controller-1";

const confirmation = {
  $schema: "../schemas/soma-host-succession-confirmation.schema.json",
  schema_version: "somavera.soma-host-succession-confirmation.v1",
  profile_status: "freeze_blocking_draft",
  confirmation_id: "0".repeat(64),
  subject_id: "0".repeat(64),
  network_lineage_id: proof.network_lineage_id,
  execution_context_id: proof.execution_context_id,
  controller_did: controllerDid,
  controller_signing_key_id: controllerKeyId,
  host_did: proof.host_did,
  origin: proof.origin,
  prior_descriptor_id: proof.prior_descriptor_id,
  prior_descriptor_sequence: proof.prior_descriptor_sequence,
  successor_descriptor_id: proof.successor_descriptor_id,
  successor_descriptor_sequence: proof.successor_descriptor_sequence,
  succession_id: proof.succession_id,
  change_scope: proof.change_scope,
  successor_active_host_signing_key_id: proof.successor_active_host_signing_key_id,
  successor_active_host_signing_key_sha256: sha256(Buffer.from(signing.public_key_base64, "base64")),
  successor_active_ingestion_key_id: proof.successor_active_ingestion_key_id,
  successor_active_ingestion_key_sha256: sha256(Buffer.from(ingestion.public_key_base64, "base64")),
  confirmed_at: "2027-01-01T12:06:00Z",
  decision: "replace_inert_pin_only",
  authority: {
    authorizes_pin_replacement: true,
    authorizes_connection: false,
    authorizes_consent: false,
    authorizes_disclosure: false,
    authorizes_send: false,
    authorizes_emergency_recovery: false
  },
  signature: {}
};
confirmation.subject_id = sha256(SUBJECT_ID_DOMAIN + canonicalize(subjectCore(confirmation)));
confirmation.confirmation_id = sha256(CONFIRMATION_ID_DOMAIN + canonicalize(confirmationCore(confirmation)));
confirmation.signature = {
  suite: "Ed25519-v1",
  key_id: controllerKeyId,
  value: sign(null, Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(confirmation.confirmation_id, "hex")]), controller.privateKey).toString("base64")
};

const vector = {
  vector_version: "somavera.host-succession-confirmation.v1",
  description: "Deterministic controller confirmation of one exact inert ordinary host succession subject.",
  source_succession_vector: "host-descriptor-succession-v1.json",
  expected_controller_did: controllerDid,
  expected_controller_signing_key_id: controllerKeyId,
  controller_public_key_base64: controller.publicKeyBase64,
  domains: {
    subject_id: SUBJECT_ID_DOMAIN.slice(0, -1),
    confirmation_id: CONFIRMATION_ID_DOMAIN.slice(0, -1),
    confirmation_signature: SIGNATURE_DOMAIN.slice(0, -1)
  },
  expected: {
    subject_core_jcs: canonicalize(subjectCore(confirmation)),
    confirmation_core_jcs: canonicalize(confirmationCore(confirmation)),
    subject_id: confirmation.subject_id,
    confirmation_id: confirmation.confirmation_id,
    signature_message_hex: Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(confirmation.confirmation_id, "hex")]).toString("hex"),
    result: "accept_inert_pin_replacement_only"
  },
  confirmation
};

const bindingFields = [
  "network_lineage_id",
  "execution_context_id",
  "host_did",
  "origin",
  "prior_descriptor_id",
  "prior_descriptor_sequence",
  "successor_descriptor_id",
  "successor_descriptor_sequence",
  "succession_id",
  "change_scope",
  "successor_active_host_signing_key_id",
  "successor_active_host_signing_key_sha256",
  "successor_active_ingestion_key_id",
  "successor_active_ingestion_key_sha256"
];
const invalid = {
  vector_version: "somavera.host-succession-confirmation-invalid.v1",
  base_vector: "host-succession-confirmation-v1.json",
  cases: [
    ...bindingFields.map((field) => ({ name: "binding_" + field, mutation: "binding:" + field, expected_error: "CONFIRMATION_BINDING_MISMATCH:" + field })),
    { name: "wrong_controller_did", mutation: "wrong_controller_did", expected_error: "CONFIRMATION_CONTROLLER_MISMATCH" },
    { name: "wrong_controller_key", mutation: "wrong_controller_key", expected_error: "CONFIRMATION_CONTROLLER_MISMATCH" },
    { name: "before_proof_window", mutation: "before_proof_window", expected_error: "CONFIRMATION_TIME_INVALID" },
    { name: "after_proof_window", mutation: "after_proof_window", expected_error: "CONFIRMATION_TIME_INVALID" },
    { name: "decision_widening", mutation: "decision_widening", expected_error: "CONFIRMATION_DECISION_INVALID" },
    { name: "pin_replacement_removed", mutation: "pin_replacement_removed", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "connection_authority_escalation", mutation: "connection_authority_escalation", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "consent_authority_escalation", mutation: "consent_authority_escalation", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "disclosure_authority_escalation", mutation: "disclosure_authority_escalation", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "send_authority_escalation", mutation: "send_authority_escalation", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "emergency_authority_escalation", mutation: "emergency_authority_escalation", expected_error: "CONFIRMATION_AUTHORITY_INVALID" },
    { name: "signature_key_mismatch", mutation: "signature_key_mismatch", expected_error: "CONFIRMATION_SIGNATURE_INVALID" },
    { name: "signature_corruption", mutation: "signature_corruption", expected_error: "CONFIRMATION_SIGNATURE_INVALID" },
    { name: "subject_id_corruption", mutation: "subject_id_corruption", expected_error: "CONFIRMATION_SUBJECT_ID_INVALID" },
    { name: "confirmation_id_corruption", mutation: "confirmation_id_corruption", expected_error: "CONFIRMATION_ID_INVALID" }
  ]
};

await writeFile(examplePath, JSON.stringify(confirmation, null, 2) + "\n");
await writeFile(vectorPath, JSON.stringify(vector, null, 2) + "\n");
await writeFile(invalidPath, JSON.stringify(invalid, null, 2) + "\n");
console.log("Generated Soma host succession confirmation example and vectors.");
