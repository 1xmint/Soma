import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const SUBJECT_ID_DOMAIN = "somavera:soma-host-succession-confirmation-subject:v1\n";
const CONFIRMATION_ID_DOMAIN = "somavera:soma-host-succession-confirmation:v1\n";
const SIGNATURE_DOMAIN = "somavera:soma-host-succession-confirmation-signature:v1\n";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const same = (left, right) => canonicalize(left) === canonicalize(right);
const keyById = (keys, id) => keys.find((key) => key.key_id === id);
const corrupt = (value) => (value[0] === "A" ? "B" : "A") + value.slice(1);
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
function confirmationCore(value) { const { $schema, confirmation_id, signature, ...core } = value; return core; }
function publicKey(rawBase64) {
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawBase64, "base64")]), format: "der", type: "spki" });
}
function validate(confirmation, source, vector) {
  const errors = [];
  const prior = source.prior_descriptor, successor = source.successor_descriptor, proof = source.succession_proof;
  const signing = keyById(successor.host_signing_keys, successor.active_host_signing_key_id);
  const ingestion = keyById(successor.ingestion_encryption_keys, successor.active_ingestion_key_id);
  const bindings = {
    network_lineage_id: proof.network_lineage_id,
    execution_context_id: proof.execution_context_id,
    host_did: proof.host_did,
    origin: proof.origin,
    prior_descriptor_id: prior.descriptor_id,
    prior_descriptor_sequence: prior.descriptor_sequence,
    successor_descriptor_id: successor.descriptor_id,
    successor_descriptor_sequence: successor.descriptor_sequence,
    succession_id: proof.succession_id,
    change_scope: proof.change_scope,
    successor_active_host_signing_key_id: successor.active_host_signing_key_id,
    successor_active_host_signing_key_sha256: sha256(Buffer.from(signing.public_key_base64, "base64")),
    successor_active_ingestion_key_id: successor.active_ingestion_key_id,
    successor_active_ingestion_key_sha256: sha256(Buffer.from(ingestion.public_key_base64, "base64"))
  };
  for (const [field, expected] of Object.entries(bindings)) if (!same(confirmation[field], expected)) errors.push("CONFIRMATION_BINDING_MISMATCH:" + field);
  if (confirmation.controller_did !== vector.expected_controller_did || confirmation.controller_signing_key_id !== vector.expected_controller_signing_key_id) errors.push("CONFIRMATION_CONTROLLER_MISMATCH");
  const confirmed = Date.parse(confirmation.confirmed_at);
  if (!(Date.parse(proof.issued_at) <= confirmed && confirmed <= Date.parse(proof.expires_at))) errors.push("CONFIRMATION_TIME_INVALID");
  if (confirmation.decision !== "replace_inert_pin_only") errors.push("CONFIRMATION_DECISION_INVALID");
  const authority = confirmation.authority || {};
  if (authority.authorizes_pin_replacement !== true || authority.authorizes_connection !== false || authority.authorizes_consent !== false || authority.authorizes_disclosure !== false || authority.authorizes_send !== false || authority.authorizes_emergency_recovery !== false) errors.push("CONFIRMATION_AUTHORITY_INVALID");
  if (sha256(SUBJECT_ID_DOMAIN + canonicalize(subjectCore(confirmation))) !== confirmation.subject_id) errors.push("CONFIRMATION_SUBJECT_ID_INVALID");
  if (sha256(CONFIRMATION_ID_DOMAIN + canonicalize(confirmationCore(confirmation))) !== confirmation.confirmation_id) errors.push("CONFIRMATION_ID_INVALID");
  const signature = confirmation.signature || {};
  let signatureValid = false;
  try {
    signatureValid = signature.suite === "Ed25519-v1" && signature.key_id === confirmation.controller_signing_key_id && verify(null, Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(confirmation.confirmation_id, "hex")]), publicKey(vector.controller_public_key_base64), Buffer.from(signature.value || "", "base64"));
  } catch {}
  if (!signatureValid) errors.push("CONFIRMATION_SIGNATURE_INVALID");
  return [...new Set(errors)];
}
function substituteBinding(value, field) {
  if (Number.isSafeInteger(value[field])) { value[field] += 1; return; }
  if (field === "network_lineage_id") { value[field] = "somavera:network:v1:" + "1".repeat(64); return; }
  if (field === "execution_context_id") { value[field] = "somavera:context:v1:" + "2".repeat(64); return; }
  if (field === "host_did") { value[field] = "did:key:attacker-host"; return; }
  if (field === "origin") { value[field] = "https://attacker.example.test"; return; }
  if (field === "change_scope") { value[field] = "renewal_only"; return; }
  if (field.endsWith("_id") && !field.endsWith("key_id")) { value[field] = "aa".repeat(32); return; }
  if (field.endsWith("_sha256")) { value[field] = "bb".repeat(32); return; }
  if (field.endsWith("_key_id")) { value[field] = "did:key:attacker#wrong-purpose"; return; }
  throw new Error("unsupported binding mutation: " + field);
}
function mutate(value, name) {
  if (name.startsWith("binding:")) substituteBinding(value, name.slice("binding:".length));
  if (name === "wrong_controller_did") value.controller_did = "did:key:attacker-controller";
  if (name === "wrong_controller_key") value.controller_signing_key_id = "did:key:example-soma-controller#controller-2";
  if (name === "before_proof_window") value.confirmed_at = "2027-01-01T11:59:59Z";
  if (name === "after_proof_window") value.confirmed_at = "2027-01-01T12:15:01Z";
  if (name === "decision_widening") value.decision = "replace_and_connect";
  if (name === "pin_replacement_removed") value.authority.authorizes_pin_replacement = false;
  if (name === "connection_authority_escalation") value.authority.authorizes_connection = true;
  if (name === "consent_authority_escalation") value.authority.authorizes_consent = true;
  if (name === "disclosure_authority_escalation") value.authority.authorizes_disclosure = true;
  if (name === "send_authority_escalation") value.authority.authorizes_send = true;
  if (name === "emergency_authority_escalation") value.authority.authorizes_emergency_recovery = true;
  if (name === "signature_key_mismatch") value.signature.key_id = "did:key:attacker#controller";
  if (name === "signature_corruption") value.signature.value = corrupt(value.signature.value);
  if (name === "subject_id_corruption") value.subject_id = "dd".repeat(32);
  if (name === "confirmation_id_corruption") value.confirmation_id = "ee".repeat(32);
}
function assert(condition, message) { if (!condition) throw new Error("host confirmation conformance failed: " + message); }

const json = async (relative) => JSON.parse(await readFile(path.join(root, relative), "utf8"));
const source = await json("conformance/host-descriptor-succession-v1.json");
const vector = await json("conformance/host-succession-confirmation-v1.json");
const confirmation = vector.confirmation;
assert(canonicalize(subjectCore(confirmation)) === vector.expected.subject_core_jcs, "subject canonical bytes differ");
assert(canonicalize(confirmationCore(confirmation)) === vector.expected.confirmation_core_jcs, "confirmation canonical bytes differ");
assert(confirmation.subject_id === vector.expected.subject_id, "subject ID differs");
assert(confirmation.confirmation_id === vector.expected.confirmation_id, "confirmation ID differs");
assert(Buffer.concat([Buffer.from(SIGNATURE_DOMAIN), Buffer.from(confirmation.confirmation_id, "hex")]).toString("hex") === vector.expected.signature_message_hex, "signature message differs");
assert(validate(confirmation, source, vector).length === 0, "valid confirmation rejected");
let checks = 1;
const invalid = await json("conformance/host-succession-confirmation-invalid-v1.json");
for (const test of invalid.cases) {
  const candidate = structuredClone(confirmation);
  mutate(candidate, test.mutation);
  const errors = validate(candidate, source, vector);
  assert(errors.includes(test.expected_error), `${test.name} did not produce ${test.expected_error}; got ${errors.join(", ")}`);
  checks += 1;
}
console.log(`Host succession confirmation conformance checks passed: ${checks}`);
console.log("Confirmation authorizes inert local pin replacement only; connection, consent, disclosure, send, and emergency recovery remain unauthorized.");
