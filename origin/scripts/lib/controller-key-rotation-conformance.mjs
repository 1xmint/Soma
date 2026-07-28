import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const PROPOSAL_ID_DOMAIN = "somavera:soma-controller-key-rotation-proposal:v1\n";
const ROTATION_ID_DOMAIN = "somavera:soma-controller-key-rotation:v1\n";
const PRIOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-prior-signature:v1\n";
const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-successor-signature:v1\n";
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const corrupt = (value) => (value[0] === "A" ? "B" : "A") + value.slice(1);
const json = async (relative) => JSON.parse(await readFile(path.join(root, relative), "utf8"));
const exactAuthority = {
  authorizes_controller_key_rotation: true,
  authorizes_agent_key_rotation: false,
  authorizes_observer_key_rotation: false,
  authorizes_identity_recovery: false,
  authorizes_emergency_recovery: false,
  authorizes_connection: false,
  authorizes_consent: false,
  authorizes_disclosure: false,
  authorizes_send: false,
  authorizes_token_action: false,
  authorizes_governance: false
};
function proposalCore(value) {
  return {
    schema_version: value.schema_version,
    profile_status: value.profile_status,
    controller_did: value.controller_did,
    rotation_sequence: value.rotation_sequence,
    previous_rotation_id: value.previous_rotation_id,
    prior_key: {
      key_id: value.prior_key.key_id,
      role: value.prior_key.role,
      suite: value.prior_key.suite,
      public_key_multibase: value.prior_key.public_key_multibase,
      public_key_sha256: value.prior_key.public_key_sha256,
      valid_from: value.prior_key.valid_from
    },
    successor_key: {
      key_id: value.successor_key.key_id,
      role: value.successor_key.role,
      suite: value.successor_key.suite,
      public_key_multibase: value.successor_key.public_key_multibase,
      public_key_sha256: value.successor_key.public_key_sha256
    },
    prepared_at: value.prepared_at,
    reason: value.reason,
    decision: value.decision,
    prior_private_key_disposition: value.prior_private_key_disposition,
    rollback_assurance: value.rollback_assurance,
    authority: value.authority
  };
}
function rotationCore(value) {
  const { $schema, rotation_id, signatures, ...core } = value;
  return core;
}
function decodeMultibase(value) {
  if (typeof value !== "string" || value[0] !== "z") throw new Error("invalid multibase");
  let number = 0n;
  for (const character of value.slice(1)) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) throw new Error("invalid base58");
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let zeroes = 0;
  for (const character of value.slice(1)) {
    if (character !== "1") break;
    zeroes += 1;
  }
  if (zeroes) bytes = Buffer.concat([Buffer.alloc(zeroes), bytes]);
  if (bytes.length !== 34 || !bytes.subarray(0, 2).equals(Buffer.from([0xed, 0x01]))) throw new Error("not Ed25519");
  return bytes.subarray(2);
}
function publicKey(multibase) {
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), decodeMultibase(multibase)]), format: "der", type: "spki" });
}
function validSignature(signature, expectedKeyId, multibase, domain, rotationId) {
  try {
    return signature?.suite === "Ed25519-v1" &&
      signature.key_id === expectedKeyId &&
      verify(null, Buffer.concat([Buffer.from(domain), Buffer.from(rotationId, "hex")]), publicKey(multibase), Buffer.from(signature.value || "", "base64"));
  } catch {
    return false;
  }
}
function validate(rotation, expected) {
  const errors = [];
  const prior = rotation.prior_key || {};
  const successor = rotation.successor_key || {};
  if (rotation.controller_did !== expected.controller_did) errors.push("ROTATION_CONTROLLER_MISMATCH");
  if (rotation.rotation_sequence !== expected.rotation_sequence) errors.push("ROTATION_SEQUENCE_INVALID");
  if (rotation.previous_rotation_id !== expected.previous_rotation_id) errors.push("ROTATION_PREDECESSOR_INVALID");
  if (prior.key_id !== expected.prior_key_id || prior.public_key_multibase !== expected.prior_public_key_multibase || prior.public_key_sha256 !== sha256(decodeMultibase(prior.public_key_multibase || "")) || prior.role !== "controller_signing" || prior.suite !== "Ed25519-v1") errors.push("ROTATION_PRIOR_KEY_INVALID");
  let successorRaw;
  try { successorRaw = decodeMultibase(successor.public_key_multibase); } catch { successorRaw = null; }
  if (!successorRaw || successor.key_id === prior.key_id || successor.public_key_multibase === prior.public_key_multibase || successor.public_key_sha256 !== (successorRaw && sha256(successorRaw)) || successor.role !== "controller_signing" || successor.suite !== "Ed25519-v1") errors.push("ROTATION_SUCCESSOR_KEY_INVALID");
  const prepared = Date.parse(rotation.prepared_at);
  const effective = Date.parse(rotation.effective_at);
  if (!Number.isFinite(prepared) || !Number.isFinite(effective) || effective < prepared || effective - prepared > 900000) errors.push("ROTATION_TIME_INVALID");
  if (prior.valid_from !== expected.prior_valid_from || prior.valid_until !== rotation.effective_at || successor.valid_from !== rotation.effective_at || successor.valid_until !== null) errors.push("ROTATION_KEY_WINDOW_INVALID");
  if (prior.status !== "retired" || successor.status !== "active") errors.push("ROTATION_KEY_STATUS_INVALID");
  if (rotation.decision !== "replace_online_controller_signing_key_only") errors.push("ROTATION_DECISION_INVALID");
  if (rotation.prior_private_key_disposition !== "destroy_after_committed_successor_is_recoverable") errors.push("ROTATION_DISPOSITION_INVALID");
  if (rotation.rollback_assurance !== "local_consistency_only_unless_exact_history_is_externally_preserved") errors.push("ROTATION_ROLLBACK_ASSURANCE_INVALID");
  if (canonicalize(rotation.authority) !== canonicalize(exactAuthority)) errors.push("ROTATION_AUTHORITY_INVALID");
  const computedProposalId = sha256(PROPOSAL_ID_DOMAIN + canonicalize(proposalCore(rotation)));
  if (computedProposalId !== rotation.proposal_id) errors.push("ROTATION_PROPOSAL_ID_INVALID");
  const computedId = sha256(ROTATION_ID_DOMAIN + canonicalize(rotationCore(rotation)));
  if (computedId !== rotation.rotation_id) errors.push("ROTATION_ID_INVALID");
  if (!validSignature(rotation.signatures?.prior, prior.key_id, prior.public_key_multibase, PRIOR_SIGNATURE_DOMAIN, rotation.rotation_id)) errors.push("ROTATION_PRIOR_SIGNATURE_INVALID");
  if (!validSignature(rotation.signatures?.successor, successor.key_id, successor.public_key_multibase, SUCCESSOR_SIGNATURE_DOMAIN, rotation.rotation_id)) errors.push("ROTATION_SUCCESSOR_SIGNATURE_INVALID");
  return [...new Set(errors)];
}
function mutate(value, name) {
  if (name === "unstable_controller_did") value.controller_did = "did:key:attacker";
  if (name === "sequence_gap") value.rotation_sequence += 2;
  if (name === "wrong_predecessor") value.previous_rotation_id = "a".repeat(64);
  if (name === "prior_key_substitution") value.prior_key.key_id = "did:key:attacker#prior";
  if (name === "same_successor_key") {
    value.successor_key.key_id = value.prior_key.key_id;
    value.successor_key.public_key_multibase = value.prior_key.public_key_multibase;
    value.successor_key.public_key_sha256 = value.prior_key.public_key_sha256;
  }
  if (name === "successor_hash_mismatch") value.successor_key.public_key_sha256 = "b".repeat(64);
  if (name === "validity_gap") value.successor_key.valid_from = "2027-01-01T12:05:01.000Z";
  if (name === "effective_before_prepare") value.effective_at = "2027-01-01T11:59:59.000Z";
  if (name === "confirmation_window_exceeded") value.effective_at = "2027-01-01T12:15:00.001Z";
  if (name === "prior_reactivation") value.prior_key.status = "active";
  if (name === "successor_not_active") value.successor_key.status = "overlap";
  if (name === "decision_widening") value.decision = "replace_and_recover_identity";
  if (name === "private_key_retention") value.prior_private_key_disposition = "retain";
  if (name === "rollback_claim_widening") value.rollback_assurance = "rollback_proof_without_external_anchor";
  if (name.endsWith("_escalation")) {
    const field = {
      agent_rotation_escalation: "authorizes_agent_key_rotation",
      identity_recovery_escalation: "authorizes_identity_recovery",
      connection_escalation: "authorizes_connection",
      consent_escalation: "authorizes_consent",
      disclosure_escalation: "authorizes_disclosure",
      send_escalation: "authorizes_send",
      token_escalation: "authorizes_token_action",
      governance_escalation: "authorizes_governance"
    }[name];
    value.authority[field] = true;
  }
  if (name === "prior_signature_key_mismatch") value.signatures.prior.key_id = "did:key:attacker#prior";
  if (name === "prior_signature_corruption") value.signatures.prior.value = corrupt(value.signatures.prior.value);
  if (name === "successor_signature_key_mismatch") value.signatures.successor.key_id = "did:key:attacker#successor";
  if (name === "successor_signature_corruption") value.signatures.successor.value = corrupt(value.signatures.successor.value);
  if (name === "proposal_id_corruption") value.proposal_id = "d".repeat(64);
  if (name === "rotation_id_corruption") value.rotation_id = "e".repeat(64);
}
function assert(condition, message) {
  if (!condition) throw new Error("controller-key rotation conformance failed: " + message);
}

const vector = await json("conformance/controller-key-rotation-v1.json");
const rotation = vector.rotation;
const expected = {
  controller_did: rotation.controller_did,
  rotation_sequence: 1,
  previous_rotation_id: null,
  prior_key_id: rotation.prior_key.key_id,
  prior_public_key_multibase: rotation.prior_key.public_key_multibase,
  prior_valid_from: rotation.prior_key.valid_from
};
assert(canonicalize(proposalCore(rotation)) === vector.expected.proposal_core_jcs, "proposal canonical core differs");
assert(sha256(PROPOSAL_ID_DOMAIN + vector.expected.proposal_core_jcs) === vector.expected.proposal_id, "proposal ID differs");
assert(canonicalize(rotationCore(rotation)) === vector.expected.rotation_core_jcs, "canonical core differs");
assert(sha256(ROTATION_ID_DOMAIN + vector.expected.rotation_core_jcs) === vector.expected.rotation_id, "rotation ID differs");
assert(validate(rotation, expected).length === 0, "valid rotation rejected");
let checks = 1;
const invalid = await json("conformance/controller-key-rotation-invalid-v1.json");
for (const test of invalid.cases) {
  const candidate = structuredClone(rotation);
  mutate(candidate, test.mutation);
  const errors = validate(candidate, expected);
  assert(errors.includes(test.expected_error), `${test.name} did not produce ${test.expected_error}; got ${errors.join(", ")}`);
  checks += 1;
}
console.log(`Controller-key rotation conformance checks passed: ${checks}`);
console.log("The event authorizes ordinary controller-key replacement only; compromise recovery and every network/economic authority remain unauthorized.");
