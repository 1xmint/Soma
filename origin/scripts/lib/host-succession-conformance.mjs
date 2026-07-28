import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const DESCRIPTOR_ID_DOMAIN = "somavera:vera-host-descriptor:v1\n";
const DESCRIPTOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-signature:v1\n";
const SUCCESSION_ID_DOMAIN = "somavera:vera-host-descriptor-succession:v1\n";
const PRIOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nprior\n";
const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nsuccessor\n";
const MAX_PROOF_SECONDS = 900;

const json = async (relative) => JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
const same = (left, right) => canonicalize(left) === canonicalize(right);
const seconds = (start, end) => (Date.parse(end) - Date.parse(start)) / 1000;
const covers = (key, start, end) => Date.parse(key.lifecycle.valid_from) <= Date.parse(start) && Date.parse(end) <= Date.parse(key.lifecycle.valid_until);
const digest = (domain, value) => createHash("sha256").update(domain, "utf8").update(canonicalize(value), "utf8").digest("hex");

export function descriptorCore(descriptor) {
  const { $schema, descriptor_id, signature, ...core } = descriptor;
  return core;
}

export function successionCore(proof) {
  const { $schema, succession_id, signatures, ...core } = proof;
  return core;
}

export const deriveDescriptorId = (descriptor) => digest(DESCRIPTOR_ID_DOMAIN, descriptorCore(descriptor));
export const deriveSuccessionId = (proof) => digest(SUCCESSION_ID_DOMAIN, successionCore(proof));

function publicKey(key) {
  const raw = Buffer.from(key.public_key_base64, "base64");
  if (raw.length !== 32) throw new Error("invalid Ed25519 public key length");
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
}

function verifyEd25519(key, domain, id, signature) {
  try {
    return verify(null, Buffer.concat([Buffer.from(domain), Buffer.from(id, "hex")]), publicKey(key), Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

function keyById(keys, id) {
  return keys.find((key) => key.key_id === id);
}

function lifecycleWithoutStatus(key) {
  const { status, ...lifecycle } = key.lifecycle;
  return lifecycle;
}

function keyIdentityEqual(left, right) {
  return Boolean(left && right) && left.key_id === right.key_id && left.purpose === right.purpose && left.suite === right.suite && left.public_key_base64 === right.public_key_base64;
}

function validateDescriptorCryptography(descriptor, errors, label) {
  if (deriveDescriptorId(descriptor) !== descriptor.descriptor_id) errors.push(label + "_DESCRIPTOR_ID_INVALID");
  const signingKeys = descriptor.host_signing_keys || [];
  const ingestionKeys = descriptor.ingestion_encryption_keys || [];
  const active = keyById(signingKeys, descriptor.active_host_signing_key_id);
  const activeIngestion = keyById(ingestionKeys, descriptor.active_ingestion_key_id);
  if (signingKeys.filter((key) => key.lifecycle.status === "active").length !== 1 || ingestionKeys.filter((key) => key.lifecycle.status === "active").length !== 1) errors.push(label + "_ACTIVE_KEY_AMBIGUOUS");
  const signingIds = new Set(signingKeys.map((key) => key.key_id));
  const ingestionIds = new Set(ingestionKeys.map((key) => key.key_id));
  const signingMaterial = new Set(signingKeys.map((key) => key.public_key_base64));
  if ([...signingIds].some((id) => ingestionIds.has(id)) || ingestionKeys.some((key) => signingMaterial.has(key.public_key_base64))) errors.push(label + "_KEY_ROLE_REUSE");
  if (!active || active.lifecycle.status !== "active") {
    errors.push(label + "_ACTIVE_SIGNING_KEY_INVALID");
    return;
  }
  if (!activeIngestion || activeIngestion.lifecycle.status !== "active") errors.push(label + "_ACTIVE_INGESTION_KEY_INVALID");
  if (!covers(active, descriptor.issued_at, descriptor.expires_at) || (activeIngestion && !covers(activeIngestion, descriptor.issued_at, descriptor.expires_at))) errors.push(label + "_ACTIVE_KEY_WINDOW_INVALID");
  if (descriptor.signature?.key_id !== active.key_id || descriptor.signature?.suite !== "Ed25519-v1" || !verifyEd25519(active, DESCRIPTOR_SIGNATURE_DOMAIN, descriptor.descriptor_id, descriptor.signature?.value || "")) {
    errors.push(label + "_DESCRIPTOR_SIGNATURE_INVALID");
  }
}

function validateKeyInventory(priorKeys, successorKeys, priorActiveId, successorActiveId, maximumOverlapSeconds, cutoverTime, role, errors) {
  const upper = role.toUpperCase();
  const priorActive = keyById(priorKeys, priorActiveId);
  const successorActive = keyById(successorKeys, successorActiveId);
  for (const [inventory, phase] of [[priorKeys, "PRIOR"], [successorKeys, "SUCCESSOR"]]) {
    if (new Set(inventory.map((key) => key.key_id)).size !== inventory.length) errors.push(phase + "_" + upper + "_KEY_ID_DUPLICATE");
    if (new Set(inventory.map((key) => key.public_key_base64)).size !== inventory.length) errors.push(phase + "_" + upper + "_KEY_MATERIAL_DUPLICATE");
    if (inventory.some((key) => seconds(key.lifecycle.valid_from, key.lifecycle.valid_until) <= 0)) errors.push("KEY_LIFECYCLE_INVALID");
  }
  if (!priorActive || priorActive.lifecycle.status !== "active") errors.push("PRIOR_ACTIVE_" + upper + "_KEY_INVALID");
  if (!successorActive || successorActive.lifecycle.status !== "active") errors.push("SUCCESSOR_ACTIVE_" + upper + "_KEY_INVALID");

  for (const key of [...priorKeys, ...successorKeys]) {
    if (key.lifecycle.status === "overlap" && seconds(key.lifecycle.valid_from, key.lifecycle.valid_until) > maximumOverlapSeconds) {
      errors.push("KEY_OVERLAP_WINDOW_INVALID");
    }
  }

  for (const oldKey of priorKeys) {
    const nextKey = keyById(successorKeys, oldKey.key_id);
    if (!nextKey) {
      errors.push("HISTORIC_KEY_REMOVED");
      continue;
    }
    if (!keyIdentityEqual(oldKey, nextKey)) errors.push("HISTORIC_KEY_IDENTITY_CHANGED");
    if (!same(lifecycleWithoutStatus(oldKey), lifecycleWithoutStatus(nextKey))) errors.push("HISTORIC_KEY_LIFECYCLE_CHANGED");
    if (oldKey.lifecycle.status === "revoked" || nextKey.lifecycle.status === "revoked") errors.push("EMERGENCY_RECOVERY_UNSUPPORTED");
    if (["retired", "revoked"].includes(oldKey.lifecycle.status) && nextKey.lifecycle.status !== oldKey.lifecycle.status) errors.push("HISTORIC_KEY_REACTIVATED");
  }

  for (const nextKey of successorKeys) {
    const oldKey = keyById(priorKeys, nextKey.key_id);
    if (!oldKey && nextKey.lifecycle.status !== "overlap") errors.push("UNCOMMITTED_NEW_ACTIVE_KEY");
  }

  if (priorActiveId !== successorActiveId) {
    const precommitted = keyById(priorKeys, successorActiveId);
    if (!precommitted || precommitted.lifecycle.status !== "overlap" || !covers(precommitted, cutoverTime, cutoverTime) || !keyIdentityEqual(precommitted, successorActive)) {
      errors.push("SUCCESSOR_" + upper + "_KEY_NOT_PRECOMMITTED");
    }
    const retiredPrior = keyById(successorKeys, priorActiveId);
    if (!retiredPrior || retiredPrior.lifecycle.status !== "retired") errors.push("PRIOR_ACTIVE_KEY_NOT_RETIRED");
  }
}

export function validateHostSuccession({ prior, successor, proof, validationTime }) {
  const errors = [];
  const immutableExclusions = new Set([
    "$schema", "descriptor_id", "descriptor_sequence", "previous_descriptor_id", "host_signing_keys",
    "ingestion_encryption_keys", "active_host_signing_key_id", "active_ingestion_key_id", "issued_at", "expires_at", "signature"
  ]);
  for (const key of new Set([...Object.keys(prior), ...Object.keys(successor)])) {
    if (!immutableExclusions.has(key) && !same(prior[key], successor[key])) errors.push("IMMUTABLE_DESCRIPTOR_FIELD_CHANGED:" + key);
  }

  if (successor.descriptor_sequence !== prior.descriptor_sequence + 1) errors.push("SUCCESSOR_SEQUENCE_INVALID");
  if (successor.previous_descriptor_id !== prior.descriptor_id) errors.push("PREDECESSOR_MISMATCH");
  if (successor.descriptor_id === prior.descriptor_id) errors.push("DESCRIPTOR_ID_REUSE");

  const bindings = [
    ["network_lineage_id", prior.network_lineage_id],
    ["execution_context_id", prior.execution_context_id],
    ["host_did", prior.host_did],
    ["origin", prior.origin],
    ["prior_descriptor_id", prior.descriptor_id],
    ["prior_descriptor_sequence", prior.descriptor_sequence],
    ["successor_descriptor_id", successor.descriptor_id],
    ["successor_descriptor_sequence", successor.descriptor_sequence],
    ["prior_active_host_signing_key_id", prior.active_host_signing_key_id],
    ["successor_active_host_signing_key_id", successor.active_host_signing_key_id],
    ["prior_active_ingestion_key_id", prior.active_ingestion_key_id],
    ["successor_active_ingestion_key_id", successor.active_ingestion_key_id]
  ];
  for (const [field, expected] of bindings) if (!same(proof[field], expected)) errors.push("SUCCESSION_BINDING_MISMATCH:" + field);

  const policy = prior.rotation_policy || {};
  if (!same(policy, successor.rotation_policy)) errors.push("ROTATION_POLICY_CHANGED");
  if (seconds(prior.issued_at, prior.expires_at) <= 0 || seconds(prior.issued_at, prior.expires_at) > policy.maximum_descriptor_lifetime_seconds) errors.push("PRIOR_DESCRIPTOR_LIFETIME_INVALID");
  if (seconds(successor.issued_at, successor.expires_at) <= 0 || seconds(successor.issued_at, successor.expires_at) > policy.maximum_descriptor_lifetime_seconds) errors.push("SUCCESSOR_DESCRIPTOR_LIFETIME_INVALID");
  if (seconds(proof.issued_at, proof.expires_at) <= 0 || seconds(proof.issued_at, proof.expires_at) > MAX_PROOF_SECONDS) errors.push("SUCCESSION_LIFETIME_INVALID");
  const issued = Date.parse(proof.issued_at);
  const expires = Date.parse(proof.expires_at);
  const now = Date.parse(validationTime);
  if (!(issued <= now && now <= expires)) errors.push("SUCCESSION_NOT_CURRENT");
  for (const descriptor of [prior, successor]) {
    if (!(Date.parse(descriptor.issued_at) <= issued && expires <= Date.parse(descriptor.expires_at))) errors.push("SUCCESSION_OUTSIDE_DESCRIPTOR_VALIDITY");
  }

  validateDescriptorCryptography(prior, errors, "PRIOR");
  validateDescriptorCryptography(successor, errors, "SUCCESSOR");
  validateKeyInventory(prior.host_signing_keys || [], successor.host_signing_keys || [], prior.active_host_signing_key_id, successor.active_host_signing_key_id, policy.maximum_overlap_seconds, proof.issued_at, "signing", errors);
  validateKeyInventory(prior.ingestion_encryption_keys || [], successor.ingestion_encryption_keys || [], prior.active_ingestion_key_id, successor.active_ingestion_key_id, policy.maximum_overlap_seconds, proof.issued_at, "ingestion", errors);

  const signingChanged = prior.active_host_signing_key_id !== successor.active_host_signing_key_id;
  const ingestionChanged = prior.active_ingestion_key_id !== successor.active_ingestion_key_id;
  const expectedScope = signingChanged && ingestionChanged ? "signing_and_ingestion_key_rotation" : signingChanged ? "signing_key_rotation" : ingestionChanged ? "ingestion_key_rotation" : "renewal_only";
  if (proof.change_scope !== expectedScope || !(policy.allowed_change_scopes || []).includes(expectedScope)) errors.push("CHANGE_SCOPE_MISMATCH");

  if (deriveSuccessionId(proof) !== proof.succession_id) errors.push("SUCCESSION_ID_INVALID");
  const priorSigning = keyById(prior.host_signing_keys || [], prior.active_host_signing_key_id);
  const successorSigning = keyById(successor.host_signing_keys || [], successor.active_host_signing_key_id);
  const priorSignature = proof.signatures?.prior_active_key_signature;
  const successorSignature = proof.signatures?.successor_active_key_signature;
  if (priorSignature?.key_id !== prior.active_host_signing_key_id || priorSignature?.suite !== "Ed25519-v1" || !priorSigning || !verifyEd25519(priorSigning, PRIOR_SIGNATURE_DOMAIN, proof.succession_id, priorSignature?.value || "")) errors.push("PRIOR_SUCCESSION_SIGNATURE_INVALID");
  if (successorSignature?.key_id !== successor.active_host_signing_key_id || successorSignature?.suite !== "Ed25519-v1" || !successorSigning || !verifyEd25519(successorSigning, SUCCESSOR_SIGNATURE_DOMAIN, proof.succession_id, successorSignature?.value || "")) errors.push("SUCCESSOR_SUCCESSION_SIGNATURE_INVALID");

  const authority = proof.authority || {};
  if (proof.controller_confirmation_required !== true || authority.continuity_only !== true || authority.authorizes_connection !== false || authority.authorizes_consent !== false || authority.authorizes_disclosure !== false || authority.authorizes_emergency_recovery !== false) errors.push("SUCCESSION_AUTHORITY_INVALID");
  return [...new Set(errors)];
}

function corruptBase64(value) {
  return (value[0] === "A" ? "B" : "A") + value.slice(1);
}

function mutate(vector, mutation) {
  const prior = vector.prior_descriptor;
  const successor = vector.successor_descriptor;
  const proof = vector.succession_proof;
  if (mutation === "sequence_skip") { successor.descriptor_sequence += 1; proof.successor_descriptor_sequence += 1; }
  if (mutation === "wrong_predecessor") successor.previous_descriptor_id = "22".repeat(32);
  if (mutation === "immutable_origin_change") successor.origin = "https://attacker.example.test";
  if (mutation === "unprecommitted_signing_key") prior.host_signing_keys[1].public_key_base64 = Buffer.alloc(32, 0x55).toString("base64");
  if (mutation === "unprecommitted_ingestion_key") prior.ingestion_encryption_keys[1].public_key_base64 = Buffer.alloc(32, 0x56).toString("base64");
  if (mutation === "expired_precommit") prior.host_signing_keys[1].lifecycle.valid_until = "2027-01-01T11:59:59Z";
  if (mutation === "scope_mismatch") proof.change_scope = "renewal_only";
  if (mutation === "proof_too_long") proof.expires_at = "2027-01-01T12:15:01Z";
  if (mutation === "role_signature_replay") proof.signatures.prior_active_key_signature.value = proof.signatures.successor_active_key_signature.value;
  if (mutation === "successor_signature_corruption") proof.signatures.successor_active_key_signature.value = corruptBase64(proof.signatures.successor_active_key_signature.value);
  if (mutation === "historic_key_removal") successor.host_signing_keys.splice(0, 1);
  if (mutation === "historic_lifecycle_rewrite") successor.host_signing_keys[0].lifecycle.valid_until = "2027-01-03T00:00:00Z";
  if (mutation === "ambiguous_active_key") successor.host_signing_keys[0].lifecycle.status = "active";
  if (mutation === "emergency_revocation_smuggling") { successor.host_signing_keys[0].lifecycle.status = "revoked"; successor.host_signing_keys[0].lifecycle.revoked_at = proof.issued_at; successor.host_signing_keys[0].lifecycle.revocation_reference = "unratified-emergency"; }
  if (mutation === "overlap_window_too_long") prior.host_signing_keys[1].lifecycle.valid_until = "2027-01-03T00:00:01Z";
  if (mutation === "descriptor_signature_corruption") prior.signature.value = corruptBase64(prior.signature.value);
  if (mutation === "authority_escalation") proof.authority.authorizes_connection = true;
}

let checks = 0;
function assert(condition, message) {
  if (!condition) throw new Error(message);
  checks += 1;
}

const vector = await json("conformance/host-descriptor-succession-v1.json");
assert(canonicalize(descriptorCore(vector.prior_descriptor)) === vector.expected.prior_descriptor_core_jcs, "prior descriptor canonical bytes differ");
assert(canonicalize(descriptorCore(vector.successor_descriptor)) === vector.expected.successor_descriptor_core_jcs, "successor descriptor canonical bytes differ");
assert(canonicalize(successionCore(vector.succession_proof)) === vector.expected.succession_core_jcs, "succession canonical bytes differ");
assert(deriveDescriptorId(vector.prior_descriptor) === vector.expected.prior_descriptor_id, "prior descriptor ID differs");
assert(deriveDescriptorId(vector.successor_descriptor) === vector.expected.successor_descriptor_id, "successor descriptor ID differs");
assert(deriveSuccessionId(vector.succession_proof) === vector.expected.succession_id, "succession ID differs");
const positiveErrors = validateHostSuccession({ prior: vector.prior_descriptor, successor: vector.successor_descriptor, proof: vector.succession_proof, validationTime: vector.validation_time });
assert(positiveErrors.length === 0, "valid host succession rejected: " + positiveErrors.join(", "));

const invalid = await json("conformance/host-descriptor-succession-invalid-v1.json");
for (const test of invalid.cases) {
  const candidate = structuredClone(vector);
  mutate(candidate, test.mutation);
  const errors = validateHostSuccession({ prior: candidate.prior_descriptor, successor: candidate.successor_descriptor, proof: candidate.succession_proof, validationTime: candidate.validation_time });
  assert(errors.some((error) => error.startsWith(test.expected_error)), test.name + " did not produce " + test.expected_error + "; got " + errors.join(", "));
}

console.log("Host descriptor succession conformance checks passed: " + checks);
console.log("Ordinary continuity remains inert until separate controller confirmation; emergency compromise recovery remains unsupported.");
