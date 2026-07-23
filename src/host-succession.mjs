import { mkdir, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { privateKeyForRole, sha256, signEd25519, verifyEd25519, verifyEd25519RawBase64 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import {
  controllerSecret,
  durableFile,
  eraseSecretBundle,
  publicIdentity,
  readCanonicalFile,
  verifiedHostPinForDid,
  verifyHostDescriptor
} from "./host.mjs";
import { assertJsonSchema } from "./json-schema.mjs";
import { RELEASE_ROOT } from "./constants.mjs";
import { successionSubject } from "./host-confirmation-domain.mjs";
import { acquireHostSuccessionLock } from "./host-lock.mjs";

const DESCRIPTOR_ID_DOMAIN = "somavera:vera-host-descriptor:v1\n";
const DESCRIPTOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-signature:v1\n";
const SUCCESSION_ID_DOMAIN = "somavera:vera-host-descriptor-succession:v1\n";
const PRIOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nprior\n";
const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nsuccessor\n";
const CANDIDATE_ID_DOMAIN = "soma:host-succession-candidate:provisional-v1\n";
const CANDIDATE_SIGNATURE_DOMAIN = "soma:host-succession-candidate-signature:provisional-v1\n";
const CANDIDATE_AUTHORITY = "offline_candidate_only_no_pin_replacement_no_connection_no_consent_no_send";
const CANDIDATE_FIELDS = [
  "authority", "candidate_id", "change_scope", "confirmed", "connected", "controller_did", "created_at",
  "host_did", "prior_descriptor_id", "prior_pin_id", "schema_version", "signature", "succession_id",
  "succession_proof", "successor_active_signing_key_sha256", "successor_descriptor", "successor_descriptor_id"
];
const SIGNATURE_FIELDS = ["key_id", "suite", "value"];

const same = (left, right) => canonicalize(left) === canonicalize(right);
const seconds = (start, end) => (Date.parse(end) - Date.parse(start)) / 1000;
const covers = (key, start, end) => Date.parse(key.lifecycle.valid_from) <= Date.parse(start) && Date.parse(end) <= Date.parse(key.lifecycle.valid_until);

function exactIso(value, code, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new SomaError(`${label} must be a canonical UTC timestamp`, 7, code);
  const normalized = new Date(value).toISOString();
  if (value !== normalized && value !== normalized.replace(".000Z", "Z")) throw new SomaError(`${label} is not a real canonical UTC instant`, 7, code);
  return Date.parse(value);
}

function exactObject(value, fields, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SomaError(`${label} must be an object`, 7, code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) throw new SomaError(`${label} has missing or unknown fields`, 7, code, { actual, expected });
}

function descriptorCore(descriptor) {
  const { $schema, descriptor_id, signature, ...core } = descriptor;
  return core;
}

function successionCore(proof) {
  const { $schema, succession_id, signatures, ...core } = proof;
  return core;
}

function candidateCore(candidate) {
  const { candidate_id, signature, ...core } = candidate;
  return core;
}

export const deriveHostDescriptorId = (descriptor) => sha256(Buffer.from(DESCRIPTOR_ID_DOMAIN + canonicalize(descriptorCore(descriptor))));
export const deriveHostSuccessionId = (proof) => sha256(Buffer.from(SUCCESSION_ID_DOMAIN + canonicalize(successionCore(proof))));

function keyById(keys, id) {
  return keys.find((key) => key.key_id === id);
}

function keyIdentityEqual(left, right) {
  return Boolean(left && right) && left.key_id === right.key_id && left.purpose === right.purpose && left.suite === right.suite && left.public_key_base64 === right.public_key_base64;
}

function lifecycleWithoutStatus(key) {
  const { status, ...lifecycle } = key.lifecycle;
  return lifecycle;
}

function verifyDescriptorCryptography(descriptor, errors, label) {
  if (deriveHostDescriptorId(descriptor) !== descriptor.descriptor_id) errors.push(`${label}_DESCRIPTOR_ID_INVALID`);
  const signing = descriptor.host_signing_keys || [];
  const ingestion = descriptor.ingestion_encryption_keys || [];
  const active = keyById(signing, descriptor.active_host_signing_key_id);
  const activeIngestion = keyById(ingestion, descriptor.active_ingestion_key_id);
  if (signing.filter((key) => key.lifecycle.status === "active").length !== 1 || ingestion.filter((key) => key.lifecycle.status === "active").length !== 1) errors.push(`${label}_ACTIVE_KEY_AMBIGUOUS`);
  if (!active || active.lifecycle.status !== "active") errors.push(`${label}_ACTIVE_SIGNING_KEY_INVALID`);
  if (!activeIngestion || activeIngestion.lifecycle.status !== "active") errors.push(`${label}_ACTIVE_INGESTION_KEY_INVALID`);
  if (active && !covers(active, descriptor.issued_at, descriptor.expires_at)) errors.push(`${label}_ACTIVE_KEY_WINDOW_INVALID`);
  if (activeIngestion && !covers(activeIngestion, descriptor.issued_at, descriptor.expires_at)) errors.push(`${label}_ACTIVE_KEY_WINDOW_INVALID`);
  if (active && (descriptor.signature?.key_id !== active.key_id || descriptor.signature?.suite !== "Ed25519-v1" || !verifyEd25519RawBase64(active.public_key_base64, Buffer.concat([Buffer.from(DESCRIPTOR_SIGNATURE_DOMAIN), Buffer.from(descriptor.descriptor_id, "hex")]), descriptor.signature?.value || ""))) errors.push(`${label}_DESCRIPTOR_SIGNATURE_INVALID`);
}

function validateInventory(priorKeys, successorKeys, priorActiveId, successorActiveId, maximumOverlapSeconds, cutoverTime, role, errors) {
  const upper = role.toUpperCase();
  for (const [inventory, phase] of [[priorKeys, "PRIOR"], [successorKeys, "SUCCESSOR"]]) {
    if (new Set(inventory.map((key) => key.key_id)).size !== inventory.length) errors.push(`${phase}_${upper}_KEY_ID_DUPLICATE`);
    if (new Set(inventory.map((key) => key.public_key_base64)).size !== inventory.length) errors.push(`${phase}_${upper}_KEY_MATERIAL_DUPLICATE`);
    for (const key of inventory) {
      if (seconds(key.lifecycle.valid_from, key.lifecycle.valid_until) <= 0) errors.push("KEY_LIFECYCLE_INVALID");
      if (key.lifecycle.status === "overlap" && seconds(key.lifecycle.valid_from, key.lifecycle.valid_until) > maximumOverlapSeconds) errors.push("KEY_OVERLAP_WINDOW_INVALID");
    }
  }
  for (const oldKey of priorKeys) {
    const nextKey = keyById(successorKeys, oldKey.key_id);
    if (!nextKey) { errors.push("HISTORIC_KEY_REMOVED"); continue; }
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
    const successorActive = keyById(successorKeys, successorActiveId);
    if (!precommitted || precommitted.lifecycle.status !== "overlap" || !covers(precommitted, cutoverTime, cutoverTime) || !keyIdentityEqual(precommitted, successorActive)) errors.push(`SUCCESSOR_${upper}_KEY_NOT_PRECOMMITTED`);
    const retiredPrior = keyById(successorKeys, priorActiveId);
    if (!retiredPrior || retiredPrior.lifecycle.status !== "retired") errors.push("PRIOR_ACTIVE_KEY_NOT_RETIRED");
  }
}

export function validateOrdinaryHostSuccession(prior, successor, proof, { validationTime = Date.now() } = {}) {
  const errors = [];
  const immutableExclusions = new Set(["$schema", "descriptor_id", "descriptor_sequence", "previous_descriptor_id", "host_signing_keys", "ingestion_encryption_keys", "active_host_signing_key_id", "active_ingestion_key_id", "issued_at", "expires_at", "signature"]);
  for (const key of new Set([...Object.keys(prior), ...Object.keys(successor)])) if (!immutableExclusions.has(key) && !same(prior[key], successor[key])) errors.push(`IMMUTABLE_DESCRIPTOR_FIELD_CHANGED:${key}`);
  if (successor.descriptor_sequence !== prior.descriptor_sequence + 1) errors.push("SUCCESSOR_SEQUENCE_INVALID");
  if (successor.previous_descriptor_id !== prior.descriptor_id) errors.push("PREDECESSOR_MISMATCH");
  const bindings = [
    ["network_lineage_id", prior.network_lineage_id], ["execution_context_id", prior.execution_context_id], ["host_did", prior.host_did], ["origin", prior.origin],
    ["prior_descriptor_id", prior.descriptor_id], ["prior_descriptor_sequence", prior.descriptor_sequence], ["successor_descriptor_id", successor.descriptor_id], ["successor_descriptor_sequence", successor.descriptor_sequence],
    ["prior_active_host_signing_key_id", prior.active_host_signing_key_id], ["successor_active_host_signing_key_id", successor.active_host_signing_key_id], ["prior_active_ingestion_key_id", prior.active_ingestion_key_id], ["successor_active_ingestion_key_id", successor.active_ingestion_key_id]
  ];
  for (const [field, expected] of bindings) if (!same(proof[field], expected)) errors.push(`SUCCESSION_BINDING_MISMATCH:${field}`);
  const policy = prior.rotation_policy || {};
  if (!same(policy, successor.rotation_policy)) errors.push("ROTATION_POLICY_CHANGED");
  if (seconds(proof.issued_at, proof.expires_at) <= 0 || seconds(proof.issued_at, proof.expires_at) > 900) errors.push("SUCCESSION_LIFETIME_INVALID");
  const issued = Date.parse(proof.issued_at), expires = Date.parse(proof.expires_at);
  if (!(issued <= validationTime && validationTime <= expires)) errors.push("SUCCESSION_NOT_CURRENT");
  for (const descriptor of [prior, successor]) if (!(Date.parse(descriptor.issued_at) <= issued && expires <= Date.parse(descriptor.expires_at))) errors.push("SUCCESSION_OUTSIDE_DESCRIPTOR_VALIDITY");
  verifyDescriptorCryptography(prior, errors, "PRIOR");
  verifyDescriptorCryptography(successor, errors, "SUCCESSOR");
  validateInventory(prior.host_signing_keys || [], successor.host_signing_keys || [], prior.active_host_signing_key_id, successor.active_host_signing_key_id, policy.maximum_overlap_seconds, proof.issued_at, "signing", errors);
  validateInventory(prior.ingestion_encryption_keys || [], successor.ingestion_encryption_keys || [], prior.active_ingestion_key_id, successor.active_ingestion_key_id, policy.maximum_overlap_seconds, proof.issued_at, "ingestion", errors);
  const signingChanged = prior.active_host_signing_key_id !== successor.active_host_signing_key_id;
  const ingestionChanged = prior.active_ingestion_key_id !== successor.active_ingestion_key_id;
  const expectedScope = signingChanged && ingestionChanged ? "signing_and_ingestion_key_rotation" : signingChanged ? "signing_key_rotation" : ingestionChanged ? "ingestion_key_rotation" : "renewal_only";
  if (proof.change_scope !== expectedScope || !(policy.allowed_change_scopes || []).includes(expectedScope)) errors.push("CHANGE_SCOPE_MISMATCH");
  if (deriveHostSuccessionId(proof) !== proof.succession_id) errors.push("SUCCESSION_ID_INVALID");
  const priorSigning = keyById(prior.host_signing_keys || [], prior.active_host_signing_key_id);
  const successorSigning = keyById(successor.host_signing_keys || [], successor.active_host_signing_key_id);
  const priorSignature = proof.signatures?.prior_active_key_signature;
  const successorSignature = proof.signatures?.successor_active_key_signature;
  if (!priorSigning || priorSignature?.key_id !== prior.active_host_signing_key_id || !verifyEd25519RawBase64(priorSigning.public_key_base64, Buffer.concat([Buffer.from(PRIOR_SIGNATURE_DOMAIN), Buffer.from(proof.succession_id, "hex")]), priorSignature?.value || "")) errors.push("PRIOR_SUCCESSION_SIGNATURE_INVALID");
  if (!successorSigning || successorSignature?.key_id !== successor.active_host_signing_key_id || !verifyEd25519RawBase64(successorSigning.public_key_base64, Buffer.concat([Buffer.from(SUCCESSOR_SIGNATURE_DOMAIN), Buffer.from(proof.succession_id, "hex")]), successorSignature?.value || "")) errors.push("SUCCESSOR_SUCCESSION_SIGNATURE_INVALID");
  const authority = proof.authority || {};
  if (proof.controller_confirmation_required !== true || authority.continuity_only !== true || authority.authorizes_connection !== false || authority.authorizes_consent !== false || authority.authorizes_disclosure !== false || authority.authorizes_emergency_recovery !== false) errors.push("SUCCESSION_AUTHORITY_INVALID");
  const violations = [...new Set(errors)];
  if (violations.length) throw new SomaError("ordinary host succession proof is invalid", 8, "HOST_SUCCESSION_INVALID", { violations });
  return { succession_id: proof.succession_id, change_scope: expectedScope, prior_descriptor_id: prior.descriptor_id, successor_descriptor_id: successor.descriptor_id };
}

async function candidateSchema() {
  return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", "host-succession-candidate.provisional.schema.json"), "utf8"));
}

async function proofSchema() {
  return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", "vera-host-descriptor-succession.v1.schema.json"), "utf8"));
}

export function candidateDirectory(home) {
  return path.join(home, "hosts", "candidates");
}

export function candidateFile(home, hostDid) {
  return path.join(candidateDirectory(home), `${sha256(Buffer.from(`soma:host-succession-candidate-file:provisional-v1\n${hostDid}`))}.json`);
}

function storedIntegrityError(error) {
  if (!(error instanceof SomaError) || error.exitCode === 7) return error;
  if (["JSON_INVALID", "JSON_NOT_CANONICAL", "JSON_PROFILE_INVALID"].includes(error.code)) {
    return new SomaError("stored host succession candidate is not canonical JSON", 7, "HOST_SUCCESSION_CANDIDATE_ENCODING_INVALID", { cause_code: error.code });
  }
  return new SomaError(error.message, 7, error.code, error.details);
}

export async function storedCandidate(home, file, identity, options = {}) {
  try {
    const record = parseCanonicalJson(await readFile(file, "utf8"), "stored host succession candidate");
    return { record, summary: await verifyCandidateRecord(home, record, identity, options) };
  } catch (error) {
    throw storedIntegrityError(error);
  }
}

export async function verifyCandidateRecord(home, record, identity, { currentTime = Date.now(), priorPin = null } = {}) {
  assertJsonSchema(record, await candidateSchema(), { code: "HOST_SUCCESSION_CANDIDATE_SCHEMA_INVALID", label: "host succession candidate", exitCode: 7 });
  exactObject(record, CANDIDATE_FIELDS, "HOST_SUCCESSION_CANDIDATE_SHAPE_INVALID", "host succession candidate");
  exactObject(record.signature, SIGNATURE_FIELDS, "HOST_SUCCESSION_CANDIDATE_SIGNATURE_INVALID", "candidate signature");
  if (record.schema_version !== "soma.host-succession-candidate.provisional-v1" || record.controller_did !== identity.controller_did || record.authority !== CANDIDATE_AUTHORITY || record.confirmed !== false || record.connected !== false) throw new SomaError("host succession candidate authority fields are invalid", 7, "HOST_SUCCESSION_CANDIDATE_INVARIANT_INVALID");
  const createdAt = exactIso(record.created_at, "HOST_SUCCESSION_CANDIDATE_TIME_INVALID", "candidate created_at");
  const pin = priorPin || (await verifiedHostPinForDid(home, record.host_did, identity)).record;
  if (pin.pin_id !== record.prior_pin_id || pin.descriptor.descriptor_id !== record.prior_descriptor_id) throw new SomaError("candidate no longer binds the current prior pin", 8, "HOST_SUCCESSION_PRIOR_PIN_MISMATCH");
  assertJsonSchema(record.succession_proof, await proofSchema(), { code: "HOST_SUCCESSION_PROOF_SCHEMA_INVALID", label: "host succession proof", exitCode: 7 });
  validateOrdinaryHostSuccession(pin.descriptor, record.successor_descriptor, record.succession_proof, { validationTime: createdAt });
  const successorKey = keyById(record.successor_descriptor.host_signing_keys, record.successor_descriptor.active_host_signing_key_id);
  const successorHash = sha256(Buffer.from(successorKey.public_key_base64, "base64"));
  const successorExpected = { ...pin.expected, active_signing_key_sha256: successorHash };
  await verifyHostDescriptor(record.successor_descriptor, successorExpected, { validationTime: createdAt, requireCurrent: true, requireKeyHash: true });
  if (record.successor_active_signing_key_sha256 !== successorHash || record.successor_descriptor_id !== record.successor_descriptor.descriptor_id || record.succession_id !== record.succession_proof.succession_id || record.change_scope !== record.succession_proof.change_scope) throw new SomaError("candidate bindings are inconsistent", 7, "HOST_SUCCESSION_CANDIDATE_BINDING_INVALID");
  const computedId = sha256(Buffer.from(CANDIDATE_ID_DOMAIN + canonicalize(candidateCore(record))));
  if (computedId !== record.candidate_id) throw new SomaError("candidate identifier mismatch", 7, "HOST_SUCCESSION_CANDIDATE_ID_INVALID");
  const controller = identity.keys?.find((key) => key.role === "controller_signing" && key.key_id === record.signature.key_id && key.status === "active");
  if (!controller || record.signature.suite !== "Ed25519-v1" || !verifyEd25519(controller.public_key_multibase, Buffer.concat([Buffer.from(CANDIDATE_SIGNATURE_DOMAIN), Buffer.from(record.candidate_id, "hex")]), record.signature.value)) throw new SomaError("candidate controller signature is invalid", 7, "HOST_SUCCESSION_CANDIDATE_SIGNATURE_INVALID");
  const subject = successionSubject(pin.descriptor, record.successor_descriptor, record.succession_proof);
  return { candidate_id: record.candidate_id, subject_id: subject.subject_id, host_did: record.host_did, succession_id: record.succession_id, prior_descriptor_id: record.prior_descriptor_id, successor_descriptor_id: record.successor_descriptor_id, change_scope: record.change_scope, successor_active_signing_key_sha256: successorHash, successor_active_ingestion_key_sha256: subject.successor_active_ingestion_key_sha256, candidate_status: currentTime <= Date.parse(record.succession_proof.expires_at) ? "pending_confirmation_current" : "expired_inert", authority: CANDIDATE_AUTHORITY };
}

async function previewHostSuccessionUnlocked(home, successorFile, proofFile) {
  const successor = await readCanonicalFile(successorFile, 262144, "HOST_SUCCESSOR_DESCRIPTOR_FILE_INVALID", "successor host descriptor");
  const proof = await readCanonicalFile(proofFile, 131072, "HOST_SUCCESSION_PROOF_FILE_INVALID", "host succession proof");
  assertJsonSchema(proof, await proofSchema(), { code: "HOST_SUCCESSION_PROOF_SCHEMA_INVALID", label: "host succession proof" });
  const identity = await publicIdentity(home);
  const { record: pin } = await verifiedHostPinForDid(home, successor.host_did, identity);
  const now = Date.now();
  validateOrdinaryHostSuccession(pin.descriptor, successor, proof, { validationTime: now });
  const successorKey = keyById(successor.host_signing_keys, successor.active_host_signing_key_id);
  const successorHash = sha256(Buffer.from(successorKey.public_key_base64, "base64"));
  await verifyHostDescriptor(successor, { ...pin.expected, active_signing_key_sha256: successorHash }, { validationTime: now, requireCurrent: true, requireKeyHash: true });
  await mkdir(candidateDirectory(home), { recursive: true, mode: 0o700 });
  const target = candidateFile(home, successor.host_did);
  try {
    const { record: existing, summary } = await storedCandidate(home, target, identity);
    if (existing.prior_pin_id === pin.pin_id && existing.successor_descriptor_id === successor.descriptor_id && existing.succession_id === proof.succession_id) return { local_mutation: false, remote_mutation: false, idempotent: true, ...summary, network_actions: 0 };
    throw new SomaError("a different pending candidate already exists for this host", 8, "HOST_SUCCESSION_CANDIDATE_CONFLICT");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const createdAt = new Date(now).toISOString();
  let secretBundle;
  try {
    secretBundle = await controllerSecret(home);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    const core = { schema_version: "soma.host-succession-candidate.provisional-v1", created_at: createdAt, controller_did: identity.controller_did, prior_pin_id: pin.pin_id, host_did: successor.host_did, prior_descriptor_id: pin.descriptor.descriptor_id, successor_descriptor_id: successor.descriptor_id, succession_id: proof.succession_id, change_scope: proof.change_scope, successor_active_signing_key_sha256: successorHash, successor_descriptor: successor, succession_proof: proof, confirmed: false, connected: false, authority: CANDIDATE_AUTHORITY };
    const candidateId = sha256(Buffer.from(CANDIDATE_ID_DOMAIN + canonicalize(core)));
    const record = { ...core, candidate_id: candidateId, signature: { suite: "Ed25519-v1", key_id: controller.key_id, value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from(CANDIDATE_SIGNATURE_DOMAIN), Buffer.from(candidateId, "hex")])) } };
    await verifyCandidateRecord(home, record, identity);
    try { await durableFile(target, `${canonicalize(record)}\n`); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      const { record: existing, summary } = await storedCandidate(home, target, identity);
      if (existing.prior_pin_id !== pin.pin_id || existing.successor_descriptor_id !== successor.descriptor_id || existing.succession_id !== proof.succession_id) throw new SomaError("a different pending candidate already exists for this host", 8, "HOST_SUCCESSION_CANDIDATE_CONFLICT");
      return { local_mutation: false, remote_mutation: false, idempotent: true, ...summary, network_actions: 0 };
    }
    return { local_mutation: true, remote_mutation: false, idempotent: false, ...(await verifyCandidateRecord(home, record, identity)), network_actions: 0 };
  } finally { eraseSecretBundle(secretBundle); }
}

export async function previewHostSuccession(home, successorFile, proofFile) {
  const release = await acquireHostSuccessionLock(home);
  try { return await previewHostSuccessionUnlocked(home, successorFile, proofFile); }
  finally { await release(); }
}

export async function verifyHostSuccessionCandidateStore(home, identity = null) {
  const localIdentity = identity || await publicIdentity(home);
  let entries;
  try { entries = await readdir(candidateDirectory(home), { withFileTypes: true }); } catch (error) { if (error.code === "ENOENT") return []; throw error; }
  const results = [];
  for (const entry of entries) {
    if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("candidate store contains an unsupported entry", 7, "HOST_SUCCESSION_CANDIDATE_STORE_INVALID");
    const file = path.join(candidateDirectory(home), entry.name);
    const { record, summary } = await storedCandidate(home, file, localIdentity);
    if (file !== candidateFile(home, record.host_did)) throw new SomaError("candidate is stored under the wrong path", 7, "HOST_SUCCESSION_CANDIDATE_PATH_INVALID");
    results.push(summary);
  }
  return results.sort((left, right) => left.host_did.localeCompare(right.host_did));
}

export async function hostSuccessionStatus(home) {
  const candidates = await verifyHostSuccessionCandidateStore(home);
  return { pending_host_successions: candidates.length, succession_candidates: candidates, succession_authority: CANDIDATE_AUTHORITY };
}
