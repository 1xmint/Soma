import { open, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { privateKeyForRole, sha256, signEd25519, validateX25519RawBase64, verifyEd25519, verifyEd25519RawBase64 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { assertJsonSchema } from "./json-schema.mjs";
import { unprotectSecretBundle } from "./keystore.mjs";
import { RELEASE_ROOT } from "./constants.mjs";
import { attachPublicKeyHistory, controllerSigningKeyAt } from "./controller-rotation.mjs";
import { restrictStateRoot } from "./platform.mjs";

export const ORIGIN_CAPSULE_HASH = "e1e986648dec5d99aeefdb3fdc14db92b601e6f3ea30bf2e3f6babb97af7e83c";
export const SUPPORTED_ORIGIN_CAPSULE_HASHES = Object.freeze([ORIGIN_CAPSULE_HASH, "3bebd4d13f733c0ad58280c0467f8e79b212400604dd595a0cf3e15af052b663", "047b76b3a96e536893f3dff1a5dc62cd3ac83669769395fe8f48d629e050084f", "9f711a3a8e53502c464efd2798266067adc2d42995246acb3b496c05ef948fb0", "24d5ad1099d9eb915e987511f9ca3725ad44e1dc599783ea1048070f497b3ac4", "8cb60c8ce3199aa35c101657834eece86e8823e9d6aa8eb47a9e23db89582431"]);
const HASH = /^[a-f0-9]{64}$/;
const DID = /^did:[a-z0-9]+:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+(?::(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+)*$/;
const NETWORK = /^somavera:network:v1:[a-f0-9]{64}$/;
const CONTEXT = /^somavera:context:v1:[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const PIN_FIELDS_V1 = ["authority", "connected", "controller_did", "descriptor", "expected", "pin_id", "pinned_at", "rotation_policy", "schema_version", "signature", "trust_basis"];
const PIN_FIELDS_V2 = [...PIN_FIELDS_V1, "confirmation_id", "predecessor_pin_id", "subject_id"];
const EXPECTED_FIELDS = ["active_signing_key_sha256", "execution_context_id", "host_did", "network_lineage_id", "origin"];
const SIGNATURE_FIELDS = ["key_id", "suite", "value"];
const TRUST_BASIS = "exact_bindings_plus_out_of_band_active_signing_key_sha256";
export const SUCCESSION_TRUST_BASIS = "prior_out_of_band_pin_plus_dual_signed_precommitted_succession_plus_controller_confirmation";
export const HOST_PIN_AUTHORITY = "offline_pin_only_no_connection_no_consent_no_send";
const AUTHORITY = HOST_PIN_AUTHORITY;

function exactObject(value, fields, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SomaError(`${label} must be an object`, 7, code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) throw new SomaError(`${label} has missing or unknown fields`, 7, code, { actual, expected });
}

function exactIso(value, code, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new SomaError(`${label} must be an exact UTC timestamp`, 7, code);
  const normalized = new Date(value).toISOString();
  if (value !== normalized && value !== normalized.replace(".000Z", "Z")) throw new SomaError(`${label} is not a real canonical UTC instant`, 7, code);
  return Date.parse(value);
}

function canonicalBase64(value, bytes, code, label) {
  const decoded = Buffer.from(value || "", "base64");
  if (decoded.length !== bytes || decoded.toString("base64") !== value) throw new SomaError(`${label} must be canonical base64 for exactly ${bytes} bytes`, 7, code);
  return decoded;
}

function noControls(value, pointer = "$") {
  if (typeof value === "string" && CONTROL.test(value)) throw new SomaError(`host descriptor contains control characters at ${pointer}`, 7, "HOST_DESCRIPTOR_CONTROL_CHARACTER", { pointer });
  if (Array.isArray(value)) value.forEach((entry, index) => noControls(entry, `${pointer}/${index}`));
  else if (value && typeof value === "object") for (const [key, entry] of Object.entries(value)) noControls(entry, `${pointer}/${key}`);
}

function validateExpectationShape(expected, requireKeyHash) {
  if (!expected || typeof expected !== "object") throw new SomaError("exact host expectations are required", 2, "HOST_EXPECTATION_REQUIRED");
  let url;
  try { url = new URL(expected.origin); } catch { throw new SomaError("expected origin is invalid", 2, "HOST_EXPECTED_ORIGIN_INVALID"); }
  if (url.protocol !== "https:" || url.username || url.password || url.origin !== expected.origin || url.pathname !== "/" || url.search || url.hash) throw new SomaError("expected origin must be one exact credential-free HTTPS origin", 2, "HOST_EXPECTED_ORIGIN_INVALID");
  if (typeof expected.host_did !== "string" || expected.host_did.length > 512 || !DID.test(expected.host_did)) throw new SomaError("expected host DID is invalid", 2, "HOST_EXPECTED_DID_INVALID");
  if (!NETWORK.test(expected.network_lineage_id || "")) throw new SomaError("expected network lineage is invalid", 2, "HOST_EXPECTED_NETWORK_INVALID");
  if (!CONTEXT.test(expected.execution_context_id || "")) throw new SomaError("expected execution context is invalid", 2, "HOST_EXPECTED_CONTEXT_INVALID");
  if (expected.active_signing_key_sha256 !== null && !HASH.test(expected.active_signing_key_sha256 || "")) throw new SomaError("expected active signing-key hash is invalid", 2, "HOST_EXPECTED_KEY_HASH_INVALID");
  if (requireKeyHash && expected.active_signing_key_sha256 === null) throw new SomaError("pinning requires an out-of-band active signing-key SHA-256", 8, "HOST_PIN_KEY_HASH_REQUIRED");
}

export async function readCanonicalFile(file, maximum, code, label) {
  if (!path.isAbsolute(file)) throw new SomaError(`${label} path must be absolute`, 2, `${code}_PATH_RELATIVE`);
  const handle = await open(file, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maximum) throw new SomaError(`${label} must be a regular file no larger than ${maximum} bytes`, 2, code);
    const bytes = Buffer.alloc(maximum + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead > maximum) throw new SomaError(`${label} grew beyond its size limit`, 2, code);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, bytesRead)); } catch { throw new SomaError(`${label} must be valid UTF-8`, 2, code.replace(/_FILE_INVALID$/, "_ENCODING_INVALID")); }
    return parseCanonicalJson(text, label);
  } finally { await handle.close(); }
}

async function descriptorSchema() {
  return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", "vera-host-descriptor.v1.schema.json"), "utf8"));
}

function lifecycle(key, at, label) {
  const from = exactIso(key.lifecycle.valid_from, "HOST_KEY_LIFECYCLE_INVALID", `${label}.valid_from`);
  const until = exactIso(key.lifecycle.valid_until, "HOST_KEY_LIFECYCLE_INVALID", `${label}.valid_until`);
  if (from >= until) throw new SomaError(`${label} has an empty or reversed validity window`, 7, "HOST_KEY_LIFECYCLE_INVALID");
  const revoked = key.lifecycle.status === "revoked";
  if (revoked !== (key.lifecycle.revoked_at !== null && key.lifecycle.revocation_reference !== null)) throw new SomaError(`${label} revocation fields and status disagree`, 7, "HOST_KEY_REVOCATION_INVALID");
  if (!revoked && (key.lifecycle.revoked_at !== null || key.lifecycle.revocation_reference !== null)) throw new SomaError(`${label} non-revoked key has revocation metadata`, 7, "HOST_KEY_REVOCATION_INVALID");
  if (key.lifecycle.status === "overlap" && (until - from) / 1000 > key.maximum_overlap_seconds) throw new SomaError("overlap key exceeds the descriptor rotation-policy window", 8, "HOST_KEY_OVERLAP_WINDOW_INVALID");
  if (revoked) exactIso(key.lifecycle.revoked_at, "HOST_KEY_REVOCATION_INVALID", `${label}.revoked_at`);
  return { activeNow: key.lifecycle.status === "active" && from <= at && at < until, from, until };
}

function descriptorCore(descriptor) {
  const { $schema: ignoredSchema, descriptor_id: ignoredId, signature: ignoredSignature, ...core } = descriptor;
  return core;
}

function pinCore(record) {
  const { pin_id: ignoredId, signature: ignoredSignature, ...core } = record;
  return core;
}

function signingKeyHash(key) {
  return sha256(canonicalBase64(key.public_key_base64, 32, "HOST_SIGNING_KEY_INVALID", "host signing public key"));
}

export async function verifyHostDescriptor(descriptor, expected, { validationTime = Date.now(), requireCurrent = true, requireKeyHash = false, schemaExitCode = 2, acceptedOriginCapsuleHashes = [ORIGIN_CAPSULE_HASH] } = {}) {
  validateExpectationShape(expected, requireKeyHash);
  assertJsonSchema(descriptor, await descriptorSchema(), { code: "HOST_DESCRIPTOR_SCHEMA_INVALID", label: "host descriptor", exitCode: schemaExitCode });
  noControls(descriptor);
  const issuedAt = exactIso(descriptor.issued_at, "HOST_DESCRIPTOR_TIME_INVALID", "descriptor issued_at");
  const expiresAt = exactIso(descriptor.expires_at, "HOST_DESCRIPTOR_TIME_INVALID", "descriptor expires_at");
  if (issuedAt >= expiresAt || issuedAt > validationTime || (requireCurrent && validationTime >= expiresAt)) throw new SomaError("host descriptor is not currently valid", 8, "HOST_DESCRIPTOR_TIME_INVALID");
  if ((expiresAt - issuedAt) / 1000 > descriptor.rotation_policy.maximum_descriptor_lifetime_seconds) throw new SomaError("host descriptor exceeds its committed maximum lifetime", 8, "HOST_DESCRIPTOR_LIFETIME_INVALID");
  if (descriptor.origin !== expected.origin) throw new SomaError("descriptor origin differs from the expected origin", 8, "HOST_ORIGIN_MISMATCH");
  if (descriptor.host_did !== expected.host_did) throw new SomaError("descriptor host DID differs from the expected DID", 8, "HOST_DID_MISMATCH");
  if (descriptor.network_lineage_id !== expected.network_lineage_id) throw new SomaError("descriptor network differs from the expected network", 8, "HOST_NETWORK_MISMATCH");
  if (descriptor.execution_context_id !== expected.execution_context_id) throw new SomaError("descriptor context differs from the expected execution context", 8, "HOST_CONTEXT_MISMATCH");
  if (!Array.isArray(acceptedOriginCapsuleHashes) || !acceptedOriginCapsuleHashes.includes(descriptor.release.origin_capsule_hash)) throw new SomaError("descriptor is bound to an unsupported Origin capsule", 8, "HOST_ORIGIN_CAPSULE_MISMATCH");
  const origin = new URL(descriptor.origin);
  if (origin.origin !== descriptor.origin || origin.hostname !== descriptor.transport_security.server_name) throw new SomaError("descriptor TLS server name does not exactly match its origin", 8, "HOST_TLS_NAME_MISMATCH");
  if (!descriptor.supported_protocols.includes("somavera-soma-vera-private-v1")) throw new SomaError("descriptor lacks the private application protocol", 8, "HOST_PRIVATE_PROTOCOL_MISSING");
  if (descriptor.private_request_endpoint.maximum_plaintext_bytes !== descriptor.capability_limits.maximum_contribution_plaintext_bytes || descriptor.private_request_endpoint.maximum_encrypted_bytes <= descriptor.private_request_endpoint.maximum_plaintext_bytes) throw new SomaError("descriptor request size bounds disagree", 8, "HOST_SIZE_BOUND_MISMATCH");
  if (descriptor.query_policy.maximum_top_k !== descriptor.capability_limits.maximum_top_k || descriptor.query_policy.private_query_retention_seconds !== descriptor.retention_behavior.maximum_private_query_seconds) throw new SomaError("descriptor duplicated query bounds disagree", 8, "HOST_QUERY_BOUND_MISMATCH");
  const regions = new Set(descriptor.data_regions.map((entry) => entry.region_code));
  if (regions.size !== descriptor.data_regions.length) throw new SomaError("descriptor region codes are not unique", 8, "HOST_REGION_DUPLICATE");
  const processorIds = new Set();
  for (const processor of descriptor.subprocessors) {
    if (processorIds.has(processor.processor_id)) throw new SomaError("descriptor subprocessor IDs are not unique", 8, "HOST_SUBPROCESSOR_DUPLICATE");
    processorIds.add(processor.processor_id);
    if (processor.region_codes.some((region) => !regions.has(region))) throw new SomaError("descriptor subprocessor references an undeclared region", 8, "HOST_SUBPROCESSOR_REGION_INVALID");
  }
  const signingIds = new Set();
  const signingPublic = new Set();
  let activeSigning = null;
  for (const [index, key] of descriptor.host_signing_keys.entries()) {
    if (!key.key_id.startsWith(`${descriptor.host_did}#`) || signingIds.has(key.key_id)) throw new SomaError("host signing key IDs are duplicate or outside the host DID", 8, "HOST_SIGNING_KEY_ID_INVALID");
    signingIds.add(key.key_id);
    const raw = canonicalBase64(key.public_key_base64, 32, "HOST_SIGNING_KEY_INVALID", `host_signing_keys[${index}] public key`);
    const publicHash = sha256(raw);
    if (signingPublic.has(publicHash)) throw new SomaError("host signing public keys are duplicated", 8, "HOST_SIGNING_KEY_DUPLICATE");
    signingPublic.add(publicHash);
    const window = lifecycle({ ...key, maximum_overlap_seconds: descriptor.rotation_policy.maximum_overlap_seconds }, validationTime, `host_signing_keys[${index}].lifecycle`);
    if (key.key_id === descriptor.active_host_signing_key_id) {
      if (activeSigning || !window.activeNow || issuedAt < window.from || expiresAt > window.until) throw new SomaError("active host signing key is not uniquely time-valid", 8, "HOST_ACTIVE_SIGNING_KEY_INVALID");
      activeSigning = key;
    }
  }
  const ingestionIds = new Set();
  const ingestionPublic = new Set();
  let activeIngestion = null;
  for (const [index, key] of descriptor.ingestion_encryption_keys.entries()) {
    if (!key.key_id.startsWith(`${descriptor.host_did}#`) || ingestionIds.has(key.key_id) || signingIds.has(key.key_id)) throw new SomaError("ingestion key IDs are duplicate, reused, or outside the host DID", 8, "HOST_INGESTION_KEY_ID_INVALID");
    ingestionIds.add(key.key_id);
    const raw = canonicalBase64(key.public_key_base64, 32, "HOST_INGESTION_KEY_INVALID", `ingestion_encryption_keys[${index}] public key`);
    if (!validateX25519RawBase64(key.public_key_base64)) throw new SomaError("ingestion key is not a usable X25519 public key", 8, "HOST_INGESTION_KEY_INVALID");
    const publicHash = sha256(raw);
    if (ingestionPublic.has(publicHash) || signingPublic.has(publicHash)) throw new SomaError("signing and ingestion public-key sets are not disjoint", 8, "HOST_KEY_ROLE_REUSE");
    ingestionPublic.add(publicHash);
    const window = lifecycle({ ...key, maximum_overlap_seconds: descriptor.rotation_policy.maximum_overlap_seconds }, validationTime, `ingestion_encryption_keys[${index}].lifecycle`);
    if (key.key_id === descriptor.active_ingestion_key_id) {
      if (activeIngestion || !window.activeNow || issuedAt < window.from || expiresAt > window.until) throw new SomaError("active ingestion key is not uniquely time-valid", 8, "HOST_ACTIVE_INGESTION_KEY_INVALID");
      activeIngestion = key;
    }
  }
  if (descriptor.host_signing_keys.filter((key) => key.lifecycle.status === "active").length !== 1 || descriptor.ingestion_encryption_keys.filter((key) => key.lifecycle.status === "active").length !== 1) throw new SomaError("descriptor must contain exactly one active key per role", 8, "HOST_ACTIVE_KEY_AMBIGUOUS");
  if (!activeSigning || !activeIngestion || descriptor.signature.key_id !== activeSigning.key_id) throw new SomaError("descriptor active-key bindings are incomplete or inconsistent", 8, "HOST_ACTIVE_KEY_BINDING_INVALID");
  const computedId = sha256(Buffer.from(`somavera:vera-host-descriptor:v1\n${canonicalize(descriptorCore(descriptor))}`));
  if (computedId !== descriptor.descriptor_id) throw new SomaError("host descriptor identifier does not match its semantic core", 8, "HOST_DESCRIPTOR_ID_MISMATCH");
  const message = Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(computedId, "hex")]);
  if (!verifyEd25519RawBase64(activeSigning.public_key_base64, message, descriptor.signature.value)) throw new SomaError("host descriptor signature is invalid", 8, "HOST_DESCRIPTOR_SIGNATURE_INVALID");
  const activeSigningKeySha256 = signingKeyHash(activeSigning);
  if (expected.active_signing_key_sha256 !== null && expected.active_signing_key_sha256 !== activeSigningKeySha256) throw new SomaError("active signing key differs from the out-of-band expectation", 8, "HOST_SIGNING_KEY_HASH_MISMATCH");
  return {
    descriptor_id: computedId,
    host_did: descriptor.host_did,
    origin: descriptor.origin,
    network_lineage_id: descriptor.network_lineage_id,
    execution_context_id: descriptor.execution_context_id,
    active_host_signing_key_id: activeSigning.key_id,
    active_signing_key_sha256: activeSigningKeySha256,
    active_ingestion_key_id: activeIngestion.key_id,
    active_ingestion_key_sha256: sha256(Buffer.from(activeIngestion.public_key_base64, "base64")),
    origin_capsule_hash: descriptor.release.origin_capsule_hash,
    expires_at: descriptor.expires_at,
    operator_memory_disclosure: descriptor.operator_memory_disclosure,
    metadata_disclosure: descriptor.metadata_disclosure,
    trust_assurance: expected.active_signing_key_sha256 === null ? "self_signature_only_not_operator_authenticated_not_pin_eligible" : TRUST_BASIS,
    pin_eligible: expected.active_signing_key_sha256 !== null,
    authority: "verification_only_no_pin_no_connection_no_consent_no_send",
    network_actions: 0
  };
}

export async function verifyHostDescriptorFile(file, expected) {
  const descriptor = await readCanonicalFile(file, 262144, "HOST_DESCRIPTOR_FILE_INVALID", "host descriptor");
  return { local_mutation: false, remote_mutation: false, ...(await verifyHostDescriptor(descriptor, expected)), descriptor_jcs: canonicalize(descriptor) };
}

export async function publicIdentity(home) {
  const [identity, history] = await Promise.all([
    readFile(path.join(home, "identity", "identity.json"), "utf8").then(JSON.parse),
    readFile(path.join(home, "identity", "public-key-history.json"), "utf8").then(JSON.parse)
  ]);
  return attachPublicKeyHistory(identity, history);
}

export function eraseSecretBundle(bundle) {
  if (!bundle) return;
  for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
  if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
  bundle.root_store_key_base64 = "";
}

export async function controllerSecret(home) {
  const config = JSON.parse(await readFile(path.join(home, "config", "config.json"), "utf8"));
  return unprotectSecretBundle(config.keystore.backend, await readFile(path.join(home, "config", "keystore.blob")));
}

export function hostFile(home, hostDid) {
  const name = sha256(Buffer.from(`soma:host-pin-file:provisional-v1\n${hostDid}`));
  return path.join(home, "hosts", `${name}.json`);
}

export async function durableFile(file, body) {
  const handle = await open(file, "wx", 0o600);
  try { await handle.writeFile(body); await handle.sync(); } finally { await handle.close(); }
}

export async function verifyPinRecord(record, identity, { currentTime = Date.now() } = {}) {
  const version = record?.schema_version;
  const v2 = version === "soma.host-pin.provisional-v2";
  exactObject(record, v2 ? PIN_FIELDS_V2 : PIN_FIELDS_V1, "HOST_PIN_SHAPE_INVALID", "host pin");
  exactObject(record.expected, EXPECTED_FIELDS, "HOST_PIN_EXPECTATION_INVALID", "host pin expectation");
  exactObject(record.signature, SIGNATURE_FIELDS, "HOST_PIN_SIGNATURE_INVALID", "host pin signature");
  const validV1 = !v2 && version === "soma.host-pin.provisional-v1" && record.trust_basis === TRUST_BASIS && record.rotation_policy === "changed_descriptor_blocked_until_ratified_rotation_proof";
  const validV2 = v2 && record.trust_basis === SUCCESSION_TRUST_BASIS && record.rotation_policy === "controller_confirmed_ordinary_succession_inert" && HASH.test(record.predecessor_pin_id || "") && HASH.test(record.confirmation_id || "") && HASH.test(record.subject_id || "");
  if ((!validV1 && !validV2) || record.controller_did !== identity.controller_did || record.authority !== AUTHORITY || record.connected !== false) throw new SomaError("host pin authority or identity fields are invalid", 7, "HOST_PIN_INVARIANT_INVALID");
  const pinnedAt = exactIso(record.pinned_at, "HOST_PIN_TIME_INVALID", "host pin pinned_at");
  if (pinnedAt > currentTime) throw new SomaError("host pin timestamp is in the future", 7, "HOST_PIN_TIME_INVALID");
  let summary;
  try { summary = await verifyHostDescriptor(record.descriptor, record.expected, { validationTime: pinnedAt, requireCurrent: true, requireKeyHash: true, schemaExitCode: 7, acceptedOriginCapsuleHashes: SUPPORTED_ORIGIN_CAPSULE_HASHES }); }
  catch (error) { if (error instanceof SomaError && error.exitCode !== 7) throw new SomaError(error.message, 7, error.code, error.details); throw error; }
  const domain = v2 ? "soma:host-pin:provisional-v2\n" : "soma:host-pin:provisional-v1\n";
  const computedId = sha256(Buffer.from(domain + canonicalize(pinCore(record))));
  if (computedId !== record.pin_id) throw new SomaError("host pin identifier mismatch", 7, "HOST_PIN_ID_MISMATCH");
  const controller = controllerSigningKeyAt(identity, record.signature.key_id, pinnedAt);
  const signatureDomain = v2 ? "soma:host-pin-signature:provisional-v2\n" : "soma:host-pin-signature:provisional-v1\n";
  if (!controller || record.signature.suite !== "Ed25519-v1" || !verifyEd25519(controller.public_key_multibase, Buffer.concat([Buffer.from(signatureDomain), Buffer.from(record.pin_id, "hex")]), record.signature.value)) throw new SomaError("host pin controller signature is invalid", 7, "HOST_PIN_SIGNATURE_INVALID");
  return {
    ...summary,
    trust_assurance: v2 ? SUCCESSION_TRUST_BASIS : summary.trust_assurance,
    pin_id: record.pin_id,
    pinned_at: record.pinned_at,
    pin_schema_version: version,
    ...(v2 ? { predecessor_pin_id: record.predecessor_pin_id, confirmation_id: record.confirmation_id, subject_id: record.subject_id } : {}),
    current_descriptor_status: currentTime < Date.parse(record.descriptor.expires_at) ? "time_valid" : "expired_inert"
  };
}

export async function existingPin(file, identity) {
  try { return parseCanonicalJson(await readFile(file, "utf8"), "stored host pin"); } catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

export async function pinHostDescriptor(home, file, expected) {
  validateExpectationShape(expected, true);
  const descriptor = await readCanonicalFile(file, 262144, "HOST_DESCRIPTOR_FILE_INVALID", "host descriptor");
  const verified = await verifyHostDescriptor(descriptor, expected, { requireKeyHash: true });
  const identity = await publicIdentity(home);
  const target = hostFile(home, descriptor.host_did);
  const current = await existingPin(target, identity);
  if (current) {
    const currentSummary = await verifyPinRecord(current, identity);
    if (current.descriptor.descriptor_id === descriptor.descriptor_id && canonicalize(current.expected) === canonicalize(expected)) return { local_mutation: false, remote_mutation: false, idempotent: true, ...currentSummary, authority: AUTHORITY, network_actions: 0 };
    throw new SomaError("a changed descriptor cannot replace an existing pin until rotation proof is ratified", 8, "HOST_DESCRIPTOR_CHANGE_UNSUPPORTED", { current_descriptor_id: current.descriptor.descriptor_id, proposed_descriptor_id: descriptor.descriptor_id });
  }
  const pinnedAt = new Date().toISOString();
  let secretBundle;
  try {
    secretBundle = await controllerSecret(home);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    const core = {
      schema_version: "soma.host-pin.provisional-v1",
      pinned_at: pinnedAt,
      controller_did: identity.controller_did,
      trust_basis: TRUST_BASIS,
      expected,
      descriptor,
      connected: false,
      rotation_policy: "changed_descriptor_blocked_until_ratified_rotation_proof",
      authority: AUTHORITY
    };
    const pinId = sha256(Buffer.from(`soma:host-pin:provisional-v1\n${canonicalize(core)}`));
    const record = {
      ...core,
      pin_id: pinId,
      signature: {
        suite: "Ed25519-v1",
        key_id: controller.key_id,
        value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from("soma:host-pin-signature:provisional-v1\n"), Buffer.from(pinId, "hex")]))
      }
    };
    await verifyPinRecord(record, identity);
    try { await durableFile(target, `${canonicalize(record)}\n`); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      const raced = await existingPin(target, identity);
      const racedSummary = await verifyPinRecord(raced, identity);
      if (raced.descriptor.descriptor_id !== descriptor.descriptor_id || canonicalize(raced.expected) !== canonicalize(expected)) throw new SomaError("concurrent host pin differs", 8, "HOST_PIN_CONCURRENT_CONFLICT");
      return { local_mutation: false, remote_mutation: false, idempotent: true, ...racedSummary, authority: AUTHORITY, network_actions: 0 };
    }
    return { local_mutation: true, remote_mutation: false, idempotent: false, ...(await verifyPinRecord(record, identity)), descriptor_verification: verified, authority: AUTHORITY, network_actions: 0 };
  } finally {
    eraseSecretBundle(secretBundle);
    if (secretBundle) await restrictStateRoot(home);
  }
}

export async function verifiedHostPinForDid(home, hostDid, identity = null) {
  const localIdentity = identity || await publicIdentity(home);
  const record = await existingPin(hostFile(home, hostDid), localIdentity);
  if (!record) throw new SomaError("no pinned prior descriptor exists for this host", 8, "HOST_PRIOR_PIN_NOT_FOUND");
  const summary = await verifyPinRecord(record, localIdentity);
  return { record, summary, identity: localIdentity };
}

export async function verifyHostPinStore(home, identity = null) {
  const localIdentity = identity || await publicIdentity(home);
  const entries = await readdir(path.join(home, "hosts"), { withFileTypes: true });
  const results = [];
  for (const entry of entries) {
    if (entry.isDirectory() && ["candidates", "history", "transactions"].includes(entry.name)) continue;
    if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("host store contains an unsupported entry", 7, "HOST_STORE_ENTRY_INVALID", { entry: entry.name });
    const file = path.join(home, "hosts", entry.name);
    const record = parseCanonicalJson(await readFile(file, "utf8"), "stored host pin");
    if (file !== hostFile(home, record.descriptor?.host_did)) throw new SomaError("host pin is stored under the wrong content-derived name", 7, "HOST_PIN_PATH_MISMATCH");
    results.push(await verifyPinRecord(record, localIdentity));
  }
  return results.sort((a, b) => a.host_did.localeCompare(b.host_did));
}

export async function hostStatus(home) {
  const pins = await verifyHostPinStore(home);
  return { local_mutation: false, remote_mutation: false, connected_hosts: 0, pinned_hosts: pins.length, pins, authority: AUTHORITY, network_actions: 0 };
}

export function expectedHostBindings(options) {
  return {
    origin: options.expect_origin ?? null,
    host_did: options.expect_host_did ?? null,
    network_lineage_id: options.expect_network ?? null,
    execution_context_id: options.expect_context ?? null,
    active_signing_key_sha256: options.expect_key_hash ?? null
  };
}
