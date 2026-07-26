import { mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { TextDecoder } from "node:util";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { sha256 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { verifyEvidenceLedger } from "./evidence.mjs";
import { restrictStateRoot } from "./platform.mjs";

const HARD_SOURCE_BYTES = 262144;
const HARD_PAYLOAD_BYTES = 400000;
const DID = /^did:[a-z0-9]+:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+(?::(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+)*$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const HASH = /^[a-f0-9]{64}$/;
const POLICY_FIELDS = ["artifact_metadata", "authorized_fields", "controller_did", "data_class", "data_state", "destination", "expires_at", "license", "max_source_bytes", "model_training", "observer_did", "operations", "policy_version", "public_release", "purposes", "redistribution", "replication", "replication_targets", "retention_seconds", "schema_version", "source_kind", "subject_did", "withdrawal_mode"];
const DESTINATION_FIELDS = ["host_did", "origin"];
const LICENSE_FIELDS = ["identifier", "version"];
const ARTIFACT_METADATA_FIELDS = ["controller_attests_rights", "media_type", "rights_basis", "source_uri", "title"];
const PURPOSES = new Set(["private_retrieval", "aggregate_research", "safety_evaluation", "model_training", "public_dataset", "dispute_resolution"]);
const OPERATIONS = new Set(["collect", "store_encrypted", "decrypt_in_attested_process", "derive", "evaluate", "train", "aggregate", "redistribute"]);
const ARTIFACT_FIELDS = Object.freeze(["artifact_hash", "byte_length", "content_base64", "license_identifier", "license_version", "media_type", "source_uri", "title"]);
const EVIDENCE_FIELDS = Object.freeze(["artifact_hashes", "assurance", "capability", "claim_hash", "domain", "evidence_id", "kind", "occurred_at", "task_id"]);
const MEDIA_TYPES = new Set(["text/plain", "text/markdown", "application/json"]);
const RIGHTS_BASES = new Set(["owner_publication", "open_license", "public_domain", "documented_permission"]);
const OPEN_LICENSE_PAIRS = new Set(["Apache@2.0", "BSD-2-Clause@N/A", "BSD-3-Clause@N/A", "CC-BY@4.0", "CC-BY-SA@4.0", "CC0@1.0", "MIT@N/A", "ODC-BY@1.0"]);

const SCAN_PATTERNS = Object.freeze([
  ["private_key_pem", /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
  ["aws_access_key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["github_token", /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g],
  ["openai_api_key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g],
  ["slack_token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ["authorization_header", /\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+\/-]+=*/gi],
  ["credential_assignment", /\b(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|refresh[_-]?token|private[_-]?key|recovery[_-]?(?:key|code))\s*[:=]\s*["']?[^\s"']{8,}/gi],
  ["credentialed_uri", /\bhttps?:\/\/[^\s/@:]+:[^\s/@]+@/gi],
  ["email_identity", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
  ["us_ssn", /\b\d{3}-\d{2}-\d{4}\b/g],
  ["phone_identity", /(?:^|\D)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?:\D|$)/g],
  ["ethereum_address", /\b0x[a-fA-F0-9]{40}\b/g],
  ["bitcoin_address", /\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g],
  ["recovery_phrase_label", /\b(?:seed phrase|recovery phrase|mnemonic)\s*[:=]/gi]
]);

function exactObject(value, fields, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SomaError(`${label} must be an object`, 2, code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new SomaError(`${label} has missing or unknown fields`, 2, code, { expected, actual });
}

function exactIso(value, code, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new SomaError(`${label} must be an exact UTC ISO timestamp`, 2, code);
  return Date.parse(value);
}

function sortedUniqueStrings(value, allowed, code, label) {
  if (!Array.isArray(value) || value.length < 1 || value.some((entry) => typeof entry !== "string") || new Set(value).size !== value.length || value.some((entry, index) => index > 0 && value[index - 1] >= entry)) throw new SomaError(`${label} must be a non-empty sorted unique array`, 2, code);
  if (allowed && value.some((entry) => !allowed.has(entry))) throw new SomaError(`${label} contains an unknown value`, 2, code);
}

function validateDestination(value, code, label = "destination") {
  exactObject(value, DESTINATION_FIELDS, code, label);
  if (typeof value.host_did !== "string" || value.host_did.length > 512 || !DID.test(value.host_did)) throw new SomaError(`${label} host DID is invalid`, 2, code);
  let url;
  try { url = new URL(value.origin); } catch { throw new SomaError(`${label} origin is invalid`, 2, code); }
  if (url.protocol !== "https:" || url.username || url.password || url.origin !== value.origin || url.pathname !== "/" || url.search || url.hash) throw new SomaError(`${label} must be one exact credential-free HTTPS origin`, 2, code);
}

async function readBounded(file, maximum, code, label) {
  if (!path.isAbsolute(file)) throw new SomaError(`${label} path must be absolute`, 2, `${code}_PATH_RELATIVE`);
  const handle = await open(file, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maximum) throw new SomaError(`${label} must be a regular file no larger than ${maximum} bytes`, 2, code);
    const buffer = Buffer.alloc(maximum + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maximum) throw new SomaError(`${label} grew beyond its limit while being read`, 2, code);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function validatePolicy(policy, identity, sourceKind) {
  exactObject(policy, POLICY_FIELDS, "PREVIEW_POLICY_SHAPE_INVALID", "preview policy");
  if (policy.schema_version !== "soma.observation-preview-policy.provisional-v1" || policy.source_kind !== sourceKind) throw new SomaError("preview policy version or source kind is invalid", 2, "PREVIEW_POLICY_INVALID");
  if (![policy.subject_did, policy.controller_did, policy.observer_did].every((value) => typeof value === "string" && value.length <= 512 && DID.test(value)) || policy.subject_did !== identity.agent_did || policy.controller_did !== identity.controller_did || policy.observer_did !== identity.observer_did) throw new SomaError("preview policy identity binding is invalid", 2, "PREVIEW_IDENTITY_MISMATCH");
  if (sourceKind === "artifact" && policy.data_class !== "public_artifact") throw new SomaError("artifact preview supports only public_artifact", 2, "PREVIEW_CLASS_UNSUPPORTED");
  if (sourceKind === "evidence" && policy.data_class !== "work_summary") throw new SomaError("evidence preview supports only work_summary", 2, "PREVIEW_CLASS_UNSUPPORTED");
  const registry = sourceKind === "artifact" ? ARTIFACT_FIELDS : EVIDENCE_FIELDS;
  sortedUniqueStrings(policy.authorized_fields, null, "PREVIEW_FIELDS_INVALID", "authorized_fields");
  if (policy.authorized_fields.some((field) => !registry.includes(field))) throw new SomaError("authorized_fields contains an unknown or prohibited field", 2, "PREVIEW_FIELDS_INVALID");
  sortedUniqueStrings(policy.purposes, PURPOSES, "PREVIEW_PURPOSES_INVALID", "purposes");
  sortedUniqueStrings(policy.operations, OPERATIONS, "PREVIEW_OPERATIONS_INVALID", "operations");
  validateDestination(policy.destination, "PREVIEW_DESTINATION_INVALID");
  if (!Array.isArray(policy.replication_targets) || new Set(policy.replication_targets.map((entry) => canonicalize(entry))).size !== policy.replication_targets.length) throw new SomaError("replication_targets must be a unique array", 2, "PREVIEW_REPLICATION_INVALID");
  for (const [index, destination] of policy.replication_targets.entries()) validateDestination(destination, "PREVIEW_REPLICATION_INVALID", `replication_targets[${index}]`);
  const orderedTargets = policy.replication_targets.map(canonicalize);
  if (orderedTargets.some((entry, index) => index > 0 && orderedTargets[index - 1] >= entry)) throw new SomaError("replication_targets must be canonically sorted", 2, "PREVIEW_REPLICATION_INVALID");
  exactObject(policy.license, LICENSE_FIELDS, "PREVIEW_LICENSE_INVALID", "license");
  if (typeof policy.license.identifier !== "string" || policy.license.identifier.length < 1 || policy.license.identifier.length > 128 || CONTROL.test(policy.license.identifier) || typeof policy.license.version !== "string" || policy.license.version.length < 1 || policy.license.version.length > 64 || CONTROL.test(policy.license.version)) throw new SomaError("license is invalid", 2, "PREVIEW_LICENSE_INVALID");
  if (!Number.isSafeInteger(policy.retention_seconds) || policy.retention_seconds < 0 || policy.retention_seconds > 31536000 || !Number.isSafeInteger(policy.max_source_bytes) || policy.max_source_bytes < 1 || policy.max_source_bytes > HARD_SOURCE_BYTES) throw new SomaError("preview size or retention bound is invalid", 2, "PREVIEW_BOUND_INVALID");
  if (!/^[a-z0-9][a-z0-9_.-]{2,63}$/.test(policy.policy_version || "")) throw new SomaError("policy_version is invalid", 2, "PREVIEW_POLICY_VERSION_INVALID");
  const expiry = exactIso(policy.expires_at, "PREVIEW_EXPIRY_INVALID", "expires_at");
  if (expiry <= Date.now()) throw new SomaError("preview policy is expired", 2, "PREVIEW_POLICY_EXPIRED");
  if (!["none", "aggregate_only", "licensed_artifact"].includes(policy.redistribution) || !["none", "named_hosts", "public"].includes(policy.replication) || !["host_confidential", "federated_training", "public_knowledge"].includes(policy.data_state) || typeof policy.model_training !== "boolean" || typeof policy.public_release !== "boolean" || !["delete_deletable_and_tombstone", "stop_future_use_only"].includes(policy.withdrawal_mode)) throw new SomaError("preview lifecycle term is unknown", 2, "PREVIEW_LIFECYCLE_INVALID");
  if (policy.replication === "none" && policy.replication_targets.length !== 0) throw new SomaError("replication none requires no targets", 2, "PREVIEW_REPLICATION_INVALID");
  if (policy.replication === "named_hosts" && (policy.replication_targets.length < 1 || !policy.replication_targets.some((entry) => canonicalize(entry) === canonicalize(policy.destination)))) throw new SomaError("named_hosts replication must explicitly include the primary destination", 2, "PREVIEW_REPLICATION_INVALID");
  if (policy.replication === "public" && policy.replication_targets.length !== 0) throw new SomaError("public replication uses no hidden named targets", 2, "PREVIEW_REPLICATION_INVALID");
  if (policy.data_state === "host_confidential" && (policy.model_training || policy.public_release || policy.redistribution !== "none" || policy.replication !== "none")) throw new SomaError("host_confidential cannot imply training, release, redistribution, or replication", 2, "PREVIEW_STATE_WIDENING");
  if (policy.data_state === "federated_training" && (!policy.model_training || policy.public_release || !policy.purposes.includes("model_training") || !policy.operations.includes("train") || policy.redistribution !== "none" || policy.replication === "public")) throw new SomaError("federated_training terms are contradictory", 2, "PREVIEW_STATE_WIDENING");
  if (policy.model_training !== policy.purposes.includes("model_training") || policy.model_training !== policy.operations.includes("train")) throw new SomaError("model training boolean, purpose, and operation must agree", 2, "PREVIEW_TRAINING_MISMATCH");
  if (policy.data_state === "public_knowledge" && (!policy.public_release || policy.model_training || policy.redistribution !== "licensed_artifact" || policy.replication !== "public" || !policy.purposes.includes("public_dataset") || !policy.operations.includes("redistribute") || !OPEN_LICENSE_PAIRS.has(`${policy.license.identifier}@${policy.license.version}`))) throw new SomaError("public_knowledge requires explicit public terms and an allow-listed open license identifier", 2, "PREVIEW_STATE_WIDENING");
  if (policy.public_release !== policy.purposes.includes("public_dataset") || policy.public_release !== policy.operations.includes("redistribute")) throw new SomaError("public release boolean, purpose, and operation must agree", 2, "PREVIEW_RELEASE_MISMATCH");
  if (sourceKind === "artifact") {
    exactObject(policy.artifact_metadata, ARTIFACT_METADATA_FIELDS, "PREVIEW_ARTIFACT_METADATA_INVALID", "artifact_metadata");
    if (!MEDIA_TYPES.has(policy.artifact_metadata.media_type) || !RIGHTS_BASES.has(policy.artifact_metadata.rights_basis) || policy.artifact_metadata.controller_attests_rights !== true || typeof policy.artifact_metadata.title !== "string" || policy.artifact_metadata.title.length < 1 || policy.artifact_metadata.title.length > 256 || CONTROL.test(policy.artifact_metadata.title)) throw new SomaError("artifact metadata or rights attestation is invalid", 2, "PREVIEW_RIGHTS_INVALID");
    let source;
    try { source = new URL(policy.artifact_metadata.source_uri); } catch { throw new SomaError("artifact source URI is invalid", 2, "PREVIEW_RIGHTS_INVALID"); }
    if (source.protocol !== "https:" || source.username || source.password) throw new SomaError("artifact source URI must be credential-free HTTPS", 2, "PREVIEW_RIGHTS_INVALID");
  } else if (policy.artifact_metadata !== null) throw new SomaError("evidence preview cannot contain artifact_metadata", 2, "PREVIEW_ARTIFACT_METADATA_INVALID");
  return registry;
}

function authorizedFieldProjection(policy) {
  return {
    schema_version: "soma.authorized-field-projection.provisional-v1",
    source_kind: policy.source_kind,
    data_class: policy.data_class,
    system_fields: ["data_class", "fields", "schema_version", "source_id", "source_kind", "subject_did"],
    authorized_fields: policy.authorized_fields
  };
}

function fieldProjectionHash(policy) {
  return sha256(Buffer.from(`soma:authorized-field-projection:provisional-v1\n${canonicalize(authorizedFieldProjection(policy))}`));
}

function scanText(text, field) {
  const findings = [];
  for (const [code, pattern] of SCAN_PATTERNS) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
      findings.push({ code, field, utf16_offset: match.index });
      if (match[0].length === 0) pattern.lastIndex += 1;
    }
  }
  return findings;
}

function decodeUtf8(bytes, { label = "artifact", code = "PREVIEW_ARTIFACT_ENCODING_DENIED", exitCode = 6 } = {}) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { throw new SomaError(`${label} must be valid UTF-8 text in this provisional profile`, exitCode, code); }
}

async function identity(home) {
  return JSON.parse(await readFile(path.join(home, "identity", "identity.json"), "utf8"));
}

async function evidenceEvent(home, evidenceId) {
  if (!HASH.test(evidenceId || "")) throw new SomaError("evidence ID must be a lowercase SHA-256 hash", 2, "PREVIEW_EVIDENCE_ID_INVALID");
  await verifyEvidenceLedger(home);
  const ledger = await readFile(path.join(home, "evidence", "ledger.jsonl"), "utf8");
  for (const line of ledger ? ledger.trimEnd().split("\n") : []) {
    const entry = parseCanonicalJson(line, "evidence ledger line");
    if (entry.evidence_event?.evidence_id === evidenceId) return entry.evidence_event;
  }
  throw new SomaError("evidence event was not found", 7, "PREVIEW_EVIDENCE_NOT_FOUND");
}

async function durableFile(file, body) {
  const handle = await open(file, "wx", 0o600);
  try { await handle.writeFile(body); await handle.sync(); } finally { await handle.close(); }
}

async function storePreview(home, previewId, payloadJcs, policyJcs, decision) {
  const parent = path.join(home, "consent", "previews");
  const stage = path.join(parent, `.preview-${randomBytes(8).toString("hex")}`);
  const target = path.join(parent, previewId);
  await mkdir(stage, { mode: 0o700 });
  try {
    await durableFile(path.join(stage, "payload.jcs"), payloadJcs);
    await durableFile(path.join(stage, "policy.jcs"), policyJcs);
    await durableFile(path.join(stage, "decision.json"), `${canonicalize(decision)}\n`);
    await rename(stage, target);
  } catch (error) {
    await rm(stage, { recursive: true, force: true });
    throw error;
  }
  return target;
}

async function storeDenial(home, sourceKind, sourceCommitment, policyHash, findings, reasonCodes) {
  const createdAt = new Date().toISOString();
  const core = {
    schema_version: "soma.observation-preview-denial.provisional-v1",
    created_at: createdAt,
    source_kind: sourceKind,
    source_commitment: sourceCommitment,
    policy_hash: policyHash,
    reason_codes: [...new Set(reasonCodes)].sort(),
    secret_scan: { profile: "soma.high-confidence-secret-and-identity-canaries.provisional-v1", passed: false, findings },
    authority: "denial_only_no_payload_no_grant_no_send"
  };
  const denialId = sha256(Buffer.from(`soma:observation-preview-denial:provisional-v1\n${canonicalize(core)}`));
  const decision = { ...core, denial_id: denialId };
  const directory = path.join(home, "consent", "denials");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await durableFile(path.join(directory, `${denialId}.json`), `${canonicalize(decision)}\n`);
  return denialId;
}

export async function observeStatus(home) {
  async function count(directory) {
    try { return (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isDirectory() || entry.isFile()).length; } catch (error) { if (error.code === "ENOENT") return 0; throw error; }
  }
  return {
    observer: "off",
    suspended: false,
    active_grants: 0,
    previews: await count(path.join(home, "consent", "previews")),
    denials: await count(path.join(home, "consent", "denials")),
    grant_capability: "absent",
    send_capability: "absent",
    network_actions: 0
  };
}

export async function previewObservation(home, { policyFile, artifactFile = null, evidenceId = null }) {
  if ((artifactFile === null) === (evidenceId === null)) throw new SomaError("preview requires exactly one of --artifact or --evidence", 2, "PREVIEW_SOURCE_INVALID");
  const sourceKind = artifactFile === null ? "evidence" : "artifact";
  const policyBytes = await readBounded(policyFile, 65536, "PREVIEW_POLICY_FILE_INVALID", "policy");
  const policy = parseCanonicalJson(decodeUtf8(policyBytes, { label: "policy", code: "PREVIEW_POLICY_ENCODING_INVALID", exitCode: 2 }), "preview policy");
  const localIdentity = await identity(home);
  const registry = validatePolicy(policy, localIdentity, sourceKind);
  const policyJcs = canonicalize(policy);
  const policyHash = sha256(Buffer.from(policyJcs));
  let sourceId;
  let available;
  let sourceBytes = null;
  if (sourceKind === "artifact") {
    sourceBytes = await readBounded(artifactFile, policy.max_source_bytes, "PREVIEW_ARTIFACT_FILE_INVALID", "artifact");
    sourceId = sha256(sourceBytes);
    const text = decodeUtf8(sourceBytes);
    available = {
      artifact_hash: sourceId,
      byte_length: sourceBytes.length,
      content_base64: sourceBytes.toString("base64"),
      license_identifier: policy.license.identifier,
      license_version: policy.license.version,
      media_type: policy.artifact_metadata.media_type,
      source_uri: policy.artifact_metadata.source_uri,
      title: policy.artifact_metadata.title
    };
    if (policy.artifact_metadata.media_type === "application/json") {
      try { JSON.parse(text); } catch { throw new SomaError("application/json artifact is invalid JSON", 6, "PREVIEW_ARTIFACT_JSON_DENIED"); }
    }
  } else {
    const event = await evidenceEvent(home, evidenceId);
    sourceId = event.evidence_id;
    available = Object.fromEntries(EVIDENCE_FIELDS.map((field) => [field, event[field]]));
  }
  const fields = Object.fromEntries(policy.authorized_fields.map((field) => [field, available[field]]));
  const scanInputs = [
    ["license_identifier", policy.license.identifier],
    ["license_version", policy.license.version],
    ["destination_host_did", policy.destination.host_did],
    ["destination_origin", policy.destination.origin],
    ...policy.replication_targets.flatMap((target, index) => [
      [`replication_target_${index}_host_did`, target.host_did],
      [`replication_target_${index}_origin`, target.origin]
    ])
  ];
  if (policy.artifact_metadata) {
    scanInputs.push(["artifact_title", policy.artifact_metadata.title]);
    scanInputs.push(["artifact_source_uri", policy.artifact_metadata.source_uri]);
  }
  for (const [field, value] of Object.entries(fields)) {
    if (field === "content_base64" && sourceBytes) scanInputs.push([field, decodeUtf8(sourceBytes)]);
    else if (typeof value === "string") scanInputs.push([field, value]);
  }
  const findings = scanInputs.flatMap(([field, value]) => scanText(value, field)).sort((a, b) => a.field.localeCompare(b.field) || a.utf16_offset - b.utf16_offset || a.code.localeCompare(b.code));
  if (findings.length) {
    const denialId = await storeDenial(home, sourceKind, sourceId, policyHash, findings, ["SECRET_OR_PROHIBITED_IDENTITY_CANARY"]);
    await restrictStateRoot(home);
    throw new SomaError("preview denied by secret and prohibited-identity scanning; no payload was stored or sent", 6, "PREVIEW_SCAN_DENIED", { local_mutation: true, denial_id: denialId, finding_codes: [...new Set(findings.map((entry) => entry.code))].sort() });
  }
  const payload = {
    schema_version: "soma.observation-payload.provisional-v1",
    source_kind: sourceKind,
    source_id: sourceId,
    data_class: policy.data_class,
    subject_did: policy.subject_did,
    fields
  };
  const payloadJcs = canonicalize(payload);
  const payloadBytes = Buffer.byteLength(payloadJcs);
  if (payloadBytes > HARD_PAYLOAD_BYTES) throw new SomaError("canonical payload exceeds the hard preview limit", 6, "PREVIEW_PAYLOAD_TOO_LARGE");
  const createdAt = new Date().toISOString();
  const decisionCore = {
    schema_version: "soma.observation-preview-decision.provisional-v1",
    created_at: createdAt,
    source_kind: sourceKind,
    source_id: sourceId,
    payload_hash: sha256(Buffer.from(payloadJcs)),
    payload_bytes: payloadBytes,
    policy_hash: policyHash,
    field_projection_hash: fieldProjectionHash(policy),
    data_class: policy.data_class,
    data_state: policy.data_state,
    authorized_fields: policy.authorized_fields,
    redactions: registry.filter((field) => !policy.authorized_fields.includes(field)).map((field) => ({ field, reason: "not_in_exact_authorized_projection" })),
    purposes: policy.purposes,
    operations: policy.operations,
    destination: policy.destination,
    retention_seconds: policy.retention_seconds,
    redistribution: policy.redistribution,
    replication: policy.replication,
    replication_targets: policy.replication_targets,
    model_training: policy.model_training,
    public_release: policy.public_release,
    license: policy.license,
    expires_at: policy.expires_at,
    withdrawal_mode: policy.withdrawal_mode,
    policy_version: policy.policy_version,
    secret_scan: { profile: "soma.high-confidence-secret-and-identity-canaries.provisional-v1", passed: true, findings: [] },
    rights_check: sourceKind === "artifact" ? { result: "controller_attested_not_independently_verified", basis: policy.artifact_metadata.rights_basis } : { result: "not_applicable_minimized_local_evidence" },
    warnings: [
      "preview_only_no_grant_no_send",
      "destination_is_proposed_not_pinned_in_this_release",
      "scanner_is_defense_in_depth_and_cannot_prove_absence_of_private_or_regulated_meaning"
    ],
    authority: "preview_only_no_grant_no_send"
  };
  const previewId = sha256(Buffer.from(`soma:observation-preview:provisional-v1\n${canonicalize(decisionCore)}`));
  const decision = { ...decisionCore, preview_id: previewId };
  const directory = await storePreview(home, previewId, payloadJcs, policyJcs, decision);
  await restrictStateRoot(home);
  return {
    local_mutation: true,
    remote_mutation: false,
    preview_id: previewId,
    payload_hash: decision.payload_hash,
    field_projection_hash: decision.field_projection_hash,
    payload_bytes: payloadBytes,
    payload_jcs: payloadJcs,
    policy_jcs: policyJcs,
    decision,
    stored_at: directory,
    network_actions: 0
  };
}
