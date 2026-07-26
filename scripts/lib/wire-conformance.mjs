import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { validateSchemaSubset } from "./schema-subset.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
let checks = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
  checks += 1;
}

async function json(relative) {
  return JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function mutatePointer(target, mutation) {
  const segments = mutation.path
    .slice(1)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  const key = segments.pop();
  let parent = target;
  for (const segment of segments) parent = parent[segment];
  if (mutation.op === "remove") {
    if (Array.isArray(parent)) parent.splice(Number(key), 1);
    else delete parent[key];
    return;
  }
  if (mutation.op !== "add" && mutation.op !== "replace") {
    throw new Error("unsupported vector mutation: " + mutation.op);
  }
  parent[key] = structuredClone(mutation.value);
}

function streamErrors(value, response = false) {
  const errors = [];
  const chunks = value.chunks || [];
  const header = response ? value : value.stream_header;
  if (chunks.length !== header.chunk_count) errors.push("WIRE_CHUNK_COUNT");
  if (chunks.reduce((sum, chunk) => sum + chunk.plaintext_bytes, 0) !== header.plaintext_bytes) {
    errors.push("WIRE_CHUNK_LENGTH_SUM");
  }
  if (chunks.some((chunk, index) => chunk.index !== index)) errors.push("WIRE_CHUNK_INDEX");
  if (new Set(chunks.map((chunk) => chunk.nonce)).size !== chunks.length) errors.push("WIRE_NONCE_REUSE");
  return errors;
}

function wireSemanticErrors(schemaName, value) {
  const errors = [];
  if (schemaName === "vera-host-descriptor.schema.json") {
    const signing = value.host_signing_keys || [];
    const ingestion = value.ingestion_encryption_keys || [];
    const signingIds = new Set(signing.map((key) => key.key_id));
    const ingestionIds = new Set(ingestion.map((key) => key.key_id));
    const signingKeys = new Set(signing.map((key) => key.public_key_base64));
    if ([...signingIds].some((id) => ingestionIds.has(id)) || ingestion.some((key) => signingKeys.has(key.public_key_base64))) {
      errors.push("WIRE_KEY_ROLE_REUSE");
    }
    const activeSigning = signing.find((key) => key.key_id === value.active_host_signing_key_id && key.lifecycle.status === "active");
    const activeIngestion = ingestion.find((key) => key.key_id === value.active_ingestion_key_id && key.lifecycle.status === "active");
    if (!activeSigning || !activeIngestion) errors.push("WIRE_ACTIVE_KEY_UNRESOLVED");
    if (value.signature?.key_id !== value.active_host_signing_key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
    const expectedRequests = [
      "host.register", "host.challenge", "consent.register", "consent.withdraw",
      "contribution.offer", "vera.query", "export.request", "status.lookup",
      "content.delete", "tombstone.status"
    ];
    const expectedResponses = [
      "host.registered", "host.challenge-result", "consent.accepted", "consent.withdrawn",
      "contribution.accepted", "contribution.rejected", "answer.source-bundle", "export.ready",
      "status.result", "content.deleted", "tombstone.result", "private.error"
    ];
    const actualRequests = [...(value.capabilities?.private_request_actions || [])].sort();
    const actualResponses = [...(value.capabilities?.private_response_actions || [])].sort();
    if (!same(actualRequests, [...expectedRequests].sort()) || !same(actualResponses, [...expectedResponses].sort())) {
      errors.push("WIRE_ACTION_REGISTRY_INCOMPLETE");
    }
    let originHost = null;
    try { originHost = new URL(value.origin).hostname; } catch { /* shape validator reports it */ }
    if (originHost !== value.transport_security?.server_name) errors.push("WIRE_TLS_BINDING_MISMATCH");
    if (value.private_request_endpoint?.maximum_plaintext_bytes !== value.capability_limits?.maximum_contribution_plaintext_bytes || value.query_policy?.maximum_top_k !== value.capability_limits?.maximum_top_k) {
      errors.push("WIRE_LIMIT_BINDING_MISMATCH");
    }
    if (value.query_policy?.private_query_retention_seconds !== value.retention_behavior?.maximum_private_query_seconds) {
      errors.push("WIRE_RETENTION_BINDING_MISMATCH");
    }
    if (value.model_use_disclosure?.inference_enabled !== false || value.model_use_disclosure?.training_enabled !== false || value.model_use_disclosure?.external_model_providers?.length !== 0) {
      errors.push("WIRE_MODEL_DISCLOSURE_INVALID");
    }
    const regionCodes = new Set((value.data_regions || []).map((entry) => entry.region_code));
    if ((value.subprocessors || []).some((entry) => entry.region_codes.some((region) => !regionCodes.has(region)))) {
      errors.push("WIRE_SUBPROCESSOR_REGION_UNKNOWN");
    }
    if (value.active_host_signing_key_id === value.active_ingestion_key_id) errors.push("WIRE_KEY_ROLE_REUSE");
  }
  if (schemaName === "vera-application-envelope.schema.json") {
    if (value.signing_key_id !== value.signature?.key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
    if (value.signing_key_id === value.recipient_ingestion_key_id) errors.push("WIRE_KEY_ROLE_REUSE");
  }
  if (schemaName === "vera-encrypted-stream.schema.json") {
    const outer = value.outer_envelope;
    const header = value.stream_header;
    for (const key of [
      "network_lineage_id", "execution_context_id", "sender_did", "destination_host_did",
      "recipient_ingestion_key_id", "inner_event_id", "consent_grant_id", "stream_id",
      "ciphertext_root", "plaintext_bytes", "outer_nonce", "issued_at", "expires_at"
    ]) {
      if (!same(outer[key], header[key])) errors.push("WIRE_BINDING_MISMATCH:" + key);
    }
    if (outer.signing_key_id !== outer.signature?.key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
    if (outer.signing_key_id === header.recipient_ingestion_key_id) errors.push("WIRE_KEY_ROLE_REUSE");
    errors.push(...streamErrors(value));
  }
  if (schemaName === "vera-encrypted-response.schema.json") {
    if (value.return_descriptor_id !== value.return_key_commitment) errors.push("WIRE_RETURN_COMMITMENT");
    if (value.outer_signature?.key_id === value.recipient_return_key_id) errors.push("WIRE_KEY_ROLE_REUSE");
    errors.push(...streamErrors(value, true));
  }
  if (schemaName === "vera-contribution-acknowledgement.schema.json") {
    if (value.host_signing_key_id !== value.signature?.key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
    if (value.host_signing_key_id === value.recipient_ingestion_key_id || value.host_signing_key_id === value.soma_return_key_id) {
      errors.push("WIRE_KEY_ROLE_REUSE");
    }
    if (value.request_event_id !== value.contribution_event_id) errors.push("WIRE_ACK_REQUEST_BINDING_MISMATCH");
    if (value.received_stream_id === value.received_envelope_ciphertext_root || value.received_envelope_ciphertext_root === value.plaintext_payload_hash) errors.push("WIRE_ACK_COMMITMENT_ALIAS");
    if (value.return_descriptor_id === value.plaintext_payload_hash) errors.push("WIRE_ACK_COMMITMENT_ALIAS");
  }
  if (schemaName === "query-delegation.schema.json") {
    if (value.signing_key_id !== value.signature?.key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
  }
  if (schemaName === "vera-answer-source-bundle.schema.json") {
    if (value.host_signing_key_id !== value.signature?.key_id) errors.push("WIRE_SIGNING_KEY_MISMATCH");
    const sourceIds = new Set(value.sources.map((source) => source.source_id));
    for (const citation of value.citations) {
      if (!sourceIds.has(citation.source_id)) errors.push("WIRE_CITATION_SOURCE_MISSING");
      const source = value.sources.find((entry) => entry.source_id === citation.source_id);
      if (source && source.excerpt_hash !== citation.excerpt_hash) errors.push("WIRE_CITATION_EXCERPT_MISMATCH");
    }
    if (sourceIds.size !== value.sources.length) errors.push("WIRE_DUPLICATE_SOURCE");
  }
  return errors;
}

const wirePairs = [
  ["vera-host-descriptor.example.json", "vera-host-descriptor.schema.json"],
  ["return-encryption-descriptor.example.json", "return-encryption-descriptor.schema.json"],
  ["vera-application-envelope.example.json", "vera-application-envelope.schema.json"],
  ["vera-encrypted-stream.example.json", "vera-encrypted-stream.schema.json"],
  ["vera-encrypted-response.example.json", "vera-encrypted-response.schema.json"],
  ["vera-contribution-acknowledgement.example.json", "vera-contribution-acknowledgement.schema.json"],
  ["query-delegation.example.json", "query-delegation.schema.json"],
  ["vera-answer-source-bundle.example.json", "vera-answer-source-bundle.schema.json"]
];

for (const [exampleName, schemaName] of wirePairs) {
  const example = await json("examples/" + exampleName);
  const schema = await json("schemas/" + schemaName);
  const shapeErrors = validateSchemaSubset(schema, example);
  assert(shapeErrors.length === 0, exampleName + " wire shape errors:\n" + shapeErrors.join("\n"));
  const semanticErrors = wireSemanticErrors(schemaName, example);
  assert(semanticErrors.length === 0, exampleName + " wire semantic errors: " + semanticErrors.join(", "));
}

const hostDescriptor = await json("examples/vera-host-descriptor.example.json");
const returnDescriptor = await json("examples/return-encryption-descriptor.example.json");
assert(hostDescriptor.capabilities.private_request_actions.includes(returnDescriptor.request_action), "return descriptor request action is not advertised by host");
for (const action of returnDescriptor.allowed_response_actions) {
  assert(hostDescriptor.capabilities.private_response_actions.includes(action), "return descriptor response action is not advertised by host: " + action);
}

function hasForbiddenClearKey(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(hasForbiddenClearKey);
  for (const [key, entry] of Object.entries(value)) {
    if (key === "plaintext_content_hash" || key === "plaintext_payload_hash" || key === "content_hash") return true;
    if (hasForbiddenClearKey(entry)) return true;
  }
  return false;
}
for (const schemaName of ["vera-application-envelope.schema.json", "vera-encrypted-stream.schema.json", "vera-encrypted-response.schema.json"]) {
  assert(!hasForbiddenClearKey(await json("schemas/" + schemaName)), schemaName + " permits a clear plaintext fingerprint field");
}

const vectors = await json("conformance/wire-invalid-v1.json");
for (const vector of vectors.cases) {
  const example = structuredClone(await json("examples/" + vector.base_example));
  const schema = await json("schemas/" + vector.schema);
  for (const mutation of vector.mutations) mutatePointer(example, mutation);
  const shapeErrors = validateSchemaSubset(schema, example);
  const semanticErrors = wireSemanticErrors(vector.schema, example);
  if (vector.validation === "schema") {
    assert(shapeErrors.some((error) => error.includes(vector.expected)), vector.name + " did not produce schema rejection " + vector.expected + "; got " + shapeErrors.join(" | "));
  } else {
    assert(shapeErrors.length === 0, vector.name + " unexpectedly failed shape before semantic validation: " + shapeErrors.join(" | "));
    assert(semanticErrors.some((error) => error.includes(vector.expected)), vector.name + " did not produce semantic rejection " + vector.expected + "; got " + semanticErrors.join(", "));
  }
}

console.log("Wire conformance checks passed: " + checks);
console.log("Wire cryptographic profile remains freeze-blocking pending independent vectors and review.");
