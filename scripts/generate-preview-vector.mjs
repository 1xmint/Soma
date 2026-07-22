import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";

const source = Buffer.from("Public Somavera preview vector.\n", "utf8");
const policy = {
  schema_version: "soma.observation-preview-policy.provisional-v1",
  source_kind: "artifact",
  data_class: "public_artifact",
  authorized_fields: ["artifact_hash", "byte_length", "media_type", "title"],
  subject_did: "did:example:agent-vector",
  controller_did: "did:example:controller-vector",
  observer_did: "did:example:observer-vector",
  destination: { host_did: "did:web:vera.example", origin: "https://vera.example" },
  purposes: ["safety_evaluation"],
  operations: ["collect", "evaluate", "store_encrypted"],
  data_state: "host_confidential",
  retention_seconds: 86400,
  redistribution: "none",
  replication: "none",
  replication_targets: [],
  model_training: false,
  public_release: false,
  license: { identifier: "CC-BY", version: "4.0" },
  expires_at: "2027-07-16T12:00:00.000Z",
  withdrawal_mode: "delete_deletable_and_tombstone",
  policy_version: "pilot.1",
  max_source_bytes: 4096,
  artifact_metadata: {
    media_type: "text/plain",
    title: "Public preview vector",
    source_uri: "https://example.org/vector.txt",
    rights_basis: "open_license",
    controller_attests_rights: true
  }
};
const sourceId = sha256(source);
const payload = {
  schema_version: "soma.observation-payload.provisional-v1",
  source_kind: "artifact",
  source_id: sourceId,
  data_class: "public_artifact",
  subject_did: policy.subject_did,
  fields: {
    artifact_hash: sourceId,
    byte_length: source.length,
    media_type: policy.artifact_metadata.media_type,
    title: policy.artifact_metadata.title
  }
};
const fieldProjection = {
  schema_version: "soma.authorized-field-projection.provisional-v1",
  source_kind: policy.source_kind,
  data_class: policy.data_class,
  system_fields: ["data_class", "fields", "schema_version", "source_id", "source_kind", "subject_did"],
  authorized_fields: policy.authorized_fields
};
const fieldProjectionHash = sha256(Buffer.from(`soma:authorized-field-projection:provisional-v1\n${canonicalize(fieldProjection)}`));
const payloadJcs = canonicalize(payload);
const decisionCore = {
  schema_version: "soma.observation-preview-decision.provisional-v1",
  created_at: "2026-07-16T12:00:00.000Z",
  source_kind: "artifact",
  source_id: sourceId,
  payload_hash: sha256(Buffer.from(payloadJcs)),
  payload_bytes: Buffer.byteLength(payloadJcs),
  policy_hash: sha256(Buffer.from(canonicalize(policy))),
  field_projection_hash: fieldProjectionHash,
  data_class: "public_artifact",
  data_state: "host_confidential",
  authorized_fields: policy.authorized_fields,
  redactions: ["content_base64", "license_identifier", "license_version", "source_uri"].map((field) => ({ field, reason: "not_in_exact_authorized_projection" })),
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
  rights_check: { result: "controller_attested_not_independently_verified", basis: "open_license" },
  warnings: ["preview_only_no_grant_no_send", "destination_is_proposed_not_pinned_in_this_release", "scanner_is_defense_in_depth_and_cannot_prove_absence_of_private_or_regulated_meaning"],
  authority: "preview_only_no_grant_no_send"
};
const previewId = sha256(Buffer.from(`soma:observation-preview:provisional-v1\n${canonicalize(decisionCore)}`));
console.log(JSON.stringify({
  vector_version: "soma.observation-preview.provisional-v1",
  status: "provisional_not_ratified",
  source_utf8: source.toString("utf8"),
  policy,
  policy_hash: decisionCore.policy_hash,
  field_projection: fieldProjection,
  field_projection_hash: fieldProjectionHash,
  payload_jcs: payloadJcs,
  payload_hash: decisionCore.payload_hash,
  decision: { ...decisionCore, preview_id: previewId },
  preview_id: previewId
}, null, 2));
