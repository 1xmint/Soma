import { createPrivateKey, sign } from "node:crypto";
import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";

const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const signingPublic = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
const ingestionPublic = Buffer.from("0101010101010101010101010101010101010101010101010101010101010101", "hex");
const hostDid = "did:example:vera-vector";
const core = {
  schema_version: "somavera.vera-host-descriptor.v1",
  profile_status: "freeze_blocking_draft",
  descriptor_sequence: 0,
  previous_descriptor_id: null,
  rotation_policy: {
    ordinary_succession: "precommitted_overlap_dual_signature_v1",
    successor_key_precommitment: "required_in_prior_descriptor",
    requires_prior_and_successor_signatures: true,
    requires_controller_confirmation: true,
    emergency_compromise_recovery: "blocked_until_recovery_authority_profile",
    maximum_overlap_seconds: 86400,
    maximum_descriptor_lifetime_seconds: 31536000,
    allowed_change_scopes: ["renewal_only", "signing_key_rotation", "ingestion_key_rotation", "signing_and_ingestion_key_rotation"]
  },
  network_lineage_id: `somavera:network:v1:${"b".repeat(64)}`,
  execution_context_id: `somavera:context:v1:${"a".repeat(64)}`,
  host_did: hostDid,
  origin: "https://vera-vector.example",
  discovery: { method: "GET", path: "/.well-known/somavera/vera-host.json", media_type: "application/json", redirects_allowed: false, cache_max_age_seconds: 300 },
  release: {
    release_id: "vera-vector-v0.1.0",
    release_manifest_hash: "2".repeat(64),
    origin_capsule_hash: "ee8bb4f2a851ecd103a84db988e24eb2241ec702c9f0743045a2e83008f89e7d",
    implementation: "somavera-fixed-conformance-vector"
  },
  policy_hash: "4".repeat(64),
  host_signing_keys: [{
    key_id: `${hostDid}#signing-1`,
    purpose: "descriptor_and_private_response_signing",
    suite: "Ed25519-v1",
    public_key_base64: signingPublic.toString("base64"),
    lifecycle: { valid_from: "2026-07-01T00:00:00Z", valid_until: "2036-07-01T00:00:00Z", status: "active", revoked_at: null, revocation_reference: null }
  }],
  ingestion_encryption_keys: [{
    key_id: `${hostDid}#ingestion-1`,
    purpose: "private_request_decryption",
    suite: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
    public_key_base64: ingestionPublic.toString("base64"),
    lifecycle: { valid_from: "2026-07-01T00:00:00Z", valid_until: "2036-07-01T00:00:00Z", status: "active", revoked_at: null, revocation_reference: null }
  }],
  active_host_signing_key_id: `${hostDid}#signing-1`,
  active_ingestion_key_id: `${hostDid}#ingestion-1`,
  private_request_endpoint: { method: "POST", path: "/v1/private/requests", media_type: "application/json", redirects_allowed: false, maximum_encrypted_bytes: 393216, maximum_plaintext_bytes: 262144, hpke_profile: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1", hpke_profile_status: "freeze_blocking_draft" },
  transport_security: { tls_required: true, minimum_tls_version: "1.3", server_name: "vera-vector.example", certificate_spki_sha256: [], redirects_allowed: false },
  supported_protocols: ["somavera-soma-vera-private-v1", "somavera-vera-checkpoint-v1"],
  capabilities: {
    private_request_actions: ["host.register", "host.challenge", "consent.register", "consent.withdraw", "contribution.offer", "vera.query", "export.request", "status.lookup", "content.delete", "tombstone.status"],
    private_response_actions: ["host.registered", "host.challenge-result", "consent.accepted", "consent.withdrawn", "contribution.accepted", "contribution.rejected", "answer.source-bundle", "export.ready", "status.result", "content.deleted", "tombstone.result", "private.error"],
    public_routes: ["host_descriptor", "public_query", "public_pack"]
  },
  query_policy: { stores_private_query_bodies: false, private_query_retention_seconds: 0, public_scope_enabled: true, controller_confidential_scope_enabled: true, requires_separate_training_consent: true, maximum_top_k: 5 },
  data_regions: [{ region_code: "vector-region", jurisdiction: "Conformance vector only" }],
  subprocessors: [],
  retention_behavior: { maximum_host_confidential_seconds: 2592000, maximum_private_query_seconds: 0, maximum_backup_deletion_seconds: 2592000, withdrawal_blocks_future_use: true },
  model_use_disclosure: { inference_enabled: false, training_enabled: false, external_model_providers: [] },
  capability_limits: { maximum_query_utf8_bytes: 16384, maximum_answer_plaintext_bytes: 1048576, maximum_contribution_plaintext_bytes: 262144, maximum_concurrent_private_requests: 16, maximum_top_k: 5 },
  operator_memory_disclosure: "ordinary_process_operator_can_access_plaintext",
  metadata_disclosure: { ip_address: true, timing: true, approximate_size: true, route_class: true },
  issued_at: "2026-07-01T00:00:00Z",
  expires_at: "2027-07-01T00:00:00Z"
};
const descriptorId = sha256(Buffer.from(`somavera:vera-host-descriptor:v1\n${canonicalize(core)}`));
const signatureMessage = Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(descriptorId, "hex")]);
const signature = sign(null, signatureMessage, privateKey).toString("base64");
const descriptor = { ...core, descriptor_id: descriptorId, signature: { suite: "Ed25519-v1", key_id: core.active_host_signing_key_id, value: signature } };
console.log(JSON.stringify({
  vector_version: "soma.vera-host-descriptor.provisional-v1",
  status: "provisional_not_ratified",
  validation_time: "2026-07-22T12:00:00Z",
  expected: {
    origin: core.origin,
    host_did: core.host_did,
    network_lineage_id: core.network_lineage_id,
    execution_context_id: core.execution_context_id,
    active_signing_key_sha256: sha256(signingPublic)
  },
  descriptor_core_jcs: canonicalize(core),
  descriptor_id: descriptorId,
  signature_message_hex: signatureMessage.toString("hex"),
  descriptor
}, null, 2));
