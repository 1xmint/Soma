import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const PROPOSAL_ID_DOMAIN = "somavera:soma-controller-key-rotation-proposal:v1\n";
const ROTATION_ID_DOMAIN = "somavera:soma-controller-key-rotation:v1\n";
const PRIOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-prior-signature:v1\n";
const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-successor-signature:v1\n";
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
function base58btc(bytes) {
  let number = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let encoded = "";
  while (number > 0n) {
    encoded = BASE58[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = "1" + encoded;
  }
  return encoded || "1";
}
function keyFromSeed(seedHex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  const raw = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" })).subarray(-32);
  const fingerprint = "z" + base58btc(Buffer.concat([ED25519_MULTICODEC, raw]));
  const did = "did:key:" + fingerprint;
  return { privateKey, raw, fingerprint, did, keyId: did + "#" + fingerprint };
}
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

const prior = keyFromSeed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const successor = keyFromSeed("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
const controllerDid = prior.did;
const preparedAt = "2027-01-01T12:00:00.000Z";
const effectiveAt = "2027-01-01T12:05:00.000Z";
const rotation = {
  $schema: "../schemas/soma-controller-key-rotation.schema.json",
  schema_version: "somavera.soma-controller-key-rotation.v1",
  profile_status: "freeze_blocking_draft",
  rotation_id: "0".repeat(64),
  proposal_id: "0".repeat(64),
  controller_did: controllerDid,
  rotation_sequence: 1,
  previous_rotation_id: null,
  prior_key: {
    key_id: prior.keyId,
    role: "controller_signing",
    suite: "Ed25519-v1",
    public_key_multibase: prior.fingerprint,
    public_key_sha256: sha256(prior.raw),
    valid_from: "2027-01-01T00:00:00.000Z",
    valid_until: effectiveAt,
    status: "retired"
  },
  successor_key: {
    key_id: successor.keyId,
    role: "controller_signing",
    suite: "Ed25519-v1",
    public_key_multibase: successor.fingerprint,
    public_key_sha256: sha256(successor.raw),
    valid_from: effectiveAt,
    valid_until: null,
    status: "active"
  },
  prepared_at: preparedAt,
  effective_at: effectiveAt,
  reason: "scheduled owner-initiated controller-key rotation",
  decision: "replace_online_controller_signing_key_only",
  prior_private_key_disposition: "destroy_after_committed_successor_is_recoverable",
  rollback_assurance: "local_consistency_only_unless_exact_history_is_externally_preserved",
  authority: {
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
  },
  signatures: {}
};
rotation.proposal_id = sha256(PROPOSAL_ID_DOMAIN + canonicalize(proposalCore(rotation)));
rotation.rotation_id = sha256(ROTATION_ID_DOMAIN + canonicalize(rotationCore(rotation)));
const message = (domain) => Buffer.concat([Buffer.from(domain), Buffer.from(rotation.rotation_id, "hex")]);
rotation.signatures = {
  prior: {
    suite: "Ed25519-v1",
    key_id: prior.keyId,
    value: sign(null, message(PRIOR_SIGNATURE_DOMAIN), prior.privateKey).toString("base64")
  },
  successor: {
    suite: "Ed25519-v1",
    key_id: successor.keyId,
    value: sign(null, message(SUCCESSOR_SIGNATURE_DOMAIN), successor.privateKey).toString("base64")
  }
};

const vector = {
  vector_version: "somavera.soma-controller-key-rotation.v1",
  description: "Deterministic ordinary offline controller-key rotation with old-key authorization and new-key proof of possession.",
  initial_controller_did: controllerDid,
  domains: {
    proposal_id: PROPOSAL_ID_DOMAIN.slice(0, -1),
    rotation_id: ROTATION_ID_DOMAIN.slice(0, -1),
    prior_signature: PRIOR_SIGNATURE_DOMAIN.slice(0, -1),
    successor_signature: SUCCESSOR_SIGNATURE_DOMAIN.slice(0, -1)
  },
  expected: {
    proposal_core_jcs: canonicalize(proposalCore(rotation)),
    proposal_id: rotation.proposal_id,
    rotation_core_jcs: canonicalize(rotationCore(rotation)),
    rotation_id: rotation.rotation_id,
    prior_signature_message_hex: message(PRIOR_SIGNATURE_DOMAIN).toString("hex"),
    successor_signature_message_hex: message(SUCCESSOR_SIGNATURE_DOMAIN).toString("hex"),
    result: "accept_controller_key_rotation_only"
  },
  rotation
};

const invalid = {
  vector_version: "somavera.soma-controller-key-rotation-invalid.v1",
  base_vector: "controller-key-rotation-v1.json",
  cases: [
    { name: "unstable_controller_did", mutation: "unstable_controller_did", expected_error: "ROTATION_CONTROLLER_MISMATCH" },
    { name: "sequence_gap", mutation: "sequence_gap", expected_error: "ROTATION_SEQUENCE_INVALID" },
    { name: "wrong_predecessor", mutation: "wrong_predecessor", expected_error: "ROTATION_PREDECESSOR_INVALID" },
    { name: "prior_key_substitution", mutation: "prior_key_substitution", expected_error: "ROTATION_PRIOR_KEY_INVALID" },
    { name: "same_successor_key", mutation: "same_successor_key", expected_error: "ROTATION_SUCCESSOR_KEY_INVALID" },
    { name: "successor_hash_mismatch", mutation: "successor_hash_mismatch", expected_error: "ROTATION_SUCCESSOR_KEY_INVALID" },
    { name: "validity_gap", mutation: "validity_gap", expected_error: "ROTATION_KEY_WINDOW_INVALID" },
    { name: "effective_before_prepare", mutation: "effective_before_prepare", expected_error: "ROTATION_TIME_INVALID" },
    { name: "confirmation_window_exceeded", mutation: "confirmation_window_exceeded", expected_error: "ROTATION_TIME_INVALID" },
    { name: "prior_reactivation", mutation: "prior_reactivation", expected_error: "ROTATION_KEY_STATUS_INVALID" },
    { name: "successor_not_active", mutation: "successor_not_active", expected_error: "ROTATION_KEY_STATUS_INVALID" },
    { name: "decision_widening", mutation: "decision_widening", expected_error: "ROTATION_DECISION_INVALID" },
    { name: "private_key_retention", mutation: "private_key_retention", expected_error: "ROTATION_DISPOSITION_INVALID" },
    { name: "rollback_claim_widening", mutation: "rollback_claim_widening", expected_error: "ROTATION_ROLLBACK_ASSURANCE_INVALID" },
    { name: "agent_rotation_escalation", mutation: "agent_rotation_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "identity_recovery_escalation", mutation: "identity_recovery_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "connection_escalation", mutation: "connection_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "consent_escalation", mutation: "consent_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "disclosure_escalation", mutation: "disclosure_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "send_escalation", mutation: "send_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "token_escalation", mutation: "token_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "governance_escalation", mutation: "governance_escalation", expected_error: "ROTATION_AUTHORITY_INVALID" },
    { name: "prior_signature_key_mismatch", mutation: "prior_signature_key_mismatch", expected_error: "ROTATION_PRIOR_SIGNATURE_INVALID" },
    { name: "prior_signature_corruption", mutation: "prior_signature_corruption", expected_error: "ROTATION_PRIOR_SIGNATURE_INVALID" },
    { name: "successor_signature_key_mismatch", mutation: "successor_signature_key_mismatch", expected_error: "ROTATION_SUCCESSOR_SIGNATURE_INVALID" },
    { name: "successor_signature_corruption", mutation: "successor_signature_corruption", expected_error: "ROTATION_SUCCESSOR_SIGNATURE_INVALID" },
    { name: "proposal_id_corruption", mutation: "proposal_id_corruption", expected_error: "ROTATION_PROPOSAL_ID_INVALID" },
    { name: "rotation_id_corruption", mutation: "rotation_id_corruption", expected_error: "ROTATION_ID_INVALID" }
  ]
};

await readFile(path.join(root, "schemas", "soma-controller-key-rotation.schema.json"));
await writeFile(path.join(root, "examples", "soma-controller-key-rotation.example.json"), JSON.stringify(rotation, null, 2) + "\n");
await writeFile(path.join(root, "conformance", "controller-key-rotation-v1.json"), JSON.stringify(vector, null, 2) + "\n");
await writeFile(path.join(root, "conformance", "controller-key-rotation-invalid-v1.json"), JSON.stringify(invalid, null, 2) + "\n");
console.log("Generated Soma controller-key rotation example and vectors.");
