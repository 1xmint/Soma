import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const descriptorExamplePath = path.join(root, "examples", "vera-host-descriptor.example.json");
const successionExamplePath = path.join(root, "examples", "vera-host-descriptor-succession.example.json");
const vectorPath = path.join(root, "conformance", "host-descriptor-succession-v1.json");

const DESCRIPTOR_ID_DOMAIN = "somavera:vera-host-descriptor:v1\n";
const DESCRIPTOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-signature:v1\n";
const SUCCESSION_ID_DOMAIN = "somavera:vera-host-descriptor-succession:v1\n";
const PRIOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nprior\n";
const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:vera-host-descriptor-succession-signature:v1\nsuccessor\n";

const rotationPolicy = Object.freeze({
  ordinary_succession: "precommitted_overlap_dual_signature_v1",
  successor_key_precommitment: "required_in_prior_descriptor",
  requires_prior_and_successor_signatures: true,
  requires_controller_confirmation: true,
  emergency_compromise_recovery: "blocked_until_recovery_authority_profile",
  maximum_overlap_seconds: 86400,
  maximum_descriptor_lifetime_seconds: 86400,
  allowed_change_scopes: [
    "renewal_only",
    "signing_key_rotation",
    "ingestion_key_rotation",
    "signing_and_ingestion_key_rotation"
  ]
});

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function ed25519FromSeed(seedHex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { privateKey, publicKeyBase64: Buffer.from(publicDer).subarray(-32).toString("base64") };
}

function descriptorCore(descriptor) {
  const { $schema, descriptor_id, signature, ...core } = descriptor;
  return core;
}

function successionCore(proof) {
  const { $schema, succession_id, signatures, ...core } = proof;
  return core;
}

function deriveDescriptorId(descriptor) {
  return sha256Hex(DESCRIPTOR_ID_DOMAIN + canonicalize(descriptorCore(descriptor)));
}

function signDescriptor(descriptor, keyId, privateKey) {
  descriptor.descriptor_id = deriveDescriptorId(descriptor);
  descriptor.signature = {
    suite: "Ed25519-v1",
    key_id: keyId,
    value: sign(null, Buffer.concat([Buffer.from(DESCRIPTOR_SIGNATURE_DOMAIN), Buffer.from(descriptor.descriptor_id, "hex")]), privateKey).toString("base64")
  };
}

function deriveSuccessionId(proof) {
  return sha256Hex(SUCCESSION_ID_DOMAIN + canonicalize(successionCore(proof)));
}

function signSuccession(proof, priorKey, successorKey) {
  proof.succession_id = deriveSuccessionId(proof);
  const id = Buffer.from(proof.succession_id, "hex");
  proof.signatures = {
    prior_active_key_signature: {
      suite: "Ed25519-v1",
      key_id: proof.prior_active_host_signing_key_id,
      value: sign(null, Buffer.concat([Buffer.from(PRIOR_SIGNATURE_DOMAIN), id]), priorKey).toString("base64")
    },
    successor_active_key_signature: {
      suite: "Ed25519-v1",
      key_id: proof.successor_active_host_signing_key_id,
      value: sign(null, Buffer.concat([Buffer.from(SUCCESSOR_SIGNATURE_DOMAIN), id]), successorKey).toString("base64")
    }
  };
}

function lifecycle(status, validFrom, validUntil) {
  return { valid_from: validFrom, valid_until: validUntil, status, revoked_at: null, revocation_reference: null };
}

const descriptorExample = JSON.parse(await readFile(descriptorExamplePath, "utf8"));
descriptorExample.descriptor_sequence = 0;
descriptorExample.previous_descriptor_id = null;
descriptorExample.rotation_policy = rotationPolicy;
const orderedExample = {
  $schema: descriptorExample.$schema,
  schema_version: descriptorExample.schema_version,
  profile_status: descriptorExample.profile_status,
  descriptor_id: descriptorExample.descriptor_id,
  descriptor_sequence: descriptorExample.descriptor_sequence,
  previous_descriptor_id: descriptorExample.previous_descriptor_id,
  rotation_policy: descriptorExample.rotation_policy,
  ...Object.fromEntries(Object.entries(descriptorExample).filter(([key]) => ![
    "$schema", "schema_version", "profile_status", "descriptor_id", "descriptor_sequence", "previous_descriptor_id", "rotation_policy"
  ].includes(key)))
};
await writeFile(descriptorExamplePath, JSON.stringify(orderedExample, null, 2) + "\n");

const priorSigning = ed25519FromSeed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const successorSigning = ed25519FromSeed("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
const priorSigningId = "did:key:example-vera-host#signing-7";
const successorSigningId = "did:key:example-vera-host#signing-8";
const priorIngestionId = "did:key:example-vera-host#ingestion-7";
const successorIngestionId = "did:key:example-vera-host#ingestion-8";

const prior = structuredClone(orderedExample);
prior.descriptor_sequence = 7;
prior.previous_descriptor_id = "1111111111111111111111111111111111111111111111111111111111111111";
prior.host_signing_keys = [
  {
    key_id: priorSigningId,
    purpose: "descriptor_and_private_response_signing",
    suite: "Ed25519-v1",
    public_key_base64: priorSigning.publicKeyBase64,
    lifecycle: lifecycle("active", "2026-12-31T00:00:00Z", "2027-01-02T00:00:00Z")
  },
  {
    key_id: successorSigningId,
    purpose: "descriptor_and_private_response_signing",
    suite: "Ed25519-v1",
    public_key_base64: successorSigning.publicKeyBase64,
    lifecycle: lifecycle("overlap", "2027-01-01T12:00:00Z", "2027-01-02T12:00:00Z")
  }
];
prior.ingestion_encryption_keys = [
  {
    key_id: priorIngestionId,
    purpose: "private_request_decryption",
    suite: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
    public_key_base64: Buffer.alloc(32, 0x31).toString("base64"),
    lifecycle: lifecycle("active", "2026-12-31T00:00:00Z", "2027-01-02T00:00:00Z")
  },
  {
    key_id: successorIngestionId,
    purpose: "private_request_decryption",
    suite: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
    public_key_base64: Buffer.alloc(32, 0x32).toString("base64"),
    lifecycle: lifecycle("overlap", "2027-01-01T12:00:00Z", "2027-01-02T12:00:00Z")
  }
];
prior.active_host_signing_key_id = priorSigningId;
prior.active_ingestion_key_id = priorIngestionId;
prior.issued_at = "2027-01-01T00:00:00Z";
prior.expires_at = "2027-01-02T00:00:00Z";
signDescriptor(prior, priorSigningId, priorSigning.privateKey);

const successor = structuredClone(prior);
successor.descriptor_sequence = 8;
successor.previous_descriptor_id = prior.descriptor_id;
successor.host_signing_keys[0].lifecycle.status = "retired";
successor.host_signing_keys[1].lifecycle.status = "active";
successor.host_signing_keys[1].lifecycle.valid_until = "2027-01-02T12:00:00Z";
successor.ingestion_encryption_keys[0].lifecycle.status = "retired";
successor.ingestion_encryption_keys[1].lifecycle.status = "active";
successor.ingestion_encryption_keys[1].lifecycle.valid_until = "2027-01-02T12:00:00Z";
successor.active_host_signing_key_id = successorSigningId;
successor.active_ingestion_key_id = successorIngestionId;
successor.issued_at = "2027-01-01T12:00:00Z";
successor.expires_at = "2027-01-02T12:00:00Z";
signDescriptor(successor, successorSigningId, successorSigning.privateKey);

const succession = {
  $schema: "../schemas/vera-host-descriptor-succession.schema.json",
  schema_version: "somavera.vera-host-descriptor-succession.v1",
  profile_status: "freeze_blocking_draft",
  succession_id: "0".repeat(64),
  network_lineage_id: prior.network_lineage_id,
  execution_context_id: prior.execution_context_id,
  host_did: prior.host_did,
  origin: prior.origin,
  prior_descriptor_id: prior.descriptor_id,
  prior_descriptor_sequence: prior.descriptor_sequence,
  successor_descriptor_id: successor.descriptor_id,
  successor_descriptor_sequence: successor.descriptor_sequence,
  change_scope: "signing_and_ingestion_key_rotation",
  prior_active_host_signing_key_id: priorSigningId,
  successor_active_host_signing_key_id: successorSigningId,
  prior_active_ingestion_key_id: priorIngestionId,
  successor_active_ingestion_key_id: successorIngestionId,
  issued_at: "2027-01-01T12:00:00Z",
  expires_at: "2027-01-01T12:15:00Z",
  controller_confirmation_required: true,
  authority: {
    continuity_only: true,
    authorizes_connection: false,
    authorizes_consent: false,
    authorizes_disclosure: false,
    authorizes_emergency_recovery: false
  },
  signatures: {}
};
signSuccession(succession, priorSigning.privateKey, successorSigning.privateKey);

const vector = {
  vector_version: "somavera.host-descriptor-succession.v1",
  description: "Deterministic test-only ordinary succession with precommitted signing and ingestion keys.",
  validation_time: "2027-01-01T12:05:00Z",
  domains: {
    descriptor_id: DESCRIPTOR_ID_DOMAIN.slice(0, -1),
    descriptor_signature: DESCRIPTOR_SIGNATURE_DOMAIN.slice(0, -1),
    succession_id: SUCCESSION_ID_DOMAIN.slice(0, -1),
    prior_succession_signature: PRIOR_SIGNATURE_DOMAIN.slice(0, -1),
    successor_succession_signature: SUCCESSOR_SIGNATURE_DOMAIN.slice(0, -1)
  },
  expected: {
    prior_descriptor_core_jcs: canonicalize(descriptorCore(prior)),
    successor_descriptor_core_jcs: canonicalize(descriptorCore(successor)),
    succession_core_jcs: canonicalize(successionCore(succession)),
    prior_descriptor_id: prior.descriptor_id,
    successor_descriptor_id: successor.descriptor_id,
    succession_id: succession.succession_id,
    result: "accept_continuity_pending_controller_confirmation"
  },
  prior_descriptor: prior,
  successor_descriptor: successor,
  succession_proof: succession
};

await writeFile(successionExamplePath, JSON.stringify(succession, null, 2) + "\n");
await writeFile(vectorPath, JSON.stringify(vector, null, 2) + "\n");
console.log("Generated host descriptor succession example and vector.");
