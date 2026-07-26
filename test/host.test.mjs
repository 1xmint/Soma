import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";
import { SUPPORTED_ORIGIN_CAPSULE_HASHES, verifyHostDescriptor } from "../src/host.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;
const capsule = "90e6a961f0b9bf9be137ea08b2f93483b3aa5e4df610a7785f13f08ad1a31c3b";

function execute(args, trace) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    timeout: 30000,
    env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(), SOMA_NETWORK_TRACE: trace }
  });
}

async function noEgress(trace) {
  try { assert.equal((await stat(trace)).size, 0); } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function setup(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-host-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const initialized = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  return { temporary, home, trace };
}

function rawPublic(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
}

function fixture(overrides = {}) {
  const signingPair = overrides.signingPair || generateKeyPairSync("ed25519");
  const signingPublic = rawPublic(signingPair.publicKey);
  const ingestionPublic = overrides.ingestionPublic || randomBytes(32);
  const now = Date.now();
  const issuedAt = new Date(now - 60000).toISOString();
  const expiresAt = new Date(now + 3600000).toISOString();
  const hostDid = "did:example:vera-host";
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
      maximum_descriptor_lifetime_seconds: 86400,
      allowed_change_scopes: ["renewal_only", "signing_key_rotation", "ingestion_key_rotation", "signing_and_ingestion_key_rotation"]
    },
    network_lineage_id: `somavera:network:v1:${"b".repeat(64)}`,
    execution_context_id: `somavera:context:v1:${"a".repeat(64)}`,
    host_did: hostDid,
    origin: "https://vera.example.test",
    discovery: { method: "GET", path: "/.well-known/somavera/vera-host.json", media_type: "application/json", redirects_allowed: false, cache_max_age_seconds: 300 },
    release: { release_id: "vera-host-v0.1.0-test", release_manifest_hash: "2".repeat(64), origin_capsule_hash: capsule, implementation: "somavera-vera-host-test-only" },
    policy_hash: "4".repeat(64),
    host_signing_keys: [{
      key_id: `${hostDid}#signing-1`, purpose: "descriptor_and_private_response_signing", suite: "Ed25519-v1", public_key_base64: signingPublic.toString("base64"),
      lifecycle: { valid_from: new Date(now - 120000).toISOString(), valid_until: new Date(now + 7200000).toISOString(), status: "active", revoked_at: null, revocation_reference: null }
    }],
    ingestion_encryption_keys: [{
      key_id: `${hostDid}#ingestion-1`, purpose: "private_request_decryption", suite: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1", public_key_base64: ingestionPublic.toString("base64"),
      lifecycle: { valid_from: new Date(now - 120000).toISOString(), valid_until: new Date(now + 7200000).toISOString(), status: "active", revoked_at: null, revocation_reference: null }
    }],
    active_host_signing_key_id: `${hostDid}#signing-1`,
    active_ingestion_key_id: `${hostDid}#ingestion-1`,
    private_request_endpoint: { method: "POST", path: "/v1/private/requests", media_type: "application/json", redirects_allowed: false, maximum_encrypted_bytes: 393216, maximum_plaintext_bytes: 262144, hpke_profile: "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1", hpke_profile_status: "freeze_blocking_draft" },
    transport_security: { tls_required: true, minimum_tls_version: "1.3", server_name: "vera.example.test", certificate_spki_sha256: [], redirects_allowed: false },
    supported_protocols: ["somavera-soma-vera-private-v1", "somavera-vera-checkpoint-v1"],
    capabilities: {
      private_request_actions: ["host.register", "host.challenge", "consent.register", "consent.withdraw", "contribution.offer", "vera.query", "export.request", "status.lookup", "content.delete", "tombstone.status"],
      private_response_actions: ["host.registered", "host.challenge-result", "consent.accepted", "consent.withdrawn", "contribution.accepted", "contribution.rejected", "answer.source-bundle", "export.ready", "status.result", "content.deleted", "tombstone.result", "private.error"],
      public_routes: ["host_descriptor", "public_query", "public_pack"]
    },
    query_policy: { stores_private_query_bodies: false, private_query_retention_seconds: 0, public_scope_enabled: true, controller_confidential_scope_enabled: true, requires_separate_training_consent: true, maximum_top_k: 5 },
    data_regions: [{ region_code: "test-region-1", jurisdiction: "Test jurisdiction" }],
    subprocessors: [],
    retention_behavior: { maximum_host_confidential_seconds: 2592000, maximum_private_query_seconds: 0, maximum_backup_deletion_seconds: 2592000, withdrawal_blocks_future_use: true },
    model_use_disclosure: { inference_enabled: false, training_enabled: false, external_model_providers: [] },
    capability_limits: { maximum_query_utf8_bytes: 16384, maximum_answer_plaintext_bytes: 1048576, maximum_contribution_plaintext_bytes: 262144, maximum_concurrent_private_requests: 16, maximum_top_k: 5 },
    operator_memory_disclosure: "ordinary_process_operator_can_access_plaintext",
    metadata_disclosure: { ip_address: true, timing: true, approximate_size: true, route_class: true },
    issued_at: issuedAt,
    expires_at: expiresAt,
    ...overrides.core
  };
  const descriptorId = sha256(Buffer.from(`somavera:vera-host-descriptor:v1\n${canonicalize(core)}`));
  const signature = sign(null, Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(descriptorId, "hex")]), signingPair.privateKey).toString("base64");
  const descriptor = { ...core, descriptor_id: descriptorId, signature: { suite: "Ed25519-v1", key_id: core.active_host_signing_key_id, value: signature } };
  const expected = {
    origin: core.origin,
    host_did: core.host_did,
    network_lineage_id: core.network_lineage_id,
    execution_context_id: core.execution_context_id,
    active_signing_key_sha256: sha256(signingPublic)
  };
  return { descriptor, expected, signingPair, signingPublic, ingestionPublic };
}

function resignDescriptor(descriptor, privateKey) {
  const { descriptor_id: ignoredId, signature: ignoredSignature, ...core } = descriptor;
  const descriptorId = sha256(Buffer.from(`somavera:vera-host-descriptor:v1\n${canonicalize(core)}`));
  const value = sign(null, Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(descriptorId, "hex")]), privateKey).toString("base64");
  return { ...core, descriptor_id: descriptorId, signature: { suite: "Ed25519-v1", key_id: core.active_host_signing_key_id, value } };
}

async function writeDescriptor(file, descriptor) {
  await writeFile(file, `${canonicalize(descriptor)}\n`, "utf8");
}

function args(action, home, file, expected, includeKey = true) {
  const result = ["host", action, "--home", home, "--descriptor", file, "--expect-origin", expected.origin, "--expect-host-did", expected.host_did, "--expect-network", expected.network_lineage_id, "--expect-context", expected.execution_context_id];
  if (includeKey) result.push("--expect-key-hash", expected.active_signing_key_sha256);
  result.push("--json");
  return result;
}

test("fixed host descriptor vector reproduces its identifier, signature, and trust bindings", async () => {
  const vector = JSON.parse(await readFile(path.join(root, "conformance", "vera-host-descriptor-provisional-v1.json"), "utf8"));
  const { descriptor_id: ignoredId, signature: ignoredSignature, ...core } = vector.descriptor;
  assert.equal(canonicalize(core), vector.descriptor_core_jcs);
  assert.equal(sha256(Buffer.from(`somavera:vera-host-descriptor:v1\n${vector.descriptor_core_jcs}`)), vector.descriptor_id);
  assert.equal(vector.descriptor.descriptor_id, vector.descriptor_id);
  const result = await verifyHostDescriptor(vector.descriptor, vector.expected, { validationTime: Date.parse(vector.validation_time), requireCurrent: true, requireKeyHash: true, acceptedOriginCapsuleHashes: SUPPORTED_ORIGIN_CAPSULE_HASHES });
  assert.equal(result.descriptor_id, vector.descriptor_id);
  assert.equal(result.active_signing_key_sha256, vector.expected.active_signing_key_sha256);
  assert.equal(Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(vector.descriptor_id, "hex")]).toString("hex"), vector.signature_message_hex);
});

test("offline descriptor verification is non-authoritative and pinning requires out-of-band key material", async (context) => {
  const { temporary, home, trace } = await setup(context);
  const file = path.join(temporary, "descriptor.json");
  const { descriptor, expected } = fixture();
  await writeDescriptor(file, descriptor);
  const verified = execute(args("verify", home, file, expected, false), trace);
  assert.equal(verified.status, 0, verified.stderr || verified.stdout);
  const verification = JSON.parse(verified.stdout);
  assert.equal(verification.pin_eligible, false);
  assert.equal(verification.authority, "verification_only_no_pin_no_connection_no_consent_no_send");
  const hostEntries = await readdir(path.join(home, "hosts"), { withFileTypes: true });
  assert.deepEqual(hostEntries.map((entry) => [entry.name, entry.isDirectory()]).sort(), [["candidates", true], ["history", true], ["transactions", true]]);
  const refused = execute(args("pin", home, file, expected, false), trace);
  assert.equal(refused.status, 8, refused.stderr || refused.stdout);
  assert.equal(JSON.parse(refused.stdout).error, "HOST_PIN_KEY_HASH_REQUIRED");
  await noEgress(trace);
});

test("controller-signed host pin is offline, idempotent, inert, and visible to doctor", async (context) => {
  const { temporary, home, trace } = await setup(context);
  const file = path.join(temporary, "descriptor.json");
  const { descriptor, expected } = fixture();
  await writeDescriptor(file, descriptor);
  const pinned = execute(args("pin", home, file, expected), trace);
  assert.equal(pinned.status, 0, pinned.stderr || pinned.stdout);
  const result = JSON.parse(pinned.stdout);
  assert.equal(result.local_mutation, true);
  assert.equal(result.remote_mutation, false);
  assert.equal(result.authority, "offline_pin_only_no_connection_no_consent_no_send");
  assert.equal(result.network_actions, 0);
  const repeated = execute(args("pin", home, file, expected), trace);
  assert.equal(repeated.status, 0, repeated.stderr || repeated.stdout);
  assert.equal(JSON.parse(repeated.stdout).idempotent, true);
  assert.equal(JSON.parse(repeated.stdout).local_mutation, false);
  const rotationPreviewCommand = execute(["identity", "controller-rotate-preview", "--home", home, "--reason", "historic host pin test", "--json"], trace);
  assert.equal(rotationPreviewCommand.status, 0, rotationPreviewCommand.stdout);
  const rotationPreview = JSON.parse(rotationPreviewCommand.stdout);
  const rotationConfirm = execute([
    "identity", "controller-rotate-confirm", "--home", home,
    "--proposal-id", rotationPreview.proposal_id,
    "--expect-successor-key-hash", rotationPreview.successor_key_sha256,
    "--confirm-controller-rotation", "--json"
  ], trace);
  assert.equal(rotationConfirm.status, 0, rotationConfirm.stdout);
  assert.equal(JSON.parse(rotationConfirm.stdout).controller_did, JSON.parse(rotationPreviewCommand.stdout).controller_did);
  const status = execute(["host", "status", "--home", home, "--json"], trace);
  assert.equal(status.status, 0, status.stderr || status.stdout);
  const hostState = JSON.parse(status.stdout);
  assert.equal(hostState.pinned_hosts, 1);
  assert.equal(hostState.connected_hosts, 0);
  assert.equal(hostState.pins[0].descriptor_id, descriptor.descriptor_id);
  const doctor = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(doctor.status, 0, doctor.stderr || doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).pinned_hosts, 1);
  assert.equal((await readdir(path.join(home, "consent", "grants"))).length, 0);
  assert.equal((await readdir(path.join(home, "queue"))).length, 0);
  await noEgress(trace);
});

test("identity substitutions, signature mutation, downgrade, expiry, and semantic inconsistencies fail closed", async (context) => {
  const { temporary, home, trace } = await setup(context);
  const file = path.join(temporary, "descriptor.json");
  const base = fixture();
  await writeDescriptor(file, base.descriptor);
  const mismatches = [
    [{ ...base.expected, origin: "https://other.example.test" }, "HOST_ORIGIN_MISMATCH"],
    [{ ...base.expected, host_did: "did:example:other-host" }, "HOST_DID_MISMATCH"],
    [{ ...base.expected, network_lineage_id: `somavera:network:v1:${"c".repeat(64)}` }, "HOST_NETWORK_MISMATCH"],
    [{ ...base.expected, execution_context_id: `somavera:context:v1:${"d".repeat(64)}` }, "HOST_CONTEXT_MISMATCH"],
    [{ ...base.expected, active_signing_key_sha256: "e".repeat(64) }, "HOST_SIGNING_KEY_HASH_MISMATCH"]
  ];
  for (const [expected, code] of mismatches) {
    const rejected = execute(args("verify", home, file, expected), trace);
    assert.notEqual(rejected.status, 0, rejected.stderr || rejected.stdout);
    assert.equal(JSON.parse(rejected.stdout).error, code);
  }
  const mutated = structuredClone(base.descriptor);
  mutated.policy_hash = "5".repeat(64);
  await writeDescriptor(file, mutated);
  let rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_ID_MISMATCH");
  const expired = fixture({ core: { issued_at: "2026-01-01T00:00:00.000Z", expires_at: "2026-01-01T01:00:00.000Z" } });
  await writeDescriptor(file, expired.descriptor);
  rejected = execute(args("verify", home, file, expired.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_TIME_INVALID");
  const wrongCapsule = fixture({ core: { release: { ...base.descriptor.release, origin_capsule_hash: "3".repeat(64) } } });
  await writeDescriptor(file, wrongCapsule.descriptor);
  rejected = execute(args("verify", home, file, wrongCapsule.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_ORIGIN_CAPSULE_MISMATCH");
  const invalidGenesisLink = fixture({ core: { previous_descriptor_id: "1".repeat(64) } });
  await writeDescriptor(file, invalidGenesisLink.descriptor);
  rejected = execute(args("verify", home, file, invalidGenesisLink.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_SCHEMA_INVALID");
  const invalidSuccessorLink = fixture({ core: { descriptor_sequence: 1, previous_descriptor_id: null } });
  await writeDescriptor(file, invalidSuccessorLink.descriptor);
  rejected = execute(args("verify", home, file, invalidSuccessorLink.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_SCHEMA_INVALID");
  const excessiveLifetime = structuredClone(base.descriptor);
  excessiveLifetime.rotation_policy.maximum_descriptor_lifetime_seconds = 900;
  await writeDescriptor(file, resignDescriptor(excessiveLifetime, base.signingPair.privateKey));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_LIFETIME_INVALID");
  const reused = fixture({ ingestionPublic: base.signingPublic, signingPair: base.signingPair });
  await writeDescriptor(file, reused.descriptor);
  rejected = execute(args("verify", home, file, reused.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_KEY_ROLE_REUSE");
  const lowOrder = fixture({ ingestionPublic: Buffer.alloc(32) });
  await writeDescriptor(file, lowOrder.descriptor);
  rejected = execute(args("verify", home, file, lowOrder.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_INGESTION_KEY_INVALID");
  const badBound = fixture({ core: { capability_limits: { ...base.descriptor.capability_limits, maximum_contribution_plaintext_bytes: 131072 } } });
  await writeDescriptor(file, badBound.descriptor);
  rejected = execute(args("verify", home, file, badBound.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_SIZE_BOUND_MISMATCH");
  const unknown = { ...base.descriptor, surprise_authority: true };
  await writeDescriptor(file, unknown);
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_SCHEMA_INVALID");
  const downgraded = structuredClone(base.descriptor);
  downgraded.host_signing_keys[0].suite = "Ed25519";
  await writeDescriptor(file, resignDescriptor(downgraded, base.signingPair.privateKey));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_SCHEMA_INVALID");
  const overlap = structuredClone(base.descriptor);
  overlap.host_signing_keys[0].lifecycle.status = "overlap";
  await writeDescriptor(file, resignDescriptor(overlap, base.signingPair.privateKey));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_ACTIVE_SIGNING_KEY_INVALID");
  const outlivesKey = structuredClone(base.descriptor);
  outlivesKey.expires_at = new Date(Date.parse(base.descriptor.host_signing_keys[0].lifecycle.valid_until) + 1000).toISOString();
  await writeDescriptor(file, resignDescriptor(outlivesKey, base.signingPair.privateKey));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_ACTIVE_SIGNING_KEY_INVALID");
  const impossibleDate = structuredClone(base.descriptor);
  impossibleDate.expires_at = "2026-02-30T00:00:00Z";
  await writeDescriptor(file, resignDescriptor(impossibleDate, base.signingPair.privateKey));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_SCHEMA_INVALID");
  await writeFile(file, Buffer.from([0xff, 0xfe, 0xfd]));
  rejected = execute(args("verify", home, file, base.expected), trace);
  assert.equal(JSON.parse(rejected.stdout).error, "HOST_DESCRIPTOR_ENCODING_INVALID");
  await noEgress(trace);
});

test("descriptor changes and local pin tampering cannot silently replace trust", async (context) => {
  const { temporary, home, trace } = await setup(context);
  const file = path.join(temporary, "descriptor.json");
  const base = fixture();
  await writeDescriptor(file, base.descriptor);
  const pinned = execute(args("pin", home, file, base.expected), trace);
  assert.equal(pinned.status, 0, pinned.stderr || pinned.stdout);
  const changed = fixture({ signingPair: base.signingPair, ingestionPublic: base.ingestionPublic, core: { policy_hash: "6".repeat(64) } });
  await writeDescriptor(file, changed.descriptor);
  const refused = execute(args("pin", home, file, changed.expected), trace);
  assert.equal(refused.status, 8, refused.stderr || refused.stdout);
  assert.equal(JSON.parse(refused.stdout).error, "HOST_DESCRIPTOR_CHANGE_UNSUPPORTED");
  const hostFiles = (await readdir(path.join(home, "hosts"), { withFileTypes: true })).filter((entry) => entry.isFile());
  assert.equal(hostFiles.length, 1);
  const pinFile = path.join(home, "hosts", hostFiles[0].name);
  const record = JSON.parse(await readFile(pinFile, "utf8"));
  record.authority = "connected_and_authorized";
  await writeFile(pinFile, `${canonicalize(record)}\n`, "utf8");
  const doctor = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(doctor.status, 7, doctor.stderr || doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).error, "HOST_PIN_INVARIANT_INVALID");
  await noEgress(trace);
});
