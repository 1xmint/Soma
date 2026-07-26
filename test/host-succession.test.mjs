import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";
import { deriveHostDescriptorId, deriveHostSuccessionId, validateOrdinaryHostSuccession } from "../src/host-succession.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;
const capsule = "90e6a961f0b9bf9be137ea08b2f93483b3aa5e4df610a7785f13f08ad1a31c3b";

function execute(args, trace) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: "utf8", windowsHide: true, timeout: 30000, env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(), SOMA_NETWORK_TRACE: trace } });
}

async function noEgress(trace) {
  try { assert.equal((await stat(trace)).size, 0); } catch (error) { if (error.code !== "ENOENT") throw error; }
}

function privateKey(seedHex) {
  return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
}

function resignDescriptor(descriptor, key) {
  descriptor.descriptor_id = deriveHostDescriptorId(descriptor);
  descriptor.signature = { suite: "Ed25519-v1", key_id: descriptor.active_host_signing_key_id, value: sign(null, Buffer.concat([Buffer.from("somavera:vera-host-descriptor-signature:v1\n"), Buffer.from(descriptor.descriptor_id, "hex")]), key).toString("base64") };
}

function resignProof(proof, priorKey, successorKey) {
  proof.succession_id = deriveHostSuccessionId(proof);
  const id = Buffer.from(proof.succession_id, "hex");
  proof.signatures = {
    prior_active_key_signature: { suite: "Ed25519-v1", key_id: proof.prior_active_host_signing_key_id, value: sign(null, Buffer.concat([Buffer.from("somavera:vera-host-descriptor-succession-signature:v1\nprior\n"), id]), priorKey).toString("base64") },
    successor_active_key_signature: { suite: "Ed25519-v1", key_id: proof.successor_active_host_signing_key_id, value: sign(null, Buffer.concat([Buffer.from("somavera:vera-host-descriptor-succession-signature:v1\nsuccessor\n"), id]), successorKey).toString("base64") }
  };
}

function corrupt(value) { return (value[0] === "A" ? "B" : "A") + value.slice(1); }

function mutate(vector, name) {
  const prior = vector.prior_descriptor, successor = vector.successor_descriptor, proof = vector.succession_proof;
  if (name === "sequence_skip") { successor.descriptor_sequence += 1; proof.successor_descriptor_sequence += 1; }
  if (name === "wrong_predecessor") successor.previous_descriptor_id = "22".repeat(32);
  if (name === "immutable_origin_change") successor.origin = "https://attacker.example.test";
  if (name === "unprecommitted_signing_key") prior.host_signing_keys[1].public_key_base64 = Buffer.alloc(32, 0x55).toString("base64");
  if (name === "unprecommitted_ingestion_key") prior.ingestion_encryption_keys[1].public_key_base64 = Buffer.alloc(32, 0x56).toString("base64");
  if (name === "expired_precommit") prior.host_signing_keys[1].lifecycle.valid_until = "2027-01-01T11:59:59Z";
  if (name === "scope_mismatch") proof.change_scope = "renewal_only";
  if (name === "proof_too_long") proof.expires_at = "2027-01-01T12:15:01Z";
  if (name === "role_signature_replay") proof.signatures.prior_active_key_signature.value = proof.signatures.successor_active_key_signature.value;
  if (name === "successor_signature_corruption") proof.signatures.successor_active_key_signature.value = corrupt(proof.signatures.successor_active_key_signature.value);
  if (name === "historic_key_removal") successor.host_signing_keys.splice(0, 1);
  if (name === "historic_lifecycle_rewrite") successor.host_signing_keys[0].lifecycle.valid_until = "2027-01-03T00:00:00Z";
  if (name === "ambiguous_active_key") successor.host_signing_keys[0].lifecycle.status = "active";
  if (name === "emergency_revocation_smuggling") { successor.host_signing_keys[0].lifecycle.status = "revoked"; successor.host_signing_keys[0].lifecycle.revoked_at = proof.issued_at; successor.host_signing_keys[0].lifecycle.revocation_reference = "unratified-emergency"; }
  if (name === "overlap_window_too_long") prior.host_signing_keys[1].lifecycle.valid_until = "2027-01-03T00:00:01Z";
  if (name === "descriptor_signature_corruption") prior.signature.value = corrupt(prior.signature.value);
  if (name === "authority_escalation") proof.authority.authorizes_connection = true;
}

test("Origin ordinary succession vector and every published adversarial recipe reproduce", async () => {
  const vector = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
  const accepted = validateOrdinaryHostSuccession(vector.prior_descriptor, vector.successor_descriptor, vector.succession_proof, { validationTime: Date.parse(vector.validation_time) });
  assert.equal(accepted.succession_id, vector.expected.succession_id);
  const invalid = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-invalid-v1.json"), "utf8"));
  for (const recipe of invalid.cases) {
    const candidate = structuredClone(vector);
    mutate(candidate, recipe.mutation);
    assert.throws(() => validateOrdinaryHostSuccession(candidate.prior_descriptor, candidate.successor_descriptor, candidate.succession_proof, { validationTime: Date.parse(candidate.validation_time) }), (error) => error.code === "HOST_SUCCESSION_INVALID" && error.details.violations.some((violation) => violation.startsWith(recipe.expected_error)), recipe.name);
  }
});

function liveSuccession(vector, now) {
  const result = structuredClone(vector);
  const priorKey = privateKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const successorKey = privateKey("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  const iso = (offset) => new Date(now + offset).toISOString();
  for (const descriptor of [result.prior_descriptor, result.successor_descriptor]) descriptor.release.origin_capsule_hash = capsule;
  result.prior_descriptor.issued_at = iso(-120000);
  result.prior_descriptor.expires_at = iso(3600000);
  result.successor_descriptor.issued_at = iso(-30000);
  result.successor_descriptor.expires_at = iso(3600000);
  for (const [index, key] of result.prior_descriptor.host_signing_keys.entries()) key.lifecycle = { ...key.lifecycle, valid_from: iso(index === 0 ? -86400000 : -60000), valid_until: iso(3600000) };
  for (const [index, key] of result.prior_descriptor.ingestion_encryption_keys.entries()) key.lifecycle = { ...key.lifecycle, valid_from: iso(index === 0 ? -86400000 : -60000), valid_until: iso(3600000) };
  result.successor_descriptor.host_signing_keys = structuredClone(result.prior_descriptor.host_signing_keys);
  result.successor_descriptor.ingestion_encryption_keys = structuredClone(result.prior_descriptor.ingestion_encryption_keys);
  result.successor_descriptor.host_signing_keys[0].lifecycle.status = "retired";
  result.successor_descriptor.host_signing_keys[1].lifecycle.status = "active";
  result.successor_descriptor.ingestion_encryption_keys[0].lifecycle.status = "retired";
  result.successor_descriptor.ingestion_encryption_keys[1].lifecycle.status = "active";
  resignDescriptor(result.prior_descriptor, priorKey);
  result.successor_descriptor.previous_descriptor_id = result.prior_descriptor.descriptor_id;
  resignDescriptor(result.successor_descriptor, successorKey);
  Object.assign(result.succession_proof, {
    prior_descriptor_id: result.prior_descriptor.descriptor_id,
    successor_descriptor_id: result.successor_descriptor.descriptor_id,
    issued_at: iso(-10000),
    expires_at: iso(300000)
  });
  resignProof(result.succession_proof, priorKey, successorKey);
  return result;
}

test("offline succession preview stores one inert signed candidate without replacing its prior pin", async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-succession-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home"), trace = path.join(temporary, "network.trace");
  let command = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  const base = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
  const live = liveSuccession(base, Date.now());
  const priorFile = path.join(temporary, "prior.json"), successorFile = path.join(temporary, "successor.json"), proofFile = path.join(temporary, "proof.json");
  await writeFile(priorFile, `${canonicalize(live.prior_descriptor)}\n`);
  await writeFile(successorFile, `${canonicalize(live.successor_descriptor)}\n`);
  await writeFile(proofFile, `${canonicalize(live.succession_proof)}\n`);
  const priorSigning = Buffer.from(live.prior_descriptor.host_signing_keys[0].public_key_base64, "base64");
  command = execute(["host", "pin", "--home", home, "--descriptor", priorFile, "--expect-origin", live.prior_descriptor.origin, "--expect-host-did", live.prior_descriptor.host_did, "--expect-network", live.prior_descriptor.network_lineage_id, "--expect-context", live.prior_descriptor.execution_context_id, "--expect-key-hash", sha256(priorSigning), "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  const pinnedId = JSON.parse(command.stdout).descriptor_id;
  command = execute(["host", "succession-preview", "--home", home, "--successor", successorFile, "--proof", proofFile, "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  const preview = JSON.parse(command.stdout);
  assert.equal(preview.local_mutation, true);
  assert.equal(preview.authority, "offline_candidate_only_no_pin_replacement_no_connection_no_consent_no_send");
  command = execute(["host", "succession-preview", "--home", home, "--successor", successorFile, "--proof", proofFile, "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).idempotent, true);
  assert.equal(JSON.parse(command.stdout).local_mutation, false);
  command = execute(["host", "status", "--home", home, "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  const status = JSON.parse(command.stdout);
  assert.equal(status.pinned_hosts, 1);
  assert.equal(status.pending_host_successions, 1);
  assert.equal(status.pins[0].descriptor_id, pinnedId);
  assert.equal(status.connected_hosts, 0);
  const successorSigning = Buffer.from(live.successor_descriptor.host_signing_keys[1].public_key_base64, "base64");
  command = execute(["host", "pin", "--home", home, "--descriptor", successorFile, "--expect-origin", live.successor_descriptor.origin, "--expect-host-did", live.successor_descriptor.host_did, "--expect-network", live.successor_descriptor.network_lineage_id, "--expect-context", live.successor_descriptor.execution_context_id, "--expect-key-hash", sha256(successorSigning), "--json"], trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_DESCRIPTOR_CHANGE_UNSUPPORTED");
  command = execute(["host", "succession-confirm", "--home", home, "--json"], trace);
  assert.equal(command.status, 2, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_CONFIRMATION_INPUT_INVALID");
  assert.equal((await readdir(path.join(home, "consent", "grants"))).length, 0);
  assert.equal((await readdir(path.join(home, "queue"))).length, 0);
  const candidateDirectory = path.join(home, "hosts", "candidates");
  const [candidateName] = await readdir(candidateDirectory);
  const candidateFile = path.join(candidateDirectory, candidateName);
  const candidate = JSON.parse(await readFile(candidateFile, "utf8"));
  candidate.authority = "connected_and_authorized";
  await writeFile(candidateFile, `${canonicalize(candidate)}\n`);
  command = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(command.status, 7, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_CANDIDATE_SCHEMA_INVALID");
  await writeFile(candidateFile, "{\"truncated\":\n");
  command = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(command.status, 7, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_CANDIDATE_ENCODING_INVALID");
  await noEgress(trace);
});
