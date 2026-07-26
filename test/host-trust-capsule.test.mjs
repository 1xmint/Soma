import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import { cp, mkdtemp, readFile, readdir, rm, stat, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { privateKeyForRole, sha256, signEd25519 } from "../src/crypto.mjs";
import { controllerSecret, eraseSecretBundle, hostFile, publicIdentity } from "../src/host.mjs";
import { deriveHostDescriptorId, deriveHostSuccessionId } from "../src/host-succession.mjs";
import { restrictStateRoot } from "../src/platform.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;
const originCapsule = "047b76b3a96e536893f3dff1a5dc62cd3ac83669769395fe8f48d629e050084f";

function execute(args, trace) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: "utf8", windowsHide: true, timeout: 30000, env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(), SOMA_NETWORK_TRACE: trace } });
}
async function noEgress(trace) { try { assert.equal((await stat(trace)).size, 0); } catch (error) { if (error.code !== "ENOENT") throw error; } }
function privateKey(seedHex) { return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" }); }
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
function liveSuccession(vector, now) {
  const result = structuredClone(vector);
  const priorKey = privateKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const successorKey = privateKey("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  const iso = (offset) => new Date(now + offset).toISOString();
  for (const descriptor of [result.prior_descriptor, result.successor_descriptor]) descriptor.release.origin_capsule_hash = originCapsule;
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
  Object.assign(result.succession_proof, { prior_descriptor_id: result.prior_descriptor.descriptor_id, successor_descriptor_id: result.successor_descriptor.descriptor_id, issued_at: iso(-10000), expires_at: iso(300000) });
  resignProof(result.succession_proof, priorKey, successorKey);
  return result;
}
async function initialize(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-trust-capsule-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home"), trace = path.join(temporary, "network.trace");
  const command = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  return { temporary, home, trace };
}
async function pinAndPreview(context) {
  const setup = await initialize(context);
  const base = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
  const live = liveSuccession(base, Date.now());
  const priorFile = path.join(setup.temporary, "prior.json"), successorFile = path.join(setup.temporary, "successor.json"), proofFile = path.join(setup.temporary, "proof.json");
  await writeFile(priorFile, `${canonicalize(live.prior_descriptor)}\n`);
  await writeFile(successorFile, `${canonicalize(live.successor_descriptor)}\n`);
  await writeFile(proofFile, `${canonicalize(live.succession_proof)}\n`);
  const priorHash = sha256(Buffer.from(live.prior_descriptor.host_signing_keys[0].public_key_base64, "base64"));
  let command = execute(["host", "pin", "--home", setup.home, "--descriptor", priorFile, "--expect-origin", live.prior_descriptor.origin, "--expect-host-did", live.prior_descriptor.host_did, "--expect-network", live.prior_descriptor.network_lineage_id, "--expect-context", live.prior_descriptor.execution_context_id, "--expect-key-hash", priorHash, "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  command = execute(["host", "succession-preview", "--home", setup.home, "--successor", successorFile, "--proof", proofFile, "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  return { ...setup, live, preview: JSON.parse(command.stdout) };
}
function exportCapsule(home, file, trace) { return execute(["host", "trust-export", "--home", home, "--out", file, "--json"], trace); }
function verifyArgs(file, exported) { return ["host", "trust-verify", "--capsule", file, "--expect-controller-did", exported.controller_did, "--expect-controller-key-hash", exported.controller_key_sha256, "--json"]; }
function compareArgs(trusted, candidate, exported) { return ["host", "trust-compare", "--trusted", trusted, "--candidate", candidate, "--expect-controller-did", exported.controller_did, "--expect-controller-key-hash", exported.controller_key_sha256, "--json"]; }

test("stored pins from the immediately prior Origin profile remain verifiable and succession-capable", async (context) => {
  const setup = await initialize(context);
  const base = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
  const live = liveSuccession(base, Date.now());
  const priorOrigin = "8cb60c8ce3199aa35c101657834eece86e8823e9d6aa8eb47a9e23db89582431";
  live.prior_descriptor.release.origin_capsule_hash = priorOrigin;
  live.successor_descriptor.release.origin_capsule_hash = priorOrigin;
  const priorKey = privateKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const successorKey = privateKey("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  resignDescriptor(live.prior_descriptor, priorKey);
  live.successor_descriptor.previous_descriptor_id = live.prior_descriptor.descriptor_id;
  resignDescriptor(live.successor_descriptor, successorKey);
  live.succession_proof.prior_descriptor_id = live.prior_descriptor.descriptor_id;
  live.succession_proof.successor_descriptor_id = live.successor_descriptor.descriptor_id;
  resignProof(live.succession_proof, priorKey, successorKey);
  const oldDescriptorFile = path.join(setup.temporary, "prior-origin-descriptor.json");
  await writeFile(oldDescriptorFile, `${canonicalize(live.prior_descriptor)}\n`);
  const oldActive = live.prior_descriptor.host_signing_keys.find((key) => key.key_id === live.prior_descriptor.active_host_signing_key_id);
  let command = execute(["host", "verify", "--home", setup.home, "--descriptor", oldDescriptorFile, "--expect-origin", live.prior_descriptor.origin, "--expect-host-did", live.prior_descriptor.host_did, "--expect-network", live.prior_descriptor.network_lineage_id, "--expect-context", live.prior_descriptor.execution_context_id, "--expect-key-hash", sha256(Buffer.from(oldActive.public_key_base64, "base64")), "--json"], setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_ORIGIN_CAPSULE_MISMATCH");
  const identity = await publicIdentity(setup.home);
  let secretBundle;
  try {
    secretBundle = await controllerSecret(setup.home);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    const active = live.prior_descriptor.host_signing_keys.find((key) => key.key_id === live.prior_descriptor.active_host_signing_key_id);
    const expected = { origin: live.prior_descriptor.origin, host_did: live.prior_descriptor.host_did, network_lineage_id: live.prior_descriptor.network_lineage_id, execution_context_id: live.prior_descriptor.execution_context_id, active_signing_key_sha256: sha256(Buffer.from(active.public_key_base64, "base64")) };
    const core = { schema_version: "soma.host-pin.provisional-v1", pinned_at: new Date().toISOString(), controller_did: identity.controller_did, trust_basis: "exact_bindings_plus_out_of_band_active_signing_key_sha256", expected, descriptor: live.prior_descriptor, connected: false, rotation_policy: "changed_descriptor_blocked_until_ratified_rotation_proof", authority: "offline_pin_only_no_connection_no_consent_no_send" };
    const pinId = sha256(Buffer.from("soma:host-pin:provisional-v1\n" + canonicalize(core)));
    const pin = { ...core, pin_id: pinId, signature: { suite: "Ed25519-v1", key_id: controller.key_id, value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from("soma:host-pin-signature:provisional-v1\n"), Buffer.from(pinId, "hex")])) } };
    await writeFile(hostFile(setup.home, live.prior_descriptor.host_did), `${canonicalize(pin)}\n`);
  } finally { eraseSecretBundle(secretBundle); }
  command = execute(["doctor", "--home", setup.home, "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const successorFile = path.join(setup.temporary, "prior-origin-successor.json"), proofFile = path.join(setup.temporary, "prior-origin-proof.json");
  await writeFile(successorFile, `${canonicalize(live.successor_descriptor)}\n`);
  await writeFile(proofFile, `${canonicalize(live.succession_proof)}\n`);
  command = execute(["host", "succession-preview", "--home", setup.home, "--successor", successorFile, "--proof", proofFile, "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  await noEgress(setup.trace);
});

test("empty portable host-trust capsule verifies standalone and remains explicitly unanchored", async (context) => {
  const setup = await initialize(context);
  const capsuleFile = path.join(setup.temporary, "empty-capsule.json");
  let command = exportCapsule(setup.home, capsuleFile, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const exported = JSON.parse(command.stdout);
  assert.equal(exported.schema_version, "somavera.soma-host-trust-capsule.v2");
  assert.equal(exported.controller_rotation_count, 0);
  assert.equal(exported.host_count, 0);
  assert.equal(exported.transition_count, 0);
  assert.equal(exported.external_anchor_created, false);
  command = execute(verifyArgs(capsuleFile, exported), setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const verified = JSON.parse(command.stdout);
  assert.equal(verified.restore_authorized, false);
  assert.equal(verified.authority, "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority");
  const capsuleText = await readFile(capsuleFile, "utf8");
  for (const prohibited of ["private_key_pkcs8", "root_store_key", "consent/grants", "intelligence/queries", "keystore.blob"]) assert.equal(capsuleText.includes(prohibited), false, prohibited);
  command = exportCapsule(setup.home, capsuleFile, setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_TRUST_CAPSULE_OUTPUT_EXISTS");
  const wrong = verifyArgs(capsuleFile, exported);
  wrong[wrong.indexOf("--expect-controller-key-hash") + 1] = "f".repeat(64);
  command = execute(wrong, setup.trace);
  assert.equal(command.status, 7, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH");
  const partialFile = path.join(setup.temporary, "partial-capsule.json");
  const partialBytes = capsuleText.slice(0, Math.floor(capsuleText.length / 2));
  await writeFile(partialFile, partialBytes);
  command = execute(verifyArgs(partialFile, exported), setup.trace);
  assert.notEqual(command.status, 0, command.stdout);
  command = exportCapsule(setup.home, partialFile, setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(await readFile(partialFile, "utf8"), partialBytes);
  await noEgress(setup.trace);
});

test("trusted capsule comparison detects rollback and controller-signed same-height fork", async (context) => {
  const setup = await pinAndPreview(context);
  const pre = path.join(setup.temporary, "trusted-pre.json"), post = path.join(setup.temporary, "trusted-post.json"), rollback = path.join(setup.temporary, "rollback-newer.json"), fork = path.join(setup.temporary, "fork-newer.json");
  let command = exportCapsule(setup.home, pre, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const exported = JSON.parse(command.stdout);
  const rolledBackHome = path.join(setup.temporary, "rolled-back-home");
  await cp(setup.home, rolledBackHome, { recursive: true });
  await restrictStateRoot(rolledBackHome);
  command = execute(["host", "succession-confirm", "--home", setup.home, "--candidate-id", setup.preview.candidate_id, "--subject", setup.preview.subject_id, "--expect-successor-descriptor", setup.live.successor_descriptor.descriptor_id, "--confirm-inert-pin-replacement", "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  command = exportCapsule(setup.home, post, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  command = execute(compareArgs(pre, post, exported), setup.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).relation, "equal_or_strict_descendant_controller_and_host_trust_state");
  command = execute(compareArgs(pre, pre, exported), setup.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).relation, "identical_capsule");
  command = exportCapsule(rolledBackHome, rollback, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  command = execute(compareArgs(post, rollback, exported), setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");

  const identity = await publicIdentity(rolledBackHome);
  const priorPinPath = hostFile(rolledBackHome, setup.live.successor_descriptor.host_did);
  const priorPin = JSON.parse(await readFile(priorPinPath, "utf8"));
  let secretBundle;
  try {
    secretBundle = await controllerSecret(rolledBackHome);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    const active = setup.live.successor_descriptor.host_signing_keys.find((key) => key.key_id === setup.live.successor_descriptor.active_host_signing_key_id);
    const core = { schema_version: "soma.host-pin.provisional-v1", pinned_at: new Date().toISOString(), controller_did: identity.controller_did, trust_basis: "exact_bindings_plus_out_of_band_active_signing_key_sha256", expected: { ...priorPin.expected, active_signing_key_sha256: sha256(Buffer.from(active.public_key_base64, "base64")) }, descriptor: setup.live.successor_descriptor, connected: false, rotation_policy: "changed_descriptor_blocked_until_ratified_rotation_proof", authority: "offline_pin_only_no_connection_no_consent_no_send" };
    const pinId = sha256(Buffer.from("soma:host-pin:provisional-v1\n" + canonicalize(core)));
    const malicious = { ...core, pin_id: pinId, signature: { suite: "Ed25519-v1", key_id: controller.key_id, value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from("soma:host-pin-signature:provisional-v1\n"), Buffer.from(pinId, "hex")])) } };
    await writeFile(priorPinPath, `${canonicalize(malicious)}\n`);
    for (const candidateName of await readdir(path.join(rolledBackHome, "hosts", "candidates"))) await unlink(path.join(rolledBackHome, "hosts", "candidates", candidateName));
  } finally { eraseSecretBundle(secretBundle); }
  command = exportCapsule(rolledBackHome, fork, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  command = execute(compareArgs(pre, fork, exported), setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");
  await noEgress(setup.trace);
});

test("capsule object, path, root, controller, claim, ID, and signature mutations fail standalone", async (context) => {
  const setup = await pinAndPreview(context);
  const capsuleFile = path.join(setup.temporary, "capsule.json");
  let command = exportCapsule(setup.home, capsuleFile, setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const exported = JSON.parse(command.stdout);
  const original = JSON.parse(await readFile(capsuleFile, "utf8"));
  const mutations = [
    ["object_bytes", (value) => { const bytes = Buffer.from(value.objects[0].canonical_json_base64, "base64"); bytes[0] ^= 1; value.objects[0].canonical_json_base64 = bytes.toString("base64"); }],
    ["object_path", (value) => { value.objects[0].path = `hosts/${"f".repeat(64)}.json`; }],
    ["object_kind", (value) => { value.objects[0].kind = "history_transition"; }],
    ["object_length", (value) => { value.objects[0].byte_length += 1; }],
    ["object_hash", (value) => { value.objects[0].sha256 = "f".repeat(64); }],
    ["current_root", (value) => { value.current_set_root = "f".repeat(64); }],
    ["object_root", (value) => { value.object_set_root = "f".repeat(64); }],
    ["controller", (value) => { value.controller.did = "did:key:attacker"; }],
    ["source", (value) => { value.source.origin_capsule_hash = "f".repeat(64); }],
    ["claim", (value) => { value.claims.external_anchor_created = true; }],
    ["capsule_id", (value) => { value.capsule_id = "f".repeat(64); }],
    ["signature", (value) => { value.signature.value = (value.signature.value[0] === "A" ? "B" : "A") + value.signature.value.slice(1); }]
  ];
  for (const [name, mutate] of mutations) {
    const candidate = structuredClone(original);
    mutate(candidate);
    const file = path.join(setup.temporary, `${name}.json`);
    await writeFile(file, `${canonicalize(candidate)}\n`);
    command = execute(verifyArgs(file, exported), setup.trace);
    assert.equal(command.status, 7, `${name}: ${command.stdout}`);
  }
  await noEgress(setup.trace);
});
