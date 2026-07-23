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
import { confirmHostSuccession } from "../src/host-confirmation.mjs";
import { deriveHostDescriptorId, deriveHostSuccessionId } from "../src/host-succession.mjs";
import { validateHostSuccessionConfirmation } from "../src/host-confirmation-domain.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;
const capsule = "9f711a3a8e53502c464efd2798266067adc2d42995246acb3b496c05ef948fb0";
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
  Object.assign(result.succession_proof, { prior_descriptor_id: result.prior_descriptor.descriptor_id, successor_descriptor_id: result.successor_descriptor.descriptor_id, issued_at: iso(-10000), expires_at: iso(300000) });
  resignProof(result.succession_proof, priorKey, successorKey);
  return result;
}
function multibase(rawBase64) {
  const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(rawBase64, "base64")]);
  let value = BigInt(`0x${bytes.toString("hex")}`), encoded = "";
  while (value > 0n) { encoded = BASE58[Number(value % 58n)] + encoded; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; encoded = `1${encoded}`; }
  return `z${encoded}`;
}
function substituteBinding(value, field) {
  if (Number.isSafeInteger(value[field])) { value[field] += 1; return; }
  if (field === "network_lineage_id") { value[field] = `somavera:network:v1:${"1".repeat(64)}`; return; }
  if (field === "execution_context_id") { value[field] = `somavera:context:v1:${"2".repeat(64)}`; return; }
  if (field === "host_did") { value[field] = "did:key:attacker-host"; return; }
  if (field === "origin") { value[field] = "https://attacker.example.test"; return; }
  if (field === "change_scope") { value[field] = "renewal_only"; return; }
  if (field.endsWith("_id") && !field.endsWith("key_id")) { value[field] = "aa".repeat(32); return; }
  if (field.endsWith("_sha256")) { value[field] = "bb".repeat(32); return; }
  if (field.endsWith("_key_id")) { value[field] = "did:key:attacker#wrong-purpose"; return; }
  throw new Error(`unsupported binding ${field}`);
}
function mutate(value, name) {
  if (name.startsWith("binding:")) substituteBinding(value, name.slice(8));
  if (name === "wrong_controller_did") value.controller_did = "did:key:attacker-controller";
  if (name === "wrong_controller_key") value.controller_signing_key_id = "did:key:example-soma-controller#controller-2";
  if (name === "before_proof_window") value.confirmed_at = "2027-01-01T11:59:59Z";
  if (name === "after_proof_window") value.confirmed_at = "2027-01-01T12:15:01Z";
  if (name === "decision_widening") value.decision = "replace_and_connect";
  if (name === "pin_replacement_removed") value.authority.authorizes_pin_replacement = false;
  if (name === "connection_authority_escalation") value.authority.authorizes_connection = true;
  if (name === "consent_authority_escalation") value.authority.authorizes_consent = true;
  if (name === "disclosure_authority_escalation") value.authority.authorizes_disclosure = true;
  if (name === "send_authority_escalation") value.authority.authorizes_send = true;
  if (name === "emergency_authority_escalation") value.authority.authorizes_emergency_recovery = true;
  if (name === "signature_key_mismatch") value.signature.key_id = "did:key:attacker#controller";
  if (name === "signature_corruption") value.signature.value = (value.signature.value[0] === "A" ? "B" : "A") + value.signature.value.slice(1);
  if (name === "subject_id_corruption") value.subject_id = "dd".repeat(32);
  if (name === "confirmation_id_corruption") value.confirmation_id = "ee".repeat(32);
}

test("Origin controller-confirmation vector and every published adversarial recipe reproduce", async () => {
  const vector = JSON.parse(await readFile(path.join(root, "conformance", "host-succession-confirmation-v1.json"), "utf8"));
  const source = JSON.parse(await readFile(path.join(root, "conformance", "host-descriptor-succession-v1.json"), "utf8"));
  const identity = { controller_did: vector.expected_controller_did, keys: [{ role: "controller_signing", status: "active", key_id: vector.expected_controller_signing_key_id, public_key_multibase: multibase(vector.controller_public_key_base64) }] };
  const accepted = validateHostSuccessionConfirmation(vector.confirmation, source.prior_descriptor, source.successor_descriptor, source.succession_proof, identity, { validationTime: Date.parse(vector.confirmation.confirmed_at) });
  assert.equal(accepted.confirmation_id, vector.expected.confirmation_id);
  const invalid = JSON.parse(await readFile(path.join(root, "conformance", "host-succession-confirmation-invalid-v1.json"), "utf8"));
  for (const recipe of invalid.cases) {
    const candidate = structuredClone(vector.confirmation);
    mutate(candidate, recipe.mutation);
    assert.throws(() => validateHostSuccessionConfirmation(candidate, source.prior_descriptor, source.successor_descriptor, source.succession_proof, identity, { validationTime: Date.parse(vector.confirmation.confirmed_at) }), (error) => error.code === "HOST_SUCCESSION_CONFIRMATION_INVALID" && error.details.violations.includes(recipe.expected_error), recipe.name);
  }
});

async function setupCandidate(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-confirm-test-"));
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
  const priorHash = sha256(Buffer.from(live.prior_descriptor.host_signing_keys[0].public_key_base64, "base64"));
  command = execute(["host", "pin", "--home", home, "--descriptor", priorFile, "--expect-origin", live.prior_descriptor.origin, "--expect-host-did", live.prior_descriptor.host_did, "--expect-network", live.prior_descriptor.network_lineage_id, "--expect-context", live.prior_descriptor.execution_context_id, "--expect-key-hash", priorHash, "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  const priorPinId = JSON.parse(command.stdout).pin_id;
  command = execute(["host", "succession-preview", "--home", home, "--successor", successorFile, "--proof", proofFile, "--json"], trace);
  assert.equal(command.status, 0, command.stdout);
  return { temporary, home, trace, live, preview: JSON.parse(command.stdout), priorPinId };
}
const confirmArgs = (setup) => ["host", "succession-confirm", "--home", setup.home, "--candidate-id", setup.preview.candidate_id, "--subject", setup.preview.subject_id, "--expect-successor-descriptor", setup.live.successor_descriptor.descriptor_id, "--confirm-inert-pin-replacement", "--json"];

test("exact controller confirmation atomically replaces only the inert pin and is idempotent", async (context) => {
  const setup = await setupCandidate(context);
  let command = execute(confirmArgs(setup).filter((entry) => entry !== "--confirm-inert-pin-replacement"), setup.trace);
  assert.equal(command.status, 9, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_CONFIRMATION_REQUIRED");
  const wrongSubject = confirmArgs(setup);
  wrongSubject[wrongSubject.indexOf("--subject") + 1] = "f".repeat(64);
  command = execute(wrongSubject, setup.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_CONFIRMATION_SUBJECT_MISMATCH");
  command = execute(confirmArgs(setup), setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const confirmed = JSON.parse(command.stdout);
  assert.equal(confirmed.committed, true);
  assert.equal(confirmed.prior_pin_id, setup.priorPinId);
  command = execute(confirmArgs(setup), setup.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).idempotent, true);
  command = execute(["host", "status", "--home", setup.home, "--json"], setup.trace);
  assert.equal(command.status, 0, command.stdout);
  const status = JSON.parse(command.stdout);
  assert.equal(status.pinned_hosts, 1);
  assert.equal(status.pending_host_successions, 0);
  assert.equal(status.completed_host_successions, 1);
  assert.equal(status.pins[0].descriptor_id, setup.live.successor_descriptor.descriptor_id);
  assert.equal(status.pins[0].pin_schema_version, "soma.host-pin.provisional-v2");
  assert.equal(status.connected_hosts, 0);
  assert.equal((await readdir(path.join(setup.home, "consent", "grants"))).length, 0);
  assert.equal((await readdir(path.join(setup.home, "queue"))).length, 0);
  assert.equal((await readdir(path.join(setup.home, "hosts", "candidates"))).length, 0);
  assert.equal((await readdir(path.join(setup.home, "hosts", "transactions"))).length, 0);
  const pinEntries = (await readdir(path.join(setup.home, "hosts"), { withFileTypes: true })).filter((entry) => entry.isFile());
  const pinFile = path.join(setup.home, "hosts", pinEntries[0].name);
  const pin = JSON.parse(await readFile(pinFile, "utf8"));
  pin.connected = true;
  await writeFile(pinFile, canonicalize(pin) + "\n");
  command = execute(["doctor", "--home", setup.home, "--json"], setup.trace);
  assert.equal(command.status, 7, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_PIN_INVARIANT_INVALID");
  pin.connected = false;
  await writeFile(pinFile, canonicalize(pin) + "\n");
  const [historyHost] = await readdir(path.join(setup.home, "hosts", "history"));
  const historyDirectory = path.join(setup.home, "hosts", "history", historyHost);
  const [historyName] = await readdir(historyDirectory);
  const historyFile = path.join(historyDirectory, historyName);
  const history = JSON.parse(await readFile(historyFile, "utf8"));
  history.authority = "connected_and_authorized";
  await writeFile(historyFile, canonicalize(history) + "\n");
  command = execute(["doctor", "--home", setup.home, "--json"], setup.trace);
  assert.equal(command.status, 7, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "HOST_SUCCESSION_TRANSITION_SCHEMA_INVALID");
  await noEgress(setup.trace);
});

test("fault recovery resolves every confirmation boundary to exactly prior or successor", async (context) => {
  const expectations = new Map([
    ["after_prepare", "prior"],
    ["after_successor_sync", "prior"],
    ["after_current_pin_commit", "successor"],
    ["after_candidate_consumed", "successor"],
    ["after_history_published", "successor"]
  ]);
  for (const [faultAt, expected] of expectations) {
    await context.test(faultAt, async (subcontext) => {
      const setup = await setupCandidate(subcontext);
      await assert.rejects(() => confirmHostSuccession(setup.home, { candidateId: setup.preview.candidate_id, subjectId: setup.preview.subject_id, successorDescriptorId: setup.live.successor_descriptor.descriptor_id, confirmInertPinReplacement: true, faultAt }), (error) => error.code === "HOST_SUCCESSION_FAULT_INJECTED");
      const doctor = execute(["doctor", "--home", setup.home, "--json"], setup.trace);
      assert.equal(doctor.status, 0, doctor.stdout);
      const state = JSON.parse(doctor.stdout);
      assert.equal(state.pending_host_successions, expected === "prior" ? 1 : 0);
      assert.equal(state.completed_host_successions, expected === "prior" ? 0 : 1);
      const status = execute(["host", "status", "--home", setup.home, "--json"], setup.trace);
      assert.equal(status.status, 0, status.stdout);
      assert.equal(JSON.parse(status.stdout).pins[0].descriptor_id, expected === "prior" ? setup.live.prior_descriptor.descriptor_id : setup.live.successor_descriptor.descriptor_id);
      assert.equal((await readdir(path.join(setup.home, "hosts", "transactions"))).length, 0);
      await noEgress(setup.trace);
    });
  }
});

test("history publication never replaces a conflicting existing record", async (context) => {
  const setup = await setupCandidate(context);
  await assert.rejects(() => confirmHostSuccession(setup.home, { candidateId: setup.preview.candidate_id, subjectId: setup.preview.subject_id, successorDescriptorId: setup.live.successor_descriptor.descriptor_id, confirmInertPinReplacement: true, faultAt: "after_candidate_consumed" }), (error) => error.code === "HOST_SUCCESSION_FAULT_INJECTED");
  const transactionDirectory = path.join(setup.home, "hosts", "transactions");
  const [preparedName] = (await readdir(transactionDirectory)).filter((name) => name.endsWith(".json"));
  const prepared = JSON.parse(await readFile(path.join(transactionDirectory, preparedName), "utf8"));
  const [historyHost] = await readdir(path.join(setup.home, "hosts", "history"));
  const destination = path.join(setup.home, "hosts", "history", historyHost, `${prepared.confirmation_id}.json`);
  const conflict = { ...prepared, authority: "connected_and_authorized" };
  const conflictBytes = canonicalize(conflict) + "\n";
  await writeFile(destination, conflictBytes);
  const doctor = execute(["doctor", "--home", setup.home, "--json"], setup.trace);
  assert.equal(doctor.status, 7, doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).error, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS");
  assert.equal(await readFile(destination, "utf8"), conflictBytes);
  assert.equal((await readdir(transactionDirectory)).filter((name) => name.endsWith(".json")).length, 1);
  await noEgress(setup.trace);
});

test("one hundred identical confirmations plus one competitor converge to one history record", async (context) => {
  const setup = await setupCandidate(context);
  const options = { candidateId: setup.preview.candidate_id, subjectId: setup.preview.subject_id, successorDescriptorId: setup.live.successor_descriptor.descriptor_id, confirmInertPinReplacement: true };
  const competing = { ...options, successorDescriptorId: "f".repeat(64) };
  const settled = await Promise.allSettled([...Array.from({ length: 100 }, () => confirmHostSuccession(setup.home, options)), confirmHostSuccession(setup.home, competing)]);
  const results = settled.filter((result) => result.status === "fulfilled").map((result) => result.value);
  const rejected = settled.filter((result) => result.status === "rejected");
  const rejectionCodes = rejected.map((result) => result.reason?.code || result.reason?.message || String(result.reason));
  assert.equal(results.length, 100, JSON.stringify(rejectionCodes));
  assert.equal(rejected.length, 1, JSON.stringify(rejectionCodes));
  assert.ok(["HOST_SUCCESSION_CONFIRMATION_SUCCESSOR_MISMATCH", "HOST_SUCCESSION_CONFIRMATION_CONFLICT"].includes(rejected[0].reason.code));
  assert.equal(results.filter((result) => result.local_mutation).length, 1);
  assert.equal(results.filter((result) => result.idempotent).length, 99);
  const status = execute(["host", "status", "--home", setup.home, "--json"], setup.trace);
  assert.equal(status.status, 0, status.stdout);
  assert.equal(JSON.parse(status.stdout).completed_host_successions, 1);
  await noEgress(setup.trace);
});
