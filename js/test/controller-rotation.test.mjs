import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  confirmControllerRotation,
  validateControllerRotation
} from "../src/controller-rotation.mjs";
import { createInitialKeyMaterial, publicRecordForPrivate, sha256 } from "../src/crypto.mjs";
import { canonicalize } from "../src/canonicalize.mjs";
import { protectSecretBundle, unprotectSecretBundle } from "../src/keystore.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;

function execute(args, trace) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    timeout: 30000,
    env: {
      ...process.env,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(),
      SOMA_NETWORK_TRACE: trace
    }
  });
}

async function noEgress(trace) {
  try { assert.equal((await stat(trace)).size, 0); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function setup(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-controller-rotation-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const initialized = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stdout || initialized.stderr);
  const initial = JSON.parse(initialized.stdout);
  const previewCommand = execute(["identity", "controller-rotate-preview", "--home", home, "--reason", "scheduled test rotation", "--json"], trace);
  assert.equal(previewCommand.status, 0, previewCommand.stdout || previewCommand.stderr);
  return { temporary, home, trace, initial, preview: JSON.parse(previewCommand.stdout) };
}

const confirmArgs = (state) => [
  "identity", "controller-rotate-confirm",
  "--home", state.home,
  "--proposal-id", state.preview.proposal_id,
  "--expect-successor-key-hash", state.preview.successor_key_sha256,
  "--confirm-controller-rotation",
  "--json"
];

function mutate(value, name) {
  if (name === "unstable_controller_did") value.controller_did = "did:key:attacker";
  if (name === "sequence_gap") value.rotation_sequence += 2;
  if (name === "wrong_predecessor") value.previous_rotation_id = "a".repeat(64);
  if (name === "prior_key_substitution") value.prior_key.key_id = "did:key:attacker#prior";
  if (name === "same_successor_key") {
    value.successor_key.key_id = value.prior_key.key_id;
    value.successor_key.public_key_multibase = value.prior_key.public_key_multibase;
    value.successor_key.public_key_sha256 = value.prior_key.public_key_sha256;
  }
  if (name === "successor_hash_mismatch") value.successor_key.public_key_sha256 = "b".repeat(64);
  if (name === "validity_gap") value.successor_key.valid_from = "2027-01-01T12:05:01.000Z";
  if (name === "effective_before_prepare") value.effective_at = "2027-01-01T11:59:59.000Z";
  if (name === "confirmation_window_exceeded") value.effective_at = "2027-01-01T12:15:00.001Z";
  if (name === "prior_reactivation") value.prior_key.status = "active";
  if (name === "successor_not_active") value.successor_key.status = "overlap";
  if (name === "decision_widening") value.decision = "replace_and_recover_identity";
  if (name === "private_key_retention") value.prior_private_key_disposition = "retain";
  if (name === "rollback_claim_widening") value.rollback_assurance = "rollback_proof_without_external_anchor";
  const escalations = {
    agent_rotation_escalation: "authorizes_agent_key_rotation",
    identity_recovery_escalation: "authorizes_identity_recovery",
    connection_escalation: "authorizes_connection",
    consent_escalation: "authorizes_consent",
    disclosure_escalation: "authorizes_disclosure",
    send_escalation: "authorizes_send",
    token_escalation: "authorizes_token_action",
    governance_escalation: "authorizes_governance"
  };
  if (escalations[name]) value.authority[escalations[name]] = true;
  if (name === "prior_signature_key_mismatch") value.signatures.prior.key_id = "did:key:attacker#prior";
  if (name === "prior_signature_corruption") value.signatures.prior.value = (value.signatures.prior.value[0] === "A" ? "B" : "A") + value.signatures.prior.value.slice(1);
  if (name === "successor_signature_key_mismatch") value.signatures.successor.key_id = "did:key:attacker#successor";
  if (name === "successor_signature_corruption") value.signatures.successor.value = (value.signatures.successor.value[0] === "A" ? "B" : "A") + value.signatures.successor.value.slice(1);
  if (name === "proposal_id_corruption") value.proposal_id = "d".repeat(64);
  if (name === "rotation_id_corruption") value.rotation_id = "e".repeat(64);
}

test("Origin controller-rotation vector and every adversarial recipe reproduce", async () => {
  const vector = JSON.parse(await readFile(path.join(root, "conformance", "controller-key-rotation-v1.json"), "utf8"));
  const invalid = JSON.parse(await readFile(path.join(root, "conformance", "controller-key-rotation-invalid-v1.json"), "utf8"));
  const rotation = vector.rotation;
  const expected = {
    controller_did: rotation.controller_did,
    rotation_sequence: 1,
    previous_rotation_id: null,
    prior_key_id: rotation.prior_key.key_id,
    prior_public_key_multibase: rotation.prior_key.public_key_multibase,
    prior_valid_from: rotation.prior_key.valid_from
  };
  assert.equal((await validateControllerRotation(rotation, expected)).rotation_id, vector.expected.rotation_id);
  for (const recipe of invalid.cases) {
    const candidate = structuredClone(rotation);
    mutate(candidate, recipe.mutation);
    await assert.rejects(
      () => validateControllerRotation(candidate, expected),
      (error) => error.code === "CONTROLLER_ROTATION_INVALID" && error.details.violations.includes(recipe.expected_error),
      recipe.name
    );
  }
});

test("exact confirmation preserves the stable controller, historic verification, and only the successor private key", async (context) => {
  const state = await setup(context);
  const initialIdentity = JSON.parse(await readFile(path.join(state.home, "identity", "identity.json"), "utf8"));
  const initialControllerKey = initialIdentity.keys.find((key) => key.role === "controller_signing").key_id;
  const pendingText = await readFile(path.join(state.home, "identity", "pending", "controller-rotation.json"), "utf8");
  assert.equal(pendingText.includes("private_key_pkcs8_base64"), false);

  const withoutFlag = confirmArgs(state).filter((value) => value !== "--confirm-controller-rotation");
  let command = execute(withoutFlag, state.trace);
  assert.equal(command.status, 9, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "CONTROLLER_ROTATION_CONFIRMATION_REQUIRED");
  const wrongProposal = confirmArgs(state);
  wrongProposal[wrongProposal.indexOf("--proposal-id") + 1] = "f".repeat(64);
  command = execute(wrongProposal, state.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "CONTROLLER_ROTATION_PROPOSAL_MISMATCH");
  const wrongKey = confirmArgs(state);
  wrongKey[wrongKey.indexOf("--expect-successor-key-hash") + 1] = "e".repeat(64);
  command = execute(wrongKey, state.trace);
  assert.equal(command.status, 8, command.stdout);
  assert.equal(JSON.parse(command.stdout).error, "CONTROLLER_ROTATION_SUCCESSOR_MISMATCH");

  command = execute(confirmArgs(state), state.trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  const confirmed = JSON.parse(command.stdout);
  assert.equal(confirmed.committed, true);
  assert.equal(confirmed.controller_did, state.initial.identity.controller_did);
  assert.notEqual(confirmed.successor_key_id, initialControllerKey);

  command = execute(confirmArgs(state), state.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).idempotent, true);
  command = execute(["doctor", "--home", state.home, "--json"], state.trace);
  assert.equal(command.status, 0, command.stdout);
  const doctor = JSON.parse(command.stdout);
  assert.equal(doctor.controller_rotation_sequence, 1);
  assert.equal(doctor.identity.controller_did, state.initial.identity.controller_did);
  assert.equal(doctor.identity.keys.filter((key) => key.role === "controller_signing" && key.status === "active").length, 1);
  assert.equal(doctor.identity.keys.find((key) => key.key_id === initialControllerKey).status, "retired");
  assert.equal(doctor.pending_controller_rotation, null);

  const history = JSON.parse(await readFile(path.join(state.home, "identity", "public-key-history.json"), "utf8"));
  assert.equal(history.controller_rotations.length, 1);
  assert.equal(history.controller_rotation_head, confirmed.rotation_id);
  const config = JSON.parse(await readFile(path.join(state.home, "config", "config.json"), "utf8"));
  const secret = unprotectSecretBundle(config.keystore.backend, await readFile(path.join(state.home, "config", "keystore.blob")));
  try {
    assert.equal(secret.private_keys.length, 4);
    assert.equal(secret.private_keys.some((key) => key.key_id === initialControllerKey), false);
    const controllerPrivate = secret.private_keys.find((key) => key.role === "controller_signing");
    assert.equal(publicRecordForPrivate(controllerPrivate, "Ed25519").key_id, confirmed.successor_key_id);
  } finally {
    for (const key of secret.private_keys) key.private_key_pkcs8_base64 = "";
    secret.private_keys.length = 0;
    secret.root_store_key_base64 = "";
  }
  command = execute(["evidence", "verify", "--home", state.home, "--json"], state.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).head.signer_key_id, initialControllerKey);
  const output = path.join(state.temporary, "post-rotation-capsule.json");
  command = execute(["host", "trust-export", "--home", state.home, "--out", output, "--json"], state.trace);
  assert.equal(command.status, 0, command.stdout);
  const capsule = JSON.parse(command.stdout);
  assert.equal(capsule.schema_version, "somavera.soma-host-trust-capsule.v2");
  assert.equal(capsule.controller_rotation_count, 1);
  assert.notEqual(capsule.controller_initial_key_sha256, capsule.controller_active_key_sha256);
  command = execute([
    "host", "trust-verify", "--capsule", output,
    "--expect-controller-did", capsule.controller_did,
    "--expect-controller-key-hash", capsule.controller_initial_key_sha256,
    "--json"
  ], state.trace);
  assert.equal(command.status, 0, command.stdout);
  assert.equal(JSON.parse(command.stdout).controller_rotation_count, 1);
  assert.equal((await readdir(path.join(state.home, "consent", "grants"))).length, 0);
  assert.equal((await readdir(path.join(state.home, "queue"))).length, 0);
  await noEgress(state.trace);
});

test("fault recovery resolves every transaction boundary to exactly prior or successor", async (context) => {
  const expectations = new Map([
    ["after_transaction", 0],
    ["after_identity_commit", 1],
    ["after_history_commit", 1],
    ["after_keystore_commit", 1],
    ["after_history_published", 1]
  ]);
  for (const [faultAt, expectedSequence] of expectations) {
    await context.test(faultAt, async (subcontext) => {
      const state = await setup(subcontext);
      await assert.rejects(
        () => confirmControllerRotation(state.home, {
          proposalId: state.preview.proposal_id,
          successorKeyHash: state.preview.successor_key_sha256,
          confirmControllerRotation: true,
          faultAt
        }),
        (error) => error.code === "CONTROLLER_ROTATION_FAULT_INJECTED"
      );
      const command = execute(["doctor", "--home", state.home, "--json"], state.trace);
      assert.equal(command.status, 0, command.stdout || command.stderr);
      const doctor = JSON.parse(command.stdout);
      assert.equal(doctor.controller_rotation_sequence, expectedSequence);
      assert.equal(doctor.identity.controller_did, state.initial.identity.controller_did);
      assert.equal(doctor.identity.keys.filter((key) => key.role === "controller_signing" && key.status === "active").length, 1);
      assert.equal((await readdir(path.join(state.home, "identity", "transactions"))).length, 0);
      assert.equal(doctor.pending_controller_rotation !== null, expectedSequence === 0);
      await noEgress(state.trace);
    });
  }
});

test("one hundred identical confirmations plus one competitor converge on one rotation", async (context) => {
  const state = await setup(context);
  const exact = {
    proposalId: state.preview.proposal_id,
    successorKeyHash: state.preview.successor_key_sha256,
    confirmControllerRotation: true
  };
  const competitor = { ...exact, successorKeyHash: "f".repeat(64) };
  const settled = await Promise.allSettled([
    ...Array.from({ length: 100 }, () => confirmControllerRotation(state.home, exact)),
    confirmControllerRotation(state.home, competitor)
  ]);
  const fulfilled = settled.filter((result) => result.status === "fulfilled").map((result) => result.value);
  const rejected = settled.filter((result) => result.status === "rejected");
  assert.equal(fulfilled.length, 100, JSON.stringify(rejected.map((result) => result.reason?.code)));
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, "CONTROLLER_ROTATION_SUCCESSOR_MISMATCH");
  assert.equal(fulfilled.filter((result) => result.local_mutation).length, 1);
  assert.equal(fulfilled.filter((result) => result.idempotent).length, 99);
  const doctor = execute(["doctor", "--home", state.home, "--json"], state.trace);
  assert.equal(doctor.status, 0, doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).controller_rotation_sequence, 1);
  await noEgress(state.trace);
});

test("tampered prepared transaction fails closed before changing the prior identity", async (context) => {
  const state = await setup(context);
  await assert.rejects(
    () => confirmControllerRotation(state.home, {
      proposalId: state.preview.proposal_id,
      successorKeyHash: state.preview.successor_key_sha256,
      confirmControllerRotation: true,
      faultAt: "after_transaction"
    }),
    (error) => error.code === "CONTROLLER_ROTATION_FAULT_INJECTED"
  );
  const identityBefore = await readFile(path.join(state.home, "identity", "identity.json"), "utf8");
  const transactionFile = path.join(state.home, "identity", "transactions", "controller-rotation.json");
  const transaction = JSON.parse(await readFile(transactionFile, "utf8"));
  transaction.event.authority.authorizes_identity_recovery = true;
  await writeFile(transactionFile, `${JSON.stringify(transaction)}\n`);
  const doctor = execute(["doctor", "--home", state.home, "--json"], state.trace);
  assert.equal(doctor.status, 7, doctor.stdout);
  assert.ok(["CONTROLLER_ROTATION_TRANSACTION_INVALID", "CONTROLLER_ROTATION_INVALID"].includes(JSON.parse(doctor.stdout).error));
  assert.equal(await readFile(path.join(state.home, "identity", "identity.json"), "utf8"), identityBefore);
  await noEgress(state.trace);
});


test("recovery rejects a successor bundle that changes any non-controller secret", async (context) => {
  const state = await setup(context);
  await assert.rejects(
    () => confirmControllerRotation(state.home, {
      proposalId: state.preview.proposal_id,
      successorKeyHash: state.preview.successor_key_sha256,
      confirmControllerRotation: true,
      faultAt: "after_identity_commit"
    }),
    (error) => error.code === "CONTROLLER_ROTATION_FAULT_INJECTED"
  );
  const config = JSON.parse(await readFile(path.join(state.home, "config", "config.json"), "utf8"));
  const temporaryFile = path.join(state.home, "identity", "transactions", "controller-rotation.keystore.tmp");
  const transactionFile = path.join(state.home, "identity", "transactions", "controller-rotation.json");
  const successorBundle = unprotectSecretBundle(config.keystore.backend, await readFile(temporaryFile));
  const generated = createInitialKeyMaterial(new Date().toISOString()).secretBundle;
  let protectedTampered;
  try {
    const replacementAgent = generated.private_keys.find((key) => key.role === "agent_signing");
    const index = successorBundle.private_keys.findIndex((key) => key.role === "agent_signing");
    successorBundle.private_keys[index] = structuredClone(replacementAgent);
    protectedTampered = protectSecretBundle(successorBundle, config.keystore.backend === "development-plaintext-file-v1");
    await writeFile(temporaryFile, protectedTampered.blob);
    const transaction = JSON.parse(await readFile(transactionFile, "utf8"));
    transaction.successor_keystore_sha256 = sha256(protectedTampered.blob);
    await writeFile(transactionFile, canonicalize(transaction) + "\n");
  } finally {
    for (const bundle of [successorBundle, generated]) {
      for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
      if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
      bundle.root_store_key_base64 = "";
    }
    protectedTampered?.blob?.fill(0);
  }
  const historyBefore = await readFile(path.join(state.home, "identity", "public-key-history.json"), "utf8");
  const doctor = execute(["doctor", "--home", state.home, "--json"], state.trace);
  assert.equal(doctor.status, 7, doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).error, "CONTROLLER_ROTATION_KEYSTORE_MISMATCH");
  assert.equal(await readFile(path.join(state.home, "identity", "public-key-history.json"), "utf8"), historyBefore);
  await noEgress(state.trace);
});
