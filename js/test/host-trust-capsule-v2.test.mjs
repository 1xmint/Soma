import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";

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

function verifyArgs(file, expected) {
  return [
    "host", "trust-verify",
    "--capsule", file,
    "--expect-controller-did", expected.controller_did,
    "--expect-controller-key-hash", expected.controller_initial_key_sha256,
    "--json"
  ];
}

function compareArgs(trusted, candidate, expected) {
  return [
    "host", "trust-compare",
    "--trusted", trusted,
    "--candidate", candidate,
    "--expect-controller-did", expected.controller_did,
    "--expect-controller-key-hash", expected.controller_initial_key_sha256,
    "--json"
  ];
}

test("v2 capsule preserves and verifies complete controller history across rotation", async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-trust-capsule-v2-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const beforeFile = path.join(temporary, "before-controller-rotation.json");
  const afterFile = path.join(temporary, "after-controller-rotation.json");

  let command = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  command = execute(["host", "trust-export", "--home", home, "--out", beforeFile, "--json"], trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  const before = JSON.parse(command.stdout);
  assert.equal(before.schema_version, "somavera.soma-host-trust-capsule.v2");
  assert.equal(before.controller_rotation_count, 0);

  command = execute(["identity", "controller-rotate-preview", "--home", home, "--reason", "host trust capsule v2 test", "--json"], trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  const preview = JSON.parse(command.stdout);
  command = execute([
    "identity", "controller-rotate-confirm", "--home", home,
    "--proposal-id", preview.proposal_id,
    "--expect-successor-key-hash", preview.successor_key_sha256,
    "--confirm-controller-rotation", "--json"
  ], trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);

  command = execute(["host", "trust-export", "--home", home, "--out", afterFile, "--json"], trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  const after = JSON.parse(command.stdout);
  assert.equal(after.schema_version, "somavera.soma-host-trust-capsule.v2");
  assert.equal(after.controller_rotation_count, 1);
  assert.equal(after.controller_initial_key_sha256, before.controller_initial_key_sha256);
  assert.notEqual(after.controller_active_key_sha256, before.controller_active_key_sha256);

  command = execute(verifyArgs(afterFile, before), trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  const verified = JSON.parse(command.stdout);
  assert.equal(verified.controller_rotation_count, 1);
  assert.equal(verified.controller_initial_key_sha256, before.controller_initial_key_sha256);
  assert.equal(verified.controller_active_key_sha256, after.controller_active_key_sha256);

  command = execute(compareArgs(beforeFile, afterFile, before), trace);
  assert.equal(command.status, 0, command.stdout || command.stderr);
  assert.equal(JSON.parse(command.stdout).relation, "equal_or_strict_descendant_controller_and_host_trust_state");
  command = execute(compareArgs(afterFile, beforeFile, before), trace);
  assert.equal(command.status, 8, command.stdout || command.stderr);
  assert.equal(JSON.parse(command.stdout).error, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");

  const original = JSON.parse(await readFile(afterFile, "utf8"));
  const rotationIndex = original.objects.findIndex((entry) => entry.kind === "controller_rotation");
  assert.notEqual(rotationIndex, -1);
  const mutations = [
    ["missing-rotation", (value) => { value.objects.splice(rotationIndex, 1); }],
    ["rotation-signature", (value) => {
      const object = value.objects[rotationIndex];
      const event = JSON.parse(Buffer.from(object.canonical_json_base64, "base64").toString("utf8"));
      event.signatures.successor.value = `${event.signatures.successor.value[0] === "A" ? "B" : "A"}${event.signatures.successor.value.slice(1)}`;
      const bytes = Buffer.from(canonicalize(event));
      object.canonical_json_base64 = bytes.toString("base64");
      object.byte_length = bytes.length;
      object.sha256 = sha256(bytes);
    }]
  ];
  for (const [name, mutate] of mutations) {
    const candidate = structuredClone(original);
    mutate(candidate);
    const file = path.join(temporary, `${name}.json`);
    await writeFile(file, `${canonicalize(candidate)}\n`);
    command = execute(verifyArgs(file, before), trace);
    assert.equal(command.status, 7, `${name}: ${command.stdout || command.stderr}`);
  }
  await noEgress(trace);
});
