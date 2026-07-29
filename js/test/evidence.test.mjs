import assert from "node:assert/strict";
import { appendFile, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize, parseCanonicalJson } from "../src/canonicalize.mjs";
import { sha256, signEd25519, verifyEd25519 } from "../src/crypto.mjs";
import { recordEvidence, verifyAndRepairEvidence, verifyEvidenceLedger } from "../src/evidence.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;

function environment(trace) {
  return {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(),
    SOMA_NETWORK_TRACE: trace
  };
}

function execute(args, trace) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: "utf8", windowsHide: true, timeout: 30000, env: environment(trace) });
}

function executeAsync(args, trace) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { cwd: root, windowsHide: true, env: environment(trace) });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (value) => { stdout += value; });
    child.stderr.setEncoding("utf8").on("data", (value) => { stderr += value; });
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function temporaryHome(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-evidence-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const initialized = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  return { temporary, home, trace };
}

function input(taskId, claim = sha256(Buffer.from(taskId))) {
  return {
    schema_version: "soma.local-evidence-input.provisional-v1",
    kind: "execution",
    task_id: taskId,
    capability: "code.review",
    domain: "software.security",
    claim_hash: claim,
    artifact_hashes: [],
    receipts: [],
    occurred_at: new Date(Date.now() - 1000).toISOString(),
    supersedes: null
  };
}

async function inputFile(directory, name) {
  const file = path.join(directory, `${name}.json`);
  await writeFile(file, `${canonicalize(input(name))}\n`, "utf8");
  return file;
}

async function assertNoEgress(trace) {
  try {
    assert.equal((await stat(trace)).size, 0);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  let output = "";
  while (value > 0n) {
    output = alphabet[Number(value % 58n)] + output;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    output = `1${output}`;
  }
  return output || "1";
}

test("Somavera canonicalization, RFC 8032, and local evidence vectors reproduce", async () => {
  const vectors = [
    [{ b: 2, a: 1 }, "{\"a\":1,\"b\":2}", "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"],
    [{ n: 9007199254740991, s: "Somavera", o: { y: 0, x: false } }, "{\"n\":9007199254740991,\"o\":{\"x\":false,\"y\":0},\"s\":\"Somavera\"}", "29fd030442259e544dcdcac5039c2af7fe82a273ae1772062c953eeab3bab5f9"]
  ];
  for (const [value, expected, hash] of vectors) {
    assert.equal(canonicalize(value), expected);
    assert.equal(sha256(Buffer.from(expected)), hash);
  }
  assert.throws(() => parseCanonicalJson("{\"a\":1,\"a\":2}"), { code: "JSON_NOT_CANONICAL" });
  assert.throws(() => canonicalize(-0), /negative zero/);
  assert.throws(() => canonicalize(9007199254740992), /unsafe integer/);
  assert.throws(() => canonicalize("\ud800"), /lone high surrogate/);

  const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const publicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]);
  const signature = signEd25519(pkcs8.toString("base64"), Buffer.alloc(0));
  assert.equal(Buffer.from(signature, "base64").toString("hex"), expected);
  const multibase = `z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(publicHex, "hex")]))}`;
  assert.equal(verifyEd25519(multibase, Buffer.alloc(0), signature), true);

  const vector = JSON.parse(await readFile(path.join(root, "conformance", "local-evidence-entry-provisional-v1.json"), "utf8"));
  const event = JSON.parse(vector.canonical_event);
  assert.equal(canonicalize(event), vector.canonical_event);
  const { evidence_id: ignoredEvidenceId, signature: eventSignature, ...eventCore } = event;
  const evidenceId = sha256(Buffer.from(`soma:local-evidence:provisional-v1\n${canonicalize(eventCore)}`));
  assert.equal(evidenceId, vector.evidence_id);
  assert.equal(event.evidence_id, vector.evidence_id);
  assert.equal(eventSignature.value, vector.evidence_signature_base64);
  assert.equal(verifyEd25519(vector.public_key_multibase, Buffer.concat([Buffer.from("soma:local-evidence:provisional-v1:signature\n"), Buffer.from(evidenceId, "hex")]), eventSignature.value), true);
  const entry = JSON.parse(vector.canonical_entry);
  assert.equal(canonicalize(entry), vector.canonical_entry);
  const { entry_hash: ignoredEntryHash, signature: entrySignature, ...entryCore } = entry;
  const entryHash = sha256(Buffer.from(`soma:local-evidence-entry:v1\n${canonicalize(entryCore)}`));
  assert.equal(entryHash, vector.entry_hash);
  assert.equal(entry.entry_hash, vector.entry_hash);
  assert.equal(entrySignature.value, vector.entry_signature_base64);
  assert.equal(verifyEd25519(vector.public_key_multibase, Buffer.concat([Buffer.from("soma:local-evidence-entry:signature:v1\n"), Buffer.from(entryHash, "hex")]), entrySignature.value), true);
});

test("record and verify create canonical signed attribution with zero egress", async (context) => {
  const { temporary, home, trace } = await temporaryHome(context);
  const file = await inputFile(temporary, "first-task");
  const recorded = execute(["evidence", "record", "--home", home, "--input", file, "--json"], trace);
  assert.equal(recorded.status, 0, recorded.stderr || recorded.stdout);
  const payload = JSON.parse(recorded.stdout);
  assert.equal(payload.assurance, "self_signed_attribution_only");
  assert.equal(payload.independent_truncation_detection, false);
  assert.equal(payload.truth_claim, "signature_proves_attribution_and_integrity_not_truth");
  const verified = execute(["evidence", "verify", "--home", home, "--json"], trace);
  assert.equal(verified.status, 0, verified.stderr || verified.stdout);
  assert.equal(JSON.parse(verified.stdout).entries, 1);
  const line = (await readFile(path.join(home, "evidence", "ledger.jsonl"), "utf8")).trimEnd();
  assert.equal(canonicalize(JSON.parse(line)), line);
  assert.doesNotMatch(line, /prompt|stdout|stderr|environment|source_code|secret/i);
  const doctor = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(doctor.status, 0, doctor.stderr || doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).evidence_entries, 1);
  await assertNoEgress(trace);
});

test("mutation, insertion, deletion, reordering, duplicate sequence, and key-window attacks fail", async (context) => {
  const { temporary, home } = await temporaryHome(context);
  for (const name of ["one", "two", "three"]) await recordEvidence(home, await inputFile(temporary, name));
  const ledgerPath = path.join(home, "evidence", "ledger.jsonl");
  const historyPath = path.join(home, "identity", "public-key-history.json");
  const originalLedger = await readFile(ledgerPath, "utf8");
  const originalHistory = await readFile(historyPath, "utf8");
  const records = originalLedger.trimEnd().split("\n").map(JSON.parse);
  async function rejectLedger(mutated, code) {
    await writeFile(ledgerPath, `${mutated.map(canonicalize).join("\n")}\n`, "utf8");
    await assert.rejects(verifyEvidenceLedger(home), (error) => !code || error.code === code);
    await writeFile(ledgerPath, originalLedger);
  }
  const changed = structuredClone(records);
  changed[1].evidence_event.claim_hash = "f".repeat(64);
  await rejectLedger(changed, "EVIDENCE_ID_MISMATCH");
  await rejectLedger([records[0], records[0], records[1], records[2]], "EVIDENCE_CHAIN_INVALID");
  await rejectLedger([records[0], records[2]], "EVIDENCE_CHAIN_INVALID");
  await rejectLedger([records[1], records[0], records[2]], "EVIDENCE_CHAIN_INVALID");
  const duplicate = structuredClone(records);
  duplicate[1].sequence = 0;
  await rejectLedger(duplicate, "EVIDENCE_CHAIN_INVALID");
  const history = JSON.parse(originalHistory);
  const agent = history.entries.find((entry) => entry.role === "agent_signing");
  agent.valid_from = new Date(Date.now() + 60000).toISOString();
  await writeFile(historyPath, `${JSON.stringify(history, null, 2)}\n`);
  await assert.rejects(verifyEvidenceLedger(home), { code: "EVIDENCE_KEY_WINDOW_INVALID" });
  await writeFile(historyPath, originalHistory);
  assert.equal((await verifyEvidenceLedger(home)).entries, 3);
});

test("partial tail and stale-head crash recovery are narrow and explicit", async (context) => {
  const { temporary, home, trace } = await temporaryHome(context);
  await recordEvidence(home, await inputFile(temporary, "stable"));
  const ledgerPath = path.join(home, "evidence", "ledger.jsonl");
  await appendFile(ledgerPath, "{\"incomplete\":", "utf8");
  const recovered = await verifyAndRepairEvidence(home);
  assert.ok(recovered.recovered_incomplete_tail_bytes > 0);
  assert.equal(recovered.independent_truncation_detection, false);
  await appendFile(ledgerPath, "{}\n", "utf8");
  await assert.rejects(verifyAndRepairEvidence(home), { code: "EVIDENCE_ENTRY_SHAPE_INVALID" });
  const body = await readFile(ledgerPath, "utf8");
  await writeFile(ledgerPath, body.slice(0, body.lastIndexOf("{}\n")), "utf8");

  const crashInput = await inputFile(temporary, "crash");
  const evidenceModule = pathToFileURL(path.join(root, "src", "evidence.mjs")).href;
  const crashProgram = `import { recordEvidence } from ${JSON.stringify(evidenceModule)}; await recordEvidence(process.argv[1], process.argv[2], { faultInjector(point) { if (point === "after_ledger_sync") process.exit(91); } });`;
  const crashed = spawnSync(process.execPath, ["--input-type=module", "-e", crashProgram, home, crashInput], { cwd: root, encoding: "utf8", windowsHide: true, timeout: 30000 });
  assert.equal(crashed.status, 91, crashed.stderr || crashed.stdout);
  await stat(path.join(home, "run", "evidence-writer.lock"));
  await assert.rejects(verifyEvidenceLedger(home), { code: "EVIDENCE_HEAD_STALE" });
  const repairedResult = execute(["evidence", "verify", "--home", home, "--json"], trace);
  assert.equal(repairedResult.status, 0, repairedResult.stderr || repairedResult.stdout);
  const repaired = JSON.parse(repairedResult.stdout);
  assert.equal(repaired.head_repaired, true);
  assert.equal(repaired.local_mutation, true);
  assert.equal(repaired.entries, 2);
  await assert.rejects(stat(path.join(home, "run", "evidence-writer.lock")), { code: "ENOENT" });
});

test("concurrent writers serialize without a fork or egress", async (context) => {
  const { temporary, home, trace } = await temporaryHome(context);
  const first = await inputFile(temporary, "parallel-a");
  const second = await inputFile(temporary, "parallel-b");
  const results = await Promise.all([
    executeAsync(["evidence", "record", "--home", home, "--input", first, "--json"], trace),
    executeAsync(["evidence", "record", "--home", home, "--input", second, "--json"], trace)
  ]);
  for (const result of results) assert.equal(result.status, 0, result.stderr || result.stdout);
  const verified = await verifyEvidenceLedger(home);
  assert.equal(verified.entries, 2);
  assert.equal(verified.head.entry_count, 2);
  await assertNoEgress(trace);
});
