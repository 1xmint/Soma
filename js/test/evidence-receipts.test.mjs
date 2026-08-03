import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { createInitialKeyMaterial, privateKeyForRole, sha256 } from "../src/crypto.mjs";
import { RECEIPT_SCHEMA, createReceipt } from "../src/receipt.mjs";

const CLI = fileURLToPath(new URL("../bin/soma.mjs", import.meta.url));

function execute(args, trace) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      encoding: "utf8",
      env: { ...process.env, SOMA_TEST_NETWORK_TRACE: trace }
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  }
}

async function temporaryHome(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-evidence-receipt-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const initialized = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  const identity = JSON.parse(await readFile(path.join(home, "identity", "identity.json"), "utf8"));
  return { temporary, home, trace, agentDid: identity.agent_did };
}

/** An unrelated party who can attest. */
function attester() {
  const material = createInitialKeyMaterial("2026-07-28T00:00:00Z");
  return {
    did: material.publicIdentity.agent_did,
    privateKeyBase64: privateKeyForRole(material.secretBundle, "agent_signing").private_key_pkcs8_base64
  };
}

function receiptFor(subjectDid, taskId, claimHash, party, overrides = {}) {
  return createReceipt(
    {
      attester_did: party.did,
      basis: "party",
      capability: "code-review",
      claim_hash: claimHash,
      domain: "software",
      fault: "none",
      issued_at: "2026-07-28T12:00:00Z",
      observed_at: "2026-07-28T11:00:00Z",
      outcome: "succeeded",
      schema_version: RECEIPT_SCHEMA,
      subject_did: subjectDid,
      task_id: taskId,
      ...overrides
    },
    party.privateKeyBase64
  );
}

function input(taskId, claim, receipts) {
  return {
    schema_version: "soma.local-evidence-input.provisional-v1",
    kind: "execution",
    task_id: taskId,
    capability: "code.review",
    domain: "software.security",
    claim_hash: claim,
    artifact_hashes: [],
    receipts,
    occurred_at: new Date(Date.now() - 1000).toISOString(),
    supersedes: null
  };
}

async function record(state, taskId, receipts, claim = sha256(Buffer.from(taskId))) {
  const file = path.join(state.temporary, `${taskId}.json`);
  await writeFile(file, `${canonicalize(input(taskId, claim, receipts))}\n`, "utf8");
  return execute(["evidence", "record", "--home", state.home, "--input", file, "--json"], state.trace);
}

async function lastEvent(home) {
  const ledger = await readFile(path.join(home, "evidence", "ledger.jsonl"), "utf8");
  const lines = ledger.trim().split("\n").filter(Boolean);
  return JSON.parse(lines[lines.length - 1]).evidence_event;
}

test("evidence with no receipts keeps the original assurance exactly", async (context) => {
  const state = await temporaryHome(context);
  const result = await record(state, "task-plain", []);
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const event = await lastEvent(state.home);
  assert.deepEqual(event.receipt_ids, []);
  assert.equal(
    event.assurance,
    "self_signed_attribution_only",
    "the receipt-free path must stay byte-identical; a frozen conformance vector signs these exact bytes"
  );
});

test("a verified receipt is cited and raises the assurance", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-attested"));
  const party = attester();
  const receipt = receiptFor(state.agentDid, "task-attested", claim, party);

  const result = await record(state, "task-attested", [receipt], claim);
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const event = await lastEvent(state.home);
  assert.deepEqual(event.receipt_ids, [receipt.receipt_id]);
  assert.equal(event.assurance, "self_signed_with_verified_counter_signatures");
});

// The assurance string must state what happened and nothing more. This
// implementation has no lineage data, so it cannot know whether an attester is
// unrelated to the subject. Any word implying independence would be a claim the
// code cannot support.
test("the assurance string never claims independence", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-wording"));
  const party = attester();

  await record(state, "task-wording", [receiptFor(state.agentDid, "task-wording", claim, party)], claim);
  const event = await lastEvent(state.home);

  for (const word of ["independent", "verified_independent", "trusted", "reputable", "score"]) {
    assert.ok(
      !event.assurance.includes(word),
      `assurance "${event.assurance}" implies ${word}, which this implementation cannot establish`
    );
  }
});

test("a receipt about a different subject is refused", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-subject"));
  const party = attester();
  const someoneElse = attester();

  const result = await record(state, "task-subject", [receiptFor(someoneElse.did, "task-subject", claim, party)], claim);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /EVIDENCE_RECEIPT_SUBJECT_MISMATCH/);
});

// Without this binding the cheapest forgery in the system needs no keys at
// all: earn one receipt on trivial work, then cite it on everything.
test("a receipt earned on another task cannot be reused here", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-important"));
  const party = attester();

  const elsewhere = receiptFor(state.agentDid, "task-trivial", claim, party);
  const result = await record(state, "task-important", [elsewhere], claim);

  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /EVIDENCE_RECEIPT_TASK_MISMATCH/);
});

test("a receipt attesting to a different claim cannot be reused here", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-claim"));
  const party = attester();

  const otherClaim = receiptFor(state.agentDid, "task-claim", sha256(Buffer.from("something-else")), party);
  const result = await record(state, "task-claim", [otherClaim], claim);

  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /EVIDENCE_RECEIPT_CLAIM_MISMATCH/);
});

test("a tampered receipt is refused", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-tampered"));
  const party = attester();

  const receipt = receiptFor(state.agentDid, "task-tampered", claim, party);
  const tampered = { ...receipt, outcome: "failed" };

  const result = await record(state, "task-tampered", [tampered], claim);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /EVIDENCE_RECEIPT_INVALID/);
});

test("a subject cannot self-attest its way to a higher assurance", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-self"));

  // The subject's own agent key, used as the attester. This is the whole
  // attack the receipt design exists to stop, driven end to end through the CLI.
  const identity = JSON.parse(await readFile(path.join(state.home, "identity", "identity.json"), "utf8"));
  const forged = {
    attester_did: identity.agent_did,
    capability: "code-review",
    claim_hash: claim,
    domain: "software",
    issued_at: "2026-07-28T12:00:00Z",
    observed_at: "2026-07-28T11:00:00Z",
    outcome: "succeeded",
    schema_version: RECEIPT_SCHEMA,
    subject_did: identity.agent_did,
    task_id: "task-self",
    receipt_id: "0".repeat(64),
    signature: { key_id: "x", suite: "Ed25519-v1", value: "AA==" }
  };

  const result = await record(state, "task-self", [forged], claim);
  assert.notEqual(result.status, 0, "a self-attested receipt must not raise assurance");

  const ledger = await readFile(path.join(state.home, "evidence", "ledger.jsonl"), "utf8").catch(() => "");
  assert.ok(
    !ledger.includes("self_signed_with_verified_counter_signatures"),
    "no event claiming counter-signatures may reach the ledger"
  );
});

test("the same receipt cannot be cited twice to inflate a count", async (context) => {
  const state = await temporaryHome(context);
  const claim = sha256(Buffer.from("task-dupe"));
  const party = attester();
  const receipt = receiptFor(state.agentDid, "task-dupe", claim, party);

  const result = await record(state, "task-dupe", [receipt, receipt], claim);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /EVIDENCE_RECEIPT_DUPLICATE/);
});

test("receipt order does not change the recorded event", async (context) => {
  const claim = sha256(Buffer.from("task-order"));

  // Two homes so each records the same task independently. Citing the same
  // receipts in opposite orders must produce the same event, which is what
  // sorting receipt_ids before they enter the canonical bytes is for.
  const forwardState = await temporaryHome(context);
  const reverseState = await temporaryHome(context);

  const a = receiptFor(forwardState.agentDid, "task-order", claim, attester());
  const b = receiptFor(forwardState.agentDid, "task-order", claim, attester());
  const a2 = receiptFor(reverseState.agentDid, "task-order", claim, attester());
  const b2 = receiptFor(reverseState.agentDid, "task-order", claim, attester());

  const forward = await record(forwardState, "task-order", [a, b], claim);
  assert.equal(forward.status, 0, forward.stderr || forward.stdout);
  const reverse = await record(reverseState, "task-order", [b2, a2], claim);
  assert.equal(reverse.status, 0, reverse.stderr || reverse.stdout);

  const forwardIds = (await lastEvent(forwardState.home)).receipt_ids;
  const reverseIds = (await lastEvent(reverseState.home)).receipt_ids;

  assert.deepEqual(forwardIds, [a.receipt_id, b.receipt_id].sort());
  assert.deepEqual(reverseIds, [a2.receipt_id, b2.receipt_id].sort());
  assert.deepEqual(
    forwardIds.map((id) => forwardIds.indexOf(id)),
    reverseIds.map((id) => reverseIds.indexOf(id)),
    "both orders must normalise to the same arrangement"
  );
});
