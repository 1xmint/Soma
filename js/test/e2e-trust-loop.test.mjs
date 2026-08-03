import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { sha256 } from "../src/crypto.mjs";
import { RECEIPT_SCHEMA } from "../src/receipt.mjs";

const CLI = fileURLToPath(new URL("../bin/soma.mjs", import.meta.url));

/**
 * The whole trust loop, driven through the CLI exactly as an operator would.
 *
 * Two separate agents, two separate homes, two separate keystores. One does
 * work; the other attests to it; the first records evidence citing that
 * attestation. Nothing here reaches inside the library to shortcut a step.
 *
 * This is the test that answers "is it actually usable end to end", as opposed
 * to "do the units pass".
 */

function run(args, trace) {
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

async function agent(root, name, trace) {
  const home = path.join(root, name);
  const created = run(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(created.status, 0, created.stderr || created.stdout);
  const identity = JSON.parse(await readFile(path.join(home, "identity", "identity.json"), "utf8"));
  return { home, did: identity.agent_did };
}

test("two agents complete the trust loop through the CLI", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "soma-e2e-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const trace = path.join(root, "network.trace");

  // 1. Two independent agents, each with their own keystore.
  const worker = await agent(root, "worker", trace);
  const reviewer = await agent(root, "reviewer", trace);

  assert.ok(worker.did.startsWith("did:key:z"), "identities must be self-certifying");
  assert.notEqual(worker.did, reviewer.did);

  const taskId = "e2e-task-001";
  const claimHash = sha256(Buffer.from("the work product"));

  // 2. The reviewer attests to the worker's task.
  const requestFile = path.join(root, "request.json");
  await writeFile(
    requestFile,
    `${canonicalize({
      capability: "code-review",
      claim_hash: claimHash,
      domain: "software",
      fault: "none",
      observed_at: new Date(Date.now() - 60_000).toISOString().slice(0, 19) + "Z",
      outcome: "succeeded",
      schema_version: RECEIPT_SCHEMA,
      subject_did: worker.did,
      task_id: taskId
    })}\n`,
    "utf8"
  );

  const receiptFile = path.join(root, "receipt.json");
  const issued = run(
    ["receipt", "issue", "--home", reviewer.home, "--input", requestFile, "--out", receiptFile, "--json"],
    trace
  );
  assert.equal(issued.status, 0, issued.stderr || issued.stdout);

  const issuedJson = JSON.parse(issued.stdout);
  assert.equal(issuedJson.attester_did, reviewer.did);
  assert.equal(issuedJson.subject_did, worker.did);

  // 3. Anyone can verify that receipt offline, with no access to either home.
  const verified = run(["receipt", "verify", "--input", receiptFile, "--json"], trace);
  assert.equal(verified.status, 0, verified.stderr || verified.stdout);
  const verifiedJson = JSON.parse(verified.stdout);
  assert.equal(verifiedJson.attester_did, reviewer.did);
  assert.equal(
    verifiedJson.independence,
    "unknown_without_lineage",
    "this implementation must not claim independence it cannot establish"
  );

  // 4. The worker records evidence citing the receipt.
  const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
  const inputFile = path.join(root, "evidence.json");
  await writeFile(
    inputFile,
    `${canonicalize({
      schema_version: "soma.local-evidence-input.provisional-v1",
      kind: "execution",
      task_id: taskId,
      capability: "code.review",
      domain: "software.security",
      claim_hash: claimHash,
      artifact_hashes: [],
      receipts: [receipt],
      occurred_at: new Date(Date.now() - 30_000).toISOString(),
      supersedes: null
    })}\n`,
    "utf8"
  );

  const recorded = run(["evidence", "record", "--home", worker.home, "--input", inputFile, "--json"], trace);
  assert.equal(recorded.status, 0, recorded.stderr || recorded.stdout);

  // 5. The evidence carries the counter-signature and says so accurately.
  const ledger = await readFile(path.join(worker.home, "evidence", "ledger.jsonl"), "utf8");
  const event = JSON.parse(ledger.trim().split("\n").filter(Boolean).pop()).evidence_event;

  assert.deepEqual(event.receipt_ids, [receipt.receipt_id]);
  assert.equal(event.assurance, "self_signed_with_verified_counter_signatures");
  assert.equal(event.subject_did, worker.did);

  // 6. The worker's own ledger verifies.
  const checked = run(["evidence", "verify", "--home", worker.home, "--json"], trace);
  assert.equal(checked.status, 0, checked.stderr || checked.stdout);

  // 7. The worker cannot attest to itself to reach the same assurance.
  const selfRequest = path.join(root, "self-request.json");
  await writeFile(
    selfRequest,
    `${canonicalize({
      capability: "code-review",
      claim_hash: claimHash,
      domain: "software",
      fault: "none",
      observed_at: new Date(Date.now() - 60_000).toISOString().slice(0, 19) + "Z",
      outcome: "succeeded",
      schema_version: RECEIPT_SCHEMA,
      subject_did: worker.did,
      task_id: taskId
    })}\n`,
    "utf8"
  );

  const selfIssued = run(
    ["receipt", "issue", "--home", worker.home, "--input", selfRequest, "--out", path.join(root, "self.json"), "--json"],
    trace
  );
  assert.notEqual(selfIssued.status, 0, "issuing a receipt about yourself must fail");
  assert.match(selfIssued.stdout + selfIssued.stderr, /RECEIPT_SELF_ATTESTED/);

  // 8. Nothing in this loop touched the network.
  const traceBytes = await readFile(trace, "utf8").catch(() => "");
  assert.equal(traceBytes.trim(), "", "the trust loop must complete entirely offline");
});
