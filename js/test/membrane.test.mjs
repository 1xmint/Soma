import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
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
  try { assert.equal((await stat(trace)).size, 0); } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function home(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-membrane-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const state = path.join(temporary, "home");
  const trace = path.join(temporary, "network.trace");
  const initialized = execute(["init", "--home", state, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  const identity = JSON.parse(await readFile(path.join(state, "identity", "identity.json"), "utf8"));
  return { temporary, state, trace, identity };
}

function policy(identity, sourceKind = "artifact") {
  return {
    schema_version: "soma.observation-preview-policy.provisional-v1",
    source_kind: sourceKind,
    data_class: sourceKind === "artifact" ? "public_artifact" : "work_summary",
    authorized_fields: sourceKind === "artifact"
      ? ["artifact_hash", "byte_length", "content_base64", "license_identifier", "license_version", "media_type", "source_uri", "title"]
      : ["artifact_hashes", "assurance", "capability", "claim_hash", "domain", "evidence_id", "kind", "occurred_at", "task_id"],
    subject_did: identity.agent_did,
    controller_did: identity.controller_did,
    observer_did: identity.observer_did,
    destination: { host_did: "did:web:vera.example", origin: "https://vera.example" },
    purposes: ["safety_evaluation"],
    operations: ["collect", "evaluate", "store_encrypted"],
    data_state: "host_confidential",
    retention_seconds: 86400,
    redistribution: "none",
    replication: "none",
    replication_targets: [],
    model_training: false,
    public_release: false,
    license: { identifier: "CC-BY", version: "4.0" },
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    withdrawal_mode: "delete_deletable_and_tombstone",
    policy_version: "pilot.1",
    max_source_bytes: 4096,
    artifact_metadata: sourceKind === "artifact" ? {
      media_type: "text/plain",
      title: "Public test artifact",
      source_uri: "https://example.org/public-artifact.txt",
      rights_basis: "open_license",
      controller_attests_rights: true
    } : null
  };
}

async function writeCanonical(file, value) {
  await writeFile(file, `${canonicalize(value)}\n`, "utf8");
}

test("fixed preview vector reproduces policy, payload, and preview commitments", async () => {
  const vector = JSON.parse(await readFile(path.join(root, "conformance", "observation-preview-provisional-v1.json"), "utf8"));
  assert.equal(sha256(Buffer.from(canonicalize(vector.policy))), vector.policy_hash);
  assert.equal(canonicalize(JSON.parse(vector.payload_jcs)), vector.payload_jcs);
  assert.equal(sha256(Buffer.from(vector.payload_jcs)), vector.payload_hash);
  assert.equal(sha256(Buffer.from(`soma:authorized-field-projection:provisional-v1\n${canonicalize(vector.field_projection)}`)), vector.field_projection_hash);
  assert.equal(vector.decision.field_projection_hash, vector.field_projection_hash);
  const { preview_id: ignoredPreviewId, ...decisionCore } = vector.decision;
  assert.equal(sha256(Buffer.from(`soma:observation-preview:provisional-v1\n${canonicalize(decisionCore)}`)), vector.preview_id);
  assert.equal(vector.decision.preview_id, vector.preview_id);
});

test("artifact preview commits exact offline bytes without creating authority", async (context) => {
  const { temporary, state, trace, identity } = await home(context);
  const artifact = path.join(temporary, "artifact.txt");
  const policyFile = path.join(temporary, "policy.json");
  const source = "A deliberately public, non-sensitive test artifact.\n";
  await writeFile(artifact, source, "utf8");
  const artifactPolicy = policy(identity);
  await writeCanonical(policyFile, artifactPolicy);
  const result = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.network_actions, 0);
  assert.equal(payload.remote_mutation, false);
  assert.equal(payload.decision.authority, "preview_only_no_grant_no_send");
  assert.equal(payload.decision.secret_scan.passed, true);
  assert.equal(payload.decision.rights_check.result, "controller_attested_not_independently_verified");
  assert.equal(payload.payload_hash, sha256(Buffer.from(payload.payload_jcs)));
  assert.equal(payload.policy_jcs, canonicalize(artifactPolicy));
  assert.equal(payload.decision.policy_hash, sha256(Buffer.from(payload.policy_jcs)));
  const projection = {
    schema_version: "soma.authorized-field-projection.provisional-v1",
    source_kind: "artifact",
    data_class: "public_artifact",
    system_fields: ["data_class", "fields", "schema_version", "source_id", "source_kind", "subject_did"],
    authorized_fields: artifactPolicy.authorized_fields
  };
  assert.equal(payload.field_projection_hash, sha256(Buffer.from(`soma:authorized-field-projection:provisional-v1\n${canonicalize(projection)}`)));
  const applicationPayload = JSON.parse(payload.payload_jcs);
  assert.equal(Buffer.from(applicationPayload.fields.content_base64, "base64").toString("utf8"), source);
  assert.equal(applicationPayload.fields.artifact_hash, sha256(Buffer.from(source)));
  assert.doesNotMatch(payload.payload_jcs, new RegExp(temporary.replaceAll("\\", "\\\\"), "i"));
  const stored = await readFile(path.join(state, "consent", "previews", payload.preview_id, "payload.jcs"), "utf8");
  assert.equal(stored, payload.payload_jcs);
  const storedPolicy = await readFile(path.join(state, "consent", "previews", payload.preview_id, "policy.jcs"), "utf8");
  assert.equal(storedPolicy, payload.policy_jcs);
  const observed = execute(["observe", "status", "--home", state, "--json"], trace);
  assert.equal(observed.status, 0, observed.stderr || observed.stdout);
  const statusPayload = JSON.parse(observed.stdout);
  assert.equal(statusPayload.observer, "off");
  assert.equal(statusPayload.previews, 1);
  assert.equal(statusPayload.active_grants, 0);
  assert.equal(statusPayload.grant_capability, "absent");
  assert.equal(statusPayload.send_capability, "absent");
  assert.equal((await readdir(path.join(state, "consent", "grants"))).length, 0);
  assert.equal((await readdir(path.join(state, "queue"))).length, 0);
  await noEgress(trace);
});

test("evidence preview exports only the exact minimized projection", async (context) => {
  const { temporary, state, trace, identity } = await home(context);
  const evidenceInput = path.join(temporary, "evidence.json");
  await writeCanonical(evidenceInput, {
    schema_version: "soma.local-evidence-input.provisional-v1",
    kind: "execution",
    task_id: "safe-review-001",
    capability: "code.review",
    domain: "software.security",
    claim_hash: sha256(Buffer.from("safe fixed claim")),
    artifact_hashes: [],
    receipt_ids: [],
    occurred_at: new Date(Date.now() - 1000).toISOString(),
    supersedes: null
  });
  const recorded = execute(["evidence", "record", "--home", state, "--input", evidenceInput, "--json"], trace);
  assert.equal(recorded.status, 0, recorded.stderr || recorded.stdout);
  const evidenceId = JSON.parse(recorded.stdout).evidence_id;
  const policyFile = path.join(temporary, "evidence-policy.json");
  await writeCanonical(policyFile, policy(identity, "evidence"));
  const previewed = execute(["observe", "preview", "--home", state, "--evidence", evidenceId, "--policy", policyFile, "--json"], trace);
  assert.equal(previewed.status, 0, previewed.stderr || previewed.stdout);
  const result = JSON.parse(previewed.stdout);
  const projected = JSON.parse(result.payload_jcs);
  assert.equal(projected.fields.evidence_id, evidenceId);
  assert.equal(projected.fields.assurance, "self_signed_attribution_only");
  assert.deepEqual(Object.keys(projected.fields), policy(identity, "evidence").authorized_fields);
  assert.doesNotMatch(result.payload_jcs, /signature|issuer_did|subject_did.*fields|private_key|stdout|stderr|prompt/i);
  assert.equal(result.decision.rights_check.result, "not_applicable_minimized_local_evidence");
  await noEgress(trace);
});

test("secret and identity canaries are denied without retaining their bytes", async (context) => {
  const { temporary, state, trace, identity } = await home(context);
  const artifact = path.join(temporary, "canary.txt");
  const policyFile = path.join(temporary, "policy.json");
  await writeCanonical(policyFile, policy(identity));
  const canaries = [
    "-----BEGIN PRIVATE KEY-----\\nnot-a-real-key\\n-----END PRIVATE KEY-----",
    "AKIAABCDEFGHIJKLMNOP",
    "ghp_abcdefghijklmnopqrstuvwxyz123456",
    "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "xox" + "b-1234567890-abcdefghijklmnop",
    "authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    "password=correct-horse-battery-staple",
    "person@example.org",
    "123-45-6789",
    "0x0123456789abcdef0123456789abcdef01234567"
  ];
  for (const canary of canaries) {
    await writeFile(artifact, canary, "utf8");
    const denied = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
    assert.equal(denied.status, 6, denied.stderr || denied.stdout);
    const failure = JSON.parse(denied.stdout);
    assert.equal(failure.error, "PREVIEW_SCAN_DENIED");
    assert.equal(failure.local_mutation, true);
    assert.equal(failure.remote_mutation, false);
  }
  const metadataCanary = "metadata-person@example.org";
  const taintedMetadataPolicy = policy(identity);
  taintedMetadataPolicy.artifact_metadata = { ...taintedMetadataPolicy.artifact_metadata, title: metadataCanary };
  await writeCanonical(policyFile, taintedMetadataPolicy);
  await writeFile(artifact, "otherwise safe public bytes", "utf8");
  const metadataDenied = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
  assert.equal(metadataDenied.status, 6, metadataDenied.stderr || metadataDenied.stdout);
  assert.equal(JSON.parse(metadataDenied.stdout).error, "PREVIEW_SCAN_DENIED");

  const denialDirectory = path.join(state, "consent", "denials");
  const denialFiles = await readdir(denialDirectory);
  assert.equal(denialFiles.length, canaries.length + 1);
  const denialBodies = (await Promise.all(denialFiles.map((file) => readFile(path.join(denialDirectory, file), "utf8")))).join("\n");
  for (const canary of [...canaries, metadataCanary]) assert.equal(denialBodies.includes(canary), false);
  assert.equal((await readdir(path.join(state, "consent", "previews"))).length, 0);
  assert.equal((await readdir(path.join(state, "consent", "grants"))).length, 0);
  await noEgress(trace);
});

test("training and public states require and preserve their exact broader terms", async (context) => {
  const { temporary, state, trace, identity } = await home(context);
  const artifact = path.join(temporary, "artifact.txt");
  const policyFile = path.join(temporary, "policy.json");
  await writeFile(artifact, "safe public material", "utf8");

  const training = policy(identity);
  training.data_state = "federated_training";
  training.purposes = ["model_training"];
  training.operations = ["collect", "store_encrypted", "train"];
  training.model_training = true;
  training.replication = "named_hosts";
  training.replication_targets = [training.destination];
  await writeCanonical(policyFile, training);
  const trainingResult = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
  assert.equal(trainingResult.status, 0, trainingResult.stderr || trainingResult.stdout);
  const trainingDecision = JSON.parse(trainingResult.stdout).decision;
  assert.equal(trainingDecision.data_state, "federated_training");
  assert.equal(trainingDecision.model_training, true);
  assert.deepEqual(trainingDecision.replication_targets, [training.destination]);

  const publicPolicy = policy(identity);
  publicPolicy.data_state = "public_knowledge";
  publicPolicy.purposes = ["public_dataset"];
  publicPolicy.operations = ["collect", "redistribute"];
  publicPolicy.public_release = true;
  publicPolicy.redistribution = "licensed_artifact";
  publicPolicy.replication = "public";
  await writeCanonical(policyFile, publicPolicy);
  const publicResult = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
  assert.equal(publicResult.status, 0, publicResult.stderr || publicResult.stdout);
  const publicDecision = JSON.parse(publicResult.stdout).decision;
  assert.equal(publicDecision.data_state, "public_knowledge");
  assert.equal(publicDecision.public_release, true);
  assert.equal(publicDecision.replication, "public");
  assert.equal((await readdir(path.join(state, "consent", "grants"))).length, 0);
  await noEgress(trace);
});

test("unknown fields, prohibited classes, widening, rights refusal, and send all fail closed", async (context) => {
  const { temporary, state, trace, identity } = await home(context);
  const artifact = path.join(temporary, "artifact.txt");
  const policyFile = path.join(temporary, "policy.json");
  await writeFile(artifact, "safe public bytes", "utf8");
  const cases = [];
  const unknown = { ...policy(identity), surprise_widening: true };
  cases.push([unknown, "PREVIEW_POLICY_SHAPE_INVALID"]);
  const prohibited = { ...policy(identity), data_class: "private_work" };
  cases.push([prohibited, "PREVIEW_CLASS_UNSUPPORTED"]);
  const training = { ...policy(identity), model_training: true };
  cases.push([training, "PREVIEW_STATE_WIDENING"]);
  const replication = { ...policy(identity), replication: "named_hosts", replication_targets: [{ host_did: "did:web:other.example", origin: "https://other.example" }] };
  cases.push([replication, "PREVIEW_REPLICATION_INVALID"]);
  const rights = policy(identity);
  rights.artifact_metadata = { ...rights.artifact_metadata, controller_attests_rights: false };
  cases.push([rights, "PREVIEW_RIGHTS_INVALID"]);
  const unknownProjection = { ...policy(identity), authorized_fields: [...policy(identity).authorized_fields, "raw_prompt"].sort() };
  cases.push([unknownProjection, "PREVIEW_FIELDS_INVALID"]);
  const controlTitle = policy(identity);
  controlTitle.artifact_metadata = { ...controlTitle.artifact_metadata, title: "line\nbreak" };
  cases.push([controlTitle, "PREVIEW_RIGHTS_INVALID"]);
  const whitespaceDid = policy(identity);
  whitespaceDid.destination = { ...whitespaceDid.destination, host_did: "did:web:bad host" };
  cases.push([whitespaceDid, "PREVIEW_DESTINATION_INVALID"]);
  const malformedPercentDid = policy(identity);
  malformedPercentDid.destination = { ...malformedPercentDid.destination, host_did: "did:web:bad%ZZ" };
  cases.push([malformedPercentDid, "PREVIEW_DESTINATION_INVALID"]);
  const licenseLookalike = policy(identity);
  licenseLookalike.data_state = "public_knowledge";
  licenseLookalike.purposes = ["public_dataset"];
  licenseLookalike.operations = ["collect", "redistribute"];
  licenseLookalike.public_release = true;
  licenseLookalike.redistribution = "licensed_artifact";
  licenseLookalike.replication = "public";
  licenseLookalike.license = { identifier: "CC-BY-NC", version: "4.0" };
  cases.push([licenseLookalike, "PREVIEW_STATE_WIDENING"]);
  for (const [candidate, expected] of cases) {
    await writeCanonical(policyFile, candidate);
    const result = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
    assert.notEqual(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).error, expected);
  }
  await writeFile(policyFile, Buffer.from([0xff, 0xfe, 0xfd]));
  const invalidEncoding = execute(["observe", "preview", "--home", state, "--artifact", artifact, "--policy", policyFile, "--json"], trace);
  assert.equal(invalidEncoding.status, 2, invalidEncoding.stderr || invalidEncoding.stdout);
  assert.equal(JSON.parse(invalidEncoding.stdout).error, "PREVIEW_POLICY_ENCODING_INVALID");
  const send = execute(["observe", "send", "--home", state, "--json"], trace);
  assert.equal(send.status, 2, send.stderr || send.stdout);
  assert.equal(JSON.parse(send.stdout).error, "OBSERVE_ACTION_INVALID");
  assert.equal((await readdir(path.join(state, "consent", "previews"))).length, 0);
  assert.equal((await readdir(path.join(state, "consent", "grants"))).length, 0);
  await noEgress(trace);
});
