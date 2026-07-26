import { open, readFile, rename, unlink } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { privateKeyForRole, sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { EMPTY_HASH } from "./constants.mjs";
import { SomaError } from "./errors.mjs";
import { unprotectSecretBundle } from "./keystore.mjs";
import { restrictStatePath, restrictStateRoot } from "./platform.mjs";

const HASH = /^[a-f0-9]{64}$/;
const NAME = /^[a-z][a-z0-9_.-]{1,127}$/;
const KINDS = new Set(["assertion", "execution", "outcome", "dispute"]);
const INPUT_FIELDS = ["artifact_hashes", "capability", "claim_hash", "domain", "kind", "occurred_at", "receipt_ids", "schema_version", "supersedes", "task_id"];
const EVENT_FIELDS = ["artifact_hashes", "assurance", "capability", "claim_hash", "context_id", "domain", "evidence_id", "issuer_did", "issued_at", "kind", "occurred_at", "receipt_ids", "schema_version", "signature", "subject_did", "supersedes", "task_id"];
const ENTRY_FIELDS = ["entry_hash", "evidence_event", "previous_entry_hash", "recorded_at", "schema_version", "sequence", "signature", "signer_key_id"];
const HEAD_FIELDS = ["anchors", "assurance", "entry_count", "entry_hash", "head_hash", "issued_at", "schema_version", "sequence", "signature", "signer_key_id"];

function exactObject(value, fields, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SomaError(`${label} must be an object`, 7, code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new SomaError(`${label} has missing or unknown fields`, 7, code, { expected, actual });
  }
}

function iso(value, code, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new SomaError(`${label} must be an exact UTC ISO timestamp`, 7, code);
  }
  return Date.parse(value);
}

function uniqueHashes(value, code, label) {
  if (!Array.isArray(value) || value.some((entry) => !HASH.test(entry)) || new Set(value).size !== value.length) {
    throw new SomaError(`${label} must contain unique lowercase SHA-256 hashes`, 7, code);
  }
}

function signatureShape(value, code) {
  exactObject(value, ["key_id", "suite", "value"], code, "signature");
  if (value.suite !== "Ed25519-v1" || typeof value.key_id !== "string" || value.key_id.length < 3 || typeof value.value !== "string") {
    throw new SomaError("signature shape is invalid", 7, code);
  }
  const decoded = Buffer.from(value.value, "base64");
  if (decoded.length !== 64 || decoded.toString("base64") !== value.value) throw new SomaError("signature base64 is not canonical", 7, code);
}

function keyAt(identity, history, keyId, role, timestamp, code) {
  const publicKey = identity.keys?.find((entry) => entry.key_id === keyId && entry.role === role && entry.algorithm === "Ed25519-v1");
  const interval = history.entries?.find((entry) => entry.key_id === keyId && entry.role === role);
  if (!publicKey || !interval) throw new SomaError(`unknown ${role} key`, 7, code, { key_id: keyId });
  const from = iso(interval.valid_from, code, "key valid_from");
  const until = interval.valid_until === null ? null : iso(interval.valid_until, code, "key valid_until");
  if (timestamp < from || (until !== null && timestamp >= until) || (interval.status !== "active" && until === null)) {
    throw new SomaError("signature was made outside the key validity window", 7, code, { key_id: keyId });
  }
  return publicKey;
}

function signRecord(core, idField, hashDomain, signatureDomain, privateRecord) {
  const id = sha256(Buffer.from(`${hashDomain}\n${canonicalize(core)}`, "utf8"));
  return {
    ...core,
    [idField]: id,
    signature: {
      suite: "Ed25519-v1",
      key_id: privateRecord.key_id,
      value: signEd25519(privateRecord.private_key_pkcs8_base64, Buffer.concat([Buffer.from(`${signatureDomain}\n`, "utf8"), Buffer.from(id, "hex")]))
    }
  };
}

function verifyLocalEvent(event, identity, history) {
  exactObject(event, EVENT_FIELDS, "EVIDENCE_EVENT_SHAPE_INVALID", "evidence event");
  if (event.schema_version !== "soma.local-evidence-event.provisional-v1" || !HASH.test(event.evidence_id)) throw new SomaError("evidence event version or ID is invalid", 7, "EVIDENCE_EVENT_SHAPE_INVALID");
  if (!/^soma:local-context:v1:[a-f0-9]{64}$/.test(event.context_id)) throw new SomaError("local evidence context is invalid", 7, "EVIDENCE_CONTEXT_INVALID");
  if (!KINDS.has(event.kind) || event.assurance !== "self_signed_attribution_only") throw new SomaError("evidence kind or assurance is invalid", 7, "EVIDENCE_CLASS_INVALID");
  if (event.subject_did !== identity.agent_did || event.issuer_did !== identity.agent_did) throw new SomaError("local evidence actor differs from this identity", 7, "EVIDENCE_ACTOR_INVALID");
  if (typeof event.task_id !== "string" || event.task_id.length < 1 || event.task_id.length > 256 || !NAME.test(event.capability) || !NAME.test(event.domain) || !HASH.test(event.claim_hash)) throw new SomaError("evidence claim fields are invalid", 7, "EVIDENCE_CLAIM_INVALID");
  uniqueHashes(event.artifact_hashes, "EVIDENCE_ARTIFACTS_INVALID", "artifact_hashes");
  uniqueHashes(event.receipt_ids, "EVIDENCE_RECEIPTS_INVALID", "receipt_ids");
  if (event.receipt_ids.length !== 0) throw new SomaError("receipt verification is not implemented; receipt_ids must remain empty", 7, "EVIDENCE_RECEIPTS_UNSUPPORTED");
  if (event.supersedes !== null && !HASH.test(event.supersedes)) throw new SomaError("supersedes is invalid", 7, "EVIDENCE_SUPERSEDES_INVALID");
  const occurred = iso(event.occurred_at, "EVIDENCE_TIME_INVALID", "occurred_at");
  const issued = iso(event.issued_at, "EVIDENCE_TIME_INVALID", "issued_at");
  if (occurred > issued) throw new SomaError("occurred_at cannot be after issued_at", 7, "EVIDENCE_TIME_INVALID");
  signatureShape(event.signature, "EVIDENCE_SIGNATURE_INVALID");
  const { evidence_id: ignoredId, signature: ignoredSignature, ...core } = event;
  const expected = sha256(Buffer.from(`soma:local-evidence:provisional-v1\n${canonicalize(core)}`, "utf8"));
  if (expected !== event.evidence_id) throw new SomaError("evidence ID does not match its canonical core", 7, "EVIDENCE_ID_MISMATCH");
  const key = keyAt(identity, history, event.signature.key_id, "agent_signing", issued, "EVIDENCE_KEY_WINDOW_INVALID");
  const message = Buffer.concat([Buffer.from("soma:local-evidence:provisional-v1:signature\n", "utf8"), Buffer.from(expected, "hex")]);
  if (!verifyEd25519(key.public_key_multibase, message, event.signature.value)) throw new SomaError("evidence signature is invalid", 7, "EVIDENCE_SIGNATURE_INVALID");
}

function entryCore(entry) {
  return {
    schema_version: entry.schema_version,
    sequence: entry.sequence,
    previous_entry_hash: entry.previous_entry_hash,
    evidence_event: entry.evidence_event,
    recorded_at: entry.recorded_at,
    signer_key_id: entry.signer_key_id
  };
}

function verifyEntry(entry, expectedSequence, previousHash, identity, history) {
  exactObject(entry, ENTRY_FIELDS, "EVIDENCE_ENTRY_SHAPE_INVALID", "ledger entry");
  if (entry.schema_version !== "soma.local-evidence-entry.provisional-v1" || entry.sequence !== expectedSequence || entry.previous_entry_hash !== previousHash || !HASH.test(entry.entry_hash)) {
    throw new SomaError("ledger sequence or hash chain is invalid", 7, "EVIDENCE_CHAIN_INVALID", { expected_sequence: expectedSequence });
  }
  const recorded = iso(entry.recorded_at, "EVIDENCE_ENTRY_TIME_INVALID", "recorded_at");
  verifyLocalEvent(entry.evidence_event, identity, history);
  if (Date.parse(entry.evidence_event.issued_at) > recorded) throw new SomaError("entry predates its evidence event", 7, "EVIDENCE_ENTRY_TIME_INVALID");
  signatureShape(entry.signature, "EVIDENCE_ENTRY_SIGNATURE_INVALID");
  if (entry.signature.key_id !== entry.signer_key_id) throw new SomaError("entry signer key mismatch", 7, "EVIDENCE_ENTRY_SIGNATURE_INVALID");
  const expectedHash = sha256(Buffer.from(`soma:local-evidence-entry:v1\n${canonicalize(entryCore(entry))}`, "utf8"));
  if (expectedHash !== entry.entry_hash) throw new SomaError("entry hash does not match its canonical core", 7, "EVIDENCE_ENTRY_HASH_MISMATCH");
  const key = keyAt(identity, history, entry.signer_key_id, "agent_signing", recorded, "EVIDENCE_ENTRY_KEY_WINDOW_INVALID");
  const message = Buffer.concat([Buffer.from("soma:local-evidence-entry:signature:v1\n", "utf8"), Buffer.from(expectedHash, "hex")]);
  if (!verifyEd25519(key.public_key_multibase, message, entry.signature.value)) throw new SomaError("entry signature is invalid", 7, "EVIDENCE_ENTRY_SIGNATURE_INVALID");
  return expectedHash;
}

function headCore(head) {
  const { head_hash: ignoredHash, signature: ignoredSignature, ...core } = head;
  return core;
}

function verifyHead(head, identity, history) {
  exactObject(head, HEAD_FIELDS, "EVIDENCE_HEAD_SHAPE_INVALID", "evidence head");
  if (head.schema_version !== "soma.evidence-head.provisional-v1" || !Number.isSafeInteger(head.entry_count) || head.entry_count < 0 || !HASH.test(head.entry_hash) || !HASH.test(head.head_hash) || head.assurance !== "local_only_unanchored" || !Array.isArray(head.anchors) || head.anchors.length !== 0) {
    throw new SomaError("evidence head shape is invalid", 7, "EVIDENCE_HEAD_SHAPE_INVALID");
  }
  if ((head.entry_count === 0 && (head.sequence !== null || head.entry_hash !== EMPTY_HASH)) || (head.entry_count > 0 && head.sequence !== head.entry_count - 1)) throw new SomaError("evidence head counters are inconsistent", 7, "EVIDENCE_HEAD_COUNTER_INVALID");
  const issued = iso(head.issued_at, "EVIDENCE_HEAD_TIME_INVALID", "head issued_at");
  signatureShape(head.signature, "EVIDENCE_HEAD_SIGNATURE_INVALID");
  if (head.signature.key_id !== head.signer_key_id) throw new SomaError("head signer key mismatch", 7, "EVIDENCE_HEAD_SIGNATURE_INVALID");
  const expected = sha256(Buffer.from(`soma:evidence-head:provisional-v1\n${canonicalize(headCore(head))}`, "utf8"));
  if (expected !== head.head_hash) throw new SomaError("head hash does not match its canonical core", 7, "EVIDENCE_HEAD_HASH_MISMATCH");
  const key = keyAt(identity, history, head.signer_key_id, "controller_signing", issued, "EVIDENCE_HEAD_KEY_WINDOW_INVALID");
  const message = Buffer.concat([Buffer.from("soma:evidence-head:signature:provisional-v1\n", "utf8"), Buffer.from(expected, "hex")]);
  if (!verifyEd25519(key.public_key_multibase, message, head.signature.value)) throw new SomaError("head signature is invalid", 7, "EVIDENCE_HEAD_SIGNATURE_INVALID");
}

function buildHead(entryCount, sequence, entryHash, issuedAt, controllerKey) {
  const core = {
    schema_version: "soma.evidence-head.provisional-v1",
    entry_count: entryCount,
    sequence,
    entry_hash: entryHash,
    signer_key_id: controllerKey.key_id,
    issued_at: issuedAt,
    assurance: "local_only_unanchored",
    anchors: []
  };
  return signRecord(core, "head_hash", "soma:evidence-head:provisional-v1", "soma:evidence-head:signature:provisional-v1", controllerKey);
}

export function createInitialEvidenceHead(secretBundle, createdAt) {
  return buildHead(0, null, EMPTY_HASH, createdAt, privateKeyForRole(secretBundle, "controller_signing"));
}

async function readPublicState(home) {
  const [identity, history] = await Promise.all([
    readFile(path.join(home, "identity", "identity.json"), "utf8").then(JSON.parse),
    readFile(path.join(home, "identity", "public-key-history.json"), "utf8").then(JSON.parse)
  ]);
  return { identity, history };
}

async function readHead(home) {
  const file = path.join(home, "evidence", "head.json");
  try {
    return parseCanonicalJson(await readFile(file, "utf8"), "evidence head");
  } catch (error) {
    if (error instanceof SomaError) throw error;
    throw new SomaError("evidence head is missing or unreadable", 7, "EVIDENCE_HEAD_INVALID", { cause: error.message });
  }
}

async function atomicHead(home, head) {
  const target = path.join(home, "evidence", "head.json");
  const temporary = `${target}.next-${process.pid}-${Date.now()}`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${canonicalize(head)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, target);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function loadSecretBundle(home) {
  const config = JSON.parse(await readFile(path.join(home, "config", "config.json"), "utf8"));
  return unprotectSecretBundle(config.keystore.backend, await readFile(path.join(home, "config", "keystore.blob")));
}

function eraseSecretBundle(bundle) {
  if (!bundle) return;
  for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
  if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
  bundle.root_store_key_base64 = "";
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

async function acquireLock(home, timeoutMs = 30000) {
  const file = path.join(home, "run", "evidence-writer.lock");
  const deadline = Date.now() + timeoutMs;
  const token = randomBytes(16).toString("hex");
  const owner = { schema_version: "soma.evidence-writer-lock.v1", pid: process.pid, token, created_at: new Date().toISOString() };
  while (true) {
    try {
      const handle = await open(file, "wx", 0o600);
      try {
        await handle.writeFile(`${canonicalize(owner)}\n`, "utf8");
        await handle.sync();
        await restrictStatePath(file);
      } catch (setupError) {
        await handle.close().catch(() => {});
        await unlink(file).catch(() => {});
        throw setupError;
      }
      return async () => {
        await handle.close();
        try {
          const current = parseCanonicalJson(await readFile(file, "utf8"), "evidence writer lock");
          if (current.token === token && current.pid === process.pid) await unlink(file);
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let existing = null;
      try {
        existing = parseCanonicalJson(await readFile(file, "utf8"), "evidence writer lock");
      } catch {}
      if (existing && Number.isSafeInteger(existing.pid) && existing.pid > 0 && typeof existing.token === "string" && /^[a-f0-9]{32}$/.test(existing.token) && !processIsAlive(existing.pid)) {
        const stale = `${file}.stale-${token}`;
        try {
          await rename(file, stale);
          await unlink(stale);
          continue;
        } catch (staleError) {
          if (staleError.code === "ENOENT") continue;
          throw staleError;
        }
      }
      if (Date.now() >= deadline) throw new SomaError("evidence writer lock is held or its owner cannot be safely identified", 7, "EVIDENCE_WRITER_LOCKED");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
}

async function ledgerRecords(home, head, recoverIncomplete) {
  const ledgerPath = path.join(home, "evidence", "ledger.jsonl");
  const bytes = await readFile(ledgerPath);
  let recoveredBytes = 0;
  let complete = bytes;
  if (bytes.length && bytes[bytes.length - 1] !== 0x0a) {
    const lastLf = bytes.lastIndexOf(0x0a);
    const tail = bytes.subarray(lastLf + 1).toString("utf8");
    let completeJson = false;
    try {
      parseCanonicalJson(tail, "unterminated ledger tail");
      completeJson = true;
    } catch {}
    if (completeJson || !recoverIncomplete) throw new SomaError("ledger ends with an uncommitted byte sequence", 7, completeJson ? "EVIDENCE_COMPLETE_RECORD_UNTERMINATED" : "EVIDENCE_INCOMPLETE_TAIL");
    recoveredBytes = bytes.length - (lastLf + 1);
    complete = bytes.subarray(0, lastLf + 1);
  }
  const text = complete.toString("utf8");
  const lines = text ? text.slice(0, -1).split("\n") : [];
  const records = lines.map((line, index) => {
    try {
      return parseCanonicalJson(line, `ledger line ${index + 1}`);
    } catch (error) {
      throw new SomaError("a complete ledger record is invalid and will not be skipped", 7, "EVIDENCE_COMPLETE_RECORD_INVALID", { line: index + 1, cause: error.code || error.message });
    }
  });
  if (recoveredBytes) {
    const expectedCount = head.entry_count;
    if (expectedCount > records.length) throw new SomaError("signed head points beyond the complete ledger", 7, "EVIDENCE_HEAD_AHEAD");
    const handle = await open(ledgerPath, "r+");
    try {
      await handle.truncate(complete.length);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  return { records, recoveredBytes };
}

export async function verifyEvidenceLedger(home, { repair = false, secretBundle = null } = {}) {
  const { identity, history } = await readPublicState(home);
  const head = await readHead(home);
  verifyHead(head, identity, history);
  const { records, recoveredBytes } = await ledgerRecords(home, head, repair);
  let previous = EMPTY_HASH;
  for (let index = 0; index < records.length; index += 1) previous = verifyEntry(records[index], index, previous, identity, history);
  const expectedSequence = records.length ? records.length - 1 : null;
  const headCurrent = head.entry_count === records.length && head.sequence === expectedSequence && head.entry_hash === previous;
  if (head.entry_count > records.length) throw new SomaError("signed head points beyond the ledger", 7, "EVIDENCE_HEAD_AHEAD");
  let finalHead = head;
  let repaired = false;
  if (!headCurrent) {
    if (!repair) throw new SomaError("signed head is stale; run evidence verify to recover", 7, "EVIDENCE_HEAD_STALE", { ledger_entries: records.length, head_entries: head.entry_count });
    if (!secretBundle) throw new SomaError("head repair requires the controller keystore", 7, "EVIDENCE_HEAD_REPAIR_KEY_REQUIRED");
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    finalHead = buildHead(records.length, expectedSequence, previous, new Date().toISOString(), controller);
    await atomicHead(home, finalHead);
    repaired = true;
  }
  return {
    ok: true,
    entries: records.length,
    head: finalHead,
    recovered_incomplete_tail_bytes: recoveredBytes,
    head_repaired: repaired,
    assurance: "local_only_unanchored",
    independent_truncation_detection: false,
    truth_claim: "signature_proves_attribution_and_integrity_not_truth"
  };
}

function validateInput(input, identity, issuedAt) {
  exactObject(input, INPUT_FIELDS, "EVIDENCE_INPUT_SHAPE_INVALID", "evidence input");
  if (input.schema_version !== "soma.local-evidence-input.provisional-v1" || !KINDS.has(input.kind)) throw new SomaError("unsupported evidence input version or kind", 2, "EVIDENCE_INPUT_INVALID");
  if (typeof input.task_id !== "string" || input.task_id.length < 1 || input.task_id.length > 256 || !NAME.test(input.capability) || !NAME.test(input.domain) || !HASH.test(input.claim_hash)) throw new SomaError("evidence input fields are invalid", 2, "EVIDENCE_INPUT_INVALID");
  uniqueHashes(input.artifact_hashes, "EVIDENCE_INPUT_INVALID", "artifact_hashes");
  uniqueHashes(input.receipt_ids, "EVIDENCE_INPUT_INVALID", "receipt_ids");
  if (input.receipt_ids.length) throw new SomaError("independent receipt verification is not implemented; receipt_ids must be empty", 8, "EVIDENCE_RECEIPTS_UNSUPPORTED");
  if (input.supersedes !== null && !HASH.test(input.supersedes)) throw new SomaError("supersedes is invalid", 2, "EVIDENCE_INPUT_INVALID");
  if (iso(input.occurred_at, "EVIDENCE_INPUT_INVALID", "occurred_at") > Date.parse(issuedAt)) throw new SomaError("occurred_at cannot be in the future", 2, "EVIDENCE_INPUT_INVALID");
  return {
    schema_version: "soma.local-evidence-event.provisional-v1",
    context_id: `soma:local-context:v1:${sha256(Buffer.from(`soma:local-evidence-context:v1\n${identity.agent_did}`, "utf8"))}`,
    kind: input.kind,
    subject_did: identity.agent_did,
    issuer_did: identity.agent_did,
    task_id: input.task_id,
    capability: input.capability,
    domain: input.domain,
    claim_hash: input.claim_hash,
    artifact_hashes: input.artifact_hashes,
    receipt_ids: input.receipt_ids,
    occurred_at: input.occurred_at,
    issued_at: issuedAt,
    supersedes: input.supersedes,
    assurance: "self_signed_attribution_only"
  };
}

export async function recordEvidence(home, inputFile, { faultInjector = null } = {}) {
  if (!path.isAbsolute(inputFile)) throw new SomaError("--input must be an absolute path", 2, "EVIDENCE_INPUT_PATH_RELATIVE");
  const inputHandle = await open(inputFile, "r");
  let inputBytes;
  try {
    const inputStat = await inputHandle.stat();
    if (!inputStat.isFile() || inputStat.size > 65536) throw new SomaError("evidence input must be a regular file no larger than 64 KiB", 2, "EVIDENCE_INPUT_FILE_INVALID");
    const buffer = Buffer.alloc(65537);
    const { bytesRead } = await inputHandle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 65536) throw new SomaError("evidence input grew beyond 64 KiB while being read", 2, "EVIDENCE_INPUT_FILE_INVALID");
    inputBytes = buffer.subarray(0, bytesRead).toString("utf8");
    buffer.fill(0);
  } finally {
    await inputHandle.close();
  }
  const input = parseCanonicalJson(inputBytes, "evidence input");
  const release = await acquireLock(home);
  let secretBundle;
  try {
    secretBundle = await loadSecretBundle(home);
    const verified = await verifyEvidenceLedger(home, { repair: true, secretBundle });
    const { identity, history } = await readPublicState(home);
    const issuedAt = new Date().toISOString();
    const agentKey = privateKeyForRole(secretBundle, "agent_signing");
    keyAt(identity, history, agentKey.key_id, "agent_signing", Date.parse(issuedAt), "EVIDENCE_ENTRY_KEY_WINDOW_INVALID");
    const eventCore = validateInput(input, identity, issuedAt);
    const event = signRecord(eventCore, "evidence_id", "soma:local-evidence:provisional-v1", "soma:local-evidence:provisional-v1:signature", agentKey);
    const core = {
      schema_version: "soma.local-evidence-entry.provisional-v1",
      sequence: verified.entries,
      previous_entry_hash: verified.head.entry_hash,
      evidence_event: event,
      recorded_at: issuedAt,
      signer_key_id: agentKey.key_id
    };
    const entry = signRecord(core, "entry_hash", "soma:local-evidence-entry:v1", "soma:local-evidence-entry:signature:v1", agentKey);
    verifyEntry(entry, verified.entries, verified.head.entry_hash, identity, history);
    const ledgerHandle = await open(path.join(home, "evidence", "ledger.jsonl"), "a", 0o600);
    try {
      await ledgerHandle.writeFile(`${canonicalize(entry)}\n`, "utf8");
      await ledgerHandle.sync();
    } finally {
      await ledgerHandle.close();
    }
    if (faultInjector) await faultInjector("after_ledger_sync");
    const head = buildHead(verified.entries + 1, entry.sequence, entry.entry_hash, issuedAt, privateKeyForRole(secretBundle, "controller_signing"));
    await atomicHead(home, head);
    return {
      local_mutation: true,
      remote_mutation: false,
      evidence_id: event.evidence_id,
      entry_hash: entry.entry_hash,
      sequence: entry.sequence,
      assurance: event.assurance,
      ledger_assurance: head.assurance,
      independent_truncation_detection: false,
      truth_claim: "signature_proves_attribution_and_integrity_not_truth"
    };
  } finally {
    eraseSecretBundle(secretBundle);
    try { await restrictStateRoot(home); } finally { await release(); }
  }
}

export async function verifyAndRepairEvidence(home) {
  const release = await acquireLock(home);
  let secretBundle;
  try {
    secretBundle = await loadSecretBundle(home);
    return await verifyEvidenceLedger(home, { repair: true, secretBundle });
  } finally {
    eraseSecretBundle(secretBundle);
    try { await restrictStateRoot(home); } finally { await release(); }
  }
}
