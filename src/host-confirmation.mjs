import { link, mkdir, readFile, readdir, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { privateKeyForRole, sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import {
  controllerSecret,
  durableFile,
  eraseSecretBundle,
  existingPin,
  HOST_PIN_AUTHORITY,
  hostFile,
  publicIdentity,
  SUCCESSION_TRUST_BASIS,
  verifyPinRecord
} from "./host.mjs";
import {
  CONFIRMATION_DECISION,
  CONFIRMATION_SIGNATURE_DOMAIN,
  deriveConfirmationId,
  successionSubject,
  validateHostSuccessionConfirmation
} from "./host-confirmation-domain.mjs";
import { acquireHostSuccessionLock } from "./host-lock.mjs";
import { candidateDirectory, candidateFile, storedCandidate, verifyCandidateRecord } from "./host-succession.mjs";
import { assertJsonSchema } from "./json-schema.mjs";
import { RELEASE_ROOT } from "./constants.mjs";
import { controllerSigningKeyAt } from "./controller-rotation.mjs";

const HASH = /^[a-f0-9]{64}$/;
const TRANSITION_AUTHORITY = "prepared_local_transition_no_connection_no_consent_no_send";
const TRANSITION_ID_DOMAIN = "soma:host-succession-transition:provisional-v1\n";
const TRANSITION_SIGNATURE_DOMAIN = "soma:host-succession-transition-signature:provisional-v1\n";
const PIN_ID_DOMAIN = "soma:host-pin:provisional-v2\n";
const PIN_SIGNATURE_DOMAIN = "soma:host-pin-signature:provisional-v2\n";

const keyById = (keys, id) => keys.find((key) => key.key_id === id);
const pinCore = (record) => { const { pin_id, signature, ...core } = record; return core; };
const transitionCore = (record) => { const { transition_id, signature, ...core } = record; return core; };
const hostToken = (hostDid) => path.basename(hostFile(".", hostDid), ".json");
const transactionDirectory = (home) => path.join(home, "hosts", "transactions");
const historyDirectory = (home) => path.join(home, "hosts", "history");
const transactionFile = (home, hostDid) => path.join(transactionDirectory(home), `${hostToken(hostDid)}.json`);
const temporaryPinFile = (home, hostDid) => path.join(transactionDirectory(home), `${hostToken(hostDid)}.pin.tmp`);
const historyHostDirectory = (home, hostDid) => path.join(historyDirectory(home), hostToken(hostDid));
const historyFile = (home, hostDid, confirmationId) => path.join(historyHostDirectory(home, hostDid), `${confirmationId}.json`);

async function schema(name) { return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", name), "utf8")); }
const confirmationSchema = () => schema("soma-host-succession-confirmation.schema.json");
const transitionSchema = () => schema("host-succession-transition.provisional.schema.json");

function storedError(error, code = error?.code) {
  if (!(error instanceof SomaError) || error.exitCode === 7) return error;
  return new SomaError(error.message, 7, code || "HOST_SUCCESSION_STORED_INVALID", error.details);
}

async function readCanonicalStored(file, label, encodingCode) {
  try { return parseCanonicalJson(await readFile(file, "utf8"), label); }
  catch (error) {
    if (error instanceof SomaError && ["JSON_INVALID", "JSON_NOT_CANONICAL", "JSON_PROFILE_INVALID"].includes(error.code)) throw new SomaError(`${label} is not canonical JSON`, 7, encodingCode, { cause_code: error.code });
    throw error;
  }
}

function confirmationRecord(subject, identity, controller, confirmedAt) {
  const record = {
    $schema: "../schemas/soma-host-succession-confirmation.schema.json",
    schema_version: "somavera.soma-host-succession-confirmation.v1",
    profile_status: "freeze_blocking_draft",
    confirmation_id: "0".repeat(64),
    ...subject,
    controller_did: identity.controller_did,
    controller_signing_key_id: controller.key_id,
    confirmed_at: confirmedAt,
    decision: CONFIRMATION_DECISION,
    authority: {
      authorizes_pin_replacement: true,
      authorizes_connection: false,
      authorizes_consent: false,
      authorizes_disclosure: false,
      authorizes_send: false,
      authorizes_emergency_recovery: false
    },
    signature: {}
  };
  record.confirmation_id = deriveConfirmationId(record);
  record.signature = {
    suite: "Ed25519-v1",
    key_id: controller.key_id,
    value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from(CONFIRMATION_SIGNATURE_DOMAIN), Buffer.from(record.confirmation_id, "hex")]))
  };
  return record;
}

function successorPinRecord(priorPin, candidate, confirmation, identity, controller) {
  const expected = { ...priorPin.expected, active_signing_key_sha256: confirmation.successor_active_host_signing_key_sha256 };
  const core = {
    schema_version: "soma.host-pin.provisional-v2",
    pinned_at: confirmation.confirmed_at,
    controller_did: identity.controller_did,
    trust_basis: SUCCESSION_TRUST_BASIS,
    expected,
    descriptor: candidate.successor_descriptor,
    connected: false,
    rotation_policy: "controller_confirmed_ordinary_succession_inert",
    authority: HOST_PIN_AUTHORITY,
    predecessor_pin_id: priorPin.pin_id,
    confirmation_id: confirmation.confirmation_id,
    subject_id: confirmation.subject_id
  };
  const pinId = sha256(Buffer.from(PIN_ID_DOMAIN + canonicalize(core)));
  return {
    ...core,
    pin_id: pinId,
    signature: {
      suite: "Ed25519-v1",
      key_id: controller.key_id,
      value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from(PIN_SIGNATURE_DOMAIN), Buffer.from(pinId, "hex")]))
    }
  };
}

function transitionRecord(priorPin, candidate, confirmation, successorPin, identity, controller) {
  const core = {
    schema_version: "soma.host-succession-transition.provisional-v1",
    prepared_at: confirmation.confirmed_at,
    controller_did: identity.controller_did,
    host_did: candidate.host_did,
    candidate_id: candidate.candidate_id,
    subject_id: confirmation.subject_id,
    confirmation_id: confirmation.confirmation_id,
    prior_pin_id: priorPin.pin_id,
    successor_pin_id: successorPin.pin_id,
    prior_pin: priorPin,
    candidate,
    confirmation,
    successor_pin: successorPin,
    authority: TRANSITION_AUTHORITY
  };
  const transitionId = sha256(Buffer.from(TRANSITION_ID_DOMAIN + canonicalize(core)));
  return {
    ...core,
    transition_id: transitionId,
    signature: {
      suite: "Ed25519-v1",
      key_id: controller.key_id,
      value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from(TRANSITION_SIGNATURE_DOMAIN), Buffer.from(transitionId, "hex")]))
    }
  };
}

export async function verifyTransition(home, record, identity) {
  assertJsonSchema(record, await transitionSchema(), { code: "HOST_SUCCESSION_TRANSITION_SCHEMA_INVALID", label: "host succession transition", exitCode: 7 });
  if (record.controller_did !== identity.controller_did || record.authority !== TRANSITION_AUTHORITY || record.prepared_at !== record.confirmation.confirmed_at) throw new SomaError("host succession transition authority is invalid", 7, "HOST_SUCCESSION_TRANSITION_INVARIANT_INVALID");
  const preparedAt = Date.parse(record.prepared_at);
  if (!Number.isFinite(preparedAt)) throw new SomaError("host succession transition time is invalid", 7, "HOST_SUCCESSION_TRANSITION_TIME_INVALID");
  await verifyPinRecord(record.prior_pin, identity, { currentTime: preparedAt });
  const candidateSummary = await verifyCandidateRecord(home, record.candidate, identity, { currentTime: preparedAt, priorPin: record.prior_pin });
  assertJsonSchema(record.confirmation, await confirmationSchema(), { code: "HOST_SUCCESSION_CONFIRMATION_SCHEMA_INVALID", label: "host succession confirmation", exitCode: 7 });
  try { validateHostSuccessionConfirmation(record.confirmation, record.prior_pin.descriptor, record.candidate.successor_descriptor, record.candidate.succession_proof, identity, { validationTime: preparedAt }); }
  catch (error) { throw storedError(error); }
  await verifyPinRecord(record.successor_pin, identity, { currentTime: preparedAt });
  if (record.host_did !== record.candidate.host_did || record.candidate_id !== record.candidate.candidate_id || record.subject_id !== candidateSummary.subject_id || record.subject_id !== record.confirmation.subject_id || record.confirmation_id !== record.confirmation.confirmation_id || record.prior_pin_id !== record.prior_pin.pin_id || record.successor_pin_id !== record.successor_pin.pin_id || record.successor_pin.predecessor_pin_id !== record.prior_pin_id || record.successor_pin.confirmation_id !== record.confirmation_id || record.successor_pin.subject_id !== record.subject_id || record.successor_pin.descriptor.descriptor_id !== record.candidate.successor_descriptor_id) throw new SomaError("host succession transition bindings are invalid", 7, "HOST_SUCCESSION_TRANSITION_BINDING_INVALID");
  const computed = sha256(Buffer.from(TRANSITION_ID_DOMAIN + canonicalize(transitionCore(record))));
  if (computed !== record.transition_id) throw new SomaError("host succession transition identifier is invalid", 7, "HOST_SUCCESSION_TRANSITION_ID_INVALID");
  const controller = controllerSigningKeyAt(identity, record.signature.key_id, preparedAt);
  if (!controller || record.signature.suite !== "Ed25519-v1" || !verifyEd25519(controller.public_key_multibase, Buffer.concat([Buffer.from(TRANSITION_SIGNATURE_DOMAIN), Buffer.from(record.transition_id, "hex")]), record.signature.value)) throw new SomaError("host succession transition signature is invalid", 7, "HOST_SUCCESSION_TRANSITION_SIGNATURE_INVALID");
  return { transition_id: record.transition_id, candidate_id: record.candidate_id, subject_id: record.subject_id, confirmation_id: record.confirmation_id, host_did: record.host_did, prior_pin_id: record.prior_pin_id, successor_pin_id: record.successor_pin_id, successor_descriptor_id: record.successor_pin.descriptor.descriptor_id };
}

async function candidateForConfirmation(home, identity, candidateId, subjectId) {
  const entries = await readdir(candidateDirectory(home), { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) continue;
    const { record, summary } = await storedCandidate(home, path.join(candidateDirectory(home), entry.name), identity);
    if (record.candidate_id === candidateId) {
      if (summary.subject_id !== subjectId) throw new SomaError("confirmation subject differs from the candidate", 8, "HOST_SUCCESSION_CONFIRMATION_SUBJECT_MISMATCH");
      return { candidate: record, summary };
    }
  }
  return null;
}

async function historyRecords(home, identity) {
  const results = [];
  const roots = await readdir(historyDirectory(home), { withFileTypes: true });
  for (const root of roots) {
    if (!root.isDirectory() || !/^[a-f0-9]{64}$/.test(root.name)) throw new SomaError("host succession history contains an unsupported entry", 7, "HOST_SUCCESSION_HISTORY_STORE_INVALID");
    const files = await readdir(path.join(historyDirectory(home), root.name), { withFileTypes: true });
    for (const entry of files) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("host succession history contains an unsupported record", 7, "HOST_SUCCESSION_HISTORY_STORE_INVALID");
      const file = path.join(historyDirectory(home), root.name, entry.name);
      const record = await readCanonicalStored(file, "stored host succession history", "HOST_SUCCESSION_HISTORY_ENCODING_INVALID");
      const summary = await verifyTransition(home, record, identity);
      if (file !== historyFile(home, record.host_did, record.confirmation_id)) throw new SomaError("host succession history is stored under the wrong path", 7, "HOST_SUCCESSION_HISTORY_PATH_INVALID");
      results.push({ record, summary });
    }
  }
  return results;
}

export async function verifyHostSuccessionHistoryStore(home, identity = null) {
  const localIdentity = identity || await publicIdentity(home);
  const transactionEntries = await readdir(transactionDirectory(home));
  if (transactionEntries.length) throw new SomaError("a prepared host succession transition requires recovery", 7, "HOST_SUCCESSION_RECOVERY_REQUIRED", { entries: transactionEntries.sort() });
  const histories = await historyRecords(home, localIdentity);
  const byHost = new Map();
  for (const item of histories) {
    const list = byHost.get(item.record.host_did) || [];
    list.push(item);
    byHost.set(item.record.host_did, list);
  }
  for (const [hostDid, items] of byHost) {
    const current = await existingPin(hostFile(home, hostDid), localIdentity);
    if (!current) throw new SomaError("host succession history has no current pin", 7, "HOST_SUCCESSION_HISTORY_CHAIN_INVALID");
    const bySuccessor = new Map();
    for (const item of items) {
      if (bySuccessor.has(item.record.successor_pin_id)) throw new SomaError("host succession history duplicates a successor pin", 7, "HOST_SUCCESSION_HISTORY_CHAIN_INVALID");
      bySuccessor.set(item.record.successor_pin_id, item);
    }
    const visited = new Set();
    let cursor = current;
    while (cursor.schema_version === "soma.host-pin.provisional-v2") {
      const item = bySuccessor.get(cursor.pin_id);
      if (!item || item.record.prior_pin_id !== cursor.predecessor_pin_id) throw new SomaError("current host pin lacks complete authenticated succession history", 7, "HOST_SUCCESSION_HISTORY_CHAIN_INVALID");
      if (visited.has(item.record.transition_id)) throw new SomaError("host succession history contains a cycle", 7, "HOST_SUCCESSION_HISTORY_CHAIN_INVALID");
      visited.add(item.record.transition_id);
      cursor = item.record.prior_pin;
    }
    if (cursor.schema_version !== "soma.host-pin.provisional-v1" || visited.size !== items.length) throw new SomaError("host succession history is incomplete or orphaned", 7, "HOST_SUCCESSION_HISTORY_CHAIN_INVALID");
  }
  return histories.map(({ summary }) => summary).sort((a, b) => a.confirmation_id.localeCompare(b.confirmation_id));
}

async function restoreCandidate(home, record, identity) {
  const target = candidateFile(home, record.candidate.host_did);
  try {
    const { record: existing } = await storedCandidate(home, target, identity, { priorPin: record.prior_pin, currentTime: Date.parse(record.prepared_at) });
    if (existing.candidate_id !== record.candidate_id) throw new SomaError("recovery found a competing candidate", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await durableFile(target, `${canonicalize(record.candidate)}\n`);
  }
}

async function consumeCandidate(home, record, identity) {
  const target = candidateFile(home, record.candidate.host_did);
  try {
    const existing = await readCanonicalStored(target, "stored host succession candidate", "HOST_SUCCESSION_CANDIDATE_ENCODING_INVALID");
    if (existing.candidate_id !== record.candidate_id) throw new SomaError("recovery found a competing candidate", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS");
    await unlink(target);
  } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function publishHistory(prepared, destination, record) {
  try { await link(prepared, destination); }
  catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = await readCanonicalStored(destination, "stored host succession history", "HOST_SUCCESSION_HISTORY_ENCODING_INVALID");
    if (canonicalize(existing) !== canonicalize(record)) throw new SomaError("competing history exists for committed transition", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS");
  }
  await unlink(prepared);
}

async function recoverUnlocked(home, identity) {
  const entries = await readdir(transactionDirectory(home), { withFileTypes: true });
  const json = entries.filter((entry) => entry.isFile() && /^[a-f0-9]{64}\.json$/.test(entry.name));
  const allowed = new Set(json.flatMap((entry) => [entry.name, entry.name.replace(/\.json$/, ".pin.tmp")]));
  for (const entry of entries) if (!entry.isFile() || !allowed.has(entry.name)) throw new SomaError("host succession transaction store is ambiguous", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS", { entry: entry.name });
  const actions = [];
  for (const entry of json) {
    const file = path.join(transactionDirectory(home), entry.name);
    const record = await readCanonicalStored(file, "prepared host succession transition", "HOST_SUCCESSION_TRANSITION_ENCODING_INVALID");
    const summary = await verifyTransition(home, record, identity);
    if (file !== transactionFile(home, record.host_did)) throw new SomaError("prepared host transition is stored under the wrong path", 7, "HOST_SUCCESSION_TRANSITION_PATH_INVALID");
    const current = await existingPin(hostFile(home, record.host_did), identity);
    if (!current) throw new SomaError("prepared transition has no current pin", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS");
    const temporary = temporaryPinFile(home, record.host_did);
    if (current.pin_id === record.prior_pin_id) {
      await restoreCandidate(home, record, identity);
      await unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
      await unlink(file);
      actions.push({ ...summary, recovery: "rolled_back_before_commit" });
    } else if (current.pin_id === record.successor_pin_id) {
      await consumeCandidate(home, record, identity);
      await unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
      await mkdir(historyHostDirectory(home, record.host_did), { recursive: true, mode: 0o700 });
      const destination = historyFile(home, record.host_did, record.confirmation_id);
      await publishHistory(file, destination, record);
      actions.push({ ...summary, recovery: "finalized_after_commit" });
    } else {
      throw new SomaError("prepared transition does not match the prior or successor current pin", 7, "HOST_SUCCESSION_RECOVERY_AMBIGUOUS", { current_pin_id: current.pin_id, prior_pin_id: record.prior_pin_id, successor_pin_id: record.successor_pin_id });
    }
  }
  return actions;
}

export async function recoverHostSuccessionTransactions(home, identity = null) {
  const release = await acquireHostSuccessionLock(home);
  try { return await recoverUnlocked(home, identity || await publicIdentity(home)); }
  finally { await release(); }
}

async function fault(options, stage) {
  if (options?.faultAt === stage) throw new SomaError(`injected host succession fault at ${stage}`, 10, "HOST_SUCCESSION_FAULT_INJECTED", { stage });
}

export async function confirmHostSuccession(home, options) {
  if (!HASH.test(options?.candidateId || "") || !HASH.test(options?.subjectId || "") || !HASH.test(options?.successorDescriptorId || "")) throw new SomaError("confirmation requires exact lowercase SHA-256 candidate, subject, and successor descriptor IDs", 2, "HOST_SUCCESSION_CONFIRMATION_INPUT_INVALID");
  if (options.confirmInertPinReplacement !== true) throw new SomaError("confirmation requires the explicit inert-pin-replacement flag", 9, "HOST_SUCCESSION_CONFIRMATION_REQUIRED");
  const release = await acquireHostSuccessionLock(home, 120000);
  let secretBundle;
  try {
    const identity = await publicIdentity(home);
    await recoverUnlocked(home, identity);
    const histories = await historyRecords(home, identity);
    const committed = histories.find(({ record }) => record.candidate_id === options.candidateId);
    if (committed) {
      if (committed.record.subject_id !== options.subjectId || committed.record.successor_pin.descriptor.descriptor_id !== options.successorDescriptorId) throw new SomaError("confirmation identifiers differ from committed history", 8, "HOST_SUCCESSION_CONFIRMATION_CONFLICT");
      return { local_mutation: false, remote_mutation: false, idempotent: true, committed: true, ...committed.summary, authority: HOST_PIN_AUTHORITY, network_actions: 0 };
    }
    const selected = await candidateForConfirmation(home, identity, options.candidateId, options.subjectId);
    if (!selected) throw new SomaError("host succession candidate was not found", 8, "HOST_SUCCESSION_CANDIDATE_NOT_FOUND");
    if (selected.candidate.successor_descriptor_id !== options.successorDescriptorId) throw new SomaError("expected successor descriptor differs from the candidate", 8, "HOST_SUCCESSION_CONFIRMATION_SUCCESSOR_MISMATCH");
    const priorPin = (await existingPin(hostFile(home, selected.candidate.host_did), identity));
    if (!priorPin || priorPin.pin_id !== selected.candidate.prior_pin_id) throw new SomaError("candidate no longer binds the current pin", 8, "HOST_SUCCESSION_PRIOR_PIN_MISMATCH");
    const now = Date.now();
    if (now < Date.parse(selected.candidate.succession_proof.issued_at) || now > Date.parse(selected.candidate.succession_proof.expires_at)) throw new SomaError("succession proof expired before confirmation", 8, "HOST_SUCCESSION_CONFIRMATION_EXPIRED");
    secretBundle = await controllerSecret(home);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    const subject = successionSubject(priorPin.descriptor, selected.candidate.successor_descriptor, selected.candidate.succession_proof);
    if (subject.subject_id !== options.subjectId) throw new SomaError("recomputed confirmation subject differs", 8, "HOST_SUCCESSION_CONFIRMATION_SUBJECT_MISMATCH");
    const confirmedAt = new Date(now).toISOString();
    const confirmation = confirmationRecord(subject, identity, controller, confirmedAt);
    assertJsonSchema(confirmation, await confirmationSchema(), { code: "HOST_SUCCESSION_CONFIRMATION_SCHEMA_INVALID", label: "host succession confirmation", exitCode: 7 });
    validateHostSuccessionConfirmation(confirmation, priorPin.descriptor, selected.candidate.successor_descriptor, selected.candidate.succession_proof, identity, { validationTime: now });
    const successorPin = successorPinRecord(priorPin, selected.candidate, confirmation, identity, controller);
    await verifyPinRecord(successorPin, identity, { currentTime: now });
    const transition = transitionRecord(priorPin, selected.candidate, confirmation, successorPin, identity, controller);
    await verifyTransition(home, transition, identity);
    await mkdir(transactionDirectory(home), { recursive: true, mode: 0o700 });
    await mkdir(historyHostDirectory(home, selected.candidate.host_did), { recursive: true, mode: 0o700 });
    const prepared = transactionFile(home, selected.candidate.host_did);
    const temporary = temporaryPinFile(home, selected.candidate.host_did);
    await durableFile(prepared, `${canonicalize(transition)}\n`);
    await fault(options, "after_prepare");
    await durableFile(temporary, `${canonicalize(successorPin)}\n`);
    await fault(options, "after_successor_sync");
    const currentBeforeCommit = await existingPin(hostFile(home, selected.candidate.host_did), identity);
    if (!currentBeforeCommit || currentBeforeCommit.pin_id !== priorPin.pin_id) throw new SomaError("current pin changed before succession commit", 7, "HOST_SUCCESSION_COMMIT_RACE");
    if (Date.now() > Date.parse(selected.candidate.succession_proof.expires_at)) throw new SomaError("succession proof expired before the atomic commit", 8, "HOST_SUCCESSION_CONFIRMATION_EXPIRED");
    await rename(temporary, hostFile(home, selected.candidate.host_did));
    await fault(options, "after_current_pin_commit");
    await consumeCandidate(home, transition, identity);
    await fault(options, "after_candidate_consumed");
    await publishHistory(prepared, historyFile(home, selected.candidate.host_did, confirmation.confirmation_id), transition);
    await fault(options, "after_history_published");
    return { local_mutation: true, remote_mutation: false, idempotent: false, committed: true, transition_id: transition.transition_id, confirmation_id: confirmation.confirmation_id, subject_id: confirmation.subject_id, candidate_id: selected.candidate.candidate_id, prior_pin_id: priorPin.pin_id, successor_pin_id: successorPin.pin_id, successor_descriptor_id: successorPin.descriptor.descriptor_id, authority: HOST_PIN_AUTHORITY, network_actions: 0 };
  } finally {
    eraseSecretBundle(secretBundle);
    await release();
  }
}

export async function hostSuccessionHistoryStatus(home) {
  const histories = await verifyHostSuccessionHistoryStore(home);
  return { completed_host_successions: histories.length, succession_history: histories, network_actions: 0 };
}
