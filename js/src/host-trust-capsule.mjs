import { lstat, open, readFile, readdir, realpath, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { ed25519MultibaseSha256, privateKeyForRole, sha256, signEd25519, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { assertJsonSchema } from "./json-schema.mjs";
import { RELEASE_ROOT } from "./constants.mjs";
import { controllerSecret, eraseSecretBundle, ORIGIN_CAPSULE_HASH, publicIdentity, readCanonicalFile, SUPPORTED_ORIGIN_CAPSULE_HASHES, verifyHostPinStore, verifyPinRecord } from "./host.mjs";
import { verifyHostSuccessionHistoryStore, verifyTransition } from "./host-confirmation.mjs";
import { attachPublicKeyHistory, validateControllerRotation, verifyPublicKeyHistory } from "./controller-rotation.mjs";
import { verifyRelease } from "./release.mjs";

const V1 = Object.freeze({ history: "somavera:soma-host-trust-history-chain:v1\n", currentSet: "somavera:soma-host-trust-current-set:v1\n", objectSet: "somavera:soma-host-trust-object-set:v1\n", capsule: "somavera:soma-host-trust-capsule:v1\n", signature: "somavera:soma-host-trust-capsule-signature:v1\n" });
const V2 = Object.freeze({ history: "somavera:soma-host-trust-history-chain:v2\n", controllerHistory: "somavera:soma-controller-history-chain:v2\n", currentSet: "somavera:soma-host-trust-current-set:v2\n", objectSet: "somavera:soma-host-trust-object-set:v2\n", capsule: "somavera:soma-host-trust-capsule:v2\n", signature: "somavera:soma-host-trust-capsule-signature:v2\n" });
const AUTHORITY = "portable_offline_host_trust_capsule_not_external_anchor_not_restore_authority";
const HASH = /^[a-f0-9]{64}$/;
const CURRENT_PATH = /^hosts\/([a-f0-9]{64})\.json$/;
const HISTORY_PATH = /^hosts\/history\/([a-f0-9]{64})\/([a-f0-9]{64})\.json$/;
const ROTATION_PATH = /^identity\/rotations\/([0-9]{12})-([a-f0-9]{64})\.json$/;
const MAX_CAPSULE_BYTES = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES = 2 * 1024 * 1024;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const CLAIMS_V1 = Object.freeze({ complete_host_trust_state: true, contains_managed_secrets: false, external_anchor_created: false, rollback_detection_without_separately_preserved_capsule: false, authorizes_restore: false, authorizes_connection: false, authorizes_consent: false, authorizes_disclosure: false, authorizes_send: false, authorizes_emergency_recovery: false });
const CLAIMS_V2 = Object.freeze({ complete_host_trust_state: true, complete_controller_rotation_history: true, contains_managed_secrets: false, external_anchor_created: false, rollback_detection_without_separately_preserved_capsule: false, authorizes_restore: false, authorizes_connection: false, authorizes_consent: false, authorizes_disclosure: false, authorizes_send: false, authorizes_emergency_recovery: false });

const stringOrder = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const objectCore = ({ canonical_json_base64, ...core }) => core;
const capsuleCore = ({ $schema, capsule_id, signature, ...core }) => core;
const hostToken = (hostDid) => sha256(Buffer.from(`soma:host-pin-file:provisional-v1\n${hostDid}`));
const historyRoot = (ids, domains) => sha256(Buffer.from(domains.history + canonicalize(ids)));
const controllerHistoryRoot = (ids) => sha256(Buffer.from(V2.controllerHistory + canonicalize(ids)));
const currentSetRoot = (hosts, domains) => sha256(Buffer.from(domains.currentSet + canonicalize(hosts)));
const objectSetRoot = (objects, domains) => sha256(Buffer.from(domains.objectSet + canonicalize(objects.map(objectCore))));

async function schema(version) {
  const name = version === "somavera.soma-host-trust-capsule.v2" ? "soma-host-trust-capsule-v2.schema.json" : "soma-host-trust-capsule.schema.json";
  return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", name), "utf8"));
}
function stored(error, fallback = "HOST_TRUST_CAPSULE_INVALID") {
  if (error instanceof SomaError && error.exitCode === 7) return error;
  return new SomaError(error.message || "host trust capsule is invalid", 7, error.code || fallback, error.details);
}
function identityFromCapsule(capsule) {
  return { controller_did: capsule.controller.did, keys: [{ role: "controller_signing", algorithm: "Ed25519-v1", did: capsule.controller.did, key_id: capsule.controller.signing_key_id, public_key_multibase: capsule.controller.public_key_multibase, status: "active" }] };
}
function relativeObject(relative, kind, bytes) {
  return { path: relative, kind, byte_length: bytes.length, sha256: sha256(bytes), canonical_json_base64: bytes.toString("base64") };
}
function comparePathOrder(values, code) {
  const sorted = [...values].sort();
  if (new Set(values).size !== values.length || canonicalize(values) !== canonicalize(sorted)) throw new SomaError("capsule entries are duplicated or unsorted", 7, code);
}

async function localObjects(home) {
  const objects = [];
  const hostsDirectory = path.join(home, "hosts");
  for (const entry of await readdir(hostsDirectory, { withFileTypes: true })) {
    if (entry.isDirectory()) continue;
    if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("host store contains an unsupported entry", 7, "HOST_STORE_ENTRY_INVALID");
    const bytes = await readFile(path.join(hostsDirectory, entry.name));
    objects.push(relativeObject(`hosts/${entry.name}`, "current_pin", bytes));
  }
  const historyRootDirectory = path.join(hostsDirectory, "history");
  for (const hostEntry of await readdir(historyRootDirectory, { withFileTypes: true })) {
    if (!hostEntry.isDirectory() || !/^[a-f0-9]{64}$/.test(hostEntry.name)) throw new SomaError("host history contains an unsupported entry", 7, "HOST_SUCCESSION_HISTORY_STORE_INVALID");
    const directory = path.join(historyRootDirectory, hostEntry.name);
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("host history contains an unsupported record", 7, "HOST_SUCCESSION_HISTORY_STORE_INVALID");
      const bytes = await readFile(path.join(directory, entry.name));
      objects.push(relativeObject(`hosts/history/${hostEntry.name}/${entry.name}`, "history_transition", bytes));
    }
  }
  const rotationsDirectory = path.join(home, "identity", "rotations");
  for (const entry of await readdir(rotationsDirectory, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[0-9]{12}-[a-f0-9]{64}\.json$/.test(entry.name)) throw new SomaError("controller rotation history contains an unsupported record", 7, "CONTROLLER_ROTATION_HISTORY_INVALID");
    const bytes = await readFile(path.join(rotationsDirectory, entry.name));
    objects.push(relativeObject(`identity/rotations/${entry.name}`, "controller_rotation", bytes));
  }
  return objects.sort((a, b) => stringOrder(a.path, b.path));
}

async function semanticState(objects, identity, createdAt, domains = V1) {
  const currents = new Map(), transitions = [];
  for (const object of objects) {
    const bytes = Buffer.from(object.canonical_json_base64, "base64");
    if (bytes.toString("base64") !== object.canonical_json_base64) throw new SomaError("capsule object base64 is not canonical", 7, "HOST_TRUST_CAPSULE_OBJECT_ENCODING_INVALID");
    if (bytes.length !== object.byte_length) throw new SomaError("capsule object length differs", 7, "HOST_TRUST_CAPSULE_OBJECT_SIZE_INVALID");
    if (bytes.length > MAX_OBJECT_BYTES || sha256(bytes) !== object.sha256) throw new SomaError("capsule object hash or bound is invalid", 7, "HOST_TRUST_CAPSULE_OBJECT_HASH_INVALID");
    let record;
    try { record = parseCanonicalJson(UTF8.decode(bytes), "host trust capsule object"); } catch (error) { throw stored(error, "HOST_TRUST_CAPSULE_OBJECT_ENCODING_INVALID"); }
    const currentMatch = CURRENT_PATH.exec(object.path), historyMatch = HISTORY_PATH.exec(object.path);
    if (object.kind === "current_pin" && currentMatch) {
      const summary = await verifyPinRecord(record, identity, { currentTime: createdAt });
      if (currentMatch[1] !== hostToken(summary.host_did) || currents.has(summary.host_did)) throw new SomaError("capsule current pin path is invalid or duplicated", 7, "HOST_TRUST_CAPSULE_OBJECT_PATH_INVALID");
      currents.set(summary.host_did, { record, summary });
    } else if (object.kind === "history_transition" && historyMatch) {
      const summary = await verifyTransition(".", record, identity);
      if (historyMatch[1] !== hostToken(summary.host_did) || historyMatch[2] !== summary.confirmation_id) throw new SomaError("capsule history path is invalid", 7, "HOST_TRUST_CAPSULE_OBJECT_PATH_INVALID");
      transitions.push({ record, summary });
    } else if (object.kind !== "controller_rotation") throw new SomaError("capsule object kind and path disagree", 7, "HOST_TRUST_CAPSULE_OBJECT_PATH_INVALID");
  }
  const hosts = [];
  const used = new Set();
  for (const [hostDid, current] of [...currents.entries()].sort(([a], [b]) => stringOrder(a, b))) {
    const items = transitions.filter((item) => item.summary.host_did === hostDid);
    const bySuccessor = new Map();
    for (const item of items) {
      if (bySuccessor.has(item.summary.successor_pin_id)) throw new SomaError("capsule history forks or duplicates a successor", 7, "HOST_TRUST_CAPSULE_HISTORY_INVALID");
      bySuccessor.set(item.summary.successor_pin_id, item);
    }
    const orderedReverse = [];
    let cursor = current.record;
    while (cursor.schema_version === "soma.host-pin.provisional-v2") {
      const item = bySuccessor.get(cursor.pin_id);
      if (!item || item.record.prior_pin_id !== cursor.predecessor_pin_id || used.has(item.summary.transition_id)) throw new SomaError("capsule history is incomplete, forked, or cyclic", 7, "HOST_TRUST_CAPSULE_HISTORY_INVALID");
      used.add(item.summary.transition_id);
      orderedReverse.push(item.summary.transition_id);
      cursor = item.record.prior_pin;
    }
    if (cursor.schema_version !== "soma.host-pin.provisional-v1" || orderedReverse.length !== items.length) throw new SomaError("capsule history is incomplete or orphaned", 7, "HOST_TRUST_CAPSULE_HISTORY_INVALID");
    const transitionIds = orderedReverse.reverse();
    hosts.push({ host_did: hostDid, current_pin_id: current.record.pin_id, current_descriptor_id: current.record.descriptor.descriptor_id, current_descriptor_sequence: current.record.descriptor.descriptor_sequence, transition_ids: transitionIds, history_chain_root: historyRoot(transitionIds, domains) });
  }
  if (used.size !== transitions.length) throw new SomaError("capsule contains history without a current pin", 7, "HOST_TRUST_CAPSULE_HISTORY_INVALID");
  return { hosts, transitionCount: transitions.length };
}

function decodeCapsuleObject(object) {
  const bytes = Buffer.from(object.canonical_json_base64 || "", "base64");
  if (bytes.toString("base64") !== object.canonical_json_base64) throw new SomaError("capsule object base64 is not canonical", 7, "HOST_TRUST_CAPSULE_OBJECT_ENCODING_INVALID");
  if (bytes.length !== object.byte_length) throw new SomaError("capsule object length differs", 7, "HOST_TRUST_CAPSULE_OBJECT_SIZE_INVALID");
  if (bytes.length > MAX_OBJECT_BYTES || sha256(bytes) !== object.sha256) throw new SomaError("capsule object hash or bound is invalid", 7, "HOST_TRUST_CAPSULE_OBJECT_HASH_INVALID");
  try { return parseCanonicalJson(UTF8.decode(bytes), "host trust capsule object"); }
  catch (error) { throw stored(error, "HOST_TRUST_CAPSULE_OBJECT_ENCODING_INVALID"); }
}

async function controllerIdentityV2(capsule, expected) {
  const controller = capsule.controller;
  const initial = controller.initial_key;
  if (!expected || controller.did !== expected.controllerDid || !HASH.test(expected.controllerKeyHash || "")) throw new SomaError("capsule controller differs from the independent expectation", 7, "HOST_TRUST_CAPSULE_CONTROLLER_MISMATCH");
  let initialHash;
  try { initialHash = ed25519MultibaseSha256(initial.public_key_multibase); }
  catch { throw new SomaError("capsule initial controller key is invalid", 7, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH"); }
  if (initialHash !== initial.public_key_sha256 || initialHash !== expected.controllerKeyHash) throw new SomaError("capsule initial controller key differs from the independent expectation", 7, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH");
  const initialDid = initial.key_id.split("#")[0];
  const identity = { controller_did: controller.did, keys: [{ role: "controller_signing", algorithm: "Ed25519-v1", did: initialDid, key_id: initial.key_id, public_key_multibase: initial.public_key_multibase, status: "active" }] };
  const history = { schema_version: "somavera.soma-public-key-history.v2", controller_did: controller.did, controller_initial_key_id: initial.key_id, controller_rotation_sequence: 0, controller_rotation_head: null, entries: [{ ...identity.keys[0], valid_from: initial.valid_from, valid_until: null, activated_by_rotation_id: null, retired_by_rotation_id: null }], controller_rotations: [] };
  const rotationObjects = capsule.objects.filter((entry) => entry.kind === "controller_rotation");
  let active = history.entries[0], head = null;
  const rotationIds = [];
  for (let index = 0; index < rotationObjects.length; index += 1) {
    const object = rotationObjects[index];
    const event = decodeCapsuleObject(object);
    const match = ROTATION_PATH.exec(object.path);
    const sequence = index + 1;
    if (!match || Number(match[1]) !== sequence || match[2] !== event.rotation_id) throw new SomaError("capsule controller rotation path or order is invalid", 7, "HOST_TRUST_CAPSULE_CONTROLLER_HISTORY_INVALID");
    await validateControllerRotation(event, { controller_did: controller.did, rotation_sequence: sequence, previous_rotation_id: head, prior_key_id: active.key_id, prior_public_key_multibase: active.public_key_multibase, prior_valid_from: active.valid_from }, { exitCode: 7 });
    const priorIdentity = identity.keys.find((entry) => entry.key_id === active.key_id);
    priorIdentity.status = "retired";
    active.status = "retired";
    active.valid_until = event.effective_at;
    active.retired_by_rotation_id = event.rotation_id;
    const nextIdentity = { role: "controller_signing", algorithm: "Ed25519-v1", did: event.successor_key.key_id.split("#")[0], key_id: event.successor_key.key_id, public_key_multibase: event.successor_key.public_key_multibase, status: "active" };
    identity.keys.push(nextIdentity);
    active = { ...nextIdentity, valid_from: event.effective_at, valid_until: null, activated_by_rotation_id: event.rotation_id, retired_by_rotation_id: null };
    history.entries.push(active);
    history.controller_rotations.push(event);
    history.controller_rotation_sequence = sequence;
    history.controller_rotation_head = event.rotation_id;
    head = event.rotation_id;
    rotationIds.push(event.rotation_id);
  }
  await verifyPublicKeyHistory(identity, history);
  attachPublicKeyHistory(identity, history);
  if (controller.rotation_sequence !== rotationIds.length || controller.rotation_head !== head || canonicalize(controller.rotation_ids) !== canonicalize(rotationIds) || capsule.controller_rotation_count !== rotationIds.length) throw new SomaError("capsule controller history summary is invalid", 7, "HOST_TRUST_CAPSULE_CONTROLLER_HISTORY_INVALID");
  if (controller.active_signing_key_id !== active.key_id || capsule.signature.key_id !== active.key_id) throw new SomaError("capsule active controller key is invalid", 7, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH");
  if (capsule.controller_history_root !== controllerHistoryRoot(rotationIds)) throw new SomaError("capsule controller-history root is invalid", 7, "HOST_TRUST_CAPSULE_CONTROLLER_HISTORY_ROOT_INVALID");
  return { identity, initialHash, active, rotationIds };
}

async function verifyV1(capsule, expected) {
  assertJsonSchema(capsule, await schema(capsule.schema_version), { code: "HOST_TRUST_CAPSULE_SCHEMA_INVALID", label: "host trust capsule", exitCode: 7 });
  if (!expected || capsule.controller.did !== expected.controllerDid || !HASH.test(expected.controllerKeyHash || "")) throw new SomaError("capsule controller differs from the independent expectation", 7, "HOST_TRUST_CAPSULE_CONTROLLER_MISMATCH");
  if (!SUPPORTED_ORIGIN_CAPSULE_HASHES.includes(capsule.source.origin_capsule_hash)) throw new SomaError("capsule source Origin profile is unsupported", 7, "HOST_TRUST_CAPSULE_SOURCE_UNSUPPORTED");
  const keyHash = ed25519MultibaseSha256(capsule.controller.public_key_multibase);
  if (keyHash !== capsule.controller.public_key_sha256 || keyHash !== expected.controllerKeyHash || capsule.controller.signing_key_id !== capsule.signature.key_id) throw new SomaError("capsule controller key differs from the independent expectation", 7, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH");
  comparePathOrder(capsule.objects.map((entry) => entry.path), "HOST_TRUST_CAPSULE_OBJECT_ORDER_INVALID");
  comparePathOrder(capsule.hosts.map((entry) => entry.host_did), "HOST_TRUST_CAPSULE_HOST_ORDER_INVALID");
  const semantic = await semanticState(capsule.objects, identityFromCapsule(capsule), Date.parse(capsule.created_at), V1);
  if (canonicalize(semantic.hosts) !== canonicalize(capsule.hosts)) throw new SomaError("capsule host summaries differ from authenticated objects", 7, "HOST_TRUST_CAPSULE_HOST_SUMMARY_INVALID");
  if (capsule.host_count !== semantic.hosts.length || capsule.transition_count !== semantic.transitionCount) throw new SomaError("capsule counts are invalid", 7, "HOST_TRUST_CAPSULE_COUNT_INVALID");
  if (capsule.current_set_root !== currentSetRoot(capsule.hosts, V1)) throw new SomaError("capsule current-set root is invalid", 7, "HOST_TRUST_CAPSULE_CURRENT_SET_ROOT_INVALID");
  if (capsule.object_set_root !== objectSetRoot(capsule.objects, V1)) throw new SomaError("capsule object-set root is invalid", 7, "HOST_TRUST_CAPSULE_OBJECT_SET_ROOT_INVALID");
  if (canonicalize(capsule.claims) !== canonicalize(CLAIMS_V1) || capsule.authority !== AUTHORITY) throw new SomaError("capsule claims exceed portable-copy authority", 7, "HOST_TRUST_CAPSULE_AUTHORITY_INVALID");
  if (sha256(Buffer.from(V1.capsule + canonicalize(capsuleCore(capsule)))) !== capsule.capsule_id) throw new SomaError("capsule identifier is invalid", 7, "HOST_TRUST_CAPSULE_ID_INVALID");
  if (capsule.signature.suite !== "Ed25519-v1" || !verifyEd25519(capsule.controller.public_key_multibase, Buffer.concat([Buffer.from(V1.signature), Buffer.from(capsule.capsule_id, "hex")]), capsule.signature.value)) throw new SomaError("capsule signature is invalid", 7, "HOST_TRUST_CAPSULE_SIGNATURE_INVALID");
  return { capsule_id: capsule.capsule_id, schema_version: capsule.schema_version, created_at: capsule.created_at, controller_did: capsule.controller.did, controller_key_sha256: keyHash, controller_initial_key_sha256: keyHash, controller_active_key_sha256: keyHash, controller_rotation_count: 0, controller_rotation_ids: [], host_count: capsule.host_count, transition_count: capsule.transition_count, current_set_root: capsule.current_set_root, object_set_root: capsule.object_set_root, hosts: capsule.hosts, source: capsule.source, authority: AUTHORITY, external_anchor_created: false, restore_authorized: false, network_actions: 0 };
}

async function verifyV2(capsule, expected) {
  assertJsonSchema(capsule, await schema(capsule.schema_version), { code: "HOST_TRUST_CAPSULE_SCHEMA_INVALID", label: "host trust capsule", exitCode: 7 });
  if (!SUPPORTED_ORIGIN_CAPSULE_HASHES.includes(capsule.source.origin_capsule_hash)) throw new SomaError("capsule source Origin profile is unsupported", 7, "HOST_TRUST_CAPSULE_SOURCE_UNSUPPORTED");
  comparePathOrder(capsule.objects.map((entry) => entry.path), "HOST_TRUST_CAPSULE_OBJECT_ORDER_INVALID");
  comparePathOrder(capsule.hosts.map((entry) => entry.host_did), "HOST_TRUST_CAPSULE_HOST_ORDER_INVALID");
  const controllerState = await controllerIdentityV2(capsule, expected);
  const semantic = await semanticState(capsule.objects, controllerState.identity, Date.parse(capsule.created_at), V2);
  if (canonicalize(semantic.hosts) !== canonicalize(capsule.hosts)) throw new SomaError("capsule host summaries differ from authenticated objects", 7, "HOST_TRUST_CAPSULE_HOST_SUMMARY_INVALID");
  if (capsule.host_count !== semantic.hosts.length || capsule.transition_count !== semantic.transitionCount) throw new SomaError("capsule counts are invalid", 7, "HOST_TRUST_CAPSULE_COUNT_INVALID");
  if (capsule.current_set_root !== currentSetRoot(capsule.hosts, V2)) throw new SomaError("capsule current-set root is invalid", 7, "HOST_TRUST_CAPSULE_CURRENT_SET_ROOT_INVALID");
  if (capsule.object_set_root !== objectSetRoot(capsule.objects, V2)) throw new SomaError("capsule object-set root is invalid", 7, "HOST_TRUST_CAPSULE_OBJECT_SET_ROOT_INVALID");
  if (canonicalize(capsule.claims) !== canonicalize(CLAIMS_V2) || capsule.authority !== AUTHORITY) throw new SomaError("capsule claims exceed portable-copy authority", 7, "HOST_TRUST_CAPSULE_AUTHORITY_INVALID");
  if (sha256(Buffer.from(V2.capsule + canonicalize(capsuleCore(capsule)))) !== capsule.capsule_id) throw new SomaError("capsule identifier is invalid", 7, "HOST_TRUST_CAPSULE_ID_INVALID");
  if (capsule.signature.suite !== "Ed25519-v1" || !verifyEd25519(controllerState.active.public_key_multibase, Buffer.concat([Buffer.from(V2.signature), Buffer.from(capsule.capsule_id, "hex")]), capsule.signature.value)) throw new SomaError("capsule signature is invalid", 7, "HOST_TRUST_CAPSULE_SIGNATURE_INVALID");
  return { capsule_id: capsule.capsule_id, schema_version: capsule.schema_version, created_at: capsule.created_at, controller_did: capsule.controller.did, controller_key_sha256: controllerState.initialHash, controller_initial_key_sha256: controllerState.initialHash, controller_active_key_sha256: ed25519MultibaseSha256(controllerState.active.public_key_multibase), controller_rotation_count: capsule.controller_rotation_count, controller_rotation_ids: controllerState.rotationIds, controller_history_root: capsule.controller_history_root, host_count: capsule.host_count, transition_count: capsule.transition_count, current_set_root: capsule.current_set_root, object_set_root: capsule.object_set_root, hosts: capsule.hosts, source: capsule.source, authority: AUTHORITY, external_anchor_created: false, restore_authorized: false, network_actions: 0 };
}

export async function verifyHostTrustCapsuleValue(capsule, expected) {
  if (capsule?.schema_version === "somavera.soma-host-trust-capsule.v1") return verifyV1(capsule, expected);
  if (capsule?.schema_version === "somavera.soma-host-trust-capsule.v2") return verifyV2(capsule, expected);
  throw new SomaError("host trust capsule version is unsupported", 7, "HOST_TRUST_CAPSULE_SCHEMA_INVALID");
}

export async function verifyHostTrustCapsuleFile(file, expected) {
  const capsule = await readCanonicalFile(file, MAX_CAPSULE_BYTES, "HOST_TRUST_CAPSULE_FILE_INVALID", "host trust capsule");
  return { local_mutation: false, remote_mutation: false, ...(await verifyHostTrustCapsuleValue(capsule, expected)) };
}

function outside(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative.startsWith("..") || path.isAbsolute(relative);
}
async function writeNewDurable(file, body) {
  const handle = await open(file, "wx", 0o600);
  let complete = false;
  try { await handle.writeFile(body); await handle.sync(); complete = true; }
  finally { await handle.close(); if (!complete) await unlink(file).catch(() => {}); }
}

export async function exportHostTrustCapsule(home, outputFile) {
  if (!outputFile || !path.isAbsolute(outputFile)) throw new SomaError("host trust export requires an absolute --out path", 2, "HOST_TRUST_CAPSULE_OUTPUT_INVALID");
  const target = path.resolve(outputFile);
  if (!outside(target, home) || !outside(target, RELEASE_ROOT)) throw new SomaError("host trust capsule output must be outside Soma state and the release", 2, "HOST_TRUST_CAPSULE_OUTPUT_INVALID");
  const parent = path.dirname(target);
  const parentStat = await stat(parent).catch((error) => { throw new SomaError("host trust capsule output parent is unavailable", 2, "HOST_TRUST_CAPSULE_OUTPUT_INVALID", { cause: error.code }); });
  if (!parentStat.isDirectory() || path.resolve(await realpath(parent)) !== path.resolve(parent)) throw new SomaError("host trust capsule output parent is indirect or invalid", 2, "HOST_TRUST_CAPSULE_OUTPUT_INVALID");
  try { await lstat(target); throw new SomaError("host trust capsule output already exists", 8, "HOST_TRUST_CAPSULE_OUTPUT_EXISTS"); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const identity = await publicIdentity(home);
  await verifyHostPinStore(home, identity);
  await verifyHostSuccessionHistoryStore(home, identity);
  const objects = await localObjects(home);
  const createdAt = new Date().toISOString();
  const controllerPublic = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
  const history = identity.key_history;
  const initial = history.entries.find((entry) => entry.key_id === history.controller_initial_key_id);
  const rotationIds = history.controller_rotations.map((entry) => entry.rotation_id);
  const semantic = await semanticState(objects, identity, Date.parse(createdAt), V2);
  const release = await verifyRelease();
  let secretBundle;
  try {
    secretBundle = await controllerSecret(home);
    const controller = privateKeyForRole(secretBundle, "controller_signing");
    if (!controllerPublic || !initial || controller.key_id !== controllerPublic.key_id || history.controller_rotation_sequence !== rotationIds.length) throw new SomaError("active controller key or history is inconsistent", 7, "HOST_TRUST_CAPSULE_CONTROLLER_KEY_MISMATCH");
    const initialHash = ed25519MultibaseSha256(initial.public_key_multibase);
    const capsule = {
      $schema: "../schemas/soma-host-trust-capsule-v2.schema.json",
      schema_version: "somavera.soma-host-trust-capsule.v2",
      profile_status: "freeze_blocking_draft",
      capsule_id: "0".repeat(64),
      created_at: createdAt,
      controller: {
        did: identity.controller_did,
        initial_key: { key_id: initial.key_id, public_key_multibase: initial.public_key_multibase, public_key_sha256: initialHash, valid_from: initial.valid_from },
        active_signing_key_id: controller.key_id,
        rotation_sequence: history.controller_rotation_sequence,
        rotation_head: history.controller_rotation_head,
        rotation_ids: rotationIds
      },
      source: { origin_capsule_hash: ORIGIN_CAPSULE_HASH, reference_release_manifest_hash: release.manifest_sha256, reference_release_version: release.release_version },
      host_count: semantic.hosts.length,
      transition_count: semantic.transitionCount,
      controller_rotation_count: rotationIds.length,
      current_set_root: currentSetRoot(semantic.hosts, V2),
      controller_history_root: controllerHistoryRoot(rotationIds),
      object_set_root: objectSetRoot(objects, V2),
      hosts: semantic.hosts,
      objects,
      claims: { ...CLAIMS_V2 },
      authority: AUTHORITY,
      signature: {}
    };
    capsule.capsule_id = sha256(Buffer.from(V2.capsule + canonicalize(capsuleCore(capsule))));
    capsule.signature = { suite: "Ed25519-v1", key_id: controller.key_id, value: signEd25519(controller.private_key_pkcs8_base64, Buffer.concat([Buffer.from(V2.signature), Buffer.from(capsule.capsule_id, "hex")])) };
    await verifyHostTrustCapsuleValue(capsule, { controllerDid: identity.controller_did, controllerKeyHash: initialHash });
    const body = `${canonicalize(capsule)}\n`;
    if (Buffer.byteLength(body) > MAX_CAPSULE_BYTES) throw new SomaError("host trust capsule exceeds the portable profile bound", 8, "HOST_TRUST_CAPSULE_TOO_LARGE");
    try { await writeNewDurable(target, body); }
    catch (error) { if (error.code === "EEXIST") throw new SomaError("host trust capsule output already exists", 8, "HOST_TRUST_CAPSULE_OUTPUT_EXISTS"); throw error; }
    return { local_mutation: true, remote_mutation: false, output: target, capsule_id: capsule.capsule_id, schema_version: capsule.schema_version, controller_did: identity.controller_did, controller_key_sha256: initialHash, controller_initial_key_sha256: initialHash, controller_active_key_sha256: ed25519MultibaseSha256(controllerPublic.public_key_multibase), controller_rotation_count: rotationIds.length, host_count: capsule.host_count, transition_count: capsule.transition_count, byte_length: Buffer.byteLength(body), authority: AUTHORITY, external_anchor_created: false, restore_authorized: false, network_actions: 0 };
  } finally { eraseSecretBundle(secretBundle); }
}

export async function compareHostTrustCapsules(trustedFile, candidateFile, expected) {
  const trusted = await readCanonicalFile(trustedFile, MAX_CAPSULE_BYTES, "HOST_TRUST_CAPSULE_FILE_INVALID", "trusted host trust capsule");
  const candidate = await readCanonicalFile(candidateFile, MAX_CAPSULE_BYTES, "HOST_TRUST_CAPSULE_FILE_INVALID", "candidate host trust capsule");
  const trustedSummary = await verifyHostTrustCapsuleValue(trusted, expected);
  const candidateSummary = await verifyHostTrustCapsuleValue(candidate, expected);
  if (Date.parse(candidate.created_at) < Date.parse(trusted.created_at)) throw new SomaError("candidate capsule creation time precedes trusted evidence", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");
  if (trustedSummary.schema_version === "somavera.soma-host-trust-capsule.v2" && candidateSummary.schema_version !== "somavera.soma-host-trust-capsule.v2") throw new SomaError("candidate capsule drops trusted controller history", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");
  const trustedRotations = trustedSummary.controller_rotation_ids || [];
  const candidateRotations = candidateSummary.controller_rotation_ids || [];
  if (candidateRotations.length < trustedRotations.length || trustedRotations.some((id, index) => candidateRotations[index] !== id)) throw new SomaError("candidate capsule removes or forks trusted controller history", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");
  if (candidateRotations.length === trustedRotations.length && candidateSummary.controller_active_key_sha256 !== trustedSummary.controller_active_key_sha256) throw new SomaError("candidate capsule changes the active controller without a descendant rotation", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK");
  const candidateHosts = new Map(candidate.hosts.map((host) => [host.host_did, host]));
  for (const prior of trusted.hosts) {
    const next = candidateHosts.get(prior.host_did);
    if (!next || next.transition_ids.length < prior.transition_ids.length || prior.transition_ids.some((id, index) => next.transition_ids[index] !== id)) throw new SomaError("candidate capsule removes or forks trusted host history", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK", { host_did: prior.host_did });
    if (next.transition_ids.length === prior.transition_ids.length && next.current_pin_id !== prior.current_pin_id) throw new SomaError("candidate capsule changes a trusted current pin without a descendant transition", 8, "HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK", { host_did: prior.host_did });
  }
  return { local_mutation: false, remote_mutation: false, trusted_capsule_id: trustedSummary.capsule_id, candidate_capsule_id: candidateSummary.capsule_id, relation: trustedSummary.capsule_id === candidateSummary.capsule_id ? "identical_capsule" : "equal_or_strict_descendant_controller_and_host_trust_state", trusted_controller_rotation_count: trustedSummary.controller_rotation_count, candidate_controller_rotation_count: candidateSummary.controller_rotation_count, trusted_host_count: trustedSummary.host_count, candidate_host_count: candidateSummary.host_count, trusted_transition_count: trustedSummary.transition_count, candidate_transition_count: candidateSummary.transition_count, authority: AUTHORITY, restore_authorized: false, network_actions: 0 };
}
