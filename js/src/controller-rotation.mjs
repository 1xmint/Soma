import { link, mkdir, open, readFile, readdir, rename as renameOnce, stat, unlink as unlinkOnce } from "node:fs/promises";
import path from "node:path";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { retryTransient } from "./fs-transient.mjs";
import {
  createControllerKeyMaterial,
  ed25519MultibaseSha256,
  privateKeyForRole,
  publicRecordForPrivate,
  sha256,
  signEd25519,
  verifyEd25519
} from "./crypto.mjs";
import { RELEASE_ROOT } from "./constants.mjs";
import { SomaError } from "./errors.mjs";
import { assertJsonSchema } from "./json-schema.mjs";
import { protectSecretBundle, unprotectSecretBundle } from "./keystore.mjs";
import { restrictStatePath, restrictStateRoot } from "./platform.mjs";

// The commit sequence renames and unlinks under concurrent contention, where
// Windows reports transient EPERM/EBUSY. Retrying here costs a failed rotation
// that would otherwise have to be recovered; it never changes which outcome a
// boundary resolves to. `open` is deliberately left unwrapped: acquireLock
// already interprets EPERM/EBUSY itself and must keep its own timing.
const rename = (from, to) => retryTransient(() => renameOnce(from, to));
const unlink = (target) => retryTransient(() => unlinkOnce(target));

export const PROPOSAL_ID_DOMAIN = "somavera:soma-controller-key-rotation-proposal:v1\n";
export const ROTATION_ID_DOMAIN = "somavera:soma-controller-key-rotation:v1\n";
export const PRIOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-prior-signature:v1\n";
export const SUCCESSOR_SIGNATURE_DOMAIN = "somavera:soma-controller-key-rotation-successor-signature:v1\n";
const HASH = /^[a-f0-9]{64}$/;
const MAX_CONFIRMATION_DELAY_MS = 900_000;
const AUTHORITY = Object.freeze({
  authorizes_controller_key_rotation: true,
  authorizes_agent_key_rotation: false,
  authorizes_observer_key_rotation: false,
  authorizes_identity_recovery: false,
  authorizes_emergency_recovery: false,
  authorizes_connection: false,
  authorizes_consent: false,
  authorizes_disclosure: false,
  authorizes_send: false,
  authorizes_token_action: false,
  authorizes_governance: false
});
const DECISION = "replace_online_controller_signing_key_only";
const DISPOSITION = "destroy_after_committed_successor_is_recoverable";
const ROLLBACK = "local_consistency_only_unless_exact_history_is_externally_preserved";
const PROPOSAL_VERSION = "soma.controller-key-rotation-proposal.provisional-v1";
const TRANSACTION_VERSION = "soma.controller-key-rotation-transaction.provisional-v1";
const PENDING_SECRET_VERSION = "soma.controller-key-rotation-pending-secret.provisional-v1";
const TRANSACTION_FIELDS = [
  "schema_version", "prepared_at", "proposal_id", "rotation_id", "prior_identity_sha256",
  "successor_identity_sha256", "prior_history_sha256", "successor_history_sha256",
  "prior_keystore_sha256", "successor_keystore_sha256", "event_sha256", "prior_identity", "prior_history", "event"
];
const PROPOSAL_FIELDS = [
  "schema_version", "profile_status", "proposal_schema_version", "proposal_id", "controller_did",
  "rotation_sequence", "previous_rotation_id", "prior_key", "successor_key", "prepared_at",
  "reason", "decision", "prior_private_key_disposition", "rollback_assurance", "authority"
];

const identityDirectory = (home) => path.join(home, "identity");
const pendingDirectory = (home) => path.join(identityDirectory(home), "pending");
const transactionDirectory = (home) => path.join(identityDirectory(home), "transactions");
const rotationDirectory = (home) => path.join(identityDirectory(home), "rotations");
const pendingProposalFile = (home) => path.join(pendingDirectory(home), "controller-rotation.json");
const pendingSecretFile = (home) => path.join(pendingDirectory(home), "controller-rotation.blob");
const transactionFile = (home) => path.join(transactionDirectory(home), "controller-rotation.json");
const identityTemporary = (home) => path.join(transactionDirectory(home), "controller-rotation.identity.tmp");
const historyTemporary = (home) => path.join(transactionDirectory(home), "controller-rotation.history.tmp");
const keystoreTemporary = (home) => path.join(transactionDirectory(home), "controller-rotation.keystore.tmp");
const priorKeystoreTemporary = (home) => path.join(transactionDirectory(home), "controller-rotation.keystore.prior.tmp");
const eventTemporary = (home) => path.join(transactionDirectory(home), "controller-rotation.event.tmp");
const identityFile = (home) => path.join(identityDirectory(home), "identity.json");
const historyFile = (home) => path.join(identityDirectory(home), "public-key-history.json");
const keystoreFile = (home) => path.join(home, "config", "keystore.blob");
const configFile = (home) => path.join(home, "config", "config.json");
const lockFile = (home) => path.join(home, "run", "controller-rotation.lock");

const exactKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
const fileHash = async (file) => sha256(await readFile(file));
const jsonHash = (value) => sha256(Buffer.from(canonicalize(value), "utf8"));
const publicKey = (value) => ({
  key_id: value.key_id,
  role: "controller_signing",
  suite: "Ed25519-v1",
  public_key_multibase: value.public_key_multibase,
  public_key_sha256: ed25519MultibaseSha256(value.public_key_multibase)
});

async function rotationSchema() {
  return JSON.parse(await readFile(path.join(RELEASE_ROOT, "schemas", "soma-controller-key-rotation.schema.json"), "utf8"));
}

async function durable(file, bytes) {
  const handle = await open(file, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readCanonical(file, label, code) {
  try {
    return parseCanonicalJson(await readFile(file, "utf8"), label);
  } catch (error) {
    if (error.code === "ENOENT") throw error;
    if (error instanceof SomaError) throw new SomaError(`${label} is invalid`, 7, code, { cause_code: error.code });
    throw new SomaError(`${label} is unreadable`, 7, code, { cause: error.message });
  }
}

function erase(bundle) {
  if (!bundle) return;
  for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
  if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
  bundle.root_store_key_base64 = "";
  if (bundle.private_key) bundle.private_key.private_key_pkcs8_base64 = "";
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

async function acquireLock(home, timeoutMs = 120000) {
  const file = lockFile(home);
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      const handle = await open(file, "wx", 0o600);
      try {
        await handle.writeFile(`${process.pid}\n`);
        await handle.sync();
        await restrictStatePath(file);
      } catch (setupError) {
        await handle.close().catch(() => {});
        await unlink(file).catch(() => {});
        throw setupError;
      }
      return async () => {
        await handle.close();
        await unlink(file).catch((error) => { if (error.code !== "ENOENT") throw error; });
      };
    } catch (error) {
      let busy = error.code === "EEXIST";
      if (!busy && ["EPERM", "EBUSY"].includes(error.code)) {
        // Windows reports EPERM/EBUSY from open() while a handle is still
        // closing a lock another writer just unlinked, but stat() already
        // reports ENOENT for that same path. Treating the missing file as
        // "not busy" leaks a raw EPERM to the caller even though the lock is
        // simply being released. Both outcomes are contention: retry until the
        // deadline. Only a stat failure that is not ENOENT is a real denial.
        try { await stat(file); busy = true; }
        catch (statError) { if (statError.code === "ENOENT") busy = true; }
      }
      if (!busy) throw error;
      let owner;
      try { owner = Number((await readFile(file, "utf8")).trim()); } catch {}
      if (Number.isSafeInteger(owner) && owner > 0 && !processAlive(owner)) {
        await unlink(file).catch((failure) => { if (failure.code !== "ENOENT") throw failure; });
        continue;
      }
      if (Date.now() >= deadline) throw new SomaError("controller rotation is busy", 8, "CONTROLLER_ROTATION_BUSY");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

export function controllerRotationProposalCore(value) {
  return {
    schema_version: value.schema_version,
    profile_status: value.profile_status,
    controller_did: value.controller_did,
    rotation_sequence: value.rotation_sequence,
    previous_rotation_id: value.previous_rotation_id,
    prior_key: {
      key_id: value.prior_key.key_id,
      role: value.prior_key.role,
      suite: value.prior_key.suite,
      public_key_multibase: value.prior_key.public_key_multibase,
      public_key_sha256: value.prior_key.public_key_sha256,
      valid_from: value.prior_key.valid_from
    },
    successor_key: {
      key_id: value.successor_key.key_id,
      role: value.successor_key.role,
      suite: value.successor_key.suite,
      public_key_multibase: value.successor_key.public_key_multibase,
      public_key_sha256: value.successor_key.public_key_sha256
    },
    prepared_at: value.prepared_at,
    reason: value.reason,
    decision: value.decision,
    prior_private_key_disposition: value.prior_private_key_disposition,
    rollback_assurance: value.rollback_assurance,
    authority: value.authority
  };
}

export function controllerRotationCore(value) {
  const { $schema, rotation_id, signatures, ...core } = value;
  return core;
}

export const deriveControllerRotationProposalId = (value) =>
  sha256(Buffer.from(PROPOSAL_ID_DOMAIN + canonicalize(controllerRotationProposalCore(value)), "utf8"));
export const deriveControllerRotationId = (value) =>
  sha256(Buffer.from(ROTATION_ID_DOMAIN + canonicalize(controllerRotationCore(value)), "utf8"));

function signatureValid(signature, key, domain, rotationId) {
  return signature?.suite === "Ed25519-v1" &&
    signature.key_id === key.key_id &&
    verifyEd25519(
      key.public_key_multibase,
      Buffer.concat([Buffer.from(domain), Buffer.from(rotationId || "", "hex")]),
      signature.value || ""
    );
}

export async function validateControllerRotation(record, expected, { exitCode = 8 } = {}) {
  const violations = [];
  let schemaError = null;
  try {
    assertJsonSchema(record, await rotationSchema(), { code: "CONTROLLER_ROTATION_SCHEMA_INVALID", label: "controller rotation", exitCode });
  } catch (error) {
    schemaError = exitCode === 7 && error instanceof SomaError && error.exitCode !== 7 ? new SomaError(error.message, 7, error.code, error.details) : error;
  }
  const prior = record.prior_key;
  const successor = record.successor_key;
  if (record.controller_did !== expected.controller_did) violations.push("ROTATION_CONTROLLER_MISMATCH");
  if (record.rotation_sequence !== expected.rotation_sequence) violations.push("ROTATION_SEQUENCE_INVALID");
  if (record.previous_rotation_id !== expected.previous_rotation_id) violations.push("ROTATION_PREDECESSOR_INVALID");
  if (prior.key_id !== expected.prior_key_id ||
      prior.public_key_multibase !== expected.prior_public_key_multibase ||
      prior.public_key_sha256 !== ed25519MultibaseSha256(prior.public_key_multibase) ||
      prior.role !== "controller_signing" || prior.suite !== "Ed25519-v1") violations.push("ROTATION_PRIOR_KEY_INVALID");
  let successorHash = null;
  try { successorHash = ed25519MultibaseSha256(successor.public_key_multibase); } catch {}
  if (!successorHash || successor.key_id === prior.key_id ||
      successor.public_key_multibase === prior.public_key_multibase ||
      successor.public_key_sha256 !== successorHash ||
      successor.role !== "controller_signing" || successor.suite !== "Ed25519-v1") violations.push("ROTATION_SUCCESSOR_KEY_INVALID");
  const prepared = Date.parse(record.prepared_at);
  const effective = Date.parse(record.effective_at);
  if (!Number.isFinite(prepared) || !Number.isFinite(effective) || effective < prepared || effective - prepared > MAX_CONFIRMATION_DELAY_MS) violations.push("ROTATION_TIME_INVALID");
  if (prior.valid_from !== expected.prior_valid_from || prior.valid_until !== record.effective_at ||
      successor.valid_from !== record.effective_at || successor.valid_until !== null) violations.push("ROTATION_KEY_WINDOW_INVALID");
  if (prior.status !== "retired" || successor.status !== "active") violations.push("ROTATION_KEY_STATUS_INVALID");
  if (record.decision !== DECISION) violations.push("ROTATION_DECISION_INVALID");
  if (record.prior_private_key_disposition !== DISPOSITION) violations.push("ROTATION_DISPOSITION_INVALID");
  if (record.rollback_assurance !== ROLLBACK) violations.push("ROTATION_ROLLBACK_ASSURANCE_INVALID");
  if (canonicalize(record.authority) !== canonicalize(AUTHORITY)) violations.push("ROTATION_AUTHORITY_INVALID");
  if (deriveControllerRotationProposalId(record) !== record.proposal_id) violations.push("ROTATION_PROPOSAL_ID_INVALID");
  if (deriveControllerRotationId(record) !== record.rotation_id) violations.push("ROTATION_ID_INVALID");
  if (!signatureValid(record.signatures?.prior, prior, PRIOR_SIGNATURE_DOMAIN, record.rotation_id)) violations.push("ROTATION_PRIOR_SIGNATURE_INVALID");
  if (!signatureValid(record.signatures?.successor, successor, SUCCESSOR_SIGNATURE_DOMAIN, record.rotation_id)) violations.push("ROTATION_SUCCESSOR_SIGNATURE_INVALID");
  const unique = [...new Set(violations)];
  if (unique.length) throw new SomaError("controller-key rotation is invalid", exitCode, "CONTROLLER_ROTATION_INVALID", { violations: unique });
  if (schemaError) throw schemaError;
  return {
    proposal_id: record.proposal_id,
    rotation_id: record.rotation_id,
    controller_did: record.controller_did,
    rotation_sequence: record.rotation_sequence,
    prior_key_id: prior.key_id,
    successor_key_id: successor.key_id,
    successor_key_sha256: successor.public_key_sha256,
    effective_at: record.effective_at
  };
}

export function initialPublicKeyHistory(identity, createdAt) {
  return {
    schema_version: "somavera.soma-public-key-history.v2",
    controller_did: identity.controller_did,
    controller_initial_key_id: identity.keys.find((key) => key.role === "controller_signing").key_id,
    controller_rotation_sequence: 0,
    controller_rotation_head: null,
    entries: identity.keys.map((key) => ({
      key_id: key.key_id,
      role: key.role,
      algorithm: key.algorithm,
      did: key.did,
      public_key_multibase: key.public_key_multibase,
      status: key.status,
      valid_from: createdAt,
      valid_until: null,
      activated_by_rotation_id: null,
      retired_by_rotation_id: null
    })),
    controller_rotations: []
  };
}

export async function verifyPublicKeyHistory(identity, history) {
  if (history?.schema_version !== "somavera.soma-public-key-history.v2" ||
      history.controller_did !== identity.controller_did ||
      !Array.isArray(history.entries) || !Array.isArray(history.controller_rotations) ||
      history.controller_rotation_sequence !== history.controller_rotations.length) {
    throw new SomaError("public key history shape is invalid", 7, "KEY_HISTORY_INVALID");
  }
  const entries = new Map();
  for (const entry of history.entries) {
    if (!entry || entries.has(entry.key_id)) throw new SomaError("public key history duplicates a key", 7, "KEY_HISTORY_INVALID");
    entries.set(entry.key_id, entry);
  }
  if (identity.keys.length !== entries.size) throw new SomaError("identity and public key history differ", 7, "KEY_HISTORY_IDENTITY_MISMATCH");
  for (const key of identity.keys) {
    const entry = entries.get(key.key_id);
    if (!entry || entry.role !== key.role || entry.algorithm !== key.algorithm || entry.did !== key.did ||
        entry.public_key_multibase !== key.public_key_multibase || entry.status !== key.status) {
      throw new SomaError("identity and public key history differ", 7, "KEY_HISTORY_IDENTITY_MISMATCH");
    }
  }
  const initial = entries.get(history.controller_initial_key_id);
  if (!initial || initial.role !== "controller_signing" || initial.activated_by_rotation_id !== null) throw new SomaError("initial controller key is invalid", 7, "KEY_HISTORY_INITIAL_CONTROLLER_INVALID");
  let current = initial;
  let head = null;
  for (let index = 0; index < history.controller_rotations.length; index += 1) {
    const event = history.controller_rotations[index];
    await validateControllerRotation(event, {
      controller_did: identity.controller_did,
      rotation_sequence: index + 1,
      previous_rotation_id: head,
      prior_key_id: current.key_id,
      prior_public_key_multibase: current.public_key_multibase,
      prior_valid_from: current.valid_from
    }, { exitCode: 7 });
    const priorEntry = entries.get(event.prior_key.key_id);
    const successorEntry = entries.get(event.successor_key.key_id);
    if (!priorEntry || !successorEntry ||
        priorEntry.valid_until !== event.effective_at || priorEntry.status !== "retired" || priorEntry.retired_by_rotation_id !== event.rotation_id ||
        successorEntry.valid_from !== event.effective_at ||
        successorEntry.activated_by_rotation_id !== event.rotation_id) {
      throw new SomaError("rotation event and public key intervals differ", 7, "KEY_HISTORY_ROTATION_MISMATCH");
    }
    current = successorEntry;
    head = event.rotation_id;
  }
  if (history.controller_rotation_head !== head || current.status !== "active") throw new SomaError("controller history head is invalid", 7, "KEY_HISTORY_HEAD_INVALID");
  const activeControllers = [...entries.values()].filter((entry) => entry.role === "controller_signing" && entry.status === "active");
  if (activeControllers.length !== 1 || activeControllers[0].key_id !== current.key_id) throw new SomaError("controller key activity is ambiguous", 7, "KEY_HISTORY_ACTIVE_CONTROLLER_INVALID");
  return { rotation_sequence: history.controller_rotation_sequence, rotation_head: head, active_controller_key_id: current.key_id };
}

export function attachPublicKeyHistory(identity, history) {
  Object.defineProperty(identity, "key_history", { value: history, enumerable: false, configurable: false });
  return identity;
}

export function controllerSigningKeyAt(identity, keyId, timestamp) {
  const key = identity.keys?.find((entry) => entry.role === "controller_signing" && entry.key_id === keyId && (entry.algorithm === "Ed25519-v1" || entry.algorithm === undefined));
  const interval = identity.key_history?.entries?.find((entry) => entry.role === "controller_signing" && entry.key_id === keyId);
  if (!key) return null;
  if (!interval) return key.status === "active" ? key : null;
  const at = Number(timestamp);
  const from = Date.parse(interval.valid_from);
  const until = interval.valid_until === null ? null : Date.parse(interval.valid_until);
  return Number.isFinite(at) && at >= from && (until === null || at < until) ? key : null;
}

function proposalFromState(identity, history, successor, preparedAt, reason) {
  const active = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
  const interval = history.entries.find((entry) => entry.key_id === active.key_id);
  const next = publicKey(successor.publicRecord);
  const proposal = {
    schema_version: "somavera.soma-controller-key-rotation.v1",
    profile_status: "freeze_blocking_draft",
    proposal_schema_version: PROPOSAL_VERSION,
    proposal_id: "0".repeat(64),
    controller_did: identity.controller_did,
    rotation_sequence: history.controller_rotation_sequence + 1,
    previous_rotation_id: history.controller_rotation_head,
    prior_key: { ...publicKey(active), valid_from: interval.valid_from },
    successor_key: next,
    prepared_at: preparedAt,
    reason,
    decision: DECISION,
    prior_private_key_disposition: DISPOSITION,
    rollback_assurance: ROLLBACK,
    authority: AUTHORITY
  };
  proposal.proposal_id = deriveControllerRotationProposalId(proposal);
  return proposal;
}

function validateProposal(proposal, identity, history) {
  if (!exactKeys(proposal, PROPOSAL_FIELDS) || proposal.proposal_schema_version !== PROPOSAL_VERSION ||
      proposal.schema_version !== "somavera.soma-controller-key-rotation.v1" || proposal.profile_status !== "freeze_blocking_draft" ||
      proposal.controller_did !== identity.controller_did ||
      proposal.rotation_sequence !== history.controller_rotation_sequence + 1 ||
      proposal.previous_rotation_id !== history.controller_rotation_head ||
      proposal.decision !== DECISION || proposal.prior_private_key_disposition !== DISPOSITION ||
      proposal.rollback_assurance !== ROLLBACK || canonicalize(proposal.authority) !== canonicalize(AUTHORITY) ||
      deriveControllerRotationProposalId(proposal) !== proposal.proposal_id) {
    throw new SomaError("pending controller rotation proposal is invalid", 7, "CONTROLLER_ROTATION_PROPOSAL_INVALID");
  }
  const active = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
  const interval = history.entries.find((entry) => entry.key_id === active?.key_id);
  if (!active || !interval || proposal.prior_key.key_id !== active.key_id ||
      proposal.prior_key.public_key_multibase !== active.public_key_multibase ||
      proposal.prior_key.valid_from !== interval.valid_from ||
      proposal.successor_key.key_id === active.key_id) {
    throw new SomaError("pending proposal does not descend from the active controller", 7, "CONTROLLER_ROTATION_PROPOSAL_STALE");
  }
  const prepared = Date.parse(proposal.prepared_at);
  if (!Number.isFinite(prepared) || Date.now() - prepared > MAX_CONFIRMATION_DELAY_MS || Date.now() < prepared) {
    throw new SomaError("pending controller rotation proposal has expired", 8, "CONTROLLER_ROTATION_PROPOSAL_EXPIRED");
  }
  return proposal;
}

async function publicState(home) {
  const [identity, history] = await Promise.all([
    readFile(identityFile(home), "utf8").then(JSON.parse).catch((error) => { throw new SomaError("public identity is invalid", 7, "IDENTITY_INVALID", { cause: error.message }); }),
    readFile(historyFile(home), "utf8").then(JSON.parse).catch((error) => { throw new SomaError("public key history is invalid", 7, "KEY_HISTORY_INVALID", { cause: error.message }); })
  ]);
  await verifyPublicKeyHistory(identity, history);
  attachPublicKeyHistory(identity, history);
  return { identity, history };
}

async function secretState(home) {
  const config = JSON.parse(await readFile(configFile(home), "utf8"));
  return {
    config,
    bundle: unprotectSecretBundle(config.keystore.backend, await readFile(keystoreFile(home)))
  };
}

async function pending(home, identity, history) {
  const proposal = await readCanonical(pendingProposalFile(home), "pending controller rotation proposal", "CONTROLLER_ROTATION_PROPOSAL_INVALID");
  validateProposal(proposal, identity, history);
  return proposal;
}

function eventFromProposal(proposal, effectiveAt, priorPrivate, successorPrivate) {
  const event = {
    $schema: "../schemas/soma-controller-key-rotation.schema.json",
    schema_version: proposal.schema_version,
    profile_status: proposal.profile_status,
    rotation_id: "0".repeat(64),
    proposal_id: proposal.proposal_id,
    controller_did: proposal.controller_did,
    rotation_sequence: proposal.rotation_sequence,
    previous_rotation_id: proposal.previous_rotation_id,
    prior_key: { ...proposal.prior_key, valid_until: effectiveAt, status: "retired" },
    successor_key: { ...proposal.successor_key, valid_from: effectiveAt, valid_until: null, status: "active" },
    prepared_at: proposal.prepared_at,
    effective_at: effectiveAt,
    reason: proposal.reason,
    decision: proposal.decision,
    prior_private_key_disposition: proposal.prior_private_key_disposition,
    rollback_assurance: proposal.rollback_assurance,
    authority: proposal.authority,
    signatures: {}
  };
  event.rotation_id = deriveControllerRotationId(event);
  const message = (domain) => Buffer.concat([Buffer.from(domain), Buffer.from(event.rotation_id, "hex")]);
  event.signatures = {
    prior: { suite: "Ed25519-v1", key_id: priorPrivate.key_id, value: signEd25519(priorPrivate.private_key_pkcs8_base64, message(PRIOR_SIGNATURE_DOMAIN)) },
    successor: { suite: "Ed25519-v1", key_id: successorPrivate.key_id, value: signEd25519(successorPrivate.private_key_pkcs8_base64, message(SUCCESSOR_SIGNATURE_DOMAIN)) }
  };
  return event;
}

function successorPublicState(identity, history, event) {
  const nextIdentity = structuredClone(identity);
  for (const key of nextIdentity.keys) if (key.role === "controller_signing" && key.status === "active") key.status = "retired";
  nextIdentity.keys.push({
    role: "controller_signing",
    algorithm: "Ed25519-v1",
    did: event.successor_key.key_id.split("#")[0],
    key_id: event.successor_key.key_id,
    public_key_multibase: event.successor_key.public_key_multibase,
    status: "active"
  });
  const nextHistory = structuredClone(history);
  const prior = nextHistory.entries.find((entry) => entry.key_id === event.prior_key.key_id);
  prior.status = "retired";
  prior.valid_until = event.effective_at;
  prior.retired_by_rotation_id = event.rotation_id;
  const publicRecord = nextIdentity.keys.find((key) => key.key_id === event.successor_key.key_id);
  nextHistory.entries.push({
    ...publicRecord,
    valid_from: event.effective_at,
    valid_until: null,
    activated_by_rotation_id: event.rotation_id,
    retired_by_rotation_id: null
  });
  nextHistory.controller_rotation_sequence = event.rotation_sequence;
  nextHistory.controller_rotation_head = event.rotation_id;
  nextHistory.controller_rotations.push(event);
  return { identity: nextIdentity, history: nextHistory };
}

function successorSecretState(bundle, successorPrivate) {
  const next = structuredClone(bundle);
  const index = next.private_keys.findIndex((key) => key.role === "controller_signing");
  if (index < 0) throw new SomaError("controller private key is unavailable", 7, "SIGNING_KEY_UNAVAILABLE");
  next.private_keys[index] = structuredClone(successorPrivate);
  return next;
}

async function publishEvent(home, event) {
  await mkdir(rotationDirectory(home), { recursive: true, mode: 0o700 });
  const destination = path.join(rotationDirectory(home), `${String(event.rotation_sequence).padStart(12, "0")}-${event.rotation_id}.json`);
  try {
    await link(eventTemporary(home), destination);
  } catch (error) {
    if (!["EEXIST", "ENOENT"].includes(error.code)) throw error;
    let existing;
    try { existing = await readCanonical(destination, "stored controller rotation", "CONTROLLER_ROTATION_HISTORY_INVALID"); }
    catch (readError) {
      if (error.code === "ENOENT" && readError.code === "ENOENT") throw new SomaError("committed rotation event bytes are unavailable", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
      throw readError;
    }
    if (canonicalize(existing) !== canonicalize(event)) throw new SomaError("competing controller rotation history exists", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
  }
  await unlink(eventTemporary(home)).catch((error) => { if (error.code !== "ENOENT") throw error; });
}

async function validateKeystoreTransition(home, priorBytes, successorBytes, event) {
  const config = JSON.parse(await readFile(configFile(home), "utf8"));
  let priorBundle;
  let successorBundle;
  try {
    priorBundle = unprotectSecretBundle(config.keystore.backend, priorBytes);
    successorBundle = unprotectSecretBundle(config.keystore.backend, successorBytes);
    const priorController = publicRecordForPrivate(privateKeyForRole(priorBundle, "controller_signing"), "Ed25519");
    const successorController = publicRecordForPrivate(privateKeyForRole(successorBundle, "controller_signing"), "Ed25519");
    const withoutController = (bundle) => ({
      schema_version: bundle.schema_version,
      created_at: bundle.created_at,
      root_store_key_base64: bundle.root_store_key_base64,
      private_keys: bundle.private_keys.filter((key) => key.role !== "controller_signing").sort((a, b) => a.role.localeCompare(b.role))
    });
    if (priorBundle.private_keys?.length !== 4 || successorBundle.private_keys?.length !== 4 ||
        priorController.key_id !== event.prior_key.key_id ||
        priorController.public_key_multibase !== event.prior_key.public_key_multibase ||
        successorController.key_id !== event.successor_key.key_id ||
        successorController.public_key_multibase !== event.successor_key.public_key_multibase ||
        canonicalize(withoutController(priorBundle)) !== canonicalize(withoutController(successorBundle))) {
      throw new SomaError("keystore transition changed material outside the exact controller successor", 7, "CONTROLLER_ROTATION_KEYSTORE_MISMATCH");
    }
  } finally {
    erase(priorBundle);
    erase(successorBundle);
  }
}

async function finalizeCommitted(home, transaction) {
  const priorKeystoreBytes = await readFile(priorKeystoreTemporary(home)).catch((error) => {
    if (error.code === "ENOENT") throw new SomaError("protected prior keystore proof is unavailable", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
    throw error;
  });
  if (sha256(priorKeystoreBytes) !== transaction.prior_keystore_sha256) throw new SomaError("protected prior keystore proof differs", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
  const currentKeystoreBytes = await readFile(keystoreFile(home));
  const currentKeystoreHash = sha256(currentKeystoreBytes);
  let successorKeystoreBytes;
  if (currentKeystoreHash === transaction.successor_keystore_sha256) successorKeystoreBytes = currentKeystoreBytes;
  else if (currentKeystoreHash === transaction.prior_keystore_sha256) {
    successorKeystoreBytes = await readFile(keystoreTemporary(home)).catch((error) => {
      if (error.code === "ENOENT") throw new SomaError("protected successor keystore is unavailable", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
      throw error;
    });
    if (sha256(successorKeystoreBytes) !== transaction.successor_keystore_sha256) throw new SomaError("protected successor keystore differs", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
  } else {
    throw new SomaError("controller keystore is neither prior nor successor", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
  }
  await validateKeystoreTransition(home, priorKeystoreBytes, successorKeystoreBytes, transaction.event);
  const finish = async (target, temporary, priorHash, successorHash, label, validateSuccessor = null) => {
    const current = await fileHash(target);
    if (current === successorHash) {
      if (validateSuccessor) await validateSuccessor(await readFile(target));
      await unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
      return;
    }
    if (current !== priorHash) throw new SomaError(`${label} is neither prior nor successor`, 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
    if (await fileHash(temporary) !== successorHash) throw new SomaError(`${label} successor bytes are unavailable`, 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
    if (validateSuccessor) await validateSuccessor(await readFile(temporary));
    await rename(temporary, target);
  };
  await finish(historyFile(home), historyTemporary(home), transaction.prior_history_sha256, transaction.successor_history_sha256, "public key history");
  await finish(keystoreFile(home), keystoreTemporary(home), transaction.prior_keystore_sha256, transaction.successor_keystore_sha256, "controller keystore", (bytes) => validateKeystoreTransition(home, priorKeystoreBytes, bytes, transaction.event));
  await publishEvent(home, transaction.event);
  await unlink(priorKeystoreTemporary(home));
  await unlink(pendingProposalFile(home)).catch((error) => { if (error.code !== "ENOENT") throw error; });
  await unlink(pendingSecretFile(home)).catch((error) => { if (error.code !== "ENOENT") throw error; });
  await unlink(transactionFile(home));
  await unlink(identityTemporary(home)).catch((error) => { if (error.code !== "ENOENT") throw error; });
}

async function validateTransaction(home, transaction) {
  if (!exactKeys(transaction, TRANSACTION_FIELDS) || transaction.schema_version !== TRANSACTION_VERSION ||
      transaction.proposal_id !== transaction.event?.proposal_id || transaction.rotation_id !== transaction.event?.rotation_id ||
      transaction.event_sha256 !== jsonHash(transaction.event) ||
      transaction.prior_identity_sha256 !== jsonHash(transaction.prior_identity)) {
    throw new SomaError("controller rotation transaction is invalid", 7, "CONTROLLER_ROTATION_TRANSACTION_INVALID");
  }
  await verifyPublicKeyHistory(transaction.prior_identity, transaction.prior_history);
  const active = transaction.prior_identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
  const interval = transaction.prior_history.entries.find((entry) => entry.key_id === active?.key_id);
  await validateControllerRotation(transaction.event, {
    controller_did: transaction.prior_identity.controller_did,
    rotation_sequence: transaction.prior_history.controller_rotation_sequence + 1,
    previous_rotation_id: transaction.prior_history.controller_rotation_head,
    prior_key_id: active?.key_id,
    prior_public_key_multibase: active?.public_key_multibase,
    prior_valid_from: interval?.valid_from
  }, { exitCode: 7 });
  const successor = successorPublicState(transaction.prior_identity, transaction.prior_history, transaction.event);
  if (transaction.successor_identity_sha256 !== jsonHash(successor.identity) ||
      transaction.successor_history_sha256 !== sha256(Buffer.from(canonicalize(successor.history) + "\n"))) {
    throw new SomaError("controller rotation transaction successor projection is invalid", 7, "CONTROLLER_ROTATION_TRANSACTION_INVALID");
  }
  return readFile(identityFile(home), "utf8").then(JSON.parse).catch((error) => {
    throw new SomaError("public identity is invalid", 7, "IDENTITY_INVALID", { cause: error.message });
  });
}

export async function recoverControllerRotationTransactions(home) {
  await mkdir(pendingDirectory(home), { recursive: true, mode: 0o700 });
  await mkdir(transactionDirectory(home), { recursive: true, mode: 0o700 });
  await mkdir(rotationDirectory(home), { recursive: true, mode: 0o700 });
  const entries = await readdir(transactionDirectory(home));
  if (!entries.length) {
    const pendingEntries = await readdir(pendingDirectory(home));
    const allowedPending = new Set(["controller-rotation.json", "controller-rotation.blob"]);
    if (pendingEntries.some((name) => !allowedPending.has(name))) throw new SomaError("controller rotation pending store is ambiguous", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
    if (pendingEntries.length === 1) {
      await unlink(path.join(pendingDirectory(home), pendingEntries[0]));
      return [{ recovery: "removed_incomplete_non_authoritative_proposal" }];
    }
    return [];
  }
  const allowed = new Set([
    "controller-rotation.json", "controller-rotation.identity.tmp", "controller-rotation.history.tmp",
    "controller-rotation.keystore.tmp", "controller-rotation.keystore.prior.tmp", "controller-rotation.event.tmp"
  ]);
  if (entries.some((name) => !allowed.has(name)) || !entries.includes("controller-rotation.json")) {
    throw new SomaError("controller rotation transaction store is ambiguous", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS", { entries: entries.sort() });
  }
  const transaction = await readCanonical(transactionFile(home), "controller rotation transaction", "CONTROLLER_ROTATION_TRANSACTION_INVALID");
  const current = await validateTransaction(home, transaction);
  const currentHash = jsonHash(current);
  if (currentHash === transaction.prior_identity_sha256) {
    for (const file of [identityTemporary(home), historyTemporary(home), keystoreTemporary(home), priorKeystoreTemporary(home), eventTemporary(home), transactionFile(home)]) {
      await unlink(file).catch((error) => { if (error.code !== "ENOENT") throw error; });
    }
    return [{ proposal_id: transaction.proposal_id, rotation_id: transaction.rotation_id, recovery: "rolled_back_before_identity_commit" }];
  }
  if (currentHash === transaction.successor_identity_sha256) {
    await finalizeCommitted(home, transaction);
    return [{ proposal_id: transaction.proposal_id, rotation_id: transaction.rotation_id, recovery: "finalized_after_identity_commit" }];
  }
  throw new SomaError("current identity is neither the transaction prior nor successor", 7, "CONTROLLER_ROTATION_RECOVERY_AMBIGUOUS");
}

export async function previewControllerRotation(home, reason) {
  if (typeof reason !== "string" || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw new SomaError("rotation reason must contain 1 through 256 safe characters", 2, "CONTROLLER_ROTATION_REASON_INVALID");
  }
  const release = await acquireLock(home);
  let mustSeal = false;
  try {
    if ((await recoverControllerRotationTransactions(home)).length) mustSeal = true;
    const { identity, history } = await publicState(home);
    try {
      const existing = await pending(home, identity, history);
      if (existing.reason !== reason) throw new SomaError("a different controller rotation proposal is pending", 8, "CONTROLLER_ROTATION_PROPOSAL_CONFLICT");
      return { local_mutation: false, remote_mutation: false, idempotent: true, ...proposalSummary(existing), network_actions: 0 };
    } catch (error) {
      if (error.code === "CONTROLLER_ROTATION_PROPOSAL_EXPIRED") {
        mustSeal = true;
        await unlink(pendingProposalFile(home)).catch(() => {});
        await unlink(pendingSecretFile(home)).catch(() => {});
      } else if (error.code !== "ENOENT") throw error;
    }
    const successor = createControllerKeyMaterial();
    const preparedAt = new Date().toISOString();
    const proposal = proposalFromState(identity, history, successor, preparedAt, reason);
    const config = JSON.parse(await readFile(configFile(home), "utf8"));
    let protectedPending;
    try {
      protectedPending = protectSecretBundle({
        schema_version: PENDING_SECRET_VERSION,
        proposal_id: proposal.proposal_id,
        private_key: successor.privateRecord
      }, config.keystore.backend === "development-plaintext-file-v1");
      if (protectedPending.backend !== config.keystore.backend) throw new SomaError("pending key store backend differs from the active keystore", 7, "CONTROLLER_ROTATION_KEYSTORE_MISMATCH");
      mustSeal = true;
      await durable(pendingSecretFile(home), protectedPending.blob);
      await durable(pendingProposalFile(home), `${canonicalize(proposal)}\n`);
    } catch (error) {
      await unlink(pendingSecretFile(home)).catch(() => {});
      throw error;
    } finally {
      successor.privateRecord.private_key_pkcs8_base64 = "";
      protectedPending?.blob?.fill(0);
    }
    return { local_mutation: true, remote_mutation: false, idempotent: false, ...proposalSummary(proposal), network_actions: 0 };
  } finally {
    try { if (mustSeal) await restrictStateRoot(home); } finally { await release(); }
  }
}

function proposalSummary(proposal) {
  return {
    proposal_id: proposal.proposal_id,
    controller_did: proposal.controller_did,
    rotation_sequence: proposal.rotation_sequence,
    previous_rotation_id: proposal.previous_rotation_id,
    prior_key_id: proposal.prior_key.key_id,
    prior_key_sha256: proposal.prior_key.public_key_sha256,
    successor_key_id: proposal.successor_key.key_id,
    successor_key_sha256: proposal.successor_key.public_key_sha256,
    prepared_at: proposal.prepared_at,
    expires_at: new Date(Date.parse(proposal.prepared_at) + MAX_CONFIRMATION_DELAY_MS).toISOString(),
    reason: proposal.reason,
    decision: proposal.decision,
    prior_private_key_disposition: proposal.prior_private_key_disposition,
    rollback_assurance: proposal.rollback_assurance,
    authority: proposal.authority
  };
}

export async function confirmControllerRotation(home, {
  proposalId,
  successorKeyHash,
  confirmControllerRotation,
  faultAt = null
}) {
  if (!confirmControllerRotation) throw new SomaError("explicit controller rotation confirmation is required", 9, "CONTROLLER_ROTATION_CONFIRMATION_REQUIRED");
  if (!HASH.test(proposalId || "") || !HASH.test(successorKeyHash || "")) throw new SomaError("exact proposal and successor key hashes are required", 2, "CONTROLLER_ROTATION_CONFIRMATION_INPUT_INVALID");
  const release = await acquireLock(home);
  let mustSeal = false;
  let currentBundle;
  let pendingBundle;
  let nextBundle;
  let protectedNext;
  try {
    if ((await recoverControllerRotationTransactions(home)).length) mustSeal = true;
    const { identity, history } = await publicState(home);
    let proposal;
    try {
      proposal = await pending(home, identity, history);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const completed = history.controller_rotations.at(-1);
      if (completed?.proposal_id !== proposalId) throw new SomaError("no matching controller rotation proposal is pending or committed", 8, "CONTROLLER_ROTATION_PROPOSAL_MISMATCH");
      if (completed.successor_key.public_key_sha256 !== successorKeyHash) throw new SomaError("committed successor key hash differs", 8, "CONTROLLER_ROTATION_SUCCESSOR_MISMATCH");
      const active = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
      if (active?.key_id !== completed.successor_key.key_id || history.controller_rotation_head !== completed.rotation_id) throw new SomaError("committed rotation is not the current controller head", 7, "CONTROLLER_ROTATION_HISTORY_INVALID");
      return {
        local_mutation: false,
        remote_mutation: false,
        committed: true,
        idempotent: true,
        proposal_id: completed.proposal_id,
        rotation_id: completed.rotation_id,
        controller_did: completed.controller_did,
        rotation_sequence: completed.rotation_sequence,
        prior_key_id: completed.prior_key.key_id,
        successor_key_id: completed.successor_key.key_id,
        successor_key_sha256: completed.successor_key.public_key_sha256,
        effective_at: completed.effective_at,
        prior_private_key_retained: false,
        independent_rollback_assurance: false,
        network_actions: 0
      };
    }
    if (proposal.proposal_id !== proposalId) throw new SomaError("confirmed proposal ID differs from pending state", 8, "CONTROLLER_ROTATION_PROPOSAL_MISMATCH");
    if (proposal.successor_key.public_key_sha256 !== successorKeyHash) throw new SomaError("confirmed successor key hash differs from pending state", 8, "CONTROLLER_ROTATION_SUCCESSOR_MISMATCH");
    const { config, bundle } = await secretState(home);
    currentBundle = bundle;
    const pendingBlob = await readFile(pendingSecretFile(home));
    pendingBundle = unprotectSecretBundle(config.keystore.backend, pendingBlob);
    if (pendingBundle.schema_version !== PENDING_SECRET_VERSION || pendingBundle.proposal_id !== proposal.proposal_id || !pendingBundle.private_key) {
      throw new SomaError("protected pending controller key is invalid", 7, "CONTROLLER_ROTATION_PENDING_KEY_INVALID");
    }
    const successorPublic = publicRecordForPrivate(pendingBundle.private_key, "Ed25519");
    if (successorPublic.key_id !== proposal.successor_key.key_id ||
        successorPublic.public_key_multibase !== proposal.successor_key.public_key_multibase) {
      throw new SomaError("protected pending key does not match the proposal", 7, "CONTROLLER_ROTATION_PENDING_KEY_MISMATCH");
    }
    const priorPrivate = privateKeyForRole(currentBundle, "controller_signing");
    const active = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
    if (priorPrivate.key_id !== active.key_id) throw new SomaError("active controller public and private keys differ", 7, "CONTROLLER_ROTATION_KEYSTORE_MISMATCH");
    const effectiveAt = new Date().toISOString();
    const event = eventFromProposal(proposal, effectiveAt, priorPrivate, pendingBundle.private_key);
    await validateControllerRotation(event, {
      controller_did: identity.controller_did,
      rotation_sequence: proposal.rotation_sequence,
      previous_rotation_id: proposal.previous_rotation_id,
      prior_key_id: active.key_id,
      prior_public_key_multibase: active.public_key_multibase,
      prior_valid_from: proposal.prior_key.valid_from
    });
    const next = successorPublicState(identity, history, event);
    await verifyPublicKeyHistory(next.identity, next.history);
    nextBundle = successorSecretState(currentBundle, pendingBundle.private_key);
    protectedNext = protectSecretBundle(nextBundle, config.keystore.backend === "development-plaintext-file-v1");
    if (protectedNext.backend !== config.keystore.backend) throw new SomaError("successor keystore backend differs", 7, "CONTROLLER_ROTATION_KEYSTORE_MISMATCH");
    const priorIdentityHash = jsonHash(identity);
    const successorIdentityHash = jsonHash(next.identity);
    const priorHistoryHash = await fileHash(historyFile(home));
    const successorHistoryHash = sha256(Buffer.from(canonicalize(next.history) + "\n"));
    const priorKeystoreBytes = await readFile(keystoreFile(home));
    const priorKeystoreHash = sha256(priorKeystoreBytes);
    const successorKeystoreHash = sha256(protectedNext.blob);
    await validateKeystoreTransition(home, priorKeystoreBytes, protectedNext.blob, event);
    const transaction = {
      schema_version: TRANSACTION_VERSION,
      prepared_at: effectiveAt,
      proposal_id: event.proposal_id,
      rotation_id: event.rotation_id,
      prior_identity_sha256: priorIdentityHash,
      successor_identity_sha256: successorIdentityHash,
      prior_history_sha256: priorHistoryHash,
      successor_history_sha256: successorHistoryHash,
      prior_keystore_sha256: priorKeystoreHash,
      successor_keystore_sha256: successorKeystoreHash,
      event_sha256: jsonHash(event),
      prior_identity: structuredClone(identity),
      prior_history: structuredClone(history),
      event
    };
    mustSeal = true;
    await durable(identityTemporary(home), `${canonicalize(next.identity)}\n`);
    await durable(historyTemporary(home), `${canonicalize(next.history)}\n`);
    await durable(keystoreTemporary(home), protectedNext.blob);
    await durable(priorKeystoreTemporary(home), priorKeystoreBytes);
    priorKeystoreBytes.fill(0);
    await durable(eventTemporary(home), `${canonicalize(event)}\n`);
    await durable(transactionFile(home), `${canonicalize(transaction)}\n`);
    if (faultAt === "after_transaction") throw new SomaError("controller rotation fault injected", 8, "CONTROLLER_ROTATION_FAULT_INJECTED");
    await rename(identityTemporary(home), identityFile(home));
    if (faultAt === "after_identity_commit") throw new SomaError("controller rotation fault injected", 8, "CONTROLLER_ROTATION_FAULT_INJECTED");
    await rename(historyTemporary(home), historyFile(home));
    if (faultAt === "after_history_commit") throw new SomaError("controller rotation fault injected", 8, "CONTROLLER_ROTATION_FAULT_INJECTED");
    await rename(keystoreTemporary(home), keystoreFile(home));
    if (faultAt === "after_keystore_commit") throw new SomaError("controller rotation fault injected", 8, "CONTROLLER_ROTATION_FAULT_INJECTED");
    await publishEvent(home, event);
    if (faultAt === "after_history_published") throw new SomaError("controller rotation fault injected", 8, "CONTROLLER_ROTATION_FAULT_INJECTED");
    await unlink(priorKeystoreTemporary(home));
    await unlink(pendingProposalFile(home));
    await unlink(pendingSecretFile(home));
    await unlink(transactionFile(home));
    return {
      local_mutation: true,
      remote_mutation: false,
      committed: true,
      ...await validateControllerRotation(event, {
        controller_did: identity.controller_did,
        rotation_sequence: proposal.rotation_sequence,
        previous_rotation_id: proposal.previous_rotation_id,
        prior_key_id: active.key_id,
        prior_public_key_multibase: active.public_key_multibase,
        prior_valid_from: proposal.prior_key.valid_from
      }),
      prior_private_key_retained: false,
      independent_rollback_assurance: false,
      network_actions: 0
    };
  } finally {
    erase(currentBundle);
    erase(pendingBundle);
    erase(nextBundle);
    protectedNext?.blob?.fill(0);
    try { if (mustSeal) await restrictStateRoot(home); } finally { await release(); }
  }
}

export async function controllerRotationStatus(home) {
  const { identity, history } = await publicState(home);
  let proposal = null;
  try { proposal = { ...proposalSummary(await pending(home, identity, history)), status: "pending_current" }; }
  catch (error) {
    if (error.code === "CONTROLLER_ROTATION_PROPOSAL_EXPIRED") {
      proposal = { ...proposalSummary(await readCanonical(pendingProposalFile(home), "pending controller rotation proposal", "CONTROLLER_ROTATION_PROPOSAL_INVALID")), status: "expired_inert" };
    } else if (error.code !== "ENOENT") throw error;
  }
  return {
    controller_did: identity.controller_did,
    controller_rotation_sequence: history.controller_rotation_sequence,
    controller_rotation_head: history.controller_rotation_head,
    active_controller_key_id: history.entries.find((entry) => entry.role === "controller_signing" && entry.status === "active").key_id,
    pending_controller_rotation: proposal,
    completed_controller_rotations: history.controller_rotations.length,
    independent_rollback_assurance: false,
    network_actions: 0
  };
}
