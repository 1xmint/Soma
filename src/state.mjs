import { randomBytes } from "node:crypto";
import { open as openOnce, mkdir, readFile, readdir, rename as renameOnce, rm, stat, statfs, lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { createInitialKeyMaterial, privateKeyForRole, publicRecordForPrivate } from "./crypto.mjs";
import { defaultSomaHome, RELEASE_ROOT, STATE_DIRECTORIES, VERSION } from "./constants.mjs";
import { SomaError } from "./errors.mjs";
import { protectSecretBundle, unprotectSecretBundle } from "./keystore.mjs";
import { inspectStateRootPermissions, restrictStateRoot } from "./platform.mjs";
import { verifyRelease } from "./release.mjs";
import { canonicalize } from "./canonicalize.mjs";
import { retryTransient } from "./fs-transient.mjs";
import { createInitialEvidenceHead, verifyEvidenceLedger } from "./evidence.mjs";
import { verifyHostPinStore } from "./host.mjs";
import { verifyHostSuccessionCandidateStore } from "./host-succession.mjs";
import { recoverHostSuccessionTransactions, verifyHostSuccessionHistoryStore } from "./host-confirmation.mjs";
import {
  attachPublicKeyHistory,
  controllerRotationStatus,
  initialPublicKeyHistory,
  recoverControllerRotationTransactions,
  verifyPublicKeyHistory
} from "./controller-rotation.mjs";

// See fs-transient.mjs: Windows reports contention as EPERM/EBUSY on the
// exclusive create and on the staging rename that publishes a new home.
const open = (file, flags, mode) => retryTransient(() => openOnce(file, flags, mode));
const rename = (from, to) => retryTransient(() => renameOnce(from, to));

const CONTROL = /[\u0000-\u001f\u007f]/;

function eraseSecretBundle(bundle) {
  if (!bundle) return;
  for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
  if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
  bundle.root_store_key_base64 = "";
}

function comparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function resolveHome(value) {
  if (value && !path.isAbsolute(value)) throw new SomaError("an alternate SOMA_HOME must be absolute", 2, "HOME_PATH_RELATIVE");
  const home = path.resolve(value || defaultSomaHome());
  if (CONTROL.test(home)) throw new SomaError("SOMA_HOME must be an absolute path without control characters", 2, "HOME_PATH_INVALID");
  if (process.platform === "win32" && home.startsWith("\\\\")) throw new SomaError("network-share homes are not supported", 8, "HOME_NETWORK_SHARE_UNSUPPORTED");
  const release = comparable(RELEASE_ROOT) + path.sep;
  const candidate = comparable(home);
  if (candidate === comparable(RELEASE_ROOT) || candidate.startsWith(release)) {
    throw new SomaError("SOMA_HOME must be outside the release tree", 7, "HOME_INSIDE_RELEASE");
  }
  return home;
}

async function writeDurable(file, bytes, mode = 0o600) {
  const handle = await open(file, "wx", mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeJson(file, value) {
  await writeDurable(file, `${JSON.stringify(value, null, 2)}\n`, 0o600);
}

async function exists(file) {
  try {
    await stat(file);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function readJson(file, code) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new SomaError("state JSON is missing or invalid", 7, code, { path: file, cause: error.message });
  }
}

async function assertNoPathIndirection(home) {
  if (!(await exists(home))) return;
  const metadata = await lstat(home);
  if (metadata.isSymbolicLink()) throw new SomaError("SOMA_HOME cannot be a symbolic link", 7, "HOME_SYMLINK");
  const resolved = await realpath(home);
  if (comparable(resolved) !== comparable(home)) throw new SomaError("SOMA_HOME resolves through an unexpected path", 7, "HOME_REALPATH_MISMATCH");
}

async function assertSafeParent(home) {
  let ancestor = path.dirname(home);
  while (!(await exists(ancestor))) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) throw new SomaError("no existing safe ancestor for SOMA_HOME", 7, "HOME_ANCESTOR_MISSING");
    ancestor = parent;
  }
  const resolved = await realpath(ancestor);
  if (comparable(resolved) !== comparable(ancestor)) {
    throw new SomaError("SOMA_HOME parent resolves through a link or reparse point", 7, "HOME_PARENT_INDIRECTION");
  }
}

async function listImmediateFiles(directory) {
  try {
    return (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => entry.name).sort();
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

export async function initialize({ home: requestedHome, label = null, recovery, allowInsecureDevelopment = false }) {
  const home = resolveHome(requestedHome);
  if (!recovery) throw new SomaError("recovery choice is required; use --recovery none", 2, "RECOVERY_CHOICE_REQUIRED");
  if (recovery !== "none") throw new SomaError("offline recovery is unavailable until its cryptographic profile is ratified", 8, "RECOVERY_PROFILE_UNAVAILABLE");
  if (label !== null && (typeof label !== "string" || label.length < 1 || label.length > 120 || CONTROL.test(label))) {
    throw new SomaError("label must contain 1 through 120 safe characters", 2, "LABEL_INVALID");
  }
  const release = await verifyRelease();
  await assertSafeParent(home);
  await assertNoPathIndirection(home);
  if (await exists(home)) {
    const current = await inspectState(home, { verifyReleaseFirst: false });
    if (label !== null && current.config.label !== label) throw new SomaError("existing identity label differs", 7, "INIT_EXISTING_LABEL_MISMATCH");
    return { created: false, local_mutation: false, remote_mutation: false, home, release, ...current.summary };
  }

  await mkdir(path.dirname(home), { recursive: true });
  await assertSafeParent(home);
  const stage = `${home}.init-${randomBytes(8).toString("hex")}`;
  let stageCreated = false;
  let finalCreated = false;
  try {
    await mkdir(stage, { recursive: false, mode: 0o700 });
    stageCreated = true;
    const permissionProfile = await restrictStateRoot(stage);
    for (const relative of STATE_DIRECTORIES) await mkdir(path.join(stage, ...relative.split("/")), { recursive: true, mode: 0o700 });
    const createdAt = new Date().toISOString();
    const { publicIdentity, secretBundle } = createInitialKeyMaterial(createdAt);
    const initialEvidenceHead = createInitialEvidenceHead(secretBundle, createdAt);
    let protectedBundle;
    try {
      protectedBundle = protectSecretBundle(secretBundle, allowInsecureDevelopment);
    } finally {
      eraseSecretBundle(secretBundle);
    }

    const config = {
      schema_version: "somavera.soma-local-config.v1",
      version: VERSION,
      initialized_at: createdAt,
      label,
      recovery_mode: "none",
      enforcement_mode: "integrated_reference",
      observer: { status: "off", active_grants: 0 },
      telemetry: false,
      automatic_updates: false,
      automatic_retries: false,
      background_watchers: false,
      connected_hosts: 0,
      keystore: {
        backend: protectedBundle.backend,
        key_reference: "config/keystore.blob",
        root_store_key_reference: "soma-root-store-key-v1"
      },
      local_encryption: { profile: "AES-256-GCM-per-object-v1", key_reference: "soma-root-store-key-v1" },
      security_degradations: protectedBundle.security_degradation ? [protectedBundle.security_degradation] : []
    };
    await writeJson(path.join(stage, "config", "config.json"), config);
    await writeJson(path.join(stage, "config", "policy.json"), {
      schema_version: "somavera.soma-effective-policy.v1",
      observer_default: "off",
      allowed_remote_actions: [],
      source: "release/defaults/policy.json"
    });
    await writeDurable(path.join(stage, "config", "keystore.blob"), protectedBundle.blob, 0o600);
    protectedBundle.blob.fill(0);
    await writeJson(path.join(stage, "identity", "identity.json"), publicIdentity);
    await writeJson(path.join(stage, "identity", "public-key-history.json"), initialPublicKeyHistory(publicIdentity, createdAt));
    await writeJson(path.join(stage, "identity", "recovery-policy.json"), {
      schema_version: "somavera.soma-recovery-policy.v1",
      mode: "none",
      warning: "Loss of this device key material creates a new identity; continuity is not recoverable."
    });
    await writeDurable(path.join(stage, "evidence", "ledger.jsonl"), "", 0o600);
    await writeDurable(path.join(stage, "evidence", "head.json"), `${canonicalize(initialEvidenceHead)}\n`, 0o600);
    await writeDurable(path.join(stage, "logs", "security.jsonl"), "", 0o600);
    await restrictStateRoot(stage);
    await rename(stage, home);
    stageCreated = false;
    finalCreated = true;
    const summary = await inspectState(home, { verifyReleaseFirst: false });
    return {
      created: true,
      local_mutation: true,
      remote_mutation: false,
      home,
      release,
      permission_profile: permissionProfile.profile,
      ...summary.summary
    };
  } catch (error) {
    if (finalCreated) await rm(home, { recursive: true, force: true });
    else if (stageCreated) await rm(stage, { recursive: true, force: true });
    throw error;
  }
}

async function scanProhibited(home) {
  const matches = [];
  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(home, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) matches.push({ path: relative, reason: "symbolic_link" });
      else if (entry.isDirectory()) await walk(absolute);
      else if (/^(\.env|heart\.secret)$|\.(pem|key|p12|sqlite)$/i.test(entry.name)) matches.push({ path: relative, reason: "prohibited_name" });
    }
  }
  await walk(home);
  return matches;
}

export async function inspectState(requestedHome, { verifyReleaseFirst = true, verifyEvidence = true } = {}) {
  const home = resolveHome(requestedHome);
  const release = verifyReleaseFirst ? await verifyRelease() : null;
  await assertSafeParent(home);
  await assertNoPathIndirection(home);
  if (!(await exists(home))) throw new SomaError("SOMA_HOME is not initialized", 7, "HOME_NOT_INITIALIZED");
  const recoveredControllerRotations = await recoverControllerRotationTransactions(home);
  const [config, identity, history, recoveryPolicy, permissions, prohibited, disk] = await Promise.all([
    readJson(path.join(home, "config", "config.json"), "CONFIG_INVALID"),
    readJson(path.join(home, "identity", "identity.json"), "IDENTITY_INVALID"),
    readJson(path.join(home, "identity", "public-key-history.json"), "KEY_HISTORY_INVALID"),
    readJson(path.join(home, "identity", "recovery-policy.json"), "RECOVERY_POLICY_INVALID"),
    Promise.resolve(inspectStateRootPermissions(home)),
    scanProhibited(home),
    statfs(home)
  ]);
  if (config.schema_version !== "somavera.soma-local-config.v1" || config.observer?.status !== "off" || config.telemetry !== false || config.background_watchers !== false) {
    throw new SomaError("local configuration violates the observer-off baseline", 7, "OBSERVER_OFF_BASELINE_INVALID");
  }
  await verifyPublicKeyHistory(identity, history);
  attachPublicKeyHistory(identity, history);
  const recoveredHostTransitions = await recoverHostSuccessionTransactions(home, identity);
  const hostPins = await verifyHostPinStore(home, identity);
  const hostCandidates = await verifyHostSuccessionCandidateStore(home, identity);
  const hostSuccessionHistory = await verifyHostSuccessionHistoryStore(home, identity);
  if (config.connected_hosts !== 0 || (await listImmediateFiles(path.join(home, "consent", "grants"))).length !== 0 || (await listImmediateFiles(path.join(home, "queue"))).length !== 0) {
    throw new SomaError("baseline contains connected authority, consent, or queued work", 7, "REMOTE_AUTHORITY_BASELINE_INVALID");
  }
  if (identity.schema_version !== "somavera.soma-local-identity.v1" || !Array.isArray(identity.keys) || identity.keys.length !== 4 + history.controller_rotation_sequence) {
    throw new SomaError("public identity has an invalid shape", 7, "IDENTITY_SHAPE_INVALID");
  }
  if (recoveryPolicy.mode !== "none") {
    throw new SomaError("identity or recovery invariants do not hold", 7, "STATE_INVARIANT_INVALID");
  }
  if (!permissions.protected || permissions.owner_matches !== true || permissions.unauthorized_allow_count !== 0 || permissions.unsafe_path_count !== 0) {
    throw new SomaError("state permissions are not owner-only", 7, "STATE_PERMISSIONS_UNSAFE", permissions);
  }
  if (prohibited.length) throw new SomaError("prohibited files exist in SOMA_HOME", 7, "PROHIBITED_STATE_FILE", { matches: prohibited });
  const blob = await readFile(path.join(home, "config", "keystore.blob"));
  const secretBundle = unprotectSecretBundle(config.keystore.backend, blob);
  let secretBundleValid = secretBundle.schema_version === "somavera.soma-secret-bundle.v1" && secretBundle.private_keys?.length === 4 && Buffer.from(secretBundle.root_store_key_base64 || "", "base64").length === 32;
  try {
    const privateController = privateKeyForRole(secretBundle, "controller_signing");
    const publicController = publicRecordForPrivate(privateController, "Ed25519");
    const activeController = identity.keys.find((key) => key.role === "controller_signing" && key.status === "active");
    secretBundleValid = secretBundleValid && publicController.key_id === activeController?.key_id;
  } catch {
    secretBundleValid = false;
  }
  eraseSecretBundle(secretBundle);
  if (!secretBundleValid) throw new SomaError("keystore contents failed integrity checks", 7, "KEYSTORE_CONTENT_INVALID");
  const evidenceVerification = verifyEvidence ? await verifyEvidenceLedger(home) : null;
  const freeBytes = Number(disk.bavail) * Number(disk.bsize);
  if (!Number.isFinite(freeBytes) || freeBytes < 50 * 1024 * 1024) throw new SomaError("insufficient disk headroom", 7, "DISK_HEADROOM_LOW");
  if (Date.now() < Date.parse("2025-01-01T00:00:00Z")) throw new SomaError("system clock is implausibly old", 7, "CLOCK_IMPLAUSIBLE");
  const rotationStatus = await controllerRotationStatus(home);
  const summary = {
    identity: {
      controller_did: identity.controller_did,
      agent_did: identity.agent_did,
      observer_did: identity.observer_did,
      assurance: identity.assurance,
      keys: identity.keys.map(({ role, key_id, algorithm, status }) => ({ role, key_id, algorithm, status }))
    },
    enforcement_mode: config.enforcement_mode,
    observer: config.observer,
    connected_hosts: 0,
    pinned_hosts: hostPins.length,
    pending_host_successions: hostCandidates.length,
    completed_host_successions: hostSuccessionHistory.length,
    recovered_host_transitions: recoveredHostTransitions,
    recovered_controller_rotations: recoveredControllerRotations,
    controller_rotation_sequence: rotationStatus.controller_rotation_sequence,
    controller_rotation_head: rotationStatus.controller_rotation_head,
    active_controller_key_id: rotationStatus.active_controller_key_id,
    pending_controller_rotation: rotationStatus.pending_controller_rotation,
    active_grants: 0,
    queued_items: 0,
    evidence_head: evidenceVerification?.head ?? null,
    evidence_entries: evidenceVerification?.entries ?? null,
    evidence_assurance: evidenceVerification?.assurance ?? "verification_deferred_for_repair",
    independent_truncation_detection: false,
    recovery_mode: recoveryPolicy.mode,
    keystore_backend: config.keystore.backend,
    security_degradations: config.security_degradations
  };
  return { home, release, config, permissions, free_bytes: freeBytes, prohibited_files: prohibited, summary };
}
