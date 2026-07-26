import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ORIGIN_CAPSULE_HASH } from "../src/host.mjs";

const somaRoot = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const repositoryRoot = path.resolve(somaRoot, "..");
const rootLockFile = path.join(repositoryRoot, "ORIGIN-LOCK.json");
const releaseLockFile = path.join(somaRoot, "release", "origin-lock.json");
const HASH = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const TOP_LEVEL_KEYS = [
  "binding_assurance",
  "implementation_scope",
  "locked_imports",
  "origin_capsule_manifest_version",
  "origin_capsule_root",
  "origin_git_commit",
  "origin_status",
  "production_claim_authorized",
  "schema_version",
  "token_activation_authorized"
].sort();
const IMPORT_KEYS = ["local_path", "origin_path", "sha256"].sort();

const exactKeys = (value, expected) =>
  value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("\0") === expected.join("\0");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
function safeRelative(value, label) {
  if (typeof value !== "string") fail(`${label} path is not a string`);
  const normalized = value.replaceAll("\\", "/");
  if (normalized !== value || path.posix.normalize(normalized) !== normalized ||
      normalized.startsWith("/") || normalized.startsWith("../") || normalized.includes("/../")) fail(`unsafe ${label} path: ${value}`);
  return normalized;
}

function fail(message) {
  throw new Error(`Origin lock verification failed: ${message}`);
}

const rootBytes = await readFile(rootLockFile);
const releaseBytes = await readFile(releaseLockFile);
if (!rootBytes.equals(releaseBytes)) fail("repository and packaged lock bytes differ");

let lock;
try { lock = JSON.parse(rootBytes.toString("utf8")); }
catch (error) { fail(`lock is invalid JSON (${error.message})`); }
const normalizedLock = Buffer.from(`${JSON.stringify(lock, null, 2)}\n`);
if (!rootBytes.equals(normalizedLock)) fail("lock is not deterministic pretty JSON or contains duplicate fields");

if (!exactKeys(lock, TOP_LEVEL_KEYS)) fail("top-level fields differ from the v2 contract");
if (lock.schema_version !== "somavera.reference-origin-lock.v2") fail("schema version is unsupported");
if (lock.origin_status !== "draft_not_ratified") fail("Origin status is overstated");
if (!COMMIT.test(lock.origin_git_commit)) fail("Origin commit is not a full Git object ID");
if (!HASH.test(lock.origin_capsule_root)) fail("Origin capsule root is invalid");
if (lock.origin_capsule_manifest_version !== "somavera.capsule-manifest.v1") fail("Origin manifest version is unsupported");
if (lock.origin_capsule_root !== ORIGIN_CAPSULE_HASH) fail("runtime Origin capsule binding differs from the lock");
if (lock.binding_assurance !== "local_import_hashes_only_origin_commit_capsule_and_publisher_not_independently_authenticated") fail("binding assurance is overstated or unknown");
if (lock.implementation_scope !== "tokenless_reference_only" ||
    lock.token_activation_authorized !== false ||
    lock.production_claim_authorized !== false) fail("implementation authority is widened");
if (!Array.isArray(lock.locked_imports) || lock.locked_imports.length === 0) fail("locked imports are absent");

const localPaths = [];
const originPaths = [];
for (const entry of lock.locked_imports) {
  if (!exactKeys(entry, IMPORT_KEYS)) fail("an import has unexpected fields");
  if (typeof entry.origin_path !== "string" || typeof entry.local_path !== "string" || !HASH.test(entry.sha256)) fail("an import binding is malformed");
  const originPath = safeRelative(entry.origin_path, "Origin");
  const normalized = safeRelative(entry.local_path, "local");
  const absolute = path.resolve(somaRoot, ...normalized.split("/"));
  const relative = path.relative(somaRoot, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) fail(`local path escapes Soma: ${entry.local_path}`);
  let actual;
  try { actual = sha256(await readFile(absolute)); }
  catch (error) { fail(`cannot read ${entry.local_path} (${error.code || error.message})`); }
  if (actual !== entry.sha256) fail(`hash mismatch for ${entry.local_path}`);
  localPaths.push(entry.local_path);
  originPaths.push(originPath);
}

if (new Set(originPaths).size !== originPaths.length) fail("Origin import paths are duplicated");
if (new Set(localPaths).size !== localPaths.length ||
    JSON.stringify(localPaths) !== JSON.stringify([...localPaths].sort())) fail("locked imports are duplicated or unsorted");

console.log(`Origin lock verified: ${lock.locked_imports.length} imported files, commit ${lock.origin_git_commit}, capsule ${lock.origin_capsule_root}`);
