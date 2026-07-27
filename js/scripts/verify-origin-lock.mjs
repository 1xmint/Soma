import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/canonicalize.mjs";
import { ORIGIN_CAPSULE_HASH } from "../src/host.mjs";

const somaRoot = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const repositoryRoot = path.resolve(somaRoot, "..");
const rootLockFile = path.join(repositoryRoot, "ORIGIN-LOCK.json");
const releaseLockFile = path.join(somaRoot, "release", "origin-lock.json");
const snapshotManifestFile = path.join(somaRoot, "release", "origin-capsule-manifest.json");
const monorepoManifestFile = path.join(repositoryRoot, "origin", "CAPSULE-MANIFEST.json");
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
const MANIFEST_KEYS = ["canonicalization", "capsule_root", "excluded_paths", "files", "hash_algorithm", "manifest_version"].sort();
const FILE_KEYS = ["bytes", "path", "sha256"].sort();
const EXPECTED_EXCLUSIONS = [".git/", ".github/", "node_modules/", "CAPSULE-MANIFEST.json"];

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

async function readPrettyJson(file, label) {
  let bytes;
  try { bytes = await readFile(file); }
  catch (error) { fail(`${label} is missing or unreadable (${error.code || error.message})`); }
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch (error) { fail(`${label} is invalid JSON (${error.message})`); }
  const normalized = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  if (!bytes.equals(normalized)) fail(`${label} is not deterministic pretty JSON or contains duplicate fields`);
  return { bytes, value };
}

const { bytes: rootBytes, value: lock } = await readPrettyJson(rootLockFile, "repository Origin lock");
const { bytes: releaseBytes } = await readPrettyJson(releaseLockFile, "packaged Origin lock");
if (!rootBytes.equals(releaseBytes)) fail("repository and packaged lock bytes differ");

if (!exactKeys(lock, TOP_LEVEL_KEYS)) fail("top-level fields differ from the v2 contract");
if (lock.schema_version !== "somavera.reference-origin-lock.v2") fail("schema version is unsupported");
if (lock.origin_status !== "draft_not_ratified") fail("Origin status is overstated");
if (!COMMIT.test(lock.origin_git_commit)) fail("Origin commit is not a full Git object ID");
if (!HASH.test(lock.origin_capsule_root)) fail("Origin capsule root is invalid");
if (lock.origin_capsule_manifest_version !== "somavera.capsule-manifest.v1") fail("Origin manifest version is unsupported");
if (lock.origin_capsule_root !== ORIGIN_CAPSULE_HASH) fail("runtime Origin capsule binding differs from the lock");
if (lock.binding_assurance !== "capsule_manifest_root_and_import_hashes_verified_commit_and_publisher_not_independently_authenticated") fail("binding assurance is overstated or unknown");
if (lock.implementation_scope !== "tokenless_reference_only" ||
    lock.token_activation_authorized !== false ||
    lock.production_claim_authorized !== false) fail("implementation authority is widened");
if (!Array.isArray(lock.locked_imports) || lock.locked_imports.length === 0) fail("locked imports are absent");

const { bytes: snapshotBytes, value: manifest } = await readPrettyJson(snapshotManifestFile, "packaged Origin capsule manifest");
if (!exactKeys(manifest, MANIFEST_KEYS)) fail("Origin capsule manifest fields differ from the v1 contract");
if (manifest.manifest_version !== lock.origin_capsule_manifest_version || manifest.hash_algorithm !== "sha256") fail("Origin capsule manifest profile differs from the lock");
if (manifest.canonicalization !== "RFC8785-JCS-with-Somavera-I-JSON-rejections") fail("Origin canonicalization profile is unsupported");
if (JSON.stringify(manifest.excluded_paths) !== JSON.stringify(EXPECTED_EXCLUSIONS)) fail("Origin capsule exclusions differ from the supported profile");
if (!Array.isArray(manifest.files) || manifest.files.length === 0) fail("Origin capsule manifest has no files");

const manifestPaths = [];
const manifestByPath = new Map();
for (const record of manifest.files) {
  if (!exactKeys(record, FILE_KEYS) || !Number.isSafeInteger(record.bytes) || record.bytes < 0 || !HASH.test(record.sha256)) fail("Origin capsule manifest contains a malformed file record");
  const recordPath = safeRelative(record.path, "Origin manifest");
  if (manifestByPath.has(recordPath)) fail(`Origin capsule manifest duplicates ${recordPath}`);
  manifestPaths.push(recordPath);
  manifestByPath.set(recordPath, record);
}
if (JSON.stringify(manifestPaths) !== JSON.stringify([...manifestPaths].sort())) fail("Origin capsule manifest paths are not sorted");

const core = {
  manifest_version: manifest.manifest_version,
  hash_algorithm: manifest.hash_algorithm,
  canonicalization: manifest.canonicalization,
  excluded_paths: manifest.excluded_paths,
  files: manifest.files
};
const computedRoot = sha256(Buffer.from(`somavera:capsule:v1\n${canonicalize(core)}`, "utf8"));
if (computedRoot !== manifest.capsule_root || computedRoot !== lock.origin_capsule_root) fail("Origin capsule manifest root does not match the lock");

let monorepoOriginAvailable = false;
try {
  const canonicalBytes = await readFile(monorepoManifestFile);
  if (!canonicalBytes.equals(snapshotBytes)) fail("packaged and canonical Origin capsule manifests differ");
  monorepoOriginAvailable = true;
} catch (error) {
  if (!String(error.message).startsWith("Origin lock verification failed:") && error.code !== "ENOENT") throw error;
  if (String(error.message).startsWith("Origin lock verification failed:")) throw error;
}

const localPaths = [];
const originPaths = [];
for (const entry of lock.locked_imports) {
  if (!exactKeys(entry, IMPORT_KEYS)) fail("an import has unexpected fields");
  if (typeof entry.origin_path !== "string" || typeof entry.local_path !== "string" || !HASH.test(entry.sha256)) fail("an import binding is malformed");
  const originPath = safeRelative(entry.origin_path, "Origin");
  const normalized = safeRelative(entry.local_path, "local");
  const manifestRecord = manifestByPath.get(originPath);
  if (!manifestRecord || manifestRecord.sha256 !== entry.sha256) fail(`Origin manifest does not bind ${originPath} to the locked hash`);
  const absolute = path.resolve(somaRoot, ...normalized.split("/"));
  const relative = path.relative(somaRoot, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) fail(`local path escapes Soma: ${entry.local_path}`);
  let actual;
  try { actual = sha256(await readFile(absolute)); }
  catch (error) { fail(`cannot read ${entry.local_path} (${error.code || error.message})`); }
  if (actual !== entry.sha256) fail(`hash mismatch for ${entry.local_path}`);
  if (monorepoOriginAvailable) {
    const canonicalPath = path.join(repositoryRoot, "origin", ...originPath.split("/"));
    let canonicalBytes;
    try { canonicalBytes = await readFile(canonicalPath); }
    catch (error) { fail(`cannot read canonical Origin file ${originPath} (${error.code || error.message})`); }
    if (canonicalBytes.length !== manifestRecord.bytes || sha256(canonicalBytes) !== entry.sha256) fail(`canonical Origin bytes differ for ${originPath}`);
  }
  localPaths.push(entry.local_path);
  originPaths.push(originPath);
}

if (new Set(originPaths).size !== originPaths.length) fail("Origin import paths are duplicated");
if (new Set(localPaths).size !== localPaths.length ||
    JSON.stringify(localPaths) !== JSON.stringify([...localPaths].sort())) fail("locked imports are duplicated or unsorted");

console.log(`Origin lock verified: ${lock.locked_imports.length} imported files, commit ${lock.origin_git_commit}, capsule ${lock.origin_capsule_root}`);
console.log(`Origin capsule manifest verified: ${manifest.files.length} files${monorepoOriginAvailable ? ", canonical monorepo bytes checked" : ", packaged proof mode"}`);
