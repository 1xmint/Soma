import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";
import {
  hashFiles,
  listCapsuleFiles
} from "./lib/capsule-files.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const manifestPath = path.join(root, "CAPSULE-MANIFEST.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

if (manifest.manifest_version !== "somavera.capsule-manifest.v1") {
  throw new Error("unsupported manifest version");
}
if (manifest.hash_algorithm !== "sha256") {
  throw new Error("unsupported hash algorithm");
}

const actualPaths = await listCapsuleFiles(root);
const expectedPaths = manifest.files.map((entry) => entry.path);
if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
  throw new Error("capsule file list differs from manifest");
}

const actualRecords = await hashFiles(root, actualPaths);
if (JSON.stringify(actualRecords) !== JSON.stringify(manifest.files)) {
  throw new Error("one or more capsule files differ from the manifest");
}

const core = {
  manifest_version: manifest.manifest_version,
  hash_algorithm: manifest.hash_algorithm,
  canonicalization: manifest.canonicalization,
  excluded_paths: manifest.excluded_paths,
  files: manifest.files
};
const actualRoot = createHash("sha256")
  .update("somavera:capsule:v1\n" + canonicalize(core), "utf8")
  .digest("hex");

if (actualRoot !== manifest.capsule_root) {
  throw new Error("capsule root mismatch");
}

console.log("Capsule verified");
console.log("Files: " + actualRecords.length);
console.log("Capsule root: " + actualRoot);

