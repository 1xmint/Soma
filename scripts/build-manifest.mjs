import { writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";
import {
  excludedPaths,
  hashFiles,
  listCapsuleFiles
} from "./lib/capsule-files.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const files = await listCapsuleFiles(root);
const records = await hashFiles(root, files);
const core = {
  manifest_version: "somavera.capsule-manifest.v1",
  hash_algorithm: "sha256",
  canonicalization: "RFC8785-JCS-with-Somavera-I-JSON-rejections",
  excluded_paths: excludedPaths,
  files: records
};
const capsuleRoot = createHash("sha256")
  .update("somavera:capsule:v1\n" + canonicalize(core), "utf8")
  .digest("hex");
const manifest = {
  ...core,
  capsule_root: capsuleRoot
};

await writeFile(
  path.join(root, "CAPSULE-MANIFEST.json"),
  JSON.stringify(manifest, null, 2) + "\n",
  "utf8"
);

console.log("Wrote CAPSULE-MANIFEST.json");
console.log("Files: " + records.length);
console.log("Capsule root: " + capsuleRoot);

