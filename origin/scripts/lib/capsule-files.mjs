import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

const EXCLUDED_NAMES = new Set([
  ".git",
  ".github",
  "node_modules",
  "CAPSULE-MANIFEST.json"
]);

export const excludedPaths = [
  ".git/",
  ".github/",
  "node_modules/",
  "CAPSULE-MANIFEST.json"
];

export async function listCapsuleFiles(root) {
  const result = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));

    for (const entry of entries) {
      if (EXCLUDED_NAMES.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error("symbolic links are forbidden in a recovery capsule: " + absolute);
      }
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile()) {
        const relative = path.relative(root, absolute).split(path.sep).join("/");
        result.push(relative);
      } else {
        throw new Error("unsupported filesystem entry: " + absolute);
      }
    }
  }

  await walk(root);
  return result.sort();
}

export async function hashFiles(root, files) {
  const records = [];
  for (const file of files) {
    const bytes = await readFile(path.join(root, ...file.split("/")));
    records.push({
      path: file,
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex")
    });
  }
  return records;
}

