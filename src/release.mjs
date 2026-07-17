import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { RELEASE_ROOT } from "./constants.mjs";
import { SomaError } from "./errors.mjs";

const EXCLUDED = new Set([".git", "node_modules", "coverage", "release/manifest.json"]);

async function listFiles(directory = RELEASE_ROOT) {
  const result = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(RELEASE_ROOT, absolute).split(path.sep).join("/");
      if (EXCLUDED.has(relative) || EXCLUDED.has(entry.name)) continue;
      if (entry.isSymbolicLink()) throw new SomaError("release contains a symbolic link", 4, "RELEASE_SYMLINK", { path: relative });
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) result.push(relative);
      else throw new SomaError("release contains an unsupported filesystem entry", 4, "RELEASE_ENTRY_UNSUPPORTED", { path: relative });
    }
  }
  await walk(directory);
  return result.sort();
}

async function record(relative) {
  const absolute = path.join(RELEASE_ROOT, ...relative.split("/"));
  const [bytes, metadata] = await Promise.all([readFile(absolute), stat(absolute)]);
  return {
    path: relative,
    bytes: metadata.size,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

export async function buildReleaseManifest() {
  const files = await listFiles();
  return {
    schema_version: "somavera.soma-release-manifest.v1",
    release_version: "0.1.0",
    generated_from: "clean-reference-source",
    excluded_paths: [...EXCLUDED].sort(),
    files: await Promise.all(files.map(record))
  };
}

export async function verifyRelease() {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(path.join(RELEASE_ROOT, "release", "manifest.json"), "utf8"));
  } catch (error) {
    throw new SomaError("release manifest is missing or invalid", 4, "RELEASE_MANIFEST_INVALID", { cause: error.message });
  }
  if (manifest.schema_version !== "somavera.soma-release-manifest.v1" || !Array.isArray(manifest.files)) {
    throw new SomaError("release manifest has an unsupported shape", 4, "RELEASE_MANIFEST_SHAPE");
  }
  const actualFiles = await listFiles();
  const expectedFiles = manifest.files.map((entry) => entry.path);
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new SomaError("release file set differs from the manifest", 4, "RELEASE_FILE_SET_MISMATCH");
  }
  const actualRecords = await Promise.all(actualFiles.map(record));
  if (JSON.stringify(actualRecords) !== JSON.stringify(manifest.files)) {
    throw new SomaError("release bytes differ from the manifest", 4, "RELEASE_HASH_MISMATCH");
  }
  const manifestBytes = await readFile(path.join(RELEASE_ROOT, "release", "manifest.json"));
  return {
    release_version: manifest.release_version,
    file_count: actualFiles.length,
    manifest_sha256: createHash("sha256").update(manifestBytes).digest("hex"),
    authenticity: "self_manifest_integrity_only_untrusted"
  };
}
