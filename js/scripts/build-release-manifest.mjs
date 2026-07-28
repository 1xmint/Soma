import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { RELEASE_ROOT } from "../src/constants.mjs";
import { buildReleaseManifest } from "../src/release.mjs";

const manifest = await buildReleaseManifest();
await mkdir(path.join(RELEASE_ROOT, "release"), { recursive: true });
await writeFile(path.join(RELEASE_ROOT, "release", "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`Wrote release/manifest.json (${manifest.files.length} files)`);
