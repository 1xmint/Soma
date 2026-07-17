import { verifyRelease } from "../src/release.mjs";

const result = await verifyRelease();
console.log(`Release verified: ${result.file_count} files, manifest ${result.manifest_sha256}`);
