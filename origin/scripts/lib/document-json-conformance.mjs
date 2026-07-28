import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const excludedDirectories = new Set([".git", "node_modules"]);

async function markdownFiles(directory) {
  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    if (excludedDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await markdownFiles(absolute));
    else if (entry.isFile() && entry.name.endsWith(".md")) files.push(absolute);
  }
  return files;
}

let checks = 0;
for (const absolute of await markdownFiles(root)) {
  const source = await readFile(absolute, "utf8");
  const relative = path.relative(root, absolute).split(path.sep).join("/");
  const pattern = /^(~~~|```)json\s*\r?\n([\s\S]*?)^\1\s*$/gm;
  for (const match of source.matchAll(pattern)) {
    const line = source.slice(0, match.index).split(/\r?\n/).length;
    try {
      JSON.parse(match[2]);
    } catch (error) {
      throw new Error(`${relative}:${line} contains invalid fenced JSON: ${error.message}`);
    }
    checks += 1;
  }
}

console.log(`Markdown fenced-JSON checks passed: ${checks}`);
