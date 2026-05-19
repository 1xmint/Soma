#!/usr/bin/env node
import { execSync } from 'node:child_process';
import { scan } from '../src/scanner.js';

const stagedFiles = execSync('git diff --cached --name-only --diff-filter=ACMR', { encoding: 'utf8' })
  .split('\n')
  .map(f => f.trim())
  .filter(Boolean);

let failed = false;

for (const file of stagedFiles) {
  let content;
  try {
    content = execSync(`git show ":${file}"`, { encoding: 'utf8' });
  } catch {
    continue; // binary or deleted
  }

  const findings = scan(content);
  for (const { line, pattern, text } of findings) {
    console.error(`\x1b[31m[secret-scanner]\x1b[0m ${file}:${line} — ${pattern}`);
    console.error(`  ${text}`);
    failed = true;
  }
}

if (failed) {
  console.error('\n\x1b[31m[secret-scanner] Commit blocked: secrets detected above.\x1b[0m');
  console.error('Remove the secrets, or use git commit --no-verify to skip (not recommended).\n');
  process.exit(1);
}
