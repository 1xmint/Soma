import { cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

// Soma ships as a single unified npm package: `soma-heart`.
//
// As of 0.3.0 the former `soma-sense` package is folded in as subpath
// exports (`soma-heart/sense`, `soma-heart/senses`, `soma-heart/atlas`,
// `soma-heart/mcp`, `soma-heart/signals`). One install, one version,
// no cross-package version matrix, no duplicated `dist/heart/` ship.
//
// See docs/secure-release-workflow.md and CHANGELOG.md.

const repoRoot = process.cwd();

function countJsFiles(dir) {
  let count = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) count += countJsFiles(fullPath);
    else if (entry.isFile() && fullPath.endsWith('.js')) count += 1;
  }
  return count;
}

function resetDir(dir) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function copy(src, dest) {
  cpSync(src, dest, { recursive: true });
}

console.log('Building TypeScript...');
execSync('npx tsc -p tsconfig.build.json', { stdio: 'inherit', cwd: repoRoot });

console.log('Assembling soma-heart (unified)...');
const heartDist = path.join(repoRoot, 'packages', 'soma-heart', 'dist');
resetDir(heartDist);

// Core trust machine
copy(path.join(repoRoot, 'dist', 'heart'), path.join(heartDist, 'heart'));
copy(path.join(repoRoot, 'dist', 'core'), path.join(heartDist, 'core'));

// Sensorium + MCP middleware (previously soma-sense)
copy(path.join(repoRoot, 'dist', 'sensorium'), path.join(heartDist, 'sensorium'));
copy(path.join(repoRoot, 'dist', 'mcp'), path.join(heartDist, 'mcp'));

// Shared signal primitives used by sensorium
mkdirSync(path.join(heartDist, 'experiment'), { recursive: true });
copy(
  path.join(repoRoot, 'dist', 'experiment', 'signals.js'),
  path.join(heartDist, 'experiment', 'signals.js'),
);
copy(
  path.join(repoRoot, 'dist', 'experiment', 'signals.d.ts'),
  path.join(heartDist, 'experiment', 'signals.d.ts'),
);
for (const ext of ['js.map', 'd.ts.map']) {
  const src = path.join(repoRoot, 'dist', 'experiment', `signals.${ext}`);
  const dest = path.join(heartDist, 'experiment', `signals.${ext}`);
  try {
    copy(src, dest);
  } catch {
    // sourcemaps are optional
  }
}

console.log('');
console.log('Package contents:');
console.log(`  soma-heart: ${countJsFiles(heartDist)} JS files`);
console.log('');
console.log('Ready to publish:');
console.log('  cd packages/soma-heart && npm publish');
