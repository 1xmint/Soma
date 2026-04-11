import { cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

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

console.log('Assembling soma-heart...');
const heartDist = path.join(repoRoot, 'packages', 'soma-heart', 'dist');
resetDir(heartDist);
copy(path.join(repoRoot, 'dist', 'heart'), path.join(heartDist, 'heart'));
copy(path.join(repoRoot, 'dist', 'core'), path.join(heartDist, 'core'));

console.log('Assembling soma-sense...');
const senseDist = path.join(repoRoot, 'packages', 'soma-sense', 'dist');
resetDir(senseDist);
copy(path.join(repoRoot, 'dist', 'sensorium'), path.join(senseDist, 'sensorium'));
copy(path.join(repoRoot, 'dist', 'mcp'), path.join(senseDist, 'mcp'));
copy(path.join(repoRoot, 'dist', 'core'), path.join(senseDist, 'core'));
copy(path.join(repoRoot, 'dist', 'heart'), path.join(senseDist, 'heart'));
mkdirSync(path.join(senseDist, 'experiment'), { recursive: true });
copy(
  path.join(repoRoot, 'dist', 'experiment', 'signals.js'),
  path.join(senseDist, 'experiment', 'signals.js'),
);
copy(
  path.join(repoRoot, 'dist', 'experiment', 'signals.d.ts'),
  path.join(senseDist, 'experiment', 'signals.d.ts'),
);
for (const ext of ['js.map', 'd.ts.map']) {
  const src = path.join(repoRoot, 'dist', 'experiment', `signals.${ext}`);
  const dest = path.join(senseDist, 'experiment', `signals.${ext}`);
  try {
    copy(src, dest);
  } catch {
    // sourcemaps are optional
  }
}

console.log('');
console.log('Package contents:');
console.log(`  soma-heart: ${countJsFiles(heartDist)} JS files`);
console.log(`  soma-sense: ${countJsFiles(senseDist)} JS files`);
console.log('');
console.log('Ready to publish:');
console.log('  cd packages/soma-heart && npm publish');
console.log('  cd packages/soma-sense && npm publish');
