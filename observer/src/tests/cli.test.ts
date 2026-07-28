/**
 * CLI smoke tests — verify the observe entry point compiles and behaves
 * correctly for the most basic invocations (no live repo or server required).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// dist/tests/cli.test.js → ../../bin/observe.js = dist/bin/observe.js
const CLI = join(__dirname, '..', 'bin', 'observe.js');

describe('observe CLI', () => {
  test('--help exits 0 and prints usage', () => {
    const result = spawnSync(process.execPath, [CLI, '--help'], {
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(
      result.status,
      0,
      `Expected exit code 0, got ${result.status ?? 'null'}.\nstderr: ${result.stderr}`
    );
    assert.ok(
      result.stdout.includes('Usage:'),
      `Expected stdout to contain "Usage:", got:\n${result.stdout}`
    );
    assert.ok(
      result.stdout.includes('--submit'),
      `Expected stdout to mention --submit, got:\n${result.stdout}`
    );
  });

  test('no args exits 0 and prints usage', () => {
    const result = spawnSync(process.execPath, [CLI], {
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(
      result.status,
      0,
      `Expected exit code 0 for no-args, got ${result.status ?? 'null'}.\nstderr: ${result.stderr}`
    );
    assert.ok(
      result.stdout.includes('Usage:'),
      `Expected usage text in stdout, got:\n${result.stdout}`
    );
  });

  test('unrecognised flag exits 1', () => {
    const result = spawnSync(process.execPath, [CLI, '--not-a-real-flag'], {
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(
      result.status,
      1,
      `Expected exit code 1 for unknown flag, got ${result.status ?? 'null'}`
    );
  });

  test('missing repo path exits 1', () => {
    // Provide a recognised flag but no repo — should fail with a clear message
    const result = spawnSync(process.execPath, [CLI, '--limit', '5'], {
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(
      result.status,
      1,
      `Expected exit code 1 for missing repo, got ${result.status ?? 'null'}`
    );
  });

  test('invalid --limit exits 1', () => {
    const result = spawnSync(
      process.execPath,
      [CLI, '/some/path', '--limit', 'notanumber'],
      { encoding: 'utf8', timeout: 10_000 }
    );
    assert.equal(
      result.status,
      1,
      `Expected exit code 1 for invalid --limit, got ${result.status ?? 'null'}`
    );
  });

  test('non-git repo path exits 1 with clear message', () => {
    // Use a path that exists but isn't a git repo (OS temp dir root)
    const notARepo = process.platform === 'win32' ? 'C:\\Windows\\Temp' : '/tmp';
    const result = spawnSync(
      process.execPath,
      [CLI, notARepo],
      { encoding: 'utf8', timeout: 10_000 }
    );
    assert.equal(
      result.status,
      1,
      `Expected exit code 1 for non-git path, got ${result.status ?? 'null'}`
    );
    // stderr should mention the path or "git repository"
    const combined = result.stderr + result.stdout;
    assert.ok(
      combined.toLowerCase().includes('git') || combined.includes(notARepo),
      `Expected error output to mention git or the path, got:\n${combined}`
    );
  });
});
