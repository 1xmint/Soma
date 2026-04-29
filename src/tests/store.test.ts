/**
 * Store tests — insert/query observations, dedup check.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ObservationStore } from '../lib/store.js';
import type { ObservationItem } from '../lib/types.js';

function makeGitCommitItem(hash: string, date?: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test Author',
      author_email: 'test@example.com',
      author_date: date ?? '2024-01-01T00:00:00Z',
      committer_name: 'Test Author',
      committer_email: 'test@example.com',
      committer_date: date ?? '2024-01-01T00:00:00Z',
      message: `commit ${hash.slice(0, 8)}`,
      message_subject: `commit ${hash.slice(0, 8)}`,
      parent_hashes: [],
      is_merge: false,
      files_changed: [],
      stats: { total_files_changed: 0, total_additions: 0, total_deletions: 0 },
      repo_path: '/test/repo',
    },
    observed_at: date ?? '2024-01-01T00:00:00Z',
  };
}

describe('ObservationStore', () => {
  let tmpDir: string;
  let store: ObservationStore;

  before(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vera-observer-test-'));
    store = await ObservationStore.open(join(tmpDir, 'test.db'));
  });

  after(() => {
    store.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('starts empty', () => {
    assert.equal(store.count(), 0);
  });

  test('inserts a single observation', () => {
    const hash = 'a'.repeat(40);
    const item = makeGitCommitItem(hash);
    const record = store.insert(item, '/test/repo');
    assert.ok(record.id, 'Should have an id');
    assert.equal(record.type, 'git_commit');
    assert.equal(record.commit_hash, hash);
    assert.equal(store.count(), 1);
  });

  test('dedup: hasCommit returns true for inserted commit', () => {
    const hash = 'a'.repeat(40);
    assert.ok(store.hasCommit(hash), 'Should find inserted commit hash');
  });

  test('dedup: hasCommit returns false for unknown commit', () => {
    assert.ok(!store.hasCommit('b'.repeat(40)), 'Unknown hash should return false');
  });

  test('insertMany skips duplicates, inserts new', () => {
    const existingHash = 'a'.repeat(40); // already inserted above
    const newHash1 = 'c'.repeat(40);
    const newHash2 = 'd'.repeat(40);
    const items = [
      makeGitCommitItem(existingHash, '2024-01-01T00:00:00Z'),
      makeGitCommitItem(newHash1, '2024-01-02T00:00:00Z'),
      makeGitCommitItem(newHash2, '2024-01-03T00:00:00Z'),
    ];
    const inserted = store.insertMany(items, '/test/repo');
    // Only the 2 new ones should be inserted; the duplicate is skipped
    assert.equal(inserted, 2);
    assert.equal(store.count(), 3);
  });

  test('query by repo_path returns matching records', () => {
    const results = store.query({ repoPath: '/test/repo' });
    assert.equal(results.length, 3);
  });

  test('query by type filters correctly', () => {
    const results = store.query({ type: 'git_commit' });
    assert.equal(results.length, 3);

    const none = store.query({ type: 'filesystem_change' });
    assert.equal(none.length, 0);
  });

  test('query by time range returns subset', () => {
    // 'd' hash was inserted with date 2024-01-03
    const results = store.query({
      fromDate: '2024-01-02T00:00:00Z',
      toDate: '2024-01-03T23:59:59Z',
    });
    // Should include the 2024-01-02 and 2024-01-03 records
    assert.ok(results.length >= 1, `Expected at least 1 result, got ${results.length}`);
    for (const r of results) {
      assert.ok(
        r.observed_at >= '2024-01-02T00:00:00Z',
        `Record observed_at ${r.observed_at} should be >= fromDate`
      );
    }
  });

  test('content round-trips through JSON correctly', () => {
    const hash = 'e'.repeat(40);
    const item = makeGitCommitItem(hash, '2024-02-01T00:00:00Z');
    store.insert(item, '/test/repo');
    const results = store.query({ repoPath: '/test/repo', type: 'git_commit' });
    const found = results.find((r) => r.commit_hash === hash);
    assert.ok(found, 'Should find the inserted record');
    assert.equal((found.content as Record<string, unknown>)['commit_hash'], hash);
  });
});
