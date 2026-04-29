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

// ---- Submission tracking tests ----

describe('ObservationStore — submission tracking', () => {
  let tmpDir: string;
  let store: ObservationStore;

  before(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vera-observer-submit-test-'));
    store = await ObservationStore.open(join(tmpDir, 'submit-test.db'));

    // Insert 4 observations with distinct dates and hashes
    store.insert(makeGitCommitItem('1'.repeat(40), '2024-03-01T00:00:00Z'), '/repo');
    store.insert(makeGitCommitItem('2'.repeat(40), '2024-03-02T00:00:00Z'), '/repo');
    store.insert(makeGitCommitItem('3'.repeat(40), '2024-03-03T00:00:00Z'), '/repo');
    store.insert(makeGitCommitItem('4'.repeat(40), '2024-03-04T00:00:00Z'), '/repo');
  });

  after(() => {
    store.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('getUnsubmitted returns all observations when none submitted', () => {
    const unsubmitted = store.getUnsubmitted();
    assert.equal(unsubmitted.length, 4, 'All 4 records should be unsubmitted');
    // Confirm submitted_at is undefined/null for all
    for (const r of unsubmitted) {
      assert.ok(r.submitted_at === undefined || r.submitted_at === null,
        'submitted_at should be null/undefined before submission');
    }
  });

  test('getUnsubmitted respects the limit parameter', () => {
    const limited = store.getUnsubmitted(2);
    assert.equal(limited.length, 2, 'Should return at most limit=2 records');
  });

  test('markSubmitted updates correct rows', () => {
    const batchId = 'test-batch-abc';
    store.markSubmitted(['1'.repeat(40), '2'.repeat(40)], batchId);

    // Check that those two rows now have submission data
    const all = store.query();
    const hash1 = all.find((r) => r.commit_hash === '1'.repeat(40));
    const hash2 = all.find((r) => r.commit_hash === '2'.repeat(40));
    const hash3 = all.find((r) => r.commit_hash === '3'.repeat(40));

    assert.ok(hash1?.submitted_at, 'hash1 should have submitted_at set');
    assert.equal(hash1?.submission_batch_id, batchId, 'hash1 should have the correct batch id');

    assert.ok(hash2?.submitted_at, 'hash2 should have submitted_at set');
    assert.equal(hash2?.submission_batch_id, batchId, 'hash2 should have the correct batch id');

    // hash3 was not submitted — should still be unsubmitted
    assert.ok(!hash3?.submitted_at, 'hash3 should NOT have submitted_at set');
  });

  test('after markSubmitted, getUnsubmitted excludes submitted observations', () => {
    // hashes 1 and 2 were marked in the previous test
    const remaining = store.getUnsubmitted();
    assert.equal(remaining.length, 2, 'Only hashes 3 and 4 should remain unsubmitted');
    for (const r of remaining) {
      assert.ok(
        r.commit_hash === '3'.repeat(40) || r.commit_hash === '4'.repeat(40),
        `Unexpected hash in unsubmitted: ${r.commit_hash ?? 'null'}`
      );
    }
  });

  test('getUnsubmitted returns observations ordered by observed_at ASC', () => {
    const unsubmitted = store.getUnsubmitted();
    assert.ok(unsubmitted.length >= 2, 'Need at least 2 records to check ordering');
    for (let i = 1; i < unsubmitted.length; i++) {
      assert.ok(
        (unsubmitted[i]?.observed_at ?? '') >= (unsubmitted[i - 1]?.observed_at ?? ''),
        'Records should be ordered ASC by observed_at'
      );
    }
  });
});
