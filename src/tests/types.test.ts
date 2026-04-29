/**
 * Type validation tests — Zod schema parsing for git observations.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  gitCommitObservationSchema,
  observationItemSchema,
  observationRecordSchema,
  fileChangeSchema,
} from '../lib/types.js';

describe('fileChangeSchema', () => {
  test('parses a valid file change', () => {
    const result = fileChangeSchema.safeParse({
      path: 'src/index.ts',
      status: 'added',
      additions: 10,
      deletions: 0,
    });
    assert.ok(result.success, `Schema should parse: ${result.success ? '' : result.error.message}`);
    assert.equal(result.data?.path, 'src/index.ts');
    assert.equal(result.data?.status, 'added');
  });

  test('parses a renamed file with old_path', () => {
    const result = fileChangeSchema.safeParse({
      path: 'src/new-name.ts',
      status: 'renamed',
      additions: 0,
      deletions: 0,
      old_path: 'src/old-name.ts',
    });
    assert.ok(result.success);
    assert.equal(result.data?.old_path, 'src/old-name.ts');
  });

  test('rejects invalid status', () => {
    const result = fileChangeSchema.safeParse({
      path: 'src/index.ts',
      status: 'invalid-status',
      additions: 0,
      deletions: 0,
    });
    assert.ok(!result.success, 'Should reject invalid status');
  });
});

describe('gitCommitObservationSchema', () => {
  const validCommit = {
    commit_hash: 'a'.repeat(40),
    author_name: 'Alice',
    author_email: 'alice@example.com',
    author_date: '2024-01-01T00:00:00Z',
    committer_name: 'Alice',
    committer_email: 'alice@example.com',
    committer_date: '2024-01-01T00:00:00Z',
    message: 'feat: add feature\n\nBody here.',
    message_subject: 'feat: add feature',
    parent_hashes: ['b'.repeat(40)],
    is_merge: false,
    files_changed: [
      { path: 'src/index.ts', status: 'added', additions: 5, deletions: 0 },
    ],
    stats: { total_files_changed: 1, total_additions: 5, total_deletions: 0 },
    repo_path: '/home/user/project',
  };

  test('parses a valid git commit observation', () => {
    const result = gitCommitObservationSchema.safeParse(validCommit);
    assert.ok(result.success, `Schema should parse: ${result.success ? '' : result.error.message}`);
    assert.equal(result.data?.commit_hash, 'a'.repeat(40));
    assert.equal(result.data?.is_merge, false);
  });

  test('parses a merge commit (multiple parents)', () => {
    const merge = { ...validCommit, parent_hashes: ['b'.repeat(40), 'c'.repeat(40)], is_merge: true };
    const result = gitCommitObservationSchema.safeParse(merge);
    assert.ok(result.success);
    assert.equal(result.data?.is_merge, true);
    assert.equal(result.data?.parent_hashes.length, 2);
  });

  test('parses an initial commit (no parents)', () => {
    const initial = { ...validCommit, parent_hashes: [], is_merge: false };
    const result = gitCommitObservationSchema.safeParse(initial);
    assert.ok(result.success);
    assert.equal(result.data?.parent_hashes.length, 0);
  });

  test('rejects commit_hash wrong length', () => {
    const bad = { ...validCommit, commit_hash: 'abc123' };
    const result = gitCommitObservationSchema.safeParse(bad);
    assert.ok(!result.success, 'Should reject short commit hash');
  });
});

describe('observationItemSchema', () => {
  test('parses a valid ObservationItem (vera-knowledge compatible)', () => {
    const item = {
      type: 'git_commit',
      content: { commit_hash: 'a'.repeat(40), message: 'test' },
      observed_at: '2024-01-01T00:00:00Z',
    };
    const result = observationItemSchema.safeParse(item);
    assert.ok(result.success);
    assert.equal(result.data?.type, 'git_commit');
  });

  test('rejects missing observed_at', () => {
    const item = { type: 'git_commit', content: {} };
    const result = observationItemSchema.safeParse(item);
    assert.ok(!result.success);
  });
});

describe('observationRecordSchema', () => {
  test('parses a full local ObservationRecord', () => {
    const record = {
      id: '123e4567-e89b-12d3-a456-426614174000',
      type: 'git_commit',
      content: {},
      observed_at: '2024-01-01T00:00:00Z',
      created_at: '2024-01-01T00:01:00Z',
      repo_path: '/home/user/project',
      commit_hash: 'a'.repeat(40),
    };
    const result = observationRecordSchema.safeParse(record);
    assert.ok(result.success, `Should parse: ${result.success ? '' : result.error.message}`);
    assert.equal(result.data?.id, record.id);
    assert.equal(result.data?.commit_hash, 'a'.repeat(40));
  });
});
