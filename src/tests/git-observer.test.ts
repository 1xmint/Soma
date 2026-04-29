/**
 * Git observer tests — test against a real git repo.
 *
 * Uses the veraAI repo at C:\Users\Josh\Desktop\GitHub\veraAI as the real
 * git fixture. Also tests against vera-observer's own repo once it's
 * initialized.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { observeGitCommits } from '../lib/git-observer.js';
import { gitCommitObservationSchema } from '../lib/types.js';

// veraAI is the reference repo — it always has commits
const VERA_AI_REPO = 'C:/Users/Josh/Desktop/GitHub/veraAI';
// vera-observer itself (will have commits after initial commit)
const VERA_OBSERVER_REPO = 'C:/Users/Josh/Desktop/GitHub/vera-observer';

describe('observeGitCommits — real repo (veraAI)', () => {
  const skipIfMissing = !existsSync(VERA_AI_REPO + '/.git');

  test('returns observations from a real git repo', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    assert.ok(result.count > 0, 'Should find at least 1 commit');
    assert.equal(result.repoPath, VERA_AI_REPO);
    assert.equal(result.observations.length, result.count);
  });

  test('all observations have type="git_commit"', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    for (const obs of result.observations) {
      assert.equal(obs.type, 'git_commit');
    }
  });

  test('observation content validates against GitCommitObservation schema', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 3 });
    assert.ok(result.count > 0, 'Need at least 1 commit to validate');
    for (const obs of result.observations) {
      const parseResult = gitCommitObservationSchema.safeParse(obs.content);
      assert.ok(
        parseResult.success,
        `Content failed schema validation: ${parseResult.success ? '' : parseResult.error.message}`
      );
    }
  });

  test('observed_at is a valid ISO 8601 date string', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    for (const obs of result.observations) {
      const d = new Date(obs.observed_at);
      assert.ok(!isNaN(d.getTime()), `observed_at "${obs.observed_at}" is not a valid date`);
    }
  });

  test('commit hashes are 40-character hex strings', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      const hash = content['commit_hash'] as string;
      assert.match(hash, /^[0-9a-f]{40}$/, `Commit hash "${hash}" is not 40 hex chars`);
    }
  });

  test('limit is respected', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 2 });
    assert.ok(result.count <= 2, `Expected <= 2 commits, got ${result.count}`);
  });

  test('files_changed array is present (may be empty for some commits)', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      assert.ok(Array.isArray(content['files_changed']), 'files_changed should be an array');
    }
  });

  test('stats fields are non-negative integers', { skip: skipIfMissing ? 'veraAI repo not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_AI_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      const stats = content['stats'] as Record<string, unknown>;
      assert.ok(typeof stats['total_files_changed'] === 'number' && stats['total_files_changed'] >= 0);
      assert.ok(typeof stats['total_additions'] === 'number' && stats['total_additions'] >= 0);
      assert.ok(typeof stats['total_deletions'] === 'number' && stats['total_deletions'] >= 0);
    }
  });
});

describe('observeGitCommits — error handling', () => {
  test('throws on non-existent path', () => {
    assert.throws(
      () => observeGitCommits({ repoPath: '/nonexistent/path/definitely-not-a-repo' }),
      /Not a git repository/
    );
  });
});

describe('observeGitCommits — vera-observer own repo', () => {
  const skipIfMissing = !existsSync(VERA_OBSERVER_REPO + '/.git');

  test('can observe vera-observer initial commit', { skip: skipIfMissing ? 'vera-observer git not initialized yet' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_OBSERVER_REPO, limit: 10 });
    // After initial commit, should have at least 1
    assert.ok(result.count >= 1, `Expected at least 1 commit, got ${result.count}`);
  });
});
