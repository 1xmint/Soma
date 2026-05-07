/**
 * Pipeline tests — unit tests for runSubmissionPipeline().
 *
 * The submitter (fetch) is mocked to avoid any real network calls.
 * The store is real (in-memory sql.js backed by a temp file).
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSubmissionPipeline, extractCandidateArtifacts, runArtifactPipeline } from '../lib/pipeline.js';
import { ObservationStore } from '../lib/store.js';
import { generateTestIdentity } from '../lib/identity.js';
import type { ObservationItem } from '../lib/types.js';

// ---- Helpers ----

function makeItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-01T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-01T00:00:00Z',
      message: `commit ${hash.slice(0, 8)}`,
      message_subject: `commit ${hash.slice(0, 8)}`,
      parent_hashes: [],
      is_merge: false,
      files_changed: [],
      stats: { total_files_changed: 0, total_additions: 0, total_deletions: 0 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-01T00:00:00Z',
  };
}

/** A git_commit that matches test_backed_resolution (test file + fix message). */
function makeFixWithTestItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-01T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-01T00:00:00Z',
      message: 'fix: resolve null pointer in UserService',
      message_subject: 'fix: resolve null pointer in UserService',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/user.service.test.ts', status: 'modified', additions: 10, deletions: 0 },
        { path: 'src/user.service.ts', status: 'modified', additions: 5, deletions: 2 },
      ],
      stats: { total_files_changed: 2, total_additions: 15, total_deletions: 2 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-01T00:00:00Z',
  };
}

/** A git_commit that matches failure_to_fix_journey (Revert subject). */
function makeRevertItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-02T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-02T00:00:00Z',
      message: 'Revert "Add feature X"',
      message_subject: 'Revert "Add feature X"',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/feature.ts', status: 'modified', additions: 0, deletions: 10 },
      ],
      stats: { total_files_changed: 1, total_additions: 0, total_deletions: 10 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-02T00:00:00Z',
  };
}

/** A normal git_commit with no test files and no fix/revert keywords. */
function makeNormalItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-03T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-03T00:00:00Z',
      message: 'chore: update dependencies',
      message_subject: 'chore: update dependencies',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'package.json', status: 'modified', additions: 5, deletions: 5 },
      ],
      stats: { total_files_changed: 1, total_additions: 5, total_deletions: 5 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-03T00:00:00Z',
  };
}

/** A git_commit that matches operator_workflow_improvement. */
function makeOperatorWorkflowItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-04T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-04T00:00:00Z',
      message: 'feat: add review guidance to catalog and inspect workflow',
      message_subject: 'feat: add review guidance to catalog and inspect workflow',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/routes/catalog.ts', status: 'modified', additions: 20, deletions: 4 },
        { path: 'src/routes/inspect.ts', status: 'modified', additions: 12, deletions: 2 },
        { path: 'src/tests/catalog.test.ts', status: 'modified', additions: 8, deletions: 1 },
      ],
      stats: { total_files_changed: 3, total_additions: 40, total_deletions: 7 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-04T00:00:00Z',
  };
}

function makeJsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

type FetchFn = typeof globalThis.fetch;
let originalFetch: FetchFn;

beforeEach(() => {
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// ---- Tests ----

describe('runSubmissionPipeline', () => {
  test('with no unsubmitted observations, returns 0/0', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-pipeline-test-'));
    const dbPath = join(tmpDir, 'test.db');

    // Empty DB — no observations
    const store = await ObservationStore.open(dbPath);
    store.close();

    const identity = generateTestIdentity();
    let fetchCalled = false;
    globalThis.fetch = async () => {
      fetchCalled = true;
      return makeJsonResponse(201, {});
    };

    try {
      const result = await runSubmissionPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.submitted, 0, 'submitted should be 0');
      assert.equal(result.failed, 0, 'failed should be 0');
      assert.ok(!fetchCalled, 'fetch should not be called when there are no observations');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('with unsubmitted observations, pipeline submits and marks them', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-pipeline-test-'));
    const dbPath = join(tmpDir, 'test.db');
    const batchId = 'pipeline-batch-xyz';

    // Pre-populate store with 2 observations
    const store = await ObservationStore.open(dbPath);
    store.insert(makeItem('a'.repeat(40)), '/repo');
    store.insert(makeItem('b'.repeat(40)), '/repo');
    store.close();

    const identity = generateTestIdentity();
    globalThis.fetch = async () => makeJsonResponse(201, {
      batch: {
        id: batchId,
        user_id: 'user-123',
        source_type: 'git',
        observation_count: 2,
        created_at: '2026-01-01T00:00:00Z',
      },
    });

    try {
      const result = await runSubmissionPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.submitted, 2, 'Both observations should be submitted');
      assert.equal(result.failed, 0, 'No failures');
      assert.equal(result.batchId, batchId, 'Should return the batch ID');

      // Re-open store and verify both records are marked
      const verifyStore = await ObservationStore.open(dbPath);
      const unsubmitted = verifyStore.getUnsubmitted();
      verifyStore.close();
      assert.equal(unsubmitted.length, 0, 'No observations should remain unsubmitted');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('on submission failure, observations remain unsubmitted', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-pipeline-test-'));
    const dbPath = join(tmpDir, 'test.db');

    // Pre-populate store
    const store = await ObservationStore.open(dbPath);
    store.insert(makeItem('c'.repeat(40)), '/repo');
    store.close();

    const identity = generateTestIdentity();
    globalThis.fetch = async () => makeJsonResponse(403, { error: 'signature_invalid' });

    try {
      const result = await runSubmissionPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.submitted, 0, 'Nothing should be submitted on failure');
      assert.equal(result.failed, 1, '1 observation failed');
      assert.ok(result.error, 'Should have an error message');

      // Verify observation is still unsubmitted
      const verifyStore = await ObservationStore.open(dbPath);
      const unsubmitted = verifyStore.getUnsubmitted();
      verifyStore.close();
      assert.equal(unsubmitted.length, 1, 'Observation should remain unsubmitted after failure');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('batchSize limits the number of observations submitted in one run', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-pipeline-test-'));
    const dbPath = join(tmpDir, 'test.db');
    const batchId = 'limited-batch-001';

    // Insert 5 observations
    const store = await ObservationStore.open(dbPath);
    for (let i = 0; i < 5; i++) {
      const hash = i.toString().repeat(40);
      store.insert(makeItem(hash), '/repo');
    }
    store.close();

    const identity = generateTestIdentity();
    let submittedCount = 0;
    globalThis.fetch = async (input, init) => {
      const body = JSON.parse((init as RequestInit).body as string) as { observations: unknown[] };
      submittedCount = body.observations.length;
      return makeJsonResponse(201, {
        batch: {
          id: batchId,
          user_id: 'user-123',
          source_type: 'git',
          observation_count: submittedCount,
          created_at: '2026-01-01T00:00:00Z',
        },
      });
    };

    try {
      const result = await runSubmissionPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
        batchSize: 3,
      });

      assert.equal(result.submitted, 3, 'Should submit only batchSize=3 observations');
      assert.equal(submittedCount, 3, 'fetch should receive exactly 3 observations');

      // 2 observations should remain unsubmitted
      const verifyStore = await ObservationStore.open(dbPath);
      const remaining = verifyStore.getUnsubmitted();
      verifyStore.close();
      assert.equal(remaining.length, 2, '2 observations should remain unsubmitted');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ---- extractCandidateArtifacts tests ----

describe('extractCandidateArtifacts', () => {
  const fixHash = 'f'.repeat(40);
  const revertHash = 'e'.repeat(40);
  const normalHash = '9'.repeat(40);
  const operatorHash = '7'.repeat(40);

  test('commit with test file + fix message → test_backed_resolution artifact', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeFixWithTestItem(fixHash),
    ]);

    assert.equal(matching.length, 1, 'Should produce one matching artifact');
    assert.equal(nonMatchingHashes.length, 0, 'No non-matching hashes');

    const m = matching[0]!;
    assert.equal(m.sourceHash, fixHash);
    assert.equal(m.artifact.artifact_type, 'test_backed_resolution');

    const art = m.artifact as import('../lib/types.js').TestBackedResolution;
    assert.equal(art.resolution_summary, 'fix: resolve null pointer in UserService');
    assert.ok(art.test_files.some((f) => f.includes('.test.ts')), 'test_files should contain the test file');
    assert.ok(art.source_files.some((f) => f === 'src/user.service.ts'), 'source_files should contain non-test file');
    assert.equal(art.commit_hash, fixHash);
    assert.equal(art.stats.total_additions, 15);
    assert.equal(art.stats.total_deletions, 2);
  });

  test('commit with "Revert" subject → failure_to_fix_journey artifact with signal=revert', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeRevertItem(revertHash),
    ]);

    assert.equal(matching.length, 1, 'Should produce one matching artifact');
    assert.equal(nonMatchingHashes.length, 0);

    const m = matching[0]!;
    assert.equal(m.sourceHash, revertHash);
    assert.equal(m.artifact.artifact_type, 'failure_to_fix_journey');

    const art = m.artifact as import('../lib/types.js').FailureToFixJourney;
    assert.equal(art.journey_summary, 'Revert "Add feature X"');
    assert.deepEqual(art.attempt_hashes, [revertHash]);
    assert.ok(art.target_files.includes('src/feature.ts'));
    assert.equal(art.signal, 'revert');
  });

  test('normal commit (no test files, no fix/revert keywords) → nonMatchingHashes', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeNormalItem(normalHash),
    ]);

    assert.equal(matching.length, 0, 'Normal commit should produce no artifact');
    assert.equal(nonMatchingHashes.length, 1, 'Hash should be in nonMatchingHashes');
    assert.equal(nonMatchingHashes[0], normalHash);
  });

  test('mixed batch: matching and non-matching observations', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeFixWithTestItem(fixHash),
      makeRevertItem(revertHash),
      makeOperatorWorkflowItem(operatorHash),
      makeNormalItem(normalHash),
    ]);

    assert.equal(matching.length, 3);
    assert.equal(nonMatchingHashes.length, 1);
    assert.equal(nonMatchingHashes[0], normalHash);

    const types = matching.map((m) => m.artifact.artifact_type);
    assert.ok(types.includes('test_backed_resolution'));
    assert.ok(types.includes('failure_to_fix_journey'));
    assert.ok(types.includes('operator_workflow_improvement'));
  });

  test('operator-facing workflow commit produces operator_workflow_improvement artifact', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeOperatorWorkflowItem(operatorHash),
    ]);

    assert.equal(matching.length, 1, 'Should produce one matching artifact');
    assert.equal(nonMatchingHashes.length, 0, 'No non-matching hashes');

    const m = matching[0]!;
    assert.equal(m.sourceHash, operatorHash);
    assert.equal(m.artifact.artifact_type, 'operator_workflow_improvement');

    const art = m.artifact as import('../lib/types.js').OperatorWorkflowImprovement;
    assert.equal(
      art.improvement_summary,
      'feat: add review guidance to catalog and inspect workflow',
    );
    assert.ok(
      art.surface_files.includes('src/routes/catalog.ts'),
      'surface_files should include operator-facing route files',
    );
    assert.ok(
      art.verification_files.includes('src/tests/catalog.test.ts'),
      'verification_files should include test coverage when present',
    );
    assert.equal(art.commit_hash, operatorHash);
    assert.equal(art.stats.total_additions, 40);
    assert.equal(art.stats.total_deletions, 7);
  });
});

// ---- runArtifactPipeline tests ----
describe('runArtifactPipeline', () => {
  const fixHash = '1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a';
  const revertHash = '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b';
  const normalHash = '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c';

  test('success path: evaluate → pending → submit → submitted', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-artifact-pipeline-'));
    const dbPath = join(tmpDir, 'test.db');
    const batchId = 'artifact-batch-001';

    // Pre-populate with a matching commit
    const store = await ObservationStore.open(dbPath);
    store.insert(makeFixWithTestItem(fixHash), '/repo');
    store.close();

    const identity = generateTestIdentity();
    globalThis.fetch = async () =>
      makeJsonResponse(201, {
        batch: {
          id: batchId,
          user_id: 'user-1',
          source_type: 'git',
          observation_count: 1,
          created_at: '2026-01-01T00:00:00Z',
        },
      });

    try {
      const result = await runArtifactPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.evaluated, 1, 'Should have evaluated 1 row');
      assert.equal(result.noSignal, 0, 'No no-signal rows');
      assert.equal(result.pending, 1, 'Phase A should mark 1 row pending');
      assert.equal(result.submitted, 1, 'Phase B should submit 1 row');
      assert.equal(result.batchId, batchId);
      assert.equal(result.error, undefined);

      // Verify store state: submitted row no longer in getPending
      const verifyStore = await ObservationStore.open(dbPath);
      assert.equal(verifyStore.getPending().length, 0, 'No rows should remain pending');
      assert.equal(verifyStore.getUnextracted().length, 0, 'No rows unextracted');
      verifyStore.close();
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('no-signal path: normal commit marked no_signal, stays out of all queues', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-artifact-nosignal-'));
    const dbPath = join(tmpDir, 'test.db');

    const store = await ObservationStore.open(dbPath);
    store.insert(makeNormalItem(normalHash), '/repo');
    store.close();

    const identity = generateTestIdentity();
    let fetchCalled = false;
    globalThis.fetch = async () => {
      fetchCalled = true;
      return makeJsonResponse(201, {});
    };

    try {
      const result = await runArtifactPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.evaluated, 1);
      assert.equal(result.noSignal, 1, 'Normal commit should be no_signal');
      assert.equal(result.pending, 0);
      assert.equal(result.submitted, 0);
      assert.ok(!fetchCalled, 'fetch should not be called when nothing to submit');

      // Row is gone from all queues
      const verifyStore = await ObservationStore.open(dbPath);
      assert.equal(verifyStore.getUnextracted().length, 0);
      assert.equal(verifyStore.getPending().length, 0);
      verifyStore.close();
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('failure path: submission error leaves rows pending, getPending() returns them', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-artifact-failure-'));
    const dbPath = join(tmpDir, 'test.db');

    const store = await ObservationStore.open(dbPath);
    store.insert(makeRevertItem(revertHash), '/repo');
    store.close();

    const identity = generateTestIdentity();
    globalThis.fetch = async () => makeJsonResponse(403, { error: 'signature_invalid' });

    try {
      const result = await runArtifactPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.submitted, 0, 'Nothing submitted on failure');
      assert.ok(result.error, 'Should have an error message');

      // Row stays pending — retried on next run
      const verifyStore = await ObservationStore.open(dbPath);
      const pending = verifyStore.getPending();
      verifyStore.close();
      assert.equal(pending.length, 1, 'Row should remain pending after failure');
      assert.equal(pending[0]?.commit_hash, revertHash);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('outbound authority: no_signal rows excluded from raw getUnsubmitted', async () => {
    // Confirms that once a row enters the artifact lifecycle (any non-NULL status),
    // the raw submission pipeline (getUnsubmitted) cannot see it.
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-authority-test-'));
    const dbPath = join(tmpDir, 'test.db');

    const store = await ObservationStore.open(dbPath);
    store.insert(makeNormalItem(normalHash), '/repo');
    store.insert(makeRevertItem(revertHash), '/repo');
    store.close();

    const identity = generateTestIdentity();
    globalThis.fetch = async () => makeJsonResponse(403, { error: 'fail' });

    try {
      // Run artifact pipeline — marks normalHash as no_signal, revertHash as pending (then fails)
      await runArtifactPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      // Raw pipeline must NOT see either row
      const verifyStore = await ObservationStore.open(dbPath);
      const unsubmitted = verifyStore.getUnsubmitted();
      verifyStore.close();

      assert.equal(
        unsubmitted.length,
        0,
        'Raw getUnsubmitted() must not return rows that entered the artifact lifecycle',
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
