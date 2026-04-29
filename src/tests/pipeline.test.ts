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
import { runSubmissionPipeline } from '../lib/pipeline.js';
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
