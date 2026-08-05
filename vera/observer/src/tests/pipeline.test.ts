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

/** A git_commit with workflow language but only README/docs surfaces. */
function makeReadmeOnlyOperatorItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-05T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-05T00:00:00Z',
      message: 'feat: add onboarding workflow notes',
      message_subject: 'feat: add onboarding workflow notes',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'README.md', status: 'modified', additions: 12, deletions: 1 },
        { path: 'docs/onboarding.md', status: 'modified', additions: 9, deletions: 0 },
      ],
      stats: { total_files_changed: 2, total_additions: 21, total_deletions: 1 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-05T00:00:00Z',
  };
}

/** A CLI-heavy operator workflow commit outside the src/routes pattern. */
function makeCliOperatorWorkflowItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-06T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-06T00:00:00Z',
      message: 'feat: make status point to the next action',
      message_subject: 'feat: make status point to the next action',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/commands.js', status: 'modified', additions: 25, deletions: 1 },
        { path: 'src/formatters.js', status: 'modified', additions: 14, deletions: 1 },
        { path: 'test/cli.test.js', status: 'modified', additions: 18, deletions: 0 },
      ],
      stats: { total_files_changed: 3, total_additions: 57, total_deletions: 2 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-06T00:00:00Z',
  };
}

/** A hosted/API workflow commit shaped like the first honest `pulse` S0 miss. */
function makeHostedApiWorkflowItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: hash,
      author_name: 'Test',
      author_email: 'test@example.com',
      author_date: '2026-01-07T00:00:00Z',
      committer_name: 'Test',
      committer_email: 'test@example.com',
      committer_date: '2026-01-07T00:00:00Z',
      message: 'feat(agent-api): Pulse agent API Slice 1 — action endpoints + delegation auth stub',
      message_subject:
        'feat(agent-api): Pulse agent API Slice 1 — action endpoints + delegation auth stub',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'hosted/agent-routes.ts', status: 'modified', additions: 40, deletions: 0 },
        { path: 'hosted/delegation-auth.ts', status: 'modified', additions: 30, deletions: 0 },
        { path: 'hosted/server.ts', status: 'modified', additions: 10, deletions: 0 },
      ],
      stats: { total_files_changed: 3, total_additions: 80, total_deletions: 0 },
      repo_path: '/repo',
    },
    observed_at: '2026-01-07T00:00:00Z',
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
      const body = JSON.parse((init as RequestInit).body as string) as {
        envelope: { observations: unknown[] };
      };
      submittedCount = body.envelope.observations.length;
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
  const readmeOnlyHash = '6'.repeat(40);
  const cliOperatorHash = '5'.repeat(40);
  const hostedApiHash = '4'.repeat(40);

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

  test('README-only workflow commit does not produce operator_workflow_improvement artifact', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeReadmeOnlyOperatorItem(readmeOnlyHash),
    ]);

    assert.equal(matching.length, 0, 'README-only workflow changes should not mint operator lessons');
    assert.equal(nonMatchingHashes.length, 1, 'README-only workflow commit should be treated as no signal');
    assert.equal(nonMatchingHashes[0], readmeOnlyHash);
  });

  test('CLI-heavy status workflow commit produces operator_workflow_improvement artifact', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeCliOperatorWorkflowItem(cliOperatorHash),
    ]);

    assert.equal(matching.length, 1, 'CLI operator workflow changes should mint one operator artifact');
    assert.equal(nonMatchingHashes.length, 0, 'CLI operator workflow commit should not be treated as no signal');

    const m = matching[0]!;
    assert.equal(m.sourceHash, cliOperatorHash);
    assert.equal(m.artifact.artifact_type, 'operator_workflow_improvement');

    const art = m.artifact as import('../lib/types.js').OperatorWorkflowImprovement;
    assert.equal(art.improvement_summary, 'feat: make status point to the next action');
    assert.ok(
      art.surface_files.includes('src/commands.js'),
      'surface_files should include CLI command surfaces',
    );
    assert.ok(
      art.surface_files.includes('src/formatters.js'),
      'surface_files should include CLI formatter surfaces',
    );
    assert.ok(
      art.verification_files.includes('test/cli.test.js'),
      'verification_files should include CLI verification tests',
    );
  });

  test('hosted agent-api workflow commit produces operator_workflow_improvement artifact', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeHostedApiWorkflowItem(hostedApiHash),
    ]);

    assert.equal(
      matching.length,
      1,
      'Hosted/API workflow changes should mint one operator artifact',
    );
    assert.equal(nonMatchingHashes.length, 0, 'Hosted/API workflow commit should not be treated as no signal');

    const m = matching[0]!;
    assert.equal(m.sourceHash, hostedApiHash);
    assert.equal(m.artifact.artifact_type, 'operator_workflow_improvement');

    const art = m.artifact as import('../lib/types.js').OperatorWorkflowImprovement;
    assert.equal(
      art.improvement_summary,
      'feat(agent-api): Pulse agent API Slice 1 — action endpoints + delegation auth stub',
    );
    assert.ok(
      art.surface_files.includes('hosted/agent-routes.ts'),
      'surface_files should include hosted route surfaces',
    );
    assert.ok(
      art.surface_files.includes('hosted/delegation-auth.ts'),
      'surface_files should include hosted auth surfaces',
    );
    assert.ok(
      art.surface_files.includes('hosted/server.ts'),
      'surface_files should include hosted server surfaces',
    );
  });
});

// ---- protocol_primitive_introduction regression cases ----

describe('extractCandidateArtifacts — protocol_primitive_introduction', () => {
  const primitiveHash = 'a'.repeat(40);
  const exportPathHash = 'b'.repeat(40);
  const docsOnlyHash = 'c'.repeat(40);
  const docsOnlySupplyChainHash = 'd'.repeat(40);
  const operatorPreservationHash = '7'.repeat(40);

  /**
   * 3835d82-shaped: feat(supply-chain): UpdateCertificate protocol primitives (Track A)
   * Has src/supply-chain/ and src/heart/*certificate.ts files + test files.
   */
  function makeSupplyChainPrimitiveItem(hash: string): ObservationItem {
    return {
      type: 'git_commit',
      content: {
        commit_hash: hash,
        author_name: 'Test',
        author_email: 'test@example.com',
        author_date: '2026-04-19T00:00:00Z',
        committer_name: 'Test',
        committer_email: 'test@example.com',
        committer_date: '2026-04-19T00:00:00Z',
        message:
          'feat(supply-chain): UpdateCertificate protocol primitives (Track A)\n\nImplements the six Track A deliverables from the update-certificate proposal.',
        message_subject: 'feat(supply-chain): UpdateCertificate protocol primitives (Track A)',
        parent_hashes: [],
        is_merge: false,
        files_changed: [
          { path: 'docs/proposals/update-certificate.md', status: 'added', additions: 865, deletions: 0 },
          { path: 'src/supply-chain/update-certificate.ts', status: 'added', additions: 571, deletions: 0 },
          { path: 'src/supply-chain/index.ts', status: 'modified', additions: 15, deletions: 0 },
          { path: 'src/heart/birth-certificate.ts', status: 'modified', additions: 40, deletions: 8 },
          { path: 'src/heart/certificate/vocabulary.ts', status: 'modified', additions: 2, deletions: 0 },
          { path: 'src/heart/heartbeat.ts', status: 'modified', additions: 4, deletions: 1 },
          { path: 'src/heart/index.ts', status: 'modified', additions: 2, deletions: 0 },
          { path: 'tests/supply-chain/update-certificate.test.ts', status: 'added', additions: 589, deletions: 0 },
          { path: 'tests/supply-chain/package-provenance.test.ts', status: 'added', additions: 279, deletions: 0 },
          { path: 'scripts/embed-release-manifest.mjs', status: 'added', additions: 14, deletions: 0 },
        ],
        stats: { total_files_changed: 10, total_additions: 2381, total_deletions: 9 },
        repo_path: '/Soma',
      },
      observed_at: '2026-04-19T00:00:00Z',
    };
  }

  /**
   * 8b3cbba-shaped: feat(soma-heart): add ./supply-chain export path and bump to 0.9.0
   * Only touches packages/soma-heart/package.json and tsconfig.build.json.
   */
  function makeSupplyChainExportPathItem(hash: string): ObservationItem {
    return {
      type: 'git_commit',
      content: {
        commit_hash: hash,
        author_name: 'Test',
        author_email: 'test@example.com',
        author_date: '2026-04-20T00:00:00Z',
        committer_name: 'Test',
        committer_email: 'test@example.com',
        committer_date: '2026-04-20T00:00:00Z',
        message:
          'feat(soma-heart): add ./supply-chain export path and bump to 0.9.0\n\nAdds ./supply-chain to the soma-heart package.json exports map so ClawNet can import supply-chain primitives directly.',
        message_subject: 'feat(soma-heart): add ./supply-chain export path and bump to 0.9.0',
        parent_hashes: [],
        is_merge: false,
        files_changed: [
          { path: 'packages/soma-heart/package.json', status: 'modified', additions: 7, deletions: 1 },
          { path: 'tsconfig.build.json', status: 'modified', additions: 3, deletions: 1 },
        ],
        stats: { total_files_changed: 2, total_additions: 10, total_deletions: 2 },
        repo_path: '/Soma',
      },
      observed_at: '2026-04-20T00:00:00Z',
    };
  }

  /**
   * Docs-only commit — all changed files are under docs/ or *.md.
   * Message has no supply-chain keywords. Should NOT match protocol_primitive_introduction.
   * (Uses neutral message + docs paths that don't accidentally match operator_workflow heuristics.)
   */
  function makeDocsOnlyItem(hash: string): ObservationItem {
    return {
      type: 'git_commit',
      content: {
        commit_hash: hash,
        author_name: 'Test',
        author_email: 'test@example.com',
        author_date: '2026-04-21T00:00:00Z',
        committer_name: 'Test',
        committer_email: 'test@example.com',
        committer_date: '2026-04-21T00:00:00Z',
        message: 'docs: update changelog and add usage examples',
        message_subject: 'docs: update changelog and add usage examples',
        parent_hashes: [],
        is_merge: false,
        files_changed: [
          { path: 'docs/changelog.md', status: 'modified', additions: 20, deletions: 0 },
          { path: 'docs/usage.md', status: 'added', additions: 50, deletions: 0 },
        ],
        stats: { total_files_changed: 2, total_additions: 70, total_deletions: 0 },
        repo_path: '/Soma',
      },
      observed_at: '2026-04-21T00:00:00Z',
    };
  }

  /**
   * Docs-only commit that mentions supply-chain in message — should NOT match.
   * Guard: allDocsOnly = true, even if message has supply-chain keyword.
   */
  function makeDocsOnlySupplyChainItem(hash: string): ObservationItem {
    return {
      type: 'git_commit',
      content: {
        commit_hash: hash,
        author_name: 'Test',
        author_email: 'test@example.com',
        author_date: '2026-04-22T00:00:00Z',
        committer_name: 'Test',
        committer_email: 'test@example.com',
        committer_date: '2026-04-22T00:00:00Z',
        message: 'docs: track WebAuthn proposal and add ./supply-chain to packages.md',
        message_subject: 'docs: track WebAuthn proposal and add ./supply-chain to packages.md',
        parent_hashes: [],
        is_merge: false,
        files_changed: [
          { path: 'docs/proposals/packages.md', status: 'modified', additions: 12, deletions: 2 },
          { path: 'docs/proposals/webauthn.md', status: 'added', additions: 45, deletions: 0 },
        ],
        stats: { total_files_changed: 2, total_additions: 57, total_deletions: 2 },
        repo_path: '/Soma',
      },
      observed_at: '2026-04-22T00:00:00Z',
    };
  }

  test('positive: 3835d82-shaped supply-chain primitive commit → protocol_primitive_introduction', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeSupplyChainPrimitiveItem(primitiveHash),
    ]);

    assert.equal(matching.length, 1, 'Should produce one matching artifact');
    assert.equal(nonMatchingHashes.length, 0, 'No non-matching hashes');

    const m = matching[0]!;
    assert.equal(m.sourceHash, primitiveHash);
    assert.equal(m.artifact.artifact_type, 'protocol_primitive_introduction');

    const art = m.artifact as import('../lib/types.js').ProtocolPrimitiveIntroduction;
    assert.equal(
      art.introduction_summary,
      'feat(supply-chain): UpdateCertificate protocol primitives (Track A)',
    );
    assert.ok(
      art.impl_files.some((f) => f.includes('src/supply-chain/')),
      'impl_files should include src/supply-chain/ files',
    );
    assert.ok(
      art.impl_files.some((f) => f.includes('birth-certificate')),
      'impl_files should include src/heart/*certificate files',
    );
    assert.ok(
      art.test_files.some((f) => f.includes('tests/supply-chain/')),
      'test_files should include supply-chain test files',
    );
    assert.equal(art.commit_hash, primitiveHash);
    assert.equal(art.stats.total_additions, 2381);
  });

  test('positive: 8b3cbba-shaped export-path + version bump commit → protocol_primitive_introduction', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeSupplyChainExportPathItem(exportPathHash),
    ]);

    assert.equal(matching.length, 1, 'Should produce one matching artifact');
    assert.equal(nonMatchingHashes.length, 0, 'No non-matching hashes');

    const m = matching[0]!;
    assert.equal(m.sourceHash, exportPathHash);
    assert.equal(m.artifact.artifact_type, 'protocol_primitive_introduction');

    const art = m.artifact as import('../lib/types.js').ProtocolPrimitiveIntroduction;
    assert.equal(
      art.introduction_summary,
      'feat(soma-heart): add ./supply-chain export path and bump to 0.9.0',
    );
    assert.ok(
      art.impl_files.some((f) => f.includes('packages/soma-heart/package.json')),
      'impl_files should include the package.json export surface file',
    );
    assert.equal(art.test_files.length, 0, 'No test files in this commit');
    assert.equal(art.stats.total_additions, 10);
  });

  test('negative: docs-only commit (no supply-chain) → no signal', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeDocsOnlyItem(docsOnlyHash),
    ]);

    assert.equal(matching.length, 0, 'Docs-only commit should produce no artifact');
    assert.equal(nonMatchingHashes.length, 1, 'Docs-only commit should be no signal');
    assert.equal(nonMatchingHashes[0], docsOnlyHash);
  });

  test('negative: docs-only commit with supply-chain keyword in message → no signal (docs-only guard)', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeDocsOnlySupplyChainItem(docsOnlySupplyChainHash),
    ]);

    assert.equal(
      matching.length,
      0,
      'Docs-only commit with supply-chain message should not match due to docs-only guard',
    );
    assert.equal(nonMatchingHashes.length, 1, 'Should be no signal');
    assert.equal(nonMatchingHashes[0], docsOnlySupplyChainHash);
  });

  test('preservation: existing operator_workflow_improvement commit still matches (no regression)', () => {
    const { matching, nonMatchingHashes } = extractCandidateArtifacts([
      makeOperatorWorkflowItem(operatorPreservationHash),
    ]);

    assert.equal(matching.length, 1, 'Operator workflow commit should still match');
    assert.equal(nonMatchingHashes.length, 0, 'Should not fall into no-signal');

    const m = matching[0]!;
    assert.equal(m.artifact.artifact_type, 'operator_workflow_improvement',
      'Should still produce operator_workflow_improvement, not the new kind');
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

  test('artifact submission preserves repo_path in outbound observation content', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'vera-artifact-repo-path-'));
    const dbPath = join(tmpDir, 'test.db');

    const store = await ObservationStore.open(dbPath);
    store.insert(makeFixWithTestItem(fixHash), '/pulse');
    store.close();

    const identity = generateTestIdentity();
    let submittedRepoPath: string | undefined;
    globalThis.fetch = async (_input, init) => {
      const body = JSON.parse((init as RequestInit).body as string) as {
        envelope: { observations: Array<{ content?: { repo_path?: string } }> };
      };
      submittedRepoPath = body.envelope.observations[0]?.content?.repo_path;
      return makeJsonResponse(201, {
        batch: {
          id: 'artifact-batch-repo-path',
          user_id: 'user-1',
          source_type: 'artifact',
          observation_count: body.envelope.observations.length,
          created_at: '2026-01-01T00:00:00Z',
        },
      });
    };

    try {
      const result = await runArtifactPipeline({
        dbPath,
        veraKnowledgeUrl: 'http://localhost:3000',
        identity,
      });

      assert.equal(result.submitted, 1, 'Artifact observation should be submitted');
      assert.equal(submittedRepoPath, '/pulse', `expected repo_path=/pulse, got: ${submittedRepoPath}`);
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
