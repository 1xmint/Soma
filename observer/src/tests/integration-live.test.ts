/**
 * Live integration test — vera-observer → vera-knowledge end-to-end.
 *
 * Validates the full submission pipeline against a live vera-knowledge server:
 *   1. Generate a fresh Soma identity
 *   2. Register it with vera-knowledge (POST /v1/register)
 *   3. Observe real git commits from the vera-observer repo itself
 *   4. Store them in a temp SQLite DB via ObservationStore
 *   5. Run runSubmissionPipeline() — signs + POSTs to vera-knowledge
 *   6. Assert: submitted > 0, failed === 0, batchId is a UUID
 *   7. Verify the batch landed in PostgreSQL via a direct SQL query
 *   8. Clean up the temp SQLite DB
 *
 * SKIP GUARD: If vera-knowledge is not reachable at http://localhost:3100,
 * this test skips with a clear message. This guard exists so developers can
 * run `npm test` without the server running. During the official integration
 * lane the server MUST be live.
 *
 * Prerequisites to run this test:
 *   1. cd veraAI && docker compose up -d    (PostgreSQL on :5433)
 *   2. cd veraAI && npm run db:migrate
 *   3. cd veraAI && npm run dev              (server on :3100)
 *   4. curl http://localhost:3100/health     (confirm 200)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';
import { generateTestIdentity } from '../lib/identity.js';
import { observeGitCommits } from '../lib/git-observer.js';
import { ObservationStore } from '../lib/store.js';
import { runSubmissionPipeline } from '../lib/pipeline.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const VERA_KNOWLEDGE_URL = 'http://localhost:3100';

// Support env override for CI or non-default setups (docker-compose default shown)
const DB_URL =
  process.env['VERA_KNOWLEDGE_DB_URL'] ??
  'postgresql://vera:vera_dev@localhost:5433/vera_knowledge';

// Compute repo root from compiled output location:
//   dist/tests/integration-live.test.js → dirname → dist/tests → .. → dist → .. → repo root
const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_PATH = join(__dirname, '..', '..');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns true if vera-knowledge /health responds with 200 within 3 s. */
async function isServerReachable(): Promise<boolean> {
  try {
    const res = await fetch(`${VERA_KNOWLEDGE_URL}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** UUID v4 validation. */
function isValidUUID(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

// ── Integration test ──────────────────────────────────────────────────────────

test('vera-observer → vera-knowledge live integration', async (t) => {
  // ── Skip guard ───────────────────────────────────────────────────────────────
  // Skip gracefully when the server is not running. This guard is for future
  // developer convenience — the test must be live during the official integration lane.
  const reachable = await isServerReachable();
  if (!reachable) {
    t.skip(
      'vera-knowledge not reachable at http://localhost:3100 — skipping integration test'
    );
    return;
  }

  // Temp directory for the SQLite store (always cleaned up in finally)
  const tmpDir = mkdtempSync(join(tmpdir(), 'vera-integration-'));
  const dbPath = join(tmpDir, 'integration.db');
  let sql: ReturnType<typeof postgres> | undefined;

  try {
    // ── Step 1: Generate a fresh Soma identity ─────────────────────────────────
    // Each test run uses a unique DID so registrations never collide.
    const identity = generateTestIdentity();

    // ── Step 2: Register with vera-knowledge ──────────────────────────────────
    const registerRes = await fetch(`${VERA_KNOWLEDGE_URL}/v1/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        soma_did: identity.somaDid,
        public_key: identity.publicKeyB64,
        display_name: 'vera-observer integration test',
      }),
    });

    if (registerRes.status !== 201) {
      const body = await registerRes.text();
      assert.fail(
        `Registration should return 201, got ${registerRes.status}: ${body}`
      );
    }

    const registerData = (await registerRes.json()) as {
      user: { id: string; soma_did: string };
    };
    assert.equal(
      registerData.user.soma_did,
      identity.somaDid,
      'Registered soma_did should match the generated identity'
    );
    assert.ok(
      isValidUUID(registerData.user.id),
      `Registered user.id should be a UUID, got: ${registerData.user.id}`
    );

    // ── Step 3: Observe real git commits from the vera-observer repo ───────────
    // Uses the repo that contains this test file itself — no external dependency.
    const { observations, count } = observeGitCommits({
      repoPath: REPO_PATH,
      limit: 5,
    });
    assert.ok(
      count >= 1,
      `observeGitCommits should find at least 1 commit in ${REPO_PATH}, found ${count}`
    );
    assert.ok(
      count <= 5,
      `observeGitCommits with limit=5 should return at most 5, found ${count}`
    );

    // ── Step 4: Store observations in temp SQLite DB ───────────────────────────
    const store = await ObservationStore.open(dbPath);
    const inserted = store.insertMany(observations, REPO_PATH);
    store.close();
    assert.ok(
      inserted >= 1,
      `Should have inserted at least 1 observation into the store, got ${inserted}`
    );

    // ── Step 5: Run the submission pipeline ────────────────────────────────────
    // runSubmissionPipeline: reads unsubmitted from store → signs → POSTs to server
    const pipelineResult = await runSubmissionPipeline({
      dbPath,
      veraKnowledgeUrl: VERA_KNOWLEDGE_URL,
      identity,
      batchSize: 5,
    });

    // ── Step 6: Assert pipeline result ────────────────────────────────────────
    assert.ok(
      pipelineResult.submitted > 0,
      `Pipeline should have submitted > 0 observations, got ${pipelineResult.submitted}. ` +
        `Pipeline error: ${pipelineResult.error ?? 'none'}`
    );
    assert.equal(
      pipelineResult.failed,
      0,
      `Pipeline should have 0 failures, got ${pipelineResult.failed}. ` +
        `Pipeline error: ${pipelineResult.error ?? 'none'}`
    );
    assert.ok(
      pipelineResult.batchId !== undefined,
      'Pipeline should return a batchId on success'
    );

    const batchId = pipelineResult.batchId as string;
    assert.ok(
      isValidUUID(batchId),
      `batchId should be a UUID, got: ${batchId}`
    );

    // ── Step 7: Verify in PostgreSQL via direct SQL query ─────────────────────
    // Do NOT use /v1/aggregate or /v1/query — those require guardian auth.
    // Instead, query the database directly using the DATABASE_URL from veraAI/.env.
    sql = postgres(DB_URL, { max: 1, idle_timeout: 10 });

    interface BatchObservationRow {
      batch_id: string;
      source_type: string;
      soma_signature: string;
      observation_type: string;
      content: Record<string, unknown>;
      observed_at: Date;
    }

    const rows = await sql<BatchObservationRow[]>`
      SELECT ob.id        AS batch_id,
             ob.source_type,
             ob.soma_signature,
             o.observation_type,
             o.content,
             o.observed_at
        FROM observation_batches ob
        JOIN observations o ON o.batch_id = ob.id
       WHERE ob.id = ${batchId}
       ORDER BY o.observed_at ASC
    `;

    // Assert batch exists
    assert.ok(
      rows.length > 0,
      `Batch ${batchId} should exist in PostgreSQL with at least one observation row`
    );

    // Assert row count matches submitted count
    assert.equal(
      rows.length,
      pipelineResult.submitted,
      `PostgreSQL should have ${pipelineResult.submitted} observation rows for batch ${batchId}, found ${rows.length}`
    );

    // Assert source_type is correct on every row
    const wrongSourceType = rows.find((r) => r.source_type !== 'git');
    assert.ok(
      wrongSourceType === undefined,
      `All batch rows should have source_type='git', found: ${wrongSourceType?.source_type ?? 'unknown'}`
    );

    // Assert all observations are git_commit type
    const wrongObsType = rows.find((r) => r.observation_type !== 'git_commit');
    assert.ok(
      wrongObsType === undefined,
      `All observation rows should have observation_type='git_commit', found: ${wrongObsType?.observation_type ?? 'unknown'}`
    );

    // Assert content JSONB contains expected git commit fields
    const firstRow = rows[0];
    assert.ok(firstRow !== undefined, 'First observation row should exist');
    const content = firstRow.content;

    const commitHash = content['commit_hash'];
    assert.ok(
      typeof commitHash === 'string' && commitHash.length === 40,
      `content.commit_hash should be a 40-char hex string, got: ${JSON.stringify(commitHash)}`
    );

    const message = content['message'];
    assert.ok(
      typeof message === 'string',
      `content.message should be a string, got: ${typeof message}`
    );

    const authorName = content['author_name'];
    assert.ok(
      typeof authorName === 'string',
      `content.author_name should be a string, got: ${typeof authorName}`
    );

    // Signing contract validated: if we got here with 201 from the server,
    // the server successfully verified our Ed25519 signature over
    // JSON.stringify(observations). No signing mismatch.
  } finally {
    // Always close the PostgreSQL connection and clean up the temp DB file.
    if (sql !== undefined) {
      await sql.end();
    }
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
