/**
 * Live artifact integration test — vera-observer artifact pipeline → veraAI end-to-end.
 *
 * Proves the full vertical slice under live infrastructure:
 *   1. Generate a fresh Soma identity and register with veraAI /v1/register
 *   2. Seed a temp SQLite store with synthetic observations matching artifact
 *      extraction heuristics (one test_backed_resolution, one failure_to_fix_journey)
 *   3. Run runArtifactPipeline() — evaluates, marks pending, submits artifacts
 *      to veraAI /v1/observations, returns a batchId (UUID)
 *   4. POST /v1/aggregate with guardian-auth headers signed inline using
 *      soma-heart crypto (same primitives as veraAI/src/guardian/signer.ts)
 *   5. Verify PostgreSQL: knowledge_entries rows with lesson_status='provisional'
 *
 * SKIP GUARD: If veraAI is not reachable at http://localhost:3100, this test
 * skips with a clear message. During the official integration lane the server
 * MUST be live.
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
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import postgres from 'postgres';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { generateTestIdentity } from '../lib/identity.js';
import { ObservationStore } from '../lib/store.js';
import { runArtifactPipeline } from '../lib/pipeline.js';
import type { ObservationItem } from '../lib/types.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const VERA_KNOWLEDGE_URL = 'http://localhost:3100';

// Support env override for CI or non-default setups (docker-compose default shown)
const DB_URL =
  process.env['VERA_KNOWLEDGE_DB_URL'] ??
  'postgresql://vera:vera_dev@localhost:5433/vera_knowledge';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns true if veraAI /health responds with 200 within 3 s. */
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

/**
 * Synthetic git_commit observation matching test_backed_resolution heuristics:
 *   - message contains 'fix' (matches FIX_MESSAGE_RE)
 *   - files_changed has a path matching /\.test\./ (matches TEST_FILE_RE)
 *
 * The commit_hash must be exactly 40 hex characters.
 */
function makeTestBackedResolutionObs(commitHash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: commitHash,
      author_name: 'Artifact Integration Test',
      author_email: 'test@vera.example',
      author_date: '2026-05-01T00:00:00Z',
      committer_name: 'Artifact Integration Test',
      committer_email: 'test@vera.example',
      committer_date: '2026-05-01T00:00:00Z',
      message: 'fix: resolve edge case in authentication flow',
      message_subject: 'fix: resolve edge case in authentication flow',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/auth.service.test.ts', status: 'modified', additions: 8, deletions: 2 },
        { path: 'src/auth.service.ts',      status: 'modified', additions: 3, deletions: 1 },
      ],
      stats: { total_files_changed: 2, total_additions: 11, total_deletions: 3 },
      repo_path: '/synthetic',
    },
    observed_at: '2026-05-01T00:00:00Z',
  };
}

/**
 * Synthetic git_commit observation matching failure_to_fix_journey heuristics:
 *   - message_subject starts with 'Revert ' (triggers signal='revert')
 *
 * The commit_hash must be exactly 40 hex characters.
 */
function makeFailureToFixJourneyObs(commitHash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: {
      commit_hash: commitHash,
      author_name: 'Artifact Integration Test',
      author_email: 'test@vera.example',
      author_date: '2026-05-01T01:00:00Z',
      committer_name: 'Artifact Integration Test',
      committer_email: 'test@vera.example',
      committer_date: '2026-05-01T01:00:00Z',
      message: 'Revert "Add retry logic to payment processor"',
      message_subject: 'Revert "Add retry logic to payment processor"',
      parent_hashes: [],
      is_merge: false,
      files_changed: [
        { path: 'src/payment.ts', status: 'modified', additions: 0, deletions: 15 },
      ],
      stats: { total_files_changed: 1, total_additions: 0, total_deletions: 15 },
      repo_path: '/synthetic',
    },
    observed_at: '2026-05-01T01:00:00Z',
  };
}

// ── Integration test ──────────────────────────────────────────────────────────

test('vera-observer artifact pipeline → veraAI aggregate → provisional lesson (live integration)', async (t) => {
  // ── Skip guard ────────────────────────────────────────────────────────────────
  // Skip gracefully when the server is not running.
  const reachable = await isServerReachable();
  if (!reachable) {
    t.skip(
      'veraAI not reachable at http://localhost:3100 — skipping artifact integration test'
    );
    return;
  }

  // Temp directory for the SQLite store (always cleaned up in finally)
  const tmpDir = mkdtempSync(join(tmpdir(), 'vera-artifact-int-'));
  const dbPath = join(tmpDir, 'artifact-integration.db');
  let sql: ReturnType<typeof postgres> | undefined;

  try {
    // ── Step 1: Generate and register a fresh Soma identity ──────────────────
    // Each test run uses a unique DID so registrations never collide.
    const identity = generateTestIdentity();

    const registerRes = await fetch(`${VERA_KNOWLEDGE_URL}/v1/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        soma_did: identity.somaDid,
        public_key: identity.publicKeyB64,
        display_name: 'vera-observer artifact integration test',
      }),
    });

    if (registerRes.status !== 201) {
      const body = await registerRes.text();
      assert.fail(`Registration should return 201, got ${registerRes.status}: ${body}`);
    }

    const registerData = (await registerRes.json()) as {
      user: { id: string; soma_did: string };
    };
    assert.equal(
      registerData.user.soma_did,
      identity.somaDid,
      'Registered soma_did should match the generated identity'
    );

    // ── Step 2: Seed temp SQLite store with synthetic artifact-matching observations ─
    // Generate unique 40-char hex hashes for this test run (avoids SQLite UNIQUE
    // constraint collisions on repeated runs since each run uses fresh hashes).
    const runSeed = randomUUID().replace(/-/g, ''); // 32 hex chars, unique per run
    const fixHash    = runSeed + '00000001'; // 40 chars — matches test_backed_resolution
    const revertHash = runSeed + '00000002'; // 40 chars — matches failure_to_fix_journey

    const store = await ObservationStore.open(dbPath);
    store.insertMany(
      [
        makeTestBackedResolutionObs(fixHash),
        makeFailureToFixJourneyObs(revertHash),
      ],
      '/synthetic',
    );
    store.close();

    // ── Step 3: Run artifact pipeline ─────────────────────────────────────────
    // Phase A: evaluates both rows, marks them 'pending'.
    // Phase B: re-derives artifacts, submits to veraAI /v1/observations.
    const pipelineResult = await runArtifactPipeline({
      dbPath,
      veraKnowledgeUrl: VERA_KNOWLEDGE_URL,
      identity,
      batchSize: 50,
    });

    assert.ok(
      pipelineResult.submitted > 0,
      `Pipeline should have submitted > 0 artifacts, got ${pipelineResult.submitted}. ` +
        `Pipeline error: ${pipelineResult.error ?? 'none'}`
    );
    assert.ok(
      pipelineResult.batchId !== undefined,
      `Pipeline should return a batchId on success. Pipeline error: ${pipelineResult.error ?? 'none'}`
    );

    const batchId = pipelineResult.batchId as string;
    assert.ok(
      isValidUUID(batchId),
      `batchId should be a valid UUID, got: ${batchId}`
    );

    // ── Step 4: POST /v1/aggregate with guardian-auth headers ─────────────────
    // Guardian signing mirrors veraAI/src/middleware/guardian-auth.ts lines 134–141:
    //   signingInput = JSON.stringify({ method, path, body, timestamp, nonce })
    // We sign with soma-heart Ed25519 using the same identity registered above.
    const provider = getCryptoProvider();

    const aggregateBody = {
      soma_did: identity.somaDid,
      batch_id: batchId,
    };

    const timestamp = new Date().toISOString();
    // 32 hex chars = 16 bytes — satisfies server's ≥32 char nonce requirement
    const nonce = randomUUID().replace(/-/g, '');

    // Canonical signing input — must exactly match guardian-auth.ts reconstruction
    const signingInput = JSON.stringify({
      method: 'POST',
      path: '/v1/aggregate',
      body: aggregateBody,
      timestamp,
      nonce,
    });

    const inputBytes = new TextEncoder().encode(signingInput);
    const signatureBytes = provider.signing.sign(inputBytes, identity.secretKey);
    const signature = provider.encoding.encodeBase64(signatureBytes);

    const aggregateRes = await fetch(`${VERA_KNOWLEDGE_URL}/v1/aggregate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Guardian-Signature': signature,
        'X-Guardian-Timestamp': timestamp,
        'X-Guardian-Nonce': nonce,
      },
      body: JSON.stringify(aggregateBody),
    });

    if (aggregateRes.status !== 201) {
      const body = await aggregateRes.text();
      assert.fail(
        `/v1/aggregate should return 201, got ${aggregateRes.status}: ${body}`
      );
    }

    const aggregateData = (await aggregateRes.json()) as {
      created: Array<{ id: string; entry_type: string; title: string }>;
      count: number;
    };

    assert.ok(
      aggregateData.count >= 2,
      `Aggregate should have created >= 2 knowledge entries, got ${aggregateData.count}`
    );

    // ── Step 5: PG verification ────────────────────────────────────────────────
    sql = postgres(DB_URL, { max: 1, idle_timeout: 10 });

    // 5a. Get observation IDs for this batch (these are the artifact observations
    //     stored with observation_type = 'test_backed_resolution' / 'failure_to_fix_journey')
    interface ObservationRow {
      id: string;
      observation_type: string;
    }

    const obsRows = await sql<ObservationRow[]>`
      SELECT id, observation_type
        FROM observations
       WHERE batch_id = ${batchId}
       ORDER BY observation_type ASC
    `;

    assert.ok(
      obsRows.length >= 2,
      `Expected >= 2 observation rows in PG for batch ${batchId}, got ${obsRows.length}`
    );

    // 5b. Get knowledge_entries derived from those observations.
    //     source_observation_ids is a uuid[] column; && checks for array overlap.
    interface KnowledgeEntryRow {
      id: string;
      source_observation_ids: string[];
      entry_type: string;
      title: string;
      confidence: number;
      tags: string[] | null;
      lesson_status: string;
    }

    const knowledgeRows = await sql<KnowledgeEntryRow[]>`
      SELECT ke.id,
             ke.source_observation_ids,
             ke.entry_type,
             ke.title,
             ke.confidence,
             ke.tags,
             ke.lesson_status
        FROM knowledge_entries ke
       WHERE ke.source_observation_ids && (
         SELECT array_agg(o.id) FROM observations o WHERE o.batch_id = ${batchId}
       )
    `;

    // 5c. At least 2 rows
    assert.ok(
      knowledgeRows.length >= 2,
      `Expected >= 2 knowledge_entries rows for batch ${batchId}, got ${knowledgeRows.length}`
    );

    // 5d. Per-row assertions: lesson_status, entry_type, confidence, day0 tag
    for (const row of knowledgeRows) {
      assert.equal(
        row.lesson_status,
        'provisional',
        `Row ${row.id}: lesson_status should be 'provisional', got '${row.lesson_status}'`
      );
      assert.equal(
        row.entry_type,
        'provisional_lesson',
        `Row ${row.id}: entry_type should be 'provisional_lesson', got '${row.entry_type}'`
      );
      // real column: may not be exactly 0.1 due to 32-bit float representation
      assert.ok(
        Math.abs(Number(row.confidence) - 0.1) < 0.001,
        `Row ${row.id}: confidence should be ~0.1, got ${row.confidence}`
      );
      const tags = row.tags ?? [];
      assert.ok(
        tags.includes('day0'),
        `Row ${row.id}: tags should include 'day0', got [${tags.join(', ')}]`
      );
    }

    // 5e. At least one row has tag 'test_backed_resolution'
    const hasTbr = knowledgeRows.some((r) => (r.tags ?? []).includes('test_backed_resolution'));
    assert.ok(
      hasTbr,
      `Expected at least one knowledge_entries row with tag 'test_backed_resolution'`
    );

    // 5f. At least one row has tag 'failure_to_fix_journey'
    const hasFtf = knowledgeRows.some((r) => (r.tags ?? []).includes('failure_to_fix_journey'));
    assert.ok(
      hasFtf,
      `Expected at least one knowledge_entries row with tag 'failure_to_fix_journey'`
    );

  } finally {
    // Always close the PostgreSQL connection and clean up the temp SQLite file.
    if (sql !== undefined) {
      await sql.end();
    }
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
