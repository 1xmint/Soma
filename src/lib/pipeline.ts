/**
 * Submission pipeline.
 *
 * Orchestrates the full observe -> submit -> mark-submitted loop:
 *   1. Open the local store
 *   2. Fetch unsubmitted observations (up to batchSize)
 *   3. Sign and POST to vera-knowledge via submitObservations()
 *   4. On success: mark the submitted records with the returned batch ID
 *   5. On failure: log the error, leave records unsubmitted (retry next run)
 *
 * This is a batch, not a daemon. Call it on a schedule or after each commit.
 */

import { ObservationStore } from './store.js';
import { submitObservations } from './submitter.js';
import type { SomaIdentity } from './identity.js';
import type { ObservationItem, CandidateArtifact } from './types.js';

// ---- Types ----

export interface PipelineConfig {
  /** Absolute path to the local SQLite database file */
  dbPath: string;
  /** Base URL of the vera-knowledge server, e.g. "https://vera.example.com" */
  veraKnowledgeUrl: string;
  /** Soma identity used to sign the submission */
  identity: SomaIdentity;
  /** Maximum number of observations to include in one submission batch. Default 50. */
  batchSize?: number;
}

export interface PipelineResult {
  submitted: number;
  failed: number;
  batchId?: string;
  error?: string;
}

export interface ArtifactPipelineResult {
  /** Number of rows evaluated by extraction heuristics in this run (0 if skipped). */
  evaluated: number;
  /** Rows marked 'no_signal' (no artifact match) in this run. */
  noSignal: number;
  /** Rows marked 'pending' (artifact derived) in Phase A of this run. */
  pending: number;
  /** Rows whose artifacts were successfully submitted in Phase B. */
  submitted: number;
  /** Batch ID returned by vera-knowledge on successful Phase B submission. */
  batchId?: string;
  /** Error message if Phase B submission failed. */
  error?: string;
}

// ---- Artifact extraction heuristics ----

const TEST_FILE_RE = /\.test\.|\/tests\//;
const FIX_MESSAGE_RE = /fix|resolve|repair|correct/i;
const FAILURE_MESSAGE_RE = /revert|retry|attempt|wip.*fix/i;
const RETRY_ATTEMPT_RE = /retry|attempt/i;
const OPERATOR_MESSAGE_RE =
  /operator|onboarding|inspect|catalog|govern|registration|register|workflow|review guidance/i;
const OPERATOR_SURFACE_RE =
  /^(src\/commands\/|src\/routes\/(catalog|inspect|govern|register|status|agents|contributions)|docs\/|README\.md$)/i;

/**
 * Evaluate a batch of observations and extract candidate artifacts.
 *
 * Returns:
 *   matching         - artifacts derived with their source commit hash
 *   nonMatchingHashes - commit hashes of observations that produced no artifact
 *
 * Only processes 'git_commit' observations. Other types are silently skipped
 * (they will remain in getUnextracted() until explicitly handled).
 */
export function extractCandidateArtifacts(
  observations: ObservationItem[],
): {
  matching: Array<{ artifact: CandidateArtifact; sourceHash: string }>;
  nonMatchingHashes: string[];
} {
  const matching: Array<{ artifact: CandidateArtifact; sourceHash: string }> = [];
  const nonMatchingHashes: string[] = [];

  for (const obs of observations) {
    if (obs.type !== 'git_commit') continue;

    const content = obs.content as Record<string, unknown>;
    const commitHash = content['commit_hash'];
    if (typeof commitHash !== 'string' || commitHash.length !== 40) continue;

    const message = typeof content['message'] === 'string' ? content['message'] : '';
    const messageSubject =
      typeof content['message_subject'] === 'string' ? content['message_subject'] : '';
    const filesChanged = Array.isArray(content['files_changed'])
      ? (content['files_changed'] as Array<{ path: string }>)
      : [];
    const stats = (content['stats'] ?? {}) as {
      total_additions?: number;
      total_deletions?: number;
    };

    // Priority 1: test_backed_resolution
    // Requires: test files present AND fix-type message.
    const testFiles = filesChanged.filter((f) => TEST_FILE_RE.test(f.path)).map((f) => f.path);
    const sourceFiles = filesChanged.filter((f) => !TEST_FILE_RE.test(f.path)).map((f) => f.path);

    if (testFiles.length > 0 && FIX_MESSAGE_RE.test(message)) {
      matching.push({
        artifact: {
          artifact_type: 'test_backed_resolution',
          resolution_summary: messageSubject || message,
          test_files: testFiles,
          source_files: sourceFiles,
          commit_hash: commitHash,
          stats: {
            total_additions:
              typeof stats['total_additions'] === 'number' ? stats['total_additions'] : 0,
            total_deletions:
              typeof stats['total_deletions'] === 'number' ? stats['total_deletions'] : 0,
          },
        },
        sourceHash: commitHash,
      });
      continue;
    }

    // Priority 1.5: operator_workflow_improvement
    // Requires: operator-facing surfaces touched AND workflow-oriented message.
    const operatorSurfaceFiles = filesChanged
      .filter((f) => OPERATOR_SURFACE_RE.test(f.path))
      .map((f) => f.path);

    if (operatorSurfaceFiles.length > 0 && OPERATOR_MESSAGE_RE.test(message)) {
      matching.push({
        artifact: {
          artifact_type: 'operator_workflow_improvement',
          improvement_summary: messageSubject || message,
          surface_files: operatorSurfaceFiles,
          verification_files: testFiles,
          commit_hash: commitHash,
          stats: {
            total_additions:
              typeof stats['total_additions'] === 'number' ? stats['total_additions'] : 0,
            total_deletions:
              typeof stats['total_deletions'] === 'number' ? stats['total_deletions'] : 0,
          },
        },
        sourceHash: commitHash,
      });
      continue;
    }

    // Priority 2: failure_to_fix_journey
    // Requires: revert/retry/attempt/wip.*fix message OR "Revert " subject prefix.
    if (FAILURE_MESSAGE_RE.test(message) || messageSubject.startsWith('Revert ')) {
      const signal = messageSubject.startsWith('Revert ')
        ? 'revert'
        : RETRY_ATTEMPT_RE.test(message)
          ? 'retry'
          : 'wip_fix';

      matching.push({
        artifact: {
          artifact_type: 'failure_to_fix_journey',
          journey_summary: messageSubject || message,
          attempt_hashes: [commitHash],
          target_files: filesChanged.map((f) => f.path),
          signal,
        },
        sourceHash: commitHash,
      });
      continue;
    }

    // No match
    nonMatchingHashes.push(commitHash);
  }

  return { matching, nonMatchingHashes };
}

// ---- Public API ----

/**
 * Run one submission cycle:
 *   - Read up to batchSize unsubmitted observations
 *   - Submit them to vera-knowledge
 *   - Mark them as submitted on success
 *
 * Returns counts of submitted / failed observations.
 * On failure, observations remain unsubmitted and can be retried.
 */
export async function runSubmissionPipeline(
  config: PipelineConfig,
): Promise<PipelineResult> {
  const { dbPath, veraKnowledgeUrl, identity, batchSize = 50 } = config;

  const store = await ObservationStore.open(dbPath);

  try {
    const unsubmitted = store.getUnsubmitted(batchSize);

    if (unsubmitted.length === 0) {
      return { submitted: 0, failed: 0 };
    }

    const observations: ObservationItem[] = unsubmitted.map((r) => ({
      type: r.type,
      content: r.content,
      observed_at: r.observed_at,
    }));

    const result = await submitObservations(
      { veraKnowledgeUrl, identity },
      observations,
    );

    if (result.success) {
      const hashes = unsubmitted
        .map((r) => r.commit_hash)
        .filter((h): h is string => h !== undefined && h !== null);

      store.markSubmitted(hashes, result.batchId);
      return {
        submitted: unsubmitted.length,
        failed: 0,
        batchId: result.batchId,
      };
    }

    console.error(
      `[vera-observer] Submission failed (HTTP ${result.statusCode}): ${result.error}`,
    );
    return {
      submitted: 0,
      failed: unsubmitted.length,
      error: result.error,
    };
  } finally {
    store.close();
  }
}

/**
 * Run one artifact pipeline cycle (two-phase):
 *
 * Phase A - Evaluate unextracted observations
 * Phase B - Submit pending artifacts
 *
 * Delivery guarantee: at-least-once. A crash between submission and status
 * update leaves rows as 'pending', causing re-submission on next run.
 */
export async function runArtifactPipeline(
  config: PipelineConfig,
): Promise<ArtifactPipelineResult> {
  const { dbPath, veraKnowledgeUrl, identity, batchSize = 50 } = config;
  const store = await ObservationStore.open(dbPath);

  const result: ArtifactPipelineResult = {
    evaluated: 0,
    noSignal: 0,
    pending: 0,
    submitted: 0,
  };

  try {
    const newRows = store.getUnextracted(batchSize);

    if (newRows.length > 0) {
      result.evaluated = newRows.length;

      const { matching, nonMatchingHashes } = extractCandidateArtifacts(newRows);

      if (nonMatchingHashes.length > 0) {
        store.setArtifactStatus(nonMatchingHashes, 'no_signal');
        result.noSignal = nonMatchingHashes.length;
      }

      const matchingHashes = matching.map((m) => m.sourceHash);
      if (matchingHashes.length > 0) {
        store.setArtifactStatus(matchingHashes, 'pending');
        result.pending = matchingHashes.length;
      }
    }

    const pendingRows = store.getPending(batchSize);

    if (pendingRows.length === 0) {
      return result;
    }

    const { matching: pendingArtifacts } = extractCandidateArtifacts(pendingRows);

    if (pendingArtifacts.length === 0) {
      return result;
    }

    const observedAtByHash = new Map<string, string>();
    for (const row of pendingRows) {
      if (row.commit_hash) {
        observedAtByHash.set(row.commit_hash, row.observed_at);
      }
    }

    const wrappedItems: ObservationItem[] = pendingArtifacts.map((m) => ({
      type: m.artifact.artifact_type,
      content: m.artifact as Record<string, unknown>,
      observed_at: observedAtByHash.get(m.sourceHash) ?? new Date().toISOString(),
    }));

    try {
      const submitResult = await submitObservations(
        { veraKnowledgeUrl, identity, sourceType: 'artifact' },
        wrappedItems,
      );

      if (submitResult.success) {
        const submittedHashes = pendingArtifacts.map((m) => m.sourceHash);
        store.setArtifactStatus(submittedHashes, 'submitted');
        result.submitted = submittedHashes.length;
        result.batchId = submitResult.batchId;
      } else {
        result.error = submitResult.error;
      }
    } catch (err: unknown) {
      result.error = err instanceof Error ? err.message : String(err);
    }

    return result;
  } finally {
    store.close();
  }
}
