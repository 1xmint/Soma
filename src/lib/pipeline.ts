/**
 * Submission pipeline.
 *
 * Orchestrates the full observe → submit → mark-submitted loop:
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
import type { ObservationItem } from './types.js';

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
  config: PipelineConfig
): Promise<PipelineResult> {
  const { dbPath, veraKnowledgeUrl, identity, batchSize = 50 } = config;

  const store = await ObservationStore.open(dbPath);

  try {
    const unsubmitted = store.getUnsubmitted(batchSize);

    if (unsubmitted.length === 0) {
      return { submitted: 0, failed: 0 };
    }

    // Build ObservationItem array (strip local-only fields)
    const observations: ObservationItem[] = unsubmitted.map((r) => ({
      type: r.type,
      content: r.content,
      observed_at: r.observed_at,
    }));

    const result = await submitObservations(
      { veraKnowledgeUrl, identity },
      observations
    );

    if (result.success) {
      // Collect the commit hashes for the submitted records so we can mark them.
      // Records without a commit_hash (non-git types) still get marked — we use
      // their IDs as a fallback key.  For now markSubmitted uses commit_hash, so
      // we filter only records that have one; the rest will be retried (acceptable
      // Day 0 behaviour for non-git types which don't exist yet).
      const hashes = unsubmitted
        .map((r) => r.commit_hash)
        .filter((h): h is string => h !== undefined && h !== null);

      store.markSubmitted(hashes, result.batchId);
      return {
        submitted: unsubmitted.length,
        failed: 0,
        batchId: result.batchId,
      };
    } else {
      console.error(
        `[vera-observer] Submission failed (HTTP ${result.statusCode}): ${result.error}`
      );
      return {
        submitted: 0,
        failed: unsubmitted.length,
        error: result.error,
      };
    }
  } finally {
    store.close();
  }
}
