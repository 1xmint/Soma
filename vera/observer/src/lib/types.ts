/**
 * vera-observer type definitions and Zod schemas.
 *
 * These types are compatible with vera-knowledge's ObservationItem schema:
 *   { type: string, content: Record<string, unknown>, observed_at: string }
 *
 * GitCommitObservation is the content shape for type="git_commit".
 */

import { z } from 'zod';

// ---- File change within a commit ----

export const fileChangeSchema = z.object({
  path: z.string().min(1),
  /** 'A' added, 'M' modified, 'D' deleted, 'R' renamed, 'C' copied, 'T' type-changed */
  status: z.enum(['added', 'modified', 'deleted', 'renamed', 'copied', 'type-changed', 'unknown']),
  additions: z.number().int().min(0),
  deletions: z.number().int().min(0),
  /** Original path before rename/copy. Only present for renamed/copied files. */
  old_path: z.string().optional(),
});

export type FileChange = z.infer<typeof fileChangeSchema>;

// ---- Git commit content (goes in ObservationItem.content) ----

/**
 * A bounded excerpt of added lines from a seam-adjacent file.
 * At most 3 excerpts per commit, at most 10 lines each.
 */
export const signatureExcerptSchema = z.object({
  /** Repo-relative file path */
  file: z.string().min(1),
  /** Added lines (up to 10) from type/function/interface declarations */
  lines: z.array(z.string()).max(10),
});

export type SignatureExcerpt = z.infer<typeof signatureExcerptSchema>;

export const gitCommitObservationSchema = z.object({
  commit_hash: z.string().length(40),
  author_name: z.string(),
  author_email: z.string(),
  author_date: z.string(), // ISO 8601
  committer_name: z.string(),
  committer_email: z.string(),
  committer_date: z.string(), // ISO 8601
  message: z.string(),
  /** Short (first line) of the commit message */
  message_subject: z.string(),
  parent_hashes: z.array(z.string()),
  is_merge: z.boolean(),
  files_changed: z.array(fileChangeSchema),
  stats: z.object({
    total_files_changed: z.number().int().min(0),
    total_additions: z.number().int().min(0),
    total_deletions: z.number().int().min(0),
  }),
  /** Path to the repo this commit came from (absolute) */
  repo_path: z.string(),
  /**
   * Richer-signal field 1: exported names introduced in seam-adjacent files.
   * Extracted via regex on added lines: export (const|function|class|type|interface|enum) <name>
   * Only populated for seam-adjacent commits (supply-chain, certificate, provenance paths).
   * Optional — absent for non-seam commits.
   */
  exported_names: z.array(z.string()).optional(),
  /**
   * Richer-signal field 2: bounded excerpts of added type/function signature lines.
   * At most 3 snippets, at most 10 lines per snippet. Only from seam-adjacent files.
   * Optional — absent for non-seam commits.
   */
  signature_excerpts: z.array(signatureExcerptSchema).max(3).optional(),
});

export type GitCommitObservation = z.infer<typeof gitCommitObservationSchema>;

// ---- ObservationItem — compatible with vera-knowledge ----
// type + content + observed_at

export const observationItemSchema = z.object({
  type: z.string().min(1),
  content: z.record(z.unknown()),
  observed_at: z.string().min(1), // ISO 8601
});

export type ObservationItem = z.infer<typeof observationItemSchema>;

// ---- ObservationRecord — full local record (includes local metadata) ----

export const observationRecordSchema = observationItemSchema.extend({
  /** Locally assigned UUID */
  id: z.string().uuid(),
  /** When this record was written to the local store */
  created_at: z.string(), // ISO 8601
  /** Absolute path to the source repo */
  repo_path: z.string(),
  /** Commit hash for git_commit observations — used for dedup */
  commit_hash: z.string().optional(),
  /** ISO 8601 timestamp when this observation was successfully submitted to vera-knowledge */
  submitted_at: z.string().optional(),
  /** Batch ID returned by vera-knowledge when this observation was submitted */
  submission_batch_id: z.string().optional(),
});

export type ObservationRecord = z.infer<typeof observationRecordSchema>;

// ---- Candidate Artifact types ----

export const testBackedResolutionSchema = z.object({
  artifact_type: z.literal('test_backed_resolution'),
  resolution_summary: z.string().min(1),
  test_files: z.array(z.string()),
  source_files: z.array(z.string()),
  commit_hash: z.string().length(40),
  stats: z.object({
    total_additions: z.number().int().min(0),
    total_deletions: z.number().int().min(0),
  }),
});

export const failureToFixJourneySchema = z.object({
  artifact_type: z.literal('failure_to_fix_journey'),
  journey_summary: z.string().min(1),
  attempt_hashes: z.array(z.string().length(40)),
  target_files: z.array(z.string()),
  signal: z.enum(['revert', 'retry', 'wip_fix']),
});

export const operatorWorkflowImprovementSchema = z.object({
  artifact_type: z.literal('operator_workflow_improvement'),
  improvement_summary: z.string().min(1),
  surface_files: z.array(z.string()),
  verification_files: z.array(z.string()),
  commit_hash: z.string().length(40),
  stats: z.object({
    total_additions: z.number().int().min(0),
    total_deletions: z.number().int().min(0),
  }),
});

export const protocolPrimitiveIntroductionSchema = z.object({
  artifact_type: z.literal('protocol_primitive_introduction'),
  introduction_summary: z.string().min(1),
  /** Implementation files touched (src/, package exports, build config) */
  impl_files: z.array(z.string()),
  /** Test files covering the new primitive, if any */
  test_files: z.array(z.string()),
  commit_hash: z.string().length(40),
  stats: z.object({
    total_additions: z.number().int().min(0),
    total_deletions: z.number().int().min(0),
  }),
  /**
   * Richer-signal: exported names introduced in seam-adjacent files.
   * Propagated from GitCommitObservation.exported_names.
   * Optional — absent if not a seam-adjacent commit or if extraction produced nothing.
   */
  exported_names: z.array(z.string()).optional(),
  /**
   * Richer-signal: bounded excerpts of added type/function signature lines.
   * Propagated from GitCommitObservation.signature_excerpts.
   * Optional — absent if not a seam-adjacent commit or if extraction produced nothing.
   */
  signature_excerpts: z.array(signatureExcerptSchema).max(3).optional(),
});

export const candidateArtifactSchema = z.discriminatedUnion('artifact_type', [
  testBackedResolutionSchema,
  failureToFixJourneySchema,
  operatorWorkflowImprovementSchema,
  protocolPrimitiveIntroductionSchema,
]);

export type CandidateArtifact = z.infer<typeof candidateArtifactSchema>;
export type TestBackedResolution = z.infer<typeof testBackedResolutionSchema>;
export type FailureToFixJourney = z.infer<typeof failureToFixJourneySchema>;
export type OperatorWorkflowImprovement = z.infer<typeof operatorWorkflowImprovementSchema>;
export type ProtocolPrimitiveIntroduction = z.infer<typeof protocolPrimitiveIntroductionSchema>;
