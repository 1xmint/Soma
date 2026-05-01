/**
 * Git observation module.
 *
 * Reads commits from a local git repo using raw git CLI commands (no npm git
 * packages). Returns structured GitCommitObservation records compatible with
 * the vera-knowledge ObservationItem content schema.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { FileChange, GitCommitObservation, ObservationItem } from './types.js';

// ---- Internal helpers ----

function runGit(repoPath: string, args: string[]): string {
  try {
    return execFileSync('git', args, {
      cwd: repoPath,
      encoding: 'utf8',
      // Suppress stderr — we handle errors by inspecting stdout
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err: unknown) {
    const error = err as { stdout?: string; stderr?: string; status?: number };
    // If it's a "no commits" error, return empty string
    if (
      error.stderr &&
      (error.stderr.includes('does not have any commits') ||
        error.stderr.includes('unknown revision') ||
        error.stderr.includes("bad default revision 'HEAD'"))
    ) {
      return '';
    }
    throw new Error(
      `git ${args[0]} failed in ${repoPath}: ${error.stderr ?? String(err)}`
    );
  }
}

/** Parse git log output formatted with our record separator delimiter. */
const LOG_SEPARATOR = '\x1f'; // unit separator — safe, never appears in commit data
const RECORD_SEPARATOR = '\x1e'; // record separator

/**
 * git log format fields (order matters — must match parseLogRecord):
 * %H  commit hash
 * %an author name
 * %ae author email
 * %aI author date ISO 8601 strict
 * %cn committer name
 * %ce committer email
 * %cI committer date ISO 8601 strict
 * %P  parent hashes (space-separated)
 * %B  raw body (full commit message) — must be last because it can be multiline
 */
const LOG_FORMAT = [
  '%H',
  '%an',
  '%ae',
  '%aI',
  '%cn',
  '%ce',
  '%cI',
  '%P',
  '%B',
].join(LOG_SEPARATOR);

interface RawLogRecord {
  commit_hash: string;
  author_name: string;
  author_email: string;
  author_date: string;
  committer_name: string;
  committer_email: string;
  committer_date: string;
  parent_hashes: string[];
  message: string;
}

function parseLogRecord(raw: string): RawLogRecord | null {
  const parts = raw.split(LOG_SEPARATOR);
  if (parts.length < 9) return null;
  // The last field (%B) may itself contain the separator if someone put one
  // in their commit message, so we join remaining parts back together.
  const [hash, authorName, authorEmail, authorDate, committerName, committerEmail, committerDate, parents, ...bodyParts] =
    parts;
  if (!hash || hash.length !== 40) return null;
  const message = bodyParts.join(LOG_SEPARATOR).trimEnd();
  return {
    commit_hash: hash,
    author_name: authorName ?? '',
    author_email: authorEmail ?? '',
    author_date: authorDate ?? '',
    committer_name: committerName ?? '',
    committer_email: committerEmail ?? '',
    committer_date: committerDate ?? '',
    parent_hashes: parents ? parents.split(' ').filter(Boolean) : [],
    message,
  };
}

/**
 * Map a git status letter to our FileChange status enum.
 * git diff-tree --name-status produces: A, M, D, R<score>, C<score>, T
 */
function mapGitStatus(
  letter: string
): FileChange['status'] {
  if (letter.startsWith('A')) return 'added';
  if (letter.startsWith('M')) return 'modified';
  if (letter.startsWith('D')) return 'deleted';
  if (letter.startsWith('R')) return 'renamed';
  if (letter.startsWith('C')) return 'copied';
  if (letter.startsWith('T')) return 'type-changed';
  return 'unknown';
}

/**
 * Parse diff-tree --numstat output.
 * Format per line: "<additions>\t<deletions>\t<path>"
 * Binary files: "-\t-\t<path>"
 * Renames: "<add>\t<del>\t<old>\t{tab}<new>"  — git uses NUL with -z, but
 *   without -z renames are shown as "old => new" or split across lines.
 *   We use --name-status for status and --numstat for stats, merging by path.
 */
interface NumStatEntry {
  path: string;
  additions: number;
  deletions: number;
}

function parseNumStat(output: string): Map<string, NumStatEntry> {
  const map = new Map<string, NumStatEntry>();
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split('\t');
    if (parts.length < 3) continue;
    const [addStr, delStr, ...pathParts] = parts;
    // For rename lines git produces: "N\tM\told => new"
    // We normalise to the "new" path (after " => ")
    let path = pathParts.join('\t');
    if (path.includes(' => ')) {
      const arrow = path.indexOf(' => ');
      path = path.slice(arrow + 4);
    }
    const additions = addStr === '-' ? 0 : parseInt(addStr ?? '0', 10);
    const deletions = delStr === '-' ? 0 : parseInt(delStr ?? '0', 10);
    map.set(path, { path, additions: isNaN(additions) ? 0 : additions, deletions: isNaN(deletions) ? 0 : deletions });
  }
  return map;
}

/**
 * Parse diff-tree --name-status output.
 * Format: "<STATUS>\t<path>" or "<STATUS>\t<old-path>\t<new-path>" for renames.
 */
interface NameStatusEntry {
  status: FileChange['status'];
  path: string;
  old_path?: string;
}

function parseNameStatus(output: string): NameStatusEntry[] {
  const entries: NameStatusEntry[] = [];
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split('\t');
    if (parts.length < 2) continue;
    const [statusCode, ...paths] = parts;
    const status = mapGitStatus(statusCode ?? '');
    if (status === 'renamed' || status === 'copied') {
      entries.push({
        status,
        path: paths[1] ?? paths[0] ?? '',
        old_path: paths[0],
      });
    } else {
      entries.push({ status, path: paths[0] ?? '' });
    }
  }
  return entries;
}

/** Merge numstat and name-status entries into FileChange array. */
function buildFileChanges(
  nameStatusEntries: NameStatusEntry[],
  numStatMap: Map<string, NumStatEntry>
): FileChange[] {
  return nameStatusEntries.map((ns) => {
    const stats = numStatMap.get(ns.path) ?? { path: ns.path, additions: 0, deletions: 0 };
    const fc: FileChange = {
      path: ns.path,
      status: ns.status,
      additions: stats.additions,
      deletions: stats.deletions,
    };
    if (ns.old_path) fc.old_path = ns.old_path;
    return fc;
  });
}

/** Get diff info for a single commit. For the initial commit use special handling. */
function getDiffForCommit(
  repoPath: string,
  commitHash: string,
  parentHashes: string[]
): { nameStatus: NameStatusEntry[]; numStat: Map<string, NumStatEntry> } {
  const isInitialCommit = parentHashes.length === 0;

  let nameStatusOutput: string;
  let numStatOutput: string;

  if (isInitialCommit) {
    // Initial commit: diff against empty tree
    const emptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
    nameStatusOutput = runGit(repoPath, [
      'diff-tree',
      '--name-status',
      '-r',
      emptyTree,
      commitHash,
    ]);
    numStatOutput = runGit(repoPath, [
      'diff-tree',
      '--numstat',
      '-r',
      emptyTree,
      commitHash,
    ]);
  } else {
    // Normal commit (including merges — diff against first parent)
    nameStatusOutput = runGit(repoPath, [
      'diff-tree',
      '--name-status',
      '-r',
      `${commitHash}^1`,
      commitHash,
    ]);
    numStatOutput = runGit(repoPath, [
      'diff-tree',
      '--numstat',
      '-r',
      `${commitHash}^1`,
      commitHash,
    ]);
  }

  return {
    nameStatus: parseNameStatus(nameStatusOutput),
    numStat: parseNumStat(numStatOutput),
  };
}

// ---- Public API ----

export interface GitObserverOptions {
  /** Absolute path to the local git repository. */
  repoPath: string;
  /** Maximum number of commits to read. Default 50. */
  limit?: number;
}

export interface GitObserverResult {
  observations: ObservationItem[];
  /** Number of commits processed */
  count: number;
  /** Repo path used */
  repoPath: string;
}

/**
 * Read the N most recent commits from a local git repo and return structured
 * ObservationItem records (type="git_commit").
 *
 * Edge cases handled:
 * - Empty repo (no commits): returns empty array
 * - Single commit (no parents): uses empty-tree diff
 * - Merge commits: diffed against first parent
 * - Binary files: numstat returns "-" — treated as 0 additions/deletions
 */
export function observeGitCommits(options: GitObserverOptions): GitObserverResult {
  const { repoPath, limit = 50 } = options;

  // Validate repo path
  const gitDir = join(repoPath, '.git');
  if (!existsSync(gitDir)) {
    throw new Error(`Not a git repository: ${repoPath}`);
  }

  // Get commit log
  const logOutput = runGit(repoPath, [
    'log',
    `--max-count=${limit}`,
    `--format=format:${LOG_FORMAT}${RECORD_SEPARATOR}`,
    'HEAD',
  ]);

  if (!logOutput.trim()) {
    return { observations: [], count: 0, repoPath };
  }

  const rawRecords = logOutput.split(RECORD_SEPARATOR).filter((r) => r.trim());
  const observations: ObservationItem[] = [];

  for (const raw of rawRecords) {
    const parsed = parseLogRecord(raw.trim());
    if (!parsed) continue;

    const { nameStatus, numStat } = getDiffForCommit(
      repoPath,
      parsed.commit_hash,
      parsed.parent_hashes
    );

    const filesChanged = buildFileChanges(nameStatus, numStat);
    const totalAdditions = filesChanged.reduce((sum, f) => sum + f.additions, 0);
    const totalDeletions = filesChanged.reduce((sum, f) => sum + f.deletions, 0);

    const content: GitCommitObservation = {
      commit_hash: parsed.commit_hash,
      author_name: parsed.author_name,
      author_email: parsed.author_email,
      author_date: parsed.author_date,
      committer_name: parsed.committer_name,
      committer_email: parsed.committer_email,
      committer_date: parsed.committer_date,
      message: parsed.message,
      message_subject: parsed.message.split('\n')[0]?.trim() ?? '',
      parent_hashes: parsed.parent_hashes,
      is_merge: parsed.parent_hashes.length > 1,
      files_changed: filesChanged,
      stats: {
        total_files_changed: filesChanged.length,
        total_additions: totalAdditions,
        total_deletions: totalDeletions,
      },
      repo_path: repoPath,
    };

    observations.push({
      type: 'git_commit',
      content: content as unknown as Record<string, unknown>,
      observed_at: parsed.author_date,
    });
  }

  return { observations, count: observations.length, repoPath };
}
