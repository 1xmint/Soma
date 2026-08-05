/**
 * Local observation store.
 *
 * Uses sql.js (pure-JS SQLite, no native compilation) to persist
 * ObservationRecord entries. The database is kept in memory and persisted to
 * a binary file on disk. Raw data stays local — this is the "secure room."
 *
 * Schema:
 *   observations(
 *     id TEXT PRIMARY KEY,              -- UUID
 *     type TEXT NOT NULL,               -- observation type e.g. "git_commit"
 *     content TEXT NOT NULL,            -- JSON string
 *     observed_at TEXT NOT NULL,        -- ISO 8601 (from the observation)
 *     created_at TEXT NOT NULL,         -- ISO 8601 (when we stored it)
 *     repo_path TEXT NOT NULL,          -- absolute path to source repo
 *     commit_hash TEXT,                 -- for git_commit dedup; NULL for other types
 *     submitted_at TEXT,                -- ISO 8601 when submitted to vera-knowledge
 *     submission_batch_id TEXT          -- batch ID returned by vera-knowledge
 *   )
 *
 * NOTE: sql.js is an in-memory database. Call save() (or close()) to persist
 * to disk. The constructor calls load() automatically if the file exists.
 */

import initSqlJs from 'sql.js';
import type { Database } from 'sql.js';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import type { ObservationItem, ObservationRecord } from './types.js';

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS observations (
  id                  TEXT PRIMARY KEY,
  type                TEXT NOT NULL,
  content             TEXT NOT NULL,
  observed_at         TEXT NOT NULL,
  created_at          TEXT NOT NULL,
  repo_path           TEXT NOT NULL,
  commit_hash         TEXT,
  submitted_at        TEXT,
  submission_batch_id TEXT,
  UNIQUE(commit_hash)
);

CREATE INDEX IF NOT EXISTS idx_observations_repo_path
  ON observations (repo_path);

CREATE INDEX IF NOT EXISTS idx_observations_observed_at
  ON observations (observed_at);
`;

// Column migrations for schema evolution (safe to re-run — wrapped in try/catch).
const MIGRATE_SQL_STEPS = [
  `ALTER TABLE observations ADD COLUMN submitted_at TEXT`,
  `ALTER TABLE observations ADD COLUMN submission_batch_id TEXT`,
  `ALTER TABLE observations ADD COLUMN artifact_status TEXT`,
];

export interface QueryOptions {
  repoPath?: string;
  fromDate?: string; // ISO 8601 inclusive
  toDate?: string;   // ISO 8601 inclusive
  type?: string;
  limit?: number;
}

export class ObservationStore {
  private db: Database;
  private dbPath: string;

  /** Use ObservationStore.open() for async construction. */
  private constructor(db: Database, dbPath: string) {
    this.db = db;
    this.dbPath = dbPath;
  }

  /** Async factory — initialises sql.js and opens/creates the database. */
  static async open(dbPath: string): Promise<ObservationStore> {
    const SQL = await initSqlJs();

    let db: Database;
    if (existsSync(dbPath)) {
      const data = readFileSync(dbPath);
      db = new SQL.Database(data);
    } else {
      db = new SQL.Database();
    }

    db.run(CREATE_TABLE_SQL);

    // Schema evolution: add new columns if they don't exist yet.
    // Each step is safe to re-run — the catch swallows "duplicate column" errors.
    for (const step of MIGRATE_SQL_STEPS) {
      try {
        db.run(step);
      } catch {
        // Column already exists — this is expected on re-open of an existing db.
      }
    }

    const store = new ObservationStore(db, dbPath);
    store.save();
    return store;
  }

  /** Persist the in-memory database to disk. */
  save(): void {
    const data = this.db.export();
    writeFileSync(this.dbPath, Buffer.from(data));
  }

  /**
   * Insert a single observation. Returns the created ObservationRecord.
   * Throws on duplicate commit_hash.
   */
  insert(item: ObservationItem, repoPath: string): ObservationRecord {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const contentJson = JSON.stringify(item.content);
    const commitHash =
      item.type === 'git_commit'
        ? (item.content as Record<string, unknown>)['commit_hash'] as string | undefined
        : undefined;

    this.db.run(
      `INSERT INTO observations (id, type, content, observed_at, created_at, repo_path, commit_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, item.type, contentJson, item.observed_at, createdAt, repoPath, commitHash ?? null]
    );
    this.save();

    return {
      id,
      type: item.type,
      content: item.content,
      observed_at: item.observed_at,
      created_at: createdAt,
      repo_path: repoPath,
      commit_hash: commitHash,
      submitted_at: undefined,
      submission_batch_id: undefined,
    };
  }

  /**
   * Insert multiple observations.
   * Skips duplicates (by commit_hash) without throwing.
   * Returns the count of actually inserted records.
   */
  insertMany(items: ObservationItem[], repoPath: string): number {
    let inserted = 0;
    for (const item of items) {
      const id = randomUUID();
      const createdAt = new Date().toISOString();
      const contentJson = JSON.stringify(item.content);
      const commitHash =
        item.type === 'git_commit'
          ? (item.content as Record<string, unknown>)['commit_hash'] as string | undefined
          : undefined;

      // Check for duplicate commit_hash first
      if (commitHash && this.hasCommit(commitHash)) {
        continue;
      }

      this.db.run(
        `INSERT OR IGNORE INTO observations (id, type, content, observed_at, created_at, repo_path, commit_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, item.type, contentJson, item.observed_at, createdAt, repoPath, commitHash ?? null]
      );
      inserted++;
    }
    this.save();
    return inserted;
  }

  /**
   * Check if a commit has already been observed (dedup check).
   */
  hasCommit(commitHash: string): boolean {
    const result = this.db.exec(
      'SELECT 1 FROM observations WHERE commit_hash = ? LIMIT 1',
      [commitHash]
    );
    return result.length > 0 && result[0] !== undefined && result[0].values.length > 0;
  }

  /**
   * Query observations with optional filters.
   */
  query(options: QueryOptions = {}): ObservationRecord[] {
    const { repoPath, fromDate, toDate, type, limit = 1000 } = options;

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (repoPath) {
      conditions.push('repo_path = ?');
      params.push(repoPath);
    }
    if (type) {
      conditions.push('type = ?');
      params.push(type);
    }
    if (fromDate) {
      conditions.push('observed_at >= ?');
      params.push(fromDate);
    }
    if (toDate) {
      conditions.push('observed_at <= ?');
      params.push(toDate);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `
      SELECT id, type, content, observed_at, created_at, repo_path, commit_hash,
             submitted_at, submission_batch_id
      FROM observations
      ${where}
      ORDER BY observed_at DESC
      LIMIT ?
    `;
    params.push(limit);

    const result = this.db.exec(sql, params);
    if (result.length === 0 || !result[0]) return [];

    return this.rowsToRecords(result[0]);
  }

  /**
   * Return observations that have not yet been submitted (submitted_at IS NULL)
   * and have not entered the artifact lifecycle (artifact_status IS NULL).
   * Ordered by observed_at ASC (oldest first). Default limit 50.
   */
  getUnsubmitted(limit = 50): ObservationRecord[] {
    const sql = `
      SELECT id, type, content, observed_at, created_at, repo_path, commit_hash,
             submitted_at, submission_batch_id
      FROM observations
      WHERE submitted_at IS NULL AND artifact_status IS NULL
      ORDER BY observed_at ASC
      LIMIT ?
    `;
    const result = this.db.exec(sql, [limit]);
    if (result.length === 0 || !result[0]) return [];
    return this.rowsToRecords(result[0]);
  }

  /**
   * Return observations that have not yet been evaluated for artifact extraction
   * (artifact_status IS NULL). Ordered by observed_at ASC (oldest first).
   * Default limit 50.
   */
  getUnextracted(limit = 50): ObservationRecord[] {
    const sql = `
      SELECT id, type, content, observed_at, created_at, repo_path, commit_hash,
             submitted_at, submission_batch_id
      FROM observations
      WHERE artifact_status IS NULL
      ORDER BY observed_at ASC
      LIMIT ?
    `;
    const result = this.db.exec(sql, [limit]);
    if (result.length === 0 || !result[0]) return [];
    return this.rowsToRecords(result[0]);
  }

  /**
   * Return observations awaiting artifact submission (artifact_status = 'pending').
   * Ordered by observed_at ASC (oldest first). Default limit 50.
   */
  getPending(limit = 50): ObservationRecord[] {
    const sql = `
      SELECT id, type, content, observed_at, created_at, repo_path, commit_hash,
             submitted_at, submission_batch_id
      FROM observations
      WHERE artifact_status = 'pending'
      ORDER BY observed_at ASC
      LIMIT ?
    `;
    const result = this.db.exec(sql, [limit]);
    if (result.length === 0 || !result[0]) return [];
    return this.rowsToRecords(result[0]);
  }

  /**
   * Set artifact_status for a set of observations (by commit_hash).
   * Persists to disk after all updates.
   *
   * Lifecycle:
   *   NULL → 'no_signal'  (evaluated, no artifact match — terminal)
   *   NULL → 'pending'    (artifact derived — awaiting submission)
   *   'pending' → 'submitted' (successfully submitted — terminal)
   */
  setArtifactStatus(
    commitHashes: string[],
    status: 'no_signal' | 'pending' | 'submitted',
  ): void {
    if (commitHashes.length === 0) return;
    for (const hash of commitHashes) {
      this.db.run(
        `UPDATE observations SET artifact_status = ? WHERE commit_hash = ?`,
        [status, hash],
      );
    }
    this.save();
  }

  /**
   * Mark a set of observations (identified by commit_hash) as submitted.
   * Updates submitted_at and submission_batch_id, then persists to disk.
   */
  markSubmitted(commitHashes: string[], batchId: string): void {
    if (commitHashes.length === 0) return;
    const submittedAt = new Date().toISOString();
    for (const hash of commitHashes) {
      this.db.run(
        `UPDATE observations SET submitted_at = ?, submission_batch_id = ?
         WHERE commit_hash = ?`,
        [submittedAt, batchId, hash]
      );
    }
    this.save();
  }

  // ---- Private helpers ----

  private rowsToRecords(resultRow: { columns: string[]; values: unknown[][] }): ObservationRecord[] {
    const { columns, values } = resultRow;
    return values.map((row) => {
      const r: Record<string, unknown> = {};
      columns.forEach((col, i) => { r[col] = row[i]; });
      return {
        id: r['id'] as string,
        type: r['type'] as string,
        content: JSON.parse(r['content'] as string) as Record<string, unknown>,
        observed_at: r['observed_at'] as string,
        created_at: r['created_at'] as string,
        repo_path: r['repo_path'] as string,
        commit_hash: r['commit_hash'] != null ? r['commit_hash'] as string : undefined,
        submitted_at: r['submitted_at'] != null ? r['submitted_at'] as string : undefined,
        submission_batch_id: r['submission_batch_id'] != null ? r['submission_batch_id'] as string : undefined,
      };
    });
  }

  /** Count total observations in the store. */
  count(): number {
    const result = this.db.exec('SELECT COUNT(*) as n FROM observations');
    if (!result.length || !result[0] || !result[0].values.length) return 0;
    return result[0].values[0]?.[0] as number ?? 0;
  }

  /** Save and close the database. */
  close(): void {
    this.save();
    this.db.close();
  }
}
