/**
 * Local observation store.
 *
 * Uses sql.js (pure-JS SQLite, no native compilation) to persist
 * ObservationRecord entries. The database is kept in memory and persisted to
 * a binary file on disk. Raw data stays local — this is the "secure room."
 *
 * Schema:
 *   observations(
 *     id TEXT PRIMARY KEY,          -- UUID
 *     type TEXT NOT NULL,           -- observation type e.g. "git_commit"
 *     content TEXT NOT NULL,        -- JSON string
 *     observed_at TEXT NOT NULL,    -- ISO 8601 (from the observation)
 *     created_at TEXT NOT NULL,     -- ISO 8601 (when we stored it)
 *     repo_path TEXT NOT NULL,      -- absolute path to source repo
 *     commit_hash TEXT              -- for git_commit dedup; NULL for other types
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
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  content     TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  repo_path   TEXT NOT NULL,
  commit_hash TEXT,
  UNIQUE(commit_hash)
);

CREATE INDEX IF NOT EXISTS idx_observations_repo_path
  ON observations (repo_path);

CREATE INDEX IF NOT EXISTS idx_observations_observed_at
  ON observations (observed_at);
`;

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
      SELECT id, type, content, observed_at, created_at, repo_path, commit_hash
      FROM observations
      ${where}
      ORDER BY observed_at DESC
      LIMIT ?
    `;
    params.push(limit);

    const result = this.db.exec(sql, params);
    if (result.length === 0 || !result[0]) return [];

    const { columns, values } = result[0];
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
