import type { Sql } from 'postgres';

/**
 * Enable required PostgreSQL extensions.
 * Must be called before running migrations when extensions are not yet present.
 */
export async function enableExtensions(sql: Sql): Promise<void> {
  await sql`CREATE EXTENSION IF NOT EXISTS vector`;
  await sql`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`;
}
