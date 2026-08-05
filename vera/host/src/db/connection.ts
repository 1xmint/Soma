import 'dotenv/config';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema/index.js';

const url = process.env['DATABASE_URL'];
if (!url) {
  throw new Error(
    'DATABASE_URL environment variable is not set. ' +
    'Expected format: postgresql://user:password@host:port/database'
  );
}

// Raw postgres.js SQL client — used for migrations and extension setup
export const sql = postgres(url, { max: 1 });

// Drizzle ORM instance bound to the schema
export const db = drizzle(sql, { schema });

export type Db = typeof db;
