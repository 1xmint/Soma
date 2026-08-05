import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

const url = process.env['DATABASE_URL'];
if (!url) {
  throw new Error('DATABASE_URL environment variable is not set');
}

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema/*.ts',
  out: './drizzle',
  dbCredentials: {
    url,
  },
});
