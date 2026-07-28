import 'dotenv/config';
import { db, sql } from './db/connection.js';
import { enableExtensions } from './db/extensions.js';
import { buildApp } from './server.js';

const PORT = parseInt(process.env['PORT'] ?? '3100', 10);

async function main() {
  await enableExtensions(sql);

  const app = await buildApp(db);

  const address = await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info(`vera-knowledge listening on ${address}`);

  async function shutdown(signal: string) {
    app.log.info(`Received ${signal}, shutting down…`);
    await app.close();
    await sql.end();
    process.exit(0);
  }

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
