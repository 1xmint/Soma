import Fastify from 'fastify';
import cors from '@fastify/cors';
import { healthRoutes } from './routes/health.js';
import { registerRoutes } from './routes/register.js';
import { observationsRoutes } from './routes/observations.js';
import { aggregateRoutes } from './routes/aggregate.js';
import { queryRoutes } from './routes/query.js';
import type { Db } from './db/connection.js';

/**
 * Build and configure the Fastify application.
 *
 * The db instance is injected so tests can provide a test database
 * without triggering the real connection.ts eager import.
 */
export async function buildApp(db: Db) {
  const app = Fastify({ logger: true });

  // Decorate the instance with the db before registering routes
  app.decorate('db', db);

  await app.register(cors);

  await app.register(healthRoutes);
  await app.register(registerRoutes);
  await app.register(observationsRoutes);
  await app.register(aggregateRoutes);
  await app.register(queryRoutes);

  return app;
}
