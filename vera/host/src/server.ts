import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { healthRoutes } from './routes/health.js';
import { registerRoutes } from './routes/register.js';
import { observationsRoutes } from './routes/observations.js';
import { aggregateRoutes } from './routes/aggregate.js';
import { queryRoutes } from './routes/query.js';
import type { Db } from './db/connection.js';

/**
 * Rate limits are operator self-defence, not protocol policy.
 *
 * This distinction is load-bearing and easy to get wrong. The protocol refuses
 * gates: there is no admission control on evidence, because a gate needs a
 * gatekeeper and a gatekeeper is an owner. A limit here is a different thing —
 * it governs how fast one host is willing to spend *its own* CPU and database,
 * and it excludes nobody from the network, because hosts are plural and
 * substitutable. An agent rate-limited by this host submits to another one, or
 * runs its own. If that ever stops being true, the problem is host
 * concentration, and no setting in this file fixes it.
 *
 * Without a limit, `POST /v1/observations` performs a database lookup and an
 * Ed25519 verification for every unauthenticated request, which is a cheap
 * amplification into expensive work.
 *
 * The numbers are deliberately environment-configurable and deliberately not
 * frozen. An operator's capacity is the operator's business; these defaults are
 * a starting point for a small host, not a recommendation.
 */
export type RateLimitOptions = {
  max?: number;
  timeWindow?: string;
};

/**
 * Build and configure the Fastify application.
 *
 * The db instance is injected so tests can provide a test database
 * without triggering the real connection.ts eager import.
 *
 * Rate limits are read here rather than at module load so a caller can supply
 * them directly. A limit that can only be configured through the environment
 * can only be tested through the environment, and a defence nobody can test is
 * a defence nobody knows still works.
 */
export async function buildApp(db: Db, rateLimitOptions: RateLimitOptions = {}) {
  const RATE_LIMIT_MAX = rateLimitOptions.max ?? Number(process.env['VERA_RATE_LIMIT_MAX'] ?? 120);
  const RATE_LIMIT_WINDOW =
    rateLimitOptions.timeWindow ?? process.env['VERA_RATE_LIMIT_WINDOW'] ?? '1 minute';

  const app = Fastify({ logger: true });

  // Decorate the instance with the db before registering routes
  app.decorate('db', db);

  await app.register(cors);

  // Registered before the routes so it covers every one of them, including any
  // added later. A route that forgets to opt in is the usual way this defence
  // is lost.
  //
  // Keyed by IP, and deliberately not by `soma_did`. Keying on the submitted
  // DID would read the bucket from unauthenticated, caller-chosen input: an
  // attacker sends a fresh DID per request and every request lands in an empty
  // bucket, so the limit measures the attacker's imagination rather than its
  // traffic. The DID is only meaningful after the signature check, which is the
  // expensive work this limit exists to protect. IP is coarse — a shared NAT
  // shares a bucket — but it is the only identifier the host has before it has
  // spent anything.
  await app.register(rateLimit, {
    max: RATE_LIMIT_MAX,
    timeWindow: RATE_LIMIT_WINDOW,
  });

  await app.register(healthRoutes);
  await app.register(registerRoutes);
  await app.register(observationsRoutes);
  await app.register(aggregateRoutes);
  await app.register(queryRoutes);

  return app;
}
