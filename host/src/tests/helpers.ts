import 'dotenv/config';
import postgres from 'postgres';
import { randomBytes } from 'node:crypto';
import {
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
} from '../lib/envelope.js';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from '../db/schema/index.js';
import { enableExtensions } from '../db/extensions.js';
import { buildApp } from '../server.js';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import type { FastifyInstance } from 'fastify';
import type { Db } from '../db/connection.js';

export type TestContext = {
  app: FastifyInstance;
  db: Db;
  sql: ReturnType<typeof postgres>;
  cleanup: () => Promise<void>;
};

/**
 * Create a fully wired test context: postgres connection, drizzle db,
 * and a Fastify app instance via buildApp().
 *
 * Caller must call cleanup() in an after() hook.
 */
export async function setupTestContext(): Promise<TestContext> {
  const url = process.env['DATABASE_URL'];
  if (!url) {
    throw new Error('DATABASE_URL is not set — cannot set up test context');
  }

  const sql = postgres(url, { max: 1 });
  await enableExtensions(sql);

  const db = drizzle(sql, { schema }) as Db;
  const app = await buildApp(db);

  const cleanup = async () => {
    await app.close();
    await sql.end();
  };

  return { app, db, sql, cleanup };
}

export type SomaIdentity = {
  did: string;
  publicKeyB64: string;
  secretKey: Uint8Array;
  keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
};

/**
 * Generate a fresh Ed25519 keypair and a test Soma DID.
 */
export function generateSomaIdentity(): SomaIdentity {
  const provider = getCryptoProvider();
  const keyPair = provider.signing.generateKeyPair();

  // Produce a random hex suffix for uniqueness
  const randomBytes = new Uint8Array(8);
  crypto.getRandomValues(randomBytes);
  const randomHex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const did = `did:soma:test-${randomHex}`;
  const publicKeyB64 = provider.encoding.encodeBase64(keyPair.publicKey);

  return { did, publicKeyB64, secretKey: keyPair.secretKey, keyPair };
}

/**
 * Sign a payload string with the given Ed25519 secret key and return
 * the base64-encoded signature.
 */
export function signPayload(payload: string, secretKey: Uint8Array): string {
  const provider = getCryptoProvider();
  const payloadBytes = new TextEncoder().encode(payload);
  const signatureBytes = provider.signing.sign(payloadBytes, secretKey);
  return provider.encoding.encodeBase64(signatureBytes);
}

/**
 * Produce the three X-Guardian-* signed request headers for a given
 * method / path / body using the provided Soma identity.
 *
 * The canonical signing input matches the server's reconstruction exactly:
 *   JSON.stringify({ method, path, body, timestamp, nonce })
 *
 * Pass the returned object spread into `headers` on inject() calls:
 *   headers: { 'content-type': 'application/json', ...guardianHeaders(...) }
 */
export function guardianHeaders(
  method: string,
  path: string,
  body: unknown,
  identity: SomaIdentity,
): {
  'x-guardian-signature': string;
  'x-guardian-timestamp': string;
  'x-guardian-nonce': string;
} {
  const provider = getCryptoProvider();

  // 16 bytes → 32 hex chars nonce
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const timestamp = new Date().toISOString();

  const signingInput = JSON.stringify({ method, path, body, timestamp, nonce });
  const inputBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = provider.signing.sign(inputBytes, identity.secretKey);
  const signature = provider.encoding.encodeBase64(signatureBytes);

  return {
    'x-guardian-signature': signature,
    'x-guardian-timestamp': timestamp,
    'x-guardian-nonce': nonce,
  };
}

/**
 * Truncate all tables in FK-safe order (children before parents).
 */
export async function cleanTables(db: Db): Promise<void> {
  // Use raw sql via the drizzle client's underlying execute or via tagged template.
  // Drizzle exposes db.$client for the underlying postgres.js sql tagged-template.
  const sql = (db as unknown as { $client: ReturnType<typeof postgres> }).$client;
  await sql`TRUNCATE TABLE observations, observation_batches, teaching_entries, knowledge_entries, users CASCADE`;
}

/**
 * Submit a signed v1 observation batch and return the created batch id.
 *
 * This lives here because four test files previously carried their own copy of
 * it. When the wire format moved from v0 to v1 the copies drifted apart
 * silently — one was updated and three were not, and the failure surfaced as
 * "envelope must be a JSON object" in suites that have nothing to do with
 * envelopes. One helper, one place to change.
 */
export async function ingestObservations(
  ctx: TestContext,
  did: string,
  secretKey: Uint8Array,
  obsItems: Array<{ type: string; content: Record<string, unknown>; observed_at: string }>,
  sourceType = 'cortex',
): Promise<string> {
  const envelope = {
    batch_id: randomBytes(16).toString('hex'),
    observations: obsItems,
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: did,
    source_type: sourceType,
    submitted_at: formatSubmittedAt(new Date()),
  };

  const provider = getCryptoProvider();
  const signature = provider.encoding.encodeBase64(
    provider.signing.sign(signedBytes(envelope), secretKey),
  );

  const response = await ctx.app.inject({
    method: 'POST',
    url: '/v1/observations',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ envelope, signature }),
  });

  if (response.statusCode !== 201) {
    throw new Error(`ingestObservations failed: ${response.statusCode} ${response.body}`);
  }
  return response.json<{ batch: { id: string } }>().batch.id;
}
