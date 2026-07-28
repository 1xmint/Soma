import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import {
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
} from '../lib/envelope.js';
import {
  setupTestContext,
  generateSomaIdentity,
  signPayload,
  guardianHeaders,
  cleanTables,
  type TestContext,
} from './helpers.js';
import { eq } from 'drizzle-orm';
import { knowledgeEntries } from '../db/schema/index.js';

/** Register a user and return 201 body — throws on non-201. */
async function registerUser(
  ctx: TestContext,
  did: string,
  publicKeyB64: string,
): Promise<{ id: string; soma_did: string }> {
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/v1/register',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ soma_did: did, public_key: publicKeyB64 }),
  });
  if (response.statusCode !== 201) {
    throw new Error(`registerUser failed: ${response.statusCode} ${response.body}`);
  }
  return response.json<{ user: { id: string; soma_did: string } }>().user;
}

/**
 * Ingest a signed observation batch via POST /v1/observations.
 * Returns the batch_id from the response.
 */
async function ingestBatch(
  ctx: TestContext,
  did: string,
  secretKey: Uint8Array,
  obsItems: Array<{ type: string; content: Record<string, unknown>; observed_at: string }>,
): Promise<string> {
  const envelope = {
    batch_id: randomBytes(16).toString('hex'),
    observations: obsItems,
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: did,
    source_type: 'cortex',
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
    throw new Error(`ingestBatch failed: ${response.statusCode} ${response.body}`);
  }

  return response.json<{ batch: { id: string } }>().batch.id;
}

describe('POST /v1/aggregate', () => {
  let ctx: TestContext;

  before(async () => {
    ctx = await setupTestContext();
  });

  after(async () => {
    await ctx.cleanup();
  });

  beforeEach(async () => {
    await cleanTables(ctx.db);
  });

  it('derives knowledge entries from observations (happy path)', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const obsItems = [
      {
        type: 'code_edit',
        content: { file: 'src/index.ts', lines_changed: 5 },
        observed_at: new Date().toISOString(),
      },
      {
        type: 'file_open',
        content: { file: 'src/lib/schemas.ts' },
        observed_at: new Date().toISOString(),
      },
    ];

    const batchId = await ingestBatch(ctx, identity.did, identity.secretKey, obsItems);

    const reqBody = { soma_did: identity.did, batch_id: batchId };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/aggregate', reqBody, identity),
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 201);

    const body = response.json<{
      created: Array<{ id: string; entry_type: string; title: string }>;
      count: number;
    }>();

    assert.equal(body.count, 2);
    assert.equal(body.created.length, 2);

    for (const entry of body.created) {
      assert.ok(typeof entry.id === 'string', 'entry should have an id string');
      assert.ok(typeof entry.entry_type === 'string', 'entry should have entry_type');
      assert.ok(typeof entry.title === 'string', 'entry should have title');
    }

    // Verify at least one entry in the DB has a non-null embedding and confidence 0.3
    const dbEntries = await ctx.db
      .select()
      .from(knowledgeEntries)
      .where(eq(knowledgeEntries.id, body.created[0]!.id));

    assert.equal(dbEntries.length, 1);
    const dbEntry = dbEntries[0]!;
    assert.ok(dbEntry.embedding !== null, 'embedding should be non-null');
    assert.ok(Array.isArray(dbEntry.embedding), 'embedding should be an array');
    assert.equal((dbEntry.embedding as number[]).length, 1536, 'embedding should have 1536 dimensions');
    assert.equal(dbEntry.confidence, 0.3, 'confidence should be 0.3');
  });

  it('returns 403 when soma_did does not own the batch', async () => {
    const identityA = generateSomaIdentity();
    const identityB = generateSomaIdentity();

    await registerUser(ctx, identityA.did, identityA.publicKeyB64);
    await registerUser(ctx, identityB.did, identityB.publicKeyB64);

    const obsItems = [
      {
        type: 'code_edit',
        content: { file: 'src/index.ts' },
        observed_at: new Date().toISOString(),
      },
    ];

    // User A creates the batch
    const batchId = await ingestBatch(ctx, identityA.did, identityA.secretKey, obsItems);

    // User B tries to aggregate user A's batch (B is registered so guardian passes,
    // but the route handler rejects because the batch doesn't belong to B)
    const reqBody = { soma_did: identityB.did, batch_id: batchId };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/aggregate', reqBody, identityB),
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 403);
  });

  it('returns 404 when batch_id does not exist', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const randomUuid = '00000000-0000-4000-8000-000000000001';

    const reqBody = { soma_did: identity.did, batch_id: randomUuid };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/aggregate', reqBody, identity),
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 404);
  });
});
