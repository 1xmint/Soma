import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  setupTestContext,
  generateSomaIdentity,
  signPayload,
  guardianHeaders,
  cleanTables,
  type TestContext,
  type SomaIdentity,
} from './helpers.js';

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
  const signedPayload = JSON.stringify(obsItems);
  const signature = signPayload(signedPayload, secretKey);

  const response = await ctx.app.inject({
    method: 'POST',
    url: '/v1/observations',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      soma_did: did,
      source_type: 'cortex',
      signature,
      observations: obsItems,
    }),
  });

  if (response.statusCode !== 201) {
    throw new Error(`ingestBatch failed: ${response.statusCode} ${response.body}`);
  }

  return response.json<{ batch: { id: string } }>().batch.id;
}

/** Aggregate a batch via POST /v1/aggregate — throws on non-201. */
async function aggregateBatch(
  ctx: TestContext,
  identity: SomaIdentity,
  batchId: string,
): Promise<void> {
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
  if (response.statusCode !== 201) {
    throw new Error(`aggregateBatch failed: ${response.statusCode} ${response.body}`);
  }
}

describe('POST /v1/query', () => {
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

  it('returns ranked knowledge entries (happy path)', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const obsItems = [
      {
        type: 'code_edit',
        content: { file: 'src/index.ts', lines_changed: 3 },
        observed_at: new Date().toISOString(),
      },
    ];

    const batchId = await ingestBatch(ctx, identity.did, identity.secretKey, obsItems);
    await aggregateBatch(ctx, identity, batchId);

    const queryReqBody = { soma_did: identity.did, query_text: 'code edit patterns', limit: 5 };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', queryReqBody, identity),
      },
      body: JSON.stringify(queryReqBody),
    });

    assert.equal(response.statusCode, 200);

    const body = response.json<{
      results: Array<{
        id: string;
        entry_type: string;
        title: string;
        content: string;
        confidence: number;
        tags: string[];
        soma_provenance: { observation_id: string; batch_id: string; soma_did: string };
        similarity: number;
        created_at: string;
      }>;
    }>();

    assert.ok(Array.isArray(body.results), 'results should be an array');
    assert.equal(body.results.length, 1);

    const result = body.results[0]!;

    assert.ok(typeof result.id === 'string', 'result.id should be a string');
    assert.ok(typeof result.entry_type === 'string', 'result.entry_type should be a string');
    assert.ok(typeof result.title === 'string', 'result.title should be a string');
    assert.ok(typeof result.content === 'string', 'result.content should be a string');
    assert.ok(typeof result.confidence === 'number', 'result.confidence should be a number');
    assert.ok(typeof result.created_at === 'string', 'result.created_at should be a string');
    assert.ok(!isNaN(Date.parse(result.created_at)), 'created_at should be a valid ISO date');

    // Check soma_provenance fields
    assert.ok(typeof result.soma_provenance === 'object', 'soma_provenance should be an object');
    assert.ok(
      typeof result.soma_provenance.observation_id === 'string',
      'soma_provenance.observation_id should be a string',
    );
    assert.ok(
      typeof result.soma_provenance.batch_id === 'string',
      'soma_provenance.batch_id should be a string',
    );

    // Check similarity is a number in [0, 1]
    assert.ok(typeof result.similarity === 'number', 'similarity should be a number');
    assert.ok(result.similarity >= 0, 'similarity should be >= 0');
    assert.ok(result.similarity <= 1, 'similarity should be <= 1');
  });

  it('returns empty results array when no knowledge entries exist', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    // Do NOT ingest or aggregate — knowledge_entries table is empty
    const queryReqBody = { soma_did: identity.did, query_text: 'anything', limit: 5 };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', queryReqBody, identity),
      },
      body: JSON.stringify(queryReqBody),
    });

    assert.equal(response.statusCode, 200);
    const body = response.json<{ results: unknown[] }>();
    assert.ok(Array.isArray(body.results), 'results should be an array');
    assert.equal(body.results.length, 0);
  });

  it('returns 401 when soma_did is not registered', async () => {
    const identity = generateSomaIdentity();
    // Deliberately do NOT register this identity.
    // Guardian auth catches the unregistered DID (returns 401, not 404)
    // to avoid leaking user existence to unsigned callers.
    const queryReqBody = { soma_did: identity.did, query_text: 'test query', limit: 5 };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', queryReqBody, identity),
      },
      body: JSON.stringify(queryReqBody),
    });

    assert.equal(response.statusCode, 401);
    const respBody = response.json<{ error: string }>();
    assert.equal(respBody.error, 'guardian_auth_failed');
  });

  it('same query text produces the same result order (determinism check)', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    // Two observations with different types to get two distinct entries
    const obsItems = [
      {
        type: 'code_edit',
        content: { file: 'src/index.ts', lines_changed: 7 },
        observed_at: new Date().toISOString(),
      },
      {
        type: 'file_open',
        content: { file: 'src/server.ts' },
        observed_at: new Date().toISOString(),
      },
    ];

    const batchId = await ingestBatch(ctx, identity.did, identity.secretKey, obsItems);
    await aggregateBatch(ctx, identity, batchId);

    // Each inject needs its own guardian headers (unique nonce per request)
    const queryReqBody = {
      soma_did: identity.did,
      query_text: 'test determinism',
      limit: 5,
    };

    const response1 = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', queryReqBody, identity),
      },
      body: JSON.stringify(queryReqBody),
    });

    const response2 = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', queryReqBody, identity),
      },
      body: JSON.stringify(queryReqBody),
    });

    assert.equal(response1.statusCode, 200);
    assert.equal(response2.statusCode, 200);

    const body1 = response1.json<{ results: Array<{ id: string }> }>();
    const body2 = response2.json<{ results: Array<{ id: string }> }>();

    assert.equal(body1.results.length, body2.results.length, 'both responses should have same number of results');
    assert.ok(body1.results.length > 0, 'should have at least one result');

    const ids1 = body1.results.map((r) => r.id);
    const ids2 = body2.results.map((r) => r.id);

    assert.deepEqual(ids1, ids2, 'result ids should be in the same order on both queries');
  });
});
