import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestContext, generateSomaIdentity, cleanTables, type TestContext } from './helpers.js';

describe('POST /v1/register', () => {
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

  it('returns 201 with the created user on successful registration', async () => {
    const identity = generateSomaIdentity();

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/register',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        soma_did: identity.did,
        public_key: identity.publicKeyB64,
        display_name: 'Test User',
      }),
    });

    assert.equal(response.statusCode, 201);

    const body = response.json<{
      user: {
        id: string;
        soma_did: string;
        public_key: string;
        display_name: string | null;
        created_at: string;
      };
    }>();

    assert.ok(body.user, 'response should have a user object');
    assert.equal(body.user.soma_did, identity.did);
    assert.equal(body.user.public_key, identity.publicKeyB64);
    assert.equal(body.user.display_name, 'Test User');
    assert.ok(typeof body.user.id === 'string', 'user.id should be a string');
    assert.ok(!isNaN(Date.parse(body.user.created_at)), 'created_at should be a valid ISO date');
  });

  it('returns 409 with already_registered when the same soma_did is registered twice', async () => {
    const identity = generateSomaIdentity();
    const payload = {
      soma_did: identity.did,
      public_key: identity.publicKeyB64,
    };

    // First registration — should succeed
    const first = await ctx.app.inject({
      method: 'POST',
      url: '/v1/register',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    assert.equal(first.statusCode, 201);

    // Second registration with the same DID — should be rejected
    const second = await ctx.app.inject({
      method: 'POST',
      url: '/v1/register',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(second.statusCode, 409);

    const body = second.json<{ error: string }>();
    assert.equal(body.error, 'already_registered');
  });

  it('returns 400 with validation_error when soma_did is missing', async () => {
    const identity = generateSomaIdentity();

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/register',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        // soma_did intentionally omitted
        public_key: identity.publicKeyB64,
      }),
    });

    assert.equal(response.statusCode, 400);

    const body = response.json<{ error: string }>();
    assert.equal(body.error, 'validation_error');
  });
});
