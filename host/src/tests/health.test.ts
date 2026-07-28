import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestContext, type TestContext } from './helpers.js';

describe('GET /health', () => {
  let ctx: TestContext;

  before(async () => {
    ctx = await setupTestContext();
  });

  after(async () => {
    await ctx.cleanup();
  });

  it('returns 200 with the expected shape', async () => {
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/health',
    });

    assert.equal(response.statusCode, 200);

    const body = response.json<{
      status: string;
      service: string;
      version: string;
      timestamp: string;
    }>();

    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'vera-knowledge');
    assert.equal(body.version, '0.1.0');
    assert.ok(typeof body.timestamp === 'string', 'timestamp should be a string');
    // Should be a valid ISO date string
    assert.ok(!isNaN(Date.parse(body.timestamp)), 'timestamp should be a valid ISO date');
  });
});
