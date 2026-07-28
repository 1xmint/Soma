/**
 * guardian-auth.test.ts
 *
 * Tests for the guardian-signed request envelope middleware.
 * Covers both POST /v1/aggregate and POST /v1/query.
 */
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import {
  ingestObservations,
  setupTestContext,
  generateSomaIdentity,
  guardianHeaders,
  cleanTables,
  type TestContext,
  type SomaIdentity,
} from './helpers.js';

/** Register a user — throws on non-201. */
async function registerUser(
  ctx: TestContext,
  did: string,
  publicKeyB64: string,
): Promise<void> {
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/v1/register',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ soma_did: did, public_key: publicKeyB64 }),
  });
  if (response.statusCode !== 201) {
    throw new Error(`registerUser failed: ${response.statusCode} ${response.body}`);
  }
}

/** Ingest a minimal observation batch — returns batch_id. */

describe('guardian-auth middleware', () => {
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

  // ── Happy path ────────────────────────────────────────────────────────────

  it('aggregate: valid guardian headers → 201', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);
    const batchId = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

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
  });

  it('query: valid guardian headers → 200', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const reqBody = { soma_did: identity.did, query_text: 'hello', limit: 5 };
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...guardianHeaders('POST', '/v1/query', reqBody, identity),
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 200);
  });

  // ── Missing headers ───────────────────────────────────────────────────────

  it('aggregate: no guardian headers → 401', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);
    const batchId = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ soma_did: identity.did, batch_id: batchId }),
    });

    assert.equal(response.statusCode, 401);
    const body = response.json<{ error: string }>();
    assert.equal(body.error, 'guardian_auth_failed');
  });

  it('query: no guardian headers → 401', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ soma_did: identity.did, query_text: 'hello', limit: 5 }),
    });

    assert.equal(response.statusCode, 401);
    const body = response.json<{ error: string }>();
    assert.equal(body.error, 'guardian_auth_failed');
  });

  // ── Expired timestamp ─────────────────────────────────────────────────────

  it('aggregate: expired timestamp → 401', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);
    const batchId = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

    const reqBody = { soma_did: identity.did, batch_id: batchId };

    // Build headers with a timestamp 6 minutes in the past
    const provider = getCryptoProvider();
    const expiredTs = new Date(Date.now() - 6 * 60 * 1000).toISOString();
    const nonceBytes = new Uint8Array(16);
    crypto.getRandomValues(nonceBytes);
    const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

    const signingInput = JSON.stringify({
      method: 'POST',
      path: '/v1/aggregate',
      body: reqBody,
      timestamp: expiredTs,
      nonce,
    });
    const inputBytes = new TextEncoder().encode(signingInput);
    const sigBytes = provider.signing.sign(inputBytes, identity.secretKey);
    const sig = provider.encoding.encodeBase64(sigBytes);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        'x-guardian-signature': sig,
        'x-guardian-timestamp': expiredTs,
        'x-guardian-nonce': nonce,
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 401);
    const body = response.json<{ error: string; message: string }>();
    assert.equal(body.error, 'guardian_auth_failed');
    assert.ok(body.message.toLowerCase().includes('timestamp'), 'message should mention timestamp');
  });

  // ── Wrong signing key ─────────────────────────────────────────────────────

  it('aggregate: wrong signing key → 401', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);
    const batchId = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

    // Sign with a completely different keypair
    const wrongIdentity = generateSomaIdentity();
    const reqBody = { soma_did: identity.did, batch_id: batchId };

    // Build signed headers using the wrong key but the correct soma_did in body
    const provider = getCryptoProvider();
    const nonceBytes = new Uint8Array(16);
    crypto.getRandomValues(nonceBytes);
    const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    const timestamp = new Date().toISOString();

    const signingInput = JSON.stringify({
      method: 'POST',
      path: '/v1/aggregate',
      body: reqBody,
      timestamp,
      nonce,
    });
    const inputBytes = new TextEncoder().encode(signingInput);
    const sigBytes = provider.signing.sign(inputBytes, wrongIdentity.secretKey);
    const sig = provider.encoding.encodeBase64(sigBytes);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        'x-guardian-signature': sig,
        'x-guardian-timestamp': timestamp,
        'x-guardian-nonce': nonce,
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 401);
    const body = response.json<{ error: string }>();
    assert.equal(body.error, 'guardian_auth_failed');
  });

  // ── Tampered body ─────────────────────────────────────────────────────────

  it('aggregate: tampered body (sign one body, send different body) → 401', async () => {
    const identityA = generateSomaIdentity();
    const identityB = generateSomaIdentity();
    await registerUser(ctx, identityA.did, identityA.publicKeyB64);
    await registerUser(ctx, identityB.did, identityB.publicKeyB64);

    const batchIdA = await ingestObservations(ctx, identityA.did, identityA.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

    // Sign request for identity A's batch
    const signedBody = { soma_did: identityA.did, batch_id: batchIdA };
    const hdrs = guardianHeaders('POST', '/v1/aggregate', signedBody, identityA);

    // Send a DIFFERENT body (different soma_did in body vs what was signed)
    const tamperedBody = { soma_did: identityB.did, batch_id: batchIdA };

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...hdrs,
      },
      body: JSON.stringify(tamperedBody),
    });

    // Signature was computed over signedBody but server reconstructs with tamperedBody → mismatch
    assert.equal(response.statusCode, 401);
    const body = response.json<{ error: string }>();
    assert.equal(body.error, 'guardian_auth_failed');
  });

  // ── Nonce replay ──────────────────────────────────────────────────────────

  it('aggregate: replayed nonce → 401 on second request', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const batchId1 = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);

    // Build a fixed nonce manually so we can reuse it
    const provider = getCryptoProvider();
    const nonceBytes = new Uint8Array(16);
    crypto.getRandomValues(nonceBytes);
    const fixedNonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    const timestamp = new Date().toISOString();

    // Helper to build signed headers with the fixed nonce
    function buildHeaders(reqBody: unknown): {
      'x-guardian-signature': string;
      'x-guardian-timestamp': string;
      'x-guardian-nonce': string;
    } {
      const signingInput = JSON.stringify({
        method: 'POST',
        path: '/v1/aggregate',
        body: reqBody,
        timestamp,
        nonce: fixedNonce,
      });
      const inputBytes = new TextEncoder().encode(signingInput);
      const sigBytes = provider.signing.sign(inputBytes, identity.secretKey);
      return {
        'x-guardian-signature': provider.encoding.encodeBase64(sigBytes),
        'x-guardian-timestamp': timestamp,
        'x-guardian-nonce': fixedNonce,
      };
    }

    const reqBody1 = { soma_did: identity.did, batch_id: batchId1 };

    // First request — should succeed
    const response1 = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...buildHeaders(reqBody1),
      },
      body: JSON.stringify(reqBody1),
    });
    assert.equal(response1.statusCode, 201, 'first request with fresh nonce should succeed');

    // Second request with the SAME nonce — replay must be rejected
    const batchId2 = await ingestObservations(ctx, identity.did, identity.secretKey, [{ type: 'code_edit', content: { file: 'test.ts' }, observed_at: new Date().toISOString() }]);
    const reqBody2 = { soma_did: identity.did, batch_id: batchId2 };

    const response2 = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...buildHeaders(reqBody2),
      },
      body: JSON.stringify(reqBody2),
    });
    assert.equal(response2.statusCode, 401, 'second request with same nonce should be rejected');
    const body2 = response2.json<{ error: string; message: string }>();
    assert.equal(body2.error, 'guardian_auth_failed');
    assert.ok(body2.message.toLowerCase().includes('replay'), 'message should mention replay');
  });
});
