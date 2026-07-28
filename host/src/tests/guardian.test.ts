/**
 * guardian.test.ts
 *
 * Unit tests for the local guardian module:
 *   - GuardianSigner: produces headers that pass server verification
 *   - ShareBoundaryPolicy: blocks denied actions before signing
 *   - GuardianState.exportBundle(): correct shape, no secret key
 */
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
import {
  createGuardianSigner,
  ShareBoundaryPolicy,
  GuardianState,
} from '../guardian/index.js';

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
async function ingestBatch(
  ctx: TestContext,
  identity: SomaIdentity,
): Promise<string> {
  const obsItems = [
    {
      type: 'code_edit',
      content: { file: 'guardian-test.ts' },
      observed_at: new Date().toISOString(),
    },
  ];
  const signature = signPayload(JSON.stringify(obsItems), identity.secretKey);

  const response = await ctx.app.inject({
    method: 'POST',
    url: '/v1/observations',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      soma_did: identity.did,
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

describe('guardian module', () => {
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

  // ── GuardianSigner ────────────────────────────────────────────────────────

  it('signer produces valid signed headers that pass server verification', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);
    const batchId = await ingestBatch(ctx, identity);

    const policy = new ShareBoundaryPolicy({ allowAggregate: true, allowQuery: true });
    const signer = createGuardianSigner(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const reqBody = { soma_did: identity.did, batch_id: batchId };
    const hdrs = signer.signRequest('POST', '/v1/aggregate', reqBody);

    // Verify the returned header keys are present
    assert.ok(typeof hdrs['x-guardian-signature'] === 'string', 'signature header should be a string');
    assert.ok(typeof hdrs['x-guardian-timestamp'] === 'string', 'timestamp header should be a string');
    assert.ok(typeof hdrs['x-guardian-nonce'] === 'string', 'nonce header should be a string');
    assert.ok(hdrs['x-guardian-nonce'].length >= 32, 'nonce should be at least 32 hex chars');

    // Send to the real server — should pass guardian auth and return 201
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/aggregate',
      headers: {
        'content-type': 'application/json',
        ...hdrs,
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 201, 'guardian-signer headers should pass server verification');
  });

  it('signer: query action produces headers that pass server verification', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const policy = new ShareBoundaryPolicy({ allowAggregate: true, allowQuery: true });
    const signer = createGuardianSigner(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const reqBody = { soma_did: identity.did, query_text: 'hello', limit: 5 };
    const hdrs = signer.signRequest('POST', '/v1/query', reqBody);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/v1/query',
      headers: {
        'content-type': 'application/json',
        ...hdrs,
      },
      body: JSON.stringify(reqBody),
    });

    assert.equal(response.statusCode, 200, 'guardian-signer query headers should pass server verification');
  });

  // ── ShareBoundaryPolicy ───────────────────────────────────────────────────

  it('policy: aggregate denied → signRequest throws before signing', async () => {
    const identity = generateSomaIdentity();
    const policy = new ShareBoundaryPolicy({ allowAggregate: false, allowQuery: true });
    const signer = createGuardianSigner(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const reqBody = { soma_did: identity.did, batch_id: '00000000-0000-4000-8000-000000000001' };

    assert.throws(
      () => signer.signRequest('POST', '/v1/aggregate', reqBody),
      /policy_denied/,
      'should throw with policy_denied when aggregate is disallowed',
    );
  });

  it('policy: query denied → signRequest throws before signing', async () => {
    const identity = generateSomaIdentity();
    const policy = new ShareBoundaryPolicy({ allowAggregate: true, allowQuery: false });
    const signer = createGuardianSigner(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const reqBody = { soma_did: identity.did, query_text: 'test', limit: 5 };

    assert.throws(
      () => signer.signRequest('POST', '/v1/query', reqBody),
      /policy_denied/,
      'should throw with policy_denied when query is disallowed',
    );
  });

  it('policy: both allowed → signRequest does not throw', async () => {
    const identity = generateSomaIdentity();
    const policy = new ShareBoundaryPolicy({ allowAggregate: true, allowQuery: true });
    const signer = createGuardianSigner(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const reqBody = { soma_did: identity.did, query_text: 'test', limit: 5 };
    assert.doesNotThrow(() => signer.signRequest('POST', '/v1/query', reqBody));
  });

  // ── GuardianState.exportBundle ────────────────────────────────────────────

  it('exportBundle: correct shape and secret key excluded', () => {
    const identity = generateSomaIdentity();
    const policy = { allowAggregate: true, allowQuery: false };

    const state = new GuardianState(
      {
        somaDid: identity.did,
        publicKey: identity.keyPair.publicKey,
        secretKey: identity.keyPair.secretKey,
      },
      policy,
    );

    const bundle = state.exportBundle();

    // Correct version
    assert.equal(bundle.version, 1, 'version should be 1');

    // Correct DID
    assert.equal(bundle.soma_did, identity.did, 'soma_did should match identity');

    // public_key is the base64-encoded public key
    assert.ok(typeof bundle.public_key === 'string', 'public_key should be a string');
    assert.equal(
      bundle.public_key,
      identity.publicKeyB64,
      'public_key should match the base64 public key',
    );

    // Policy exported correctly
    assert.deepEqual(bundle.policy, policy, 'policy should be included verbatim');

    // exported_at is a valid ISO 8601 string
    assert.ok(typeof bundle.exported_at === 'string', 'exported_at should be a string');
    assert.ok(!isNaN(Date.parse(bundle.exported_at)), 'exported_at should be a valid ISO date');

    // Secret key MUST NOT appear anywhere in the bundle
    const bundleStr = JSON.stringify(bundle);
    assert.ok(
      !bundleStr.includes('secretKey'),
      'bundle must not contain "secretKey"',
    );
    assert.ok(
      !bundleStr.includes('secret'),
      'bundle must not contain "secret"',
    );
    // The actual secret key bytes must not be base64-encoded in the bundle
    // (we don't have a direct way to check bytes, but we can verify the
    //  public_key field matches the public key, not something longer)
    assert.ok(
      Object.keys(bundle).length === 5,
      'bundle should have exactly 5 keys: version, soma_did, public_key, policy, exported_at',
    );
  });
});
