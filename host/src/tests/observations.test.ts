import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import {
  setupTestContext,
  generateSomaIdentity,
  cleanTables,
  type TestContext,
  type SomaIdentity,
} from './helpers.js';
import {
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
  type ObservationEnvelope,
} from '../lib/envelope.js';

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

const sampleObservations = [
  {
    type: 'git_commit',
    content: { hash: 'abc123', message: 'initial' },
    observed_at: '2026-07-28T00:00:00Z',
  },
];

function buildEnvelope(
  identity: SomaIdentity,
  overrides: Partial<ObservationEnvelope> = {},
): ObservationEnvelope {
  return {
    batch_id: randomBytes(16).toString('hex'),
    observations: sampleObservations,
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: identity.did,
    source_type: 'git',
    submitted_at: formatSubmittedAt(new Date()),
    ...overrides,
  };
}

function sign(envelope: ObservationEnvelope, secretKey: Uint8Array): string {
  const provider = getCryptoProvider();
  return provider.encoding.encodeBase64(provider.signing.sign(signedBytes(envelope), secretKey));
}

async function post(ctx: TestContext, body: unknown) {
  return ctx.app.inject({
    method: 'POST',
    url: '/v1/observations',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('POST /v1/observations', () => {
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

  it('accepts a valid v1 envelope', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const response = await post(ctx, { envelope, signature: sign(envelope, identity.secretKey) });

    assert.equal(response.statusCode, 201, response.body);
    const body = response.json<{ batch: { source_type: string; observation_count: number } }>();
    assert.equal(body.batch.source_type, 'git');
    assert.equal(body.batch.observation_count, 1);
  });

  it('verifies over recomputed canonical bytes, so wire key order is irrelevant', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const signature = sign(envelope, identity.secretKey);

    // Same members, deliberately reordered. Canonicalization sorts, so this is
    // the same content and must verify against the same signature.
    const reordered = {
      submitted_at: envelope.submitted_at,
      source_type: envelope.source_type,
      soma_did: envelope.soma_did,
      schema_version: envelope.schema_version,
      observations: envelope.observations,
      batch_id: envelope.batch_id,
    };

    const response = await post(ctx, { envelope: reordered, signature });
    assert.equal(response.statusCode, 201, response.body);
  });

  it('treats a replayed batch_id as idempotent, returning the original batch', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const signature = sign(envelope, identity.secretKey);

    const first = await post(ctx, { envelope, signature });
    assert.equal(first.statusCode, 201, first.body);
    const firstId = first.json<{ batch: { id: string } }>().batch.id;

    const second = await post(ctx, { envelope, signature });
    assert.equal(second.statusCode, 200, second.body);
    const secondBody = second.json<{ batch: { id: string }; duplicate: boolean }>();
    assert.equal(secondBody.duplicate, true);
    assert.equal(
      secondBody.batch.id,
      firstId,
      'a replay must resolve to the original batch, not create another',
    );
  });

  it('rejects source_type tampering, because the signature now covers it', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const signature = sign(envelope, identity.secretKey);

    // v0 signed only the observations array, so relabelling provenance in
    // transit was undetectable. It must not be now.
    const tampered = { ...envelope, source_type: 'trusted-enterprise-audit' };

    const response = await post(ctx, { envelope: tampered, signature });
    assert.equal(response.statusCode, 403, response.body);
    assert.equal(response.json<{ error: string }>().error, 'signature_invalid');
  });

  it('rejects a stale submitted_at even when the signature is valid', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const old = new Date(Date.now() - 3600 * 1000);
    const envelope = buildEnvelope(identity, { submitted_at: formatSubmittedAt(old) });

    const response = await post(ctx, { envelope, signature: sign(envelope, identity.secretKey) });
    assert.equal(response.statusCode, 403, response.body);
    assert.equal(response.json<{ error: string }>().error, 'submitted_at_stale');
  });

  it('rejects an unknown envelope field rather than ignoring it', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const signature = sign(envelope, identity.secretKey);
    const extended = { ...envelope, priority: 'high' };

    const response = await post(ctx, { envelope: extended, signature });
    assert.equal(response.statusCode, 400, response.body);
    assert.equal(response.json<{ error: string }>().error, 'envelope_fields_invalid');
  });

  it('rejects a signature made by a different identity', async () => {
    const identity = generateSomaIdentity();
    const attacker = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const response = await post(ctx, { envelope, signature: sign(envelope, attacker.secretKey) });

    assert.equal(response.statusCode, 403, response.body);
    assert.equal(response.json<{ error: string }>().error, 'signature_invalid');
  });

  it('returns 404 for an unregistered DID', async () => {
    const identity = generateSomaIdentity();
    const envelope = buildEnvelope(identity);

    const response = await post(ctx, { envelope, signature: sign(envelope, identity.secretKey) });
    assert.equal(response.statusCode, 404, response.body);
    assert.equal(response.json<{ error: string }>().error, 'user_not_found');
  });

  it('rejects garbage in the signature field', async () => {
    const identity = generateSomaIdentity();
    await registerUser(ctx, identity.did, identity.publicKeyB64);

    const envelope = buildEnvelope(identity);
    const response = await post(ctx, { envelope, signature: 'not-a-signature' });

    assert.equal(response.statusCode, 403, response.body);
    assert.equal(response.json<{ error: string }>().error, 'signature_invalid');
  });
});
