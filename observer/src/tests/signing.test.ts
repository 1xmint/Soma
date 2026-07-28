/**
 * Signing contract tests.
 *
 * These assert the properties SIGNING-SPEC.md depends on, not that Ed25519
 * works. A round-trip test that signs and verifies the same bytes passes no
 * matter what those bytes are, so it cannot notice the domain prefix being
 * dropped or the metadata falling outside the signature — which are exactly
 * the failures that matter.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import {
  OBSERVATION_BATCH_DOMAIN,
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
  type ObservationEnvelope,
} from '../lib/envelope.js';

function envelope(overrides: Partial<ObservationEnvelope> = {}): ObservationEnvelope {
  return {
    batch_id: randomBytes(16).toString('hex'),
    observations: [
      { type: 'git_commit', content: { commit_hash: 'a'.repeat(40) }, observed_at: '2026-01-01T00:00:00Z' },
    ],
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: 'did:soma:test',
    source_type: 'git',
    submitted_at: formatSubmittedAt(new Date('2026-01-01T00:00:00Z')),
    ...overrides,
  };
}

describe('observation batch signing contract', () => {
  test('signed bytes begin with the domain prefix', () => {
    const bytes = signedBytes(envelope());
    const prefix = new TextDecoder().decode(bytes.slice(0, OBSERVATION_BATCH_DOMAIN.length));
    assert.equal(
      prefix,
      OBSERVATION_BATCH_DOMAIN,
      'a signature without the domain prefix can be presented in another context',
    );
  });

  test('sign and verify round-trip over the real signed bytes', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();
    const bytes = signedBytes(envelope());

    const signature = provider.signing.sign(bytes, keyPair.secretKey);
    assert.ok(provider.signing.verify(bytes, signature, keyPair.publicKey));
  });

  test('member order does not change the signed bytes', () => {
    const base = envelope();
    const reordered = {
      submitted_at: base.submitted_at,
      source_type: base.source_type,
      soma_did: base.soma_did,
      schema_version: base.schema_version,
      observations: base.observations,
      batch_id: base.batch_id,
    } as ObservationEnvelope;

    assert.deepEqual(
      Array.from(signedBytes(base)),
      Array.from(signedBytes(reordered)),
      'canonicalization must make wire order irrelevant',
    );
  });

  test('changing any signed field changes the signed bytes', () => {
    const base = envelope();
    const baseline = Buffer.from(signedBytes(base)).toString('hex');

    const mutations: Array<[string, ObservationEnvelope]> = [
      ['source_type', { ...base, source_type: 'trusted-enterprise-audit' }],
      ['soma_did', { ...base, soma_did: 'did:soma:someone-else' }],
      ['batch_id', { ...base, batch_id: randomBytes(16).toString('hex') }],
      ['submitted_at', { ...base, submitted_at: formatSubmittedAt(new Date('2026-01-02T00:00:00Z')) }],
      ['observations', { ...base, observations: [{ type: 'x', content: {}, observed_at: '2026-01-01T00:00:00Z' }] }],
    ];

    for (const [field, mutated] of mutations) {
      assert.notEqual(
        Buffer.from(signedBytes(mutated)).toString('hex'),
        baseline,
        `mutating ${field} left the signed bytes unchanged, so it is not actually covered`,
      );
    }
  });

  test('signature is 64 bytes when decoded', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();
    const signature = provider.signing.sign(signedBytes(envelope()), keyPair.secretKey);
    const b64 = provider.encoding.encodeBase64(signature);
    assert.equal(provider.encoding.decodeBase64(b64).length, 64);
  });
});
