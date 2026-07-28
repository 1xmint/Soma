/**
 * Submitter tests — unit tests for the HTTP submission client.
 *
 * fetch is mocked globally so no live server is required.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { submitObservations } from '../lib/submitter.js';
import { generateTestIdentity } from '../lib/identity.js';
import type { ObservationItem } from '../lib/types.js';

// ---- Helpers ----

function makeItem(hash: string): ObservationItem {
  return {
    type: 'git_commit',
    content: { commit_hash: hash },
    observed_at: '2026-01-01T00:00:00Z',
  };
}

function makeJsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Store the original fetch so we can restore it after each test.
// Node 22 has fetch as a global.
type FetchFn = typeof globalThis.fetch;
let originalFetch: FetchFn;

beforeEach(() => {
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// ---- Tests ----

describe('submitObservations', () => {
  test('201 response returns success with batchId', async () => {
    const identity = generateTestIdentity();
    const observations = [makeItem('a'.repeat(40))];

    globalThis.fetch = async () => makeJsonResponse(201, {
      batch: {
        id: 'batch-uuid-1234',
        user_id: 'user-uuid-5678',
        source_type: 'git',
        observation_count: 1,
        created_at: '2026-01-01T00:00:00Z',
      },
    });

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      observations
    );

    assert.ok(result.success, 'Should return success');
    assert.equal(result.success === true && result.batchId, 'batch-uuid-1234');
  });

  test('404 response returns failure with user_not_found error', async () => {
    const identity = generateTestIdentity();
    const observations = [makeItem('b'.repeat(40))];

    globalThis.fetch = async () => makeJsonResponse(404, { error: 'user_not_found' });

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      observations
    );

    assert.ok(!result.success, 'Should return failure');
    if (!result.success) {
      assert.equal(result.statusCode, 404);
      assert.ok(result.error.includes('user_not_found'), `Expected user_not_found in error, got: ${result.error}`);
    }
  });

  test('403 response returns failure with signature_invalid error', async () => {
    const identity = generateTestIdentity();
    const observations = [makeItem('c'.repeat(40))];

    globalThis.fetch = async () => makeJsonResponse(403, { error: 'signature_invalid' });

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      observations
    );

    assert.ok(!result.success, 'Should return failure');
    if (!result.success) {
      assert.equal(result.statusCode, 403);
      assert.ok(result.error.includes('signature_invalid'), `Expected signature_invalid in error, got: ${result.error}`);
    }
  });

  test('network error (fetch throws) returns failure with statusCode 0', async () => {
    const identity = generateTestIdentity();
    const observations = [makeItem('d'.repeat(40))];

    globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      observations
    );

    assert.ok(!result.success, 'Should return failure');
    if (!result.success) {
      assert.equal(result.statusCode, 0, 'Network errors should produce statusCode 0');
      assert.ok(result.error.includes('ECONNREFUSED'), `Expected ECONNREFUSED in error, got: ${result.error}`);
    }
  });

  test('500 server error returns failure with correct statusCode', async () => {
    const identity = generateTestIdentity();
    const observations = [makeItem('e'.repeat(40))];

    globalThis.fetch = async () => makeJsonResponse(500, { error: 'internal server error' });

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      observations
    );

    assert.ok(!result.success, 'Should return failure for 500');
    if (!result.success) {
      assert.equal(result.statusCode, 500);
    }
  });

  test('empty observations array returns early failure', async () => {
    const identity = generateTestIdentity();
    // Ensure fetch is never called for empty arrays
    let fetchCalled = false;
    globalThis.fetch = async () => {
      fetchCalled = true;
      return makeJsonResponse(201, {});
    };

    const result = await submitObservations(
      { veraKnowledgeUrl: 'http://localhost:3000', identity },
      []
    );

    assert.ok(!result.success, 'Should return failure for empty batch');
    assert.ok(!fetchCalled, 'fetch should not be called for empty arrays');
  });
});
