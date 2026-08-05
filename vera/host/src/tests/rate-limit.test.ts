/**
 * Rate limiting — operator self-defence on the host's own resources.
 *
 * `POST /v1/observations` performs a database lookup and an Ed25519
 * verification for every unauthenticated request. Without a limit that is a
 * cheap amplification into expensive work, and CodeQL flags it as such
 * (js/missing-rate-limiting, high).
 *
 * These tests need no database. That is deliberate: the property under test is
 * that the limiter is registered *ahead of every route*, which is exactly the
 * property that quietly disappears when someone adds a route later. Requiring
 * Postgres to check it would mean it stopped being checked.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../server.js';
import type { Db } from '../db/connection.js';

// The limiter runs before any handler touches the database, so a stub suffices.
// If a future change makes app construction depend on a live db, this cast will
// stop compiling rather than silently pass.
const stubDb = {} as Db;

async function appWithLimit(max: number) {
  return buildApp(stubDb, { max, timeWindow: '1 minute' });
}

describe('rate limiting', () => {
  test('requests up to the limit are served', async () => {
    const app = await appWithLimit(3);
    try {
      for (let i = 0; i < 3; i += 1) {
        const res = await app.inject({ method: 'GET', url: '/health' });
        assert.notEqual(res.statusCode, 429, `request ${i + 1} of 3 was limited too early`);
      }
    } finally {
      await app.close();
    }
  });

  test('the request past the limit is refused with 429', async () => {
    const app = await appWithLimit(3);
    try {
      for (let i = 0; i < 3; i += 1) {
        await app.inject({ method: 'GET', url: '/health' });
      }
      const res = await app.inject({ method: 'GET', url: '/health' });
      assert.equal(res.statusCode, 429, 'the fourth request should have been refused');
    } finally {
      await app.close();
    }
  });

  test('the ingest route is covered, and refused before any verification work', async () => {
    const app = await appWithLimit(2);
    try {
      const body = JSON.stringify({ envelope: {}, signature: 'not-a-signature' });
      const headers = { 'content-type': 'application/json' };

      for (let i = 0; i < 2; i += 1) {
        await app.inject({ method: 'POST', url: '/v1/observations', headers, body });
      }
      const res = await app.inject({ method: 'POST', url: '/v1/observations', headers, body });

      // 429 rather than 400 is the whole point: the limiter answered before the
      // handler looked at the envelope, so no database query and no signature
      // verification was spent on this request.
      assert.equal(res.statusCode, 429, 'ingest route was not covered by the limiter');
    } finally {
      await app.close();
    }
  });

  test('a fresh soma_did per request does not buy a fresh bucket', async () => {
    // The bucket is keyed by IP, deliberately not by the submitted DID. Keying
    // on the DID would key on unauthenticated caller-chosen input: an attacker
    // sends a new DID every time, every request lands in an empty bucket, and
    // the limit measures nothing. This test exists because the first draft of
    // this limiter did exactly that.
    const app = await appWithLimit(2);
    try {
      const headers = { 'content-type': 'application/json' };
      const send = (did: string) =>
        app.inject({
          method: 'POST',
          url: '/v1/observations',
          headers,
          body: JSON.stringify({ envelope: { soma_did: did }, signature: 'x' }),
        });

      await send('did:key:zAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      await send('did:key:zBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
      const res = await send('did:key:zCcccccccccccccccccccccccccccccccccccccccccc');

      assert.equal(res.statusCode, 429, 'a new DID per request evaded the limit');
    } finally {
      await app.close();
    }
  });
});
