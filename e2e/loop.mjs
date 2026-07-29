#!/usr/bin/env node
/**
 * End-to-end: one identity, work observed, batch signed, host verifies, corpus grows.
 *
 * Run against a live host:
 *
 *   cd host && docker compose up -d && npm run db:migrate && npm start &
 *   node e2e/loop.mjs http://localhost:3000
 *
 * This exercises the real HTTP surface with real signatures. It mocks nothing.
 * If it passes, the observation half of Vera works against a running server.
 *
 * What it does NOT prove is stated at the end rather than glossed over.
 */

import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { randomBytes } from 'node:crypto';
import { didFromPublicKey } from '../observer/dist/lib/did.js';
import {
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
} from '../observer/dist/lib/envelope.js';

const HOST = process.argv[2] ?? process.env.VERA_HOST ?? 'http://localhost:3000';

let failures = 0;
function check(label, condition, detail = '') {
  const mark = condition ? 'ok  ' : 'FAIL';
  if (!condition) failures += 1;
  console.log(`${mark} ${label}${detail ? ` — ${detail}` : ''}`);
}

async function post(path, body) {
  const response = await fetch(`${HOST}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  let json = null;
  try {
    json = await response.json();
  } catch {
    // some errors have no body
  }
  return { status: response.status, json };
}

const provider = getCryptoProvider();

function identity() {
  const keyPair = provider.signing.generateKeyPair();
  return {
    did: didFromPublicKey(keyPair.publicKey),
    publicKeyB64: provider.encoding.encodeBase64(keyPair.publicKey),
    secretKey: keyPair.secretKey,
  };
}

function envelopeFor(who, observations, overrides = {}) {
  return {
    batch_id: randomBytes(16).toString('hex'),
    observations,
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: who.did,
    source_type: 'git',
    submitted_at: formatSubmittedAt(new Date()),
    ...overrides,
  };
}

function sign(envelope, secretKey) {
  return provider.encoding.encodeBase64(provider.signing.sign(signedBytes(envelope), secretKey));
}

const work = [
  {
    type: 'git_commit',
    content: { hash: 'e2e0000000000000000000000000000000000001', message: 'end to end' },
    observed_at: new Date().toISOString(),
  },
];

console.log(`vera end-to-end against ${HOST}\n`);

// 1. Health
const health = await fetch(`${HOST}/health`).catch(() => null);
check('host is reachable', health !== null && health.ok, health ? `status ${health.status}` : 'no response');
if (!health || !health.ok) {
  console.log('\nhost unreachable; start it first (see the header of this file)');
  process.exit(1);
}

// 2. An identity that is its own key
const agent = identity();
check('identity is self-certifying', agent.did.startsWith('did:key:z'), agent.did.slice(0, 24) + '…');

// 3. Registration binds the DID to the key it commits to
const registered = await post('/v1/register', {
  soma_did: agent.did,
  public_key: agent.publicKeyB64,
});
check('registration accepted', registered.status === 201, `status ${registered.status}`);

// 4. Registration refuses a key the DID does not commit to
const impostor = identity();
const mismatched = await post('/v1/register', {
  soma_did: `${agent.did}x`,
  public_key: impostor.publicKeyB64,
});
check(
  'registration refuses a mismatched DID/key pair',
  mismatched.status === 400,
  `status ${mismatched.status}`,
);

// 5. A signed batch is accepted
const envelope = envelopeFor(agent, work);
const signature = sign(envelope, agent.secretKey);
const submitted = await post('/v1/observations', { envelope, signature });
check('signed observation batch accepted', submitted.status === 201, `status ${submitted.status}`);
check('batch reports the observations it carried', submitted.json?.batch?.observation_count === 1);

// 6. Replay is idempotent, not a second batch
const replayed = await post('/v1/observations', { envelope, signature });
check('replay returns the original batch', replayed.status === 200 && replayed.json?.duplicate === true);
check(
  'replay did not create a second batch',
  replayed.json?.batch?.id === submitted.json?.batch?.id,
);

// 7. Provenance is inside the signature
const relabelled = { ...envelope, source_type: 'trusted-enterprise-audit' };
const tampered = await post('/v1/observations', { envelope: relabelled, signature });
check('relabelled provenance is rejected', tampered.status === 403, `status ${tampered.status}`);

// 8. Wire order is irrelevant; canonical bytes are the content
const reordered = {
  submitted_at: envelope.submitted_at,
  source_type: envelope.source_type,
  soma_did: envelope.soma_did,
  schema_version: envelope.schema_version,
  observations: envelope.observations,
  batch_id: randomBytes(16).toString('hex'),
};
const reorderedSignature = sign(reordered, agent.secretKey);
const reorderedResult = await post('/v1/observations', {
  envelope: reordered,
  signature: reorderedSignature,
});
check('member order does not affect verification', reorderedResult.status === 201);

// 9. Another identity cannot sign for this one
const forged = envelopeFor(agent, work);
const forgedResult = await post('/v1/observations', {
  envelope: forged,
  signature: sign(forged, impostor.secretKey),
});
check('a foreign signature is rejected', forgedResult.status === 403, `status ${forgedResult.status}`);

// 10. Stale submissions are refused even when correctly signed
const stale = envelopeFor(agent, work, {
  submitted_at: formatSubmittedAt(new Date(Date.now() - 3600 * 1000)),
});
const staleResult = await post('/v1/observations', {
  envelope: stale,
  signature: sign(stale, agent.secretKey),
});
check('a stale submission is refused', staleResult.status === 403, `status ${staleResult.status}`);

console.log('');
if (failures > 0) {
  console.log(`${failures} check(s) failed`);
  process.exit(1);
}

console.log('all checks passed\n');
console.log('What this proves: an identity that is its own key can register, sign work,');
console.log('and have a running host verify it — with provenance inside the signature,');
console.log('replay idempotent, and forged or stale submissions refused.');
console.log('');
console.log('What it does not prove: that the observed work actually happened. A signature');
console.log('establishes who said something, never whether it is true. Counter-signed');
console.log('receipts in Soma address attribution by a second party; nothing here does.');
