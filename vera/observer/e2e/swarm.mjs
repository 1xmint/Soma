#!/usr/bin/env node
/**
 * Swarm simulation — honest agents and adversaries against a live host.
 *
 *   node e2e/swarm.mjs http://127.0.0.1:3199 [agentCount]
 *
 * A simulation where everyone behaves proves nothing. This one runs attacks
 * alongside honest work and reports which the network caught and which it did
 * not. The failures are the point: an attack that succeeds here is a finding,
 * not a bug in the simulation.
 *
 * Every signature is real. Nothing is mocked.
 */

import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { randomBytes } from 'node:crypto';
import { didFromPublicKey } from '../dist/lib/did.js';
import {
  OBSERVATION_BATCH_SCHEMA,
  formatSubmittedAt,
  signedBytes,
} from '../dist/lib/envelope.js';

const HOST = process.argv[2] ?? 'http://127.0.0.1:3199';
const HONEST_COUNT = Number(process.argv[3] ?? 12);

const provider = getCryptoProvider();

const results = { caught: [], uncaught: [], notes: [] };
function caught(what, detail) { results.caught.push(`${what}${detail ? ` — ${detail}` : ''}`); }
function uncaught(what, detail) { results.uncaught.push(`${what}${detail ? ` — ${detail}` : ''}`); }
function note(what) { results.notes.push(what); }

async function post(path, body) {
  const response = await fetch(`${HOST}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  let json = null;
  try { json = await response.json(); } catch { /* some errors have no body */ }
  return { status: response.status, json };
}

function identity(label) {
  const keyPair = provider.signing.generateKeyPair();
  return {
    label,
    did: didFromPublicKey(keyPair.publicKey),
    publicKeyB64: provider.encoding.encodeBase64(keyPair.publicKey),
    secretKey: keyPair.secretKey,
  };
}

async function register(who) {
  const r = await post('/v1/register', { soma_did: who.did, public_key: who.publicKeyB64 });
  return r.status === 201;
}

function work(agent, index) {
  return [{
    type: 'git_commit',
    content: { hash: randomBytes(20).toString('hex'), message: `${agent.label} task ${index}` },
    observed_at: new Date().toISOString(),
  }];
}

function envelope(who, observations, overrides = {}) {
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

function sign(env, secretKey) {
  return provider.encoding.encodeBase64(provider.signing.sign(signedBytes(env), secretKey));
}

async function submit(who, env) {
  return post('/v1/observations', { envelope: env, signature: sign(env, who.secretKey) });
}

console.log(`swarm against ${HOST}\n`);

// ── Honest population ────────────────────────────────────────────────────────
const honest = [];
for (let i = 0; i < HONEST_COUNT; i += 1) honest.push(identity(`honest-${i}`));

let registered = 0;
for (const who of honest) if (await register(who)) registered += 1;
console.log(`registered ${registered}/${honest.length} honest agents`);

let accepted = 0;
for (const [i, who] of honest.entries()) {
  const r = await submit(who, envelope(who, work(who, i)));
  if (r.status === 201) accepted += 1;
}
console.log(`accepted ${accepted}/${honest.length} honest batches\n`);
if (accepted !== honest.length) note(`only ${accepted} of ${honest.length} honest submissions succeeded`);

// ── Attack: sign for someone else's DID ──────────────────────────────────────
{
  const victim = honest[0];
  const attacker = identity('impostor');
  const env = envelope(victim, work(attacker, 0));
  const r = await post('/v1/observations', { envelope: env, signature: sign(env, attacker.secretKey) });
  r.status === 403
    ? caught('forging another identity', `403`)
    : uncaught('forging another identity', `status ${r.status}`);
}

// ── Attack: register your own key against someone else's identifier ──────────
{
  const victim = honest[1];
  const attacker = identity('key-swapper');
  const r = await post('/v1/register', { soma_did: victim.did, public_key: attacker.publicKeyB64 });
  r.status === 400 || r.status === 409
    ? caught('binding a foreign key to an identifier', `${r.status}`)
    : uncaught('binding a foreign key to an identifier', `status ${r.status}`);
}

// ── Attack: relabel provenance after signing ─────────────────────────────────
{
  const who = honest[2];
  const env = envelope(who, work(who, 99));
  const signature = sign(env, who.secretKey);
  const r = await post('/v1/observations', {
    envelope: { ...env, source_type: 'audited-enterprise-source' },
    signature,
  });
  r.status === 403
    ? caught('relabelling provenance', '403')
    : uncaught('relabelling provenance', `status ${r.status}`);
}

// ── Attack: replay the same signed batch repeatedly ──────────────────────────
{
  const who = honest[3];
  const env = envelope(who, work(who, 5));
  const signature = sign(env, who.secretKey);
  const first = await post('/v1/observations', { envelope: env, signature });
  let duplicates = 0;
  let extras = 0;
  for (let i = 0; i < 5; i += 1) {
    const r = await post('/v1/observations', { envelope: env, signature });
    if (r.status === 200 && r.json?.duplicate) duplicates += 1;
    if (r.status === 201) extras += 1;
  }
  extras === 0 && duplicates === 5
    ? caught('replaying a signed batch', `${duplicates} idempotent, 0 duplicates stored`)
    : uncaught('replaying a signed batch', `${extras} extra batches created`);
  if (first.status !== 201) note('replay setup batch was not accepted');
}

// ── Attack: volume. One identity, many DISTINCT valid batches ────────────────
// Nothing about this is forged. The question is whether the network has any
// answer to an honest-looking flood, which is how a corpus gets poisoned by
// weight of numbers rather than by forgery.
{
  const flooder = identity('flooder');
  await register(flooder);
  const target = 60;
  let stored = 0;
  const started = Date.now();
  for (let i = 0; i < target; i += 1) {
    const r = await submit(flooder, envelope(flooder, work(flooder, i)));
    if (r.status === 201) stored += 1;
  }
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  stored === target
    ? uncaught('flooding with valid batches', `${stored}/${target} stored in ${seconds}s from one identity — no rate limit, no cost`)
    : caught('flooding with valid batches', `${stored}/${target} stored`);
}

// ── Attack: Sybil cluster. Many identities, one operator ─────────────────────
// Each identity is independently valid. Nothing distinguishes them from
// strangers at the wire level, which is the whole Sybil problem.
{
  const clusterSize = 25;
  let clusterStored = 0;
  for (let i = 0; i < clusterSize; i += 1) {
    const sybil = identity(`sybil-${i}`);
    if (!(await register(sybil))) continue;
    const r = await submit(sybil, envelope(sybil, work(sybil, i)));
    if (r.status === 201) clusterStored += 1;
  }
  clusterStored === clusterSize
    ? uncaught('sybil cluster', `${clusterStored} identities created and accepted at zero cost`)
    : caught('sybil cluster', `${clusterStored}/${clusterSize} accepted`);
}

// ── Attack: stale and future timestamps ──────────────────────────────────────
{
  const who = honest[4];
  const old = envelope(who, work(who, 1), { submitted_at: formatSubmittedAt(new Date(Date.now() - 3600e3)) });
  const ahead = envelope(who, work(who, 2), { submitted_at: formatSubmittedAt(new Date(Date.now() + 3600e3)) });
  const a = await submit(who, old);
  const b = await submit(who, ahead);
  a.status === 403 ? caught('stale submission', '403') : uncaught('stale submission', `status ${a.status}`);
  b.status === 403 ? caught('future-dated submission', '403') : uncaught('future-dated submission', `status ${b.status}`);
}

// ── Attack: unregistered identity ────────────────────────────────────────────
{
  const stranger = identity('unregistered');
  const r = await submit(stranger, envelope(stranger, work(stranger, 0)));
  r.status === 404
    ? caught('unregistered identity', '404')
    : uncaught('unregistered identity', `status ${r.status}`);
}

// ── Attack: enormous batch ───────────────────────────────────────────────────
{
  const who = honest[5];
  const many = Array.from({ length: 5000 }, (_, i) => ({
    type: 'git_commit',
    content: { hash: randomBytes(20).toString('hex'), message: `bulk ${i}` },
    observed_at: new Date().toISOString(),
  }));
  const started = Date.now();
  const r = await submit(who, envelope(who, many));
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  r.status === 201
    ? uncaught('5000-observation batch', `accepted in ${seconds}s — no size bound`)
    : caught('5000-observation batch', `status ${r.status}`);
}

// ── Report ───────────────────────────────────────────────────────────────────
console.log('CAUGHT');
for (const line of results.caught) console.log(`  ok    ${line}`);
console.log('\nNOT CAUGHT');
if (results.uncaught.length === 0) console.log('  (none)');
for (const line of results.uncaught) console.log(`  GAP   ${line}`);
if (results.notes.length) {
  console.log('\nNOTES');
  for (const line of results.notes) console.log(`  -     ${line}`);
}
console.log(`\n${results.caught.length} caught, ${results.uncaught.length} not caught`);
console.log('\nAn attack in NOT CAUGHT is a finding about the design, not a failure of the run.');
