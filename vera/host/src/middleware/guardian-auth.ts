import type { FastifyRequest, FastifyReply } from 'fastify';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema/index.js';
import { verifySignature } from '../lib/soma-verify.js';

const FRESHNESS_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Module-level nonce replay cache.
 * Maps nonce string → expiry timestamp (ms since epoch).
 * A nonce is valid within the 5-minute freshness window and is
 * rejected on any subsequent attempt inside that window.
 */
const nonceCache = new Map<string, number>();

/**
 * Periodic cleanup: evict expired nonces every 60 seconds.
 * .unref() ensures this timer never keeps the process alive (safe in tests).
 */
setInterval(() => {
  const now = Date.now();
  for (const [nonce, expiry] of nonceCache.entries()) {
    if (now > expiry) {
      nonceCache.delete(nonce);
    }
  }
}, 60_000).unref();

/**
 * Fastify preHandler: enforces guardian-signed request envelopes.
 *
 * Required headers:
 *   X-Guardian-Signature  — base64 Ed25519 signature over the canonical signing input
 *   X-Guardian-Timestamp  — ISO 8601 timestamp
 *   X-Guardian-Nonce      — hex string, ≥32 chars (≥16 bytes)
 *
 * Canonical signing input:
 *   JSON.stringify({ method, path, body, timestamp, nonce })
 *
 * On any failure: 401 { error: "guardian_auth_failed", message: "<reason>" }
 * On success: stores nonce, continues to route handler.
 */
export async function guardianAuth(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  // 1. Extract headers
  const rawSig = request.headers['x-guardian-signature'];
  const rawTs = request.headers['x-guardian-timestamp'];
  const rawNonce = request.headers['x-guardian-nonce'];

  if (!rawSig || !rawTs || !rawNonce) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Missing guardian authentication headers',
    });
  }

  // Flatten in case headers appear multiple times (defensive)
  const sigStr = Array.isArray(rawSig) ? rawSig[0] : rawSig;
  const tsStr = Array.isArray(rawTs) ? rawTs[0] : rawTs;
  const nonceStr = Array.isArray(rawNonce) ? rawNonce[0] : rawNonce;

  if (!sigStr || !tsStr || !nonceStr) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Missing guardian authentication headers',
    });
  }

  // 2. Validate nonce length: ≥32 hex chars = ≥16 bytes
  if (nonceStr.length < 32) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Nonce too short — must be at least 32 hex characters',
    });
  }

  // 3. Validate and check timestamp freshness
  const tsDate = new Date(tsStr);
  if (isNaN(tsDate.getTime())) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Invalid timestamp format',
    });
  }

  const now = Date.now();
  if (Math.abs(now - tsDate.getTime()) > FRESHNESS_WINDOW_MS) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Timestamp expired or too far in the future',
    });
  }

  // 4. Check nonce replay BEFORE DB lookup to fail fast
  if (nonceCache.has(nonceStr)) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Nonce already used — replay detected',
    });
  }

  // 5. Extract soma_did from the parsed request body
  const body = request.body as Record<string, unknown> | null | undefined;
  const somaDid = body?.soma_did;

  if (!somaDid || typeof somaDid !== 'string') {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Missing soma_did in request body',
    });
  }

  // 6. Look up user — return 401 (NOT 404) to avoid leaking user existence
  const db = request.server.db;
  const userRows = await db
    .select()
    .from(users)
    .where(eq(users.somaDid, somaDid))
    .limit(1);

  if (userRows.length === 0) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Authentication failed',
    });
  }

  const user = userRows[0]!;

  // 7. Reconstruct the canonical signing input
  //    path = URL pathname only (no query string)
  const path = new URL(request.url, 'http://localhost').pathname;

  const signingInput = JSON.stringify({
    method: request.method,
    path,
    body,
    timestamp: tsStr,
    nonce: nonceStr,
  });

  // 8. Verify signature using getCryptoProvider() (via verifySignature helper)
  //
  // TODO(SIGNING-SPEC): this scheme calls its input "canonical" but builds it
  // with JSON.stringify, and carries no domain prefix, while signing with the
  // same identity key as observation batches. Nothing but a structural accident
  // keeps a signature from one context from being presented in the other. It
  // does bind a timestamp and nonce, so replay is handled. Bring it under
  // SIGNING-SPEC.md with its own domain and canonicalization.
  const valid = verifySignature(new TextEncoder().encode(signingInput), sigStr, user.publicKey);
  if (!valid) {
    return reply.status(401).send({
      error: 'guardian_auth_failed',
      message: 'Signature verification failed',
    });
  }

  // 9. Store nonce in replay cache — expires one freshness window from now
  nonceCache.set(nonceStr, now + FRESHNESS_WINDOW_MS);
}
