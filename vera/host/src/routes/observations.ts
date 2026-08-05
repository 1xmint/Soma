import type { FastifyInstance } from 'fastify';
import { and, eq } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import { users, observationBatches, observations } from '../db/schema/index.js';
import { verifySignature } from '../lib/soma-verify.js';
import {
  EnvelopeError,
  assertValidEnvelope,
  signedBytes,
  type ObservationEnvelope,
} from '../lib/envelope.js';

/**
 * Accepted clock skew between the submitter and this host, in seconds.
 *
 * This bounds replay independently of the uniqueness index, and keeps bounding
 * it even if that index is lost or rebuilt. Neither mechanism suffices alone: a
 * window without uniqueness permits unlimited replay inside the window, and
 * uniqueness without a window requires the index to be kept forever.
 * See SIGNING-SPEC.md.
 */
const MAX_SKEW_SECONDS = 300;

interface ObservationItemShape {
  type: string;
  content: unknown;
  observed_at: string;
}

export async function observationsRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/observations', async (request, reply) => {
    const body = request.body as { envelope?: unknown; signature?: unknown } | null;

    if (!body || typeof body !== 'object' || typeof body.signature !== 'string') {
      return reply.status(400).send({
        error: 'validation_error',
        message: 'body must carry an envelope and a signature',
      });
    }

    let envelope: ObservationEnvelope;
    try {
      assertValidEnvelope(body.envelope);
      envelope = body.envelope;
    } catch (err: unknown) {
      const code = err instanceof EnvelopeError ? err.code : 'envelope_invalid';
      const message = err instanceof Error ? err.message : 'envelope is invalid';
      return reply.status(400).send({ error: code, message });
    }

    const db = request.server.db;

    const userRows = await db
      .select()
      .from(users)
      .where(eq(users.somaDid, envelope.soma_did))
      .limit(1);

    if (userRows.length === 0) {
      return reply.status(404).send({
        error: 'user_not_found',
        message: 'No user registered with this Soma DID',
      });
    }
    const user = userRows[0]!;

    // Verification is over bytes recomputed from the parsed envelope, never
    // over the bytes as received. A sender emitting non-canonical JSON is not
    // rejected for that alone: the canonical form is the identity of the
    // content. Canonicalization can still throw, on input this profile forbids.
    let payload: Uint8Array;
    try {
      payload = signedBytes(envelope);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'not canonicalizable';
      return reply.status(400).send({ error: 'envelope_not_canonicalizable', message });
    }

    if (!verifySignature(payload, body.signature, user.publicKey)) {
      return reply.status(403).send({
        error: 'signature_invalid',
        message: 'Soma signature verification failed',
      });
    }

    // Only once the signature holds is submitted_at trustworthy enough to
    // judge. Checking it earlier would let an unauthenticated field decide
    // whether authenticated work gets done.
    const submittedAt = new Date(envelope.submitted_at);
    const skewSeconds = Math.abs(Date.now() - submittedAt.getTime()) / 1000;
    if (skewSeconds > MAX_SKEW_SECONDS) {
      return reply.status(403).send({
        error: 'submitted_at_stale',
        message: `submitted_at is ${Math.round(skewSeconds)}s from host time; limit is ${MAX_SKEW_SECONDS}s`,
      });
    }

    // Replay is idempotent, not fatal. An observer retrying after a network
    // timeout has done nothing wrong and must not be punished for it.
    const existing = await db
      .select()
      .from(observationBatches)
      .where(
        and(
          eq(observationBatches.userId, user.id),
          eq(observationBatches.batchId, envelope.batch_id),
        ),
      )
      .limit(1);

    if (existing.length > 0) {
      const batch = existing[0]!;
      return reply.status(200).send({
        batch: {
          id: batch.id,
          user_id: batch.userId,
          source_type: batch.sourceType,
          observation_count: envelope.observations.length,
          created_at: batch.createdAt.toISOString(),
        },
        duplicate: true,
      });
    }

    const payloadHash = createHash('sha256').update(payload).digest('hex');

    const batchRows = await db
      .insert(observationBatches)
      .values({
        userId: user.id,
        batchId: envelope.batch_id,
        somaSignature: body.signature,
        signedPayloadHash: payloadHash,
        sourceType: envelope.source_type,
        submittedAt,
        metadata: null,
      })
      .returning();

    const batch = batchRows[0];
    if (!batch) {
      return reply.status(500).send({
        error: 'internal_error',
        message: 'Failed to create observation batch',
      });
    }

    const obsValues = (envelope.observations as ObservationItemShape[]).map((item) => ({
      batchId: batch.id,
      observationType: item.type,
      content: item.content,
      observedAt: new Date(item.observed_at),
    }));

    await db.insert(observations).values(obsValues);

    return reply.status(201).send({
      batch: {
        id: batch.id,
        user_id: batch.userId,
        source_type: batch.sourceType,
        observation_count: envelope.observations.length,
        created_at: batch.createdAt.toISOString(),
      },
    });
  });
}
