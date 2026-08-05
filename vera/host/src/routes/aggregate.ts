import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { users, observationBatches, observations, knowledgeEntries } from '../db/schema/index.js';
import { aggregateBodySchema } from '../lib/schemas.js';
import { stubEmbed } from '../lib/embeddings.js';
import { guardianAuth } from '../middleware/guardian-auth.js';

export async function aggregateRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/aggregate', { preHandler: guardianAuth }, async (request, reply) => {
    // 1. Validate request body
    const parseResult = aggregateBodySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'validation_error',
        message: 'Request body validation failed',
        details: parseResult.error.errors,
      });
    }

    const { soma_did, batch_id } = parseResult.data;
    const db = request.server.db;

    // 2. Look up user by soma_did
    const userRows = await db
      .select()
      .from(users)
      .where(eq(users.somaDid, soma_did))
      .limit(1);

    if (userRows.length === 0) {
      return reply.status(404).send({
        error: 'user_not_found',
        message: 'No user registered with this Soma DID',
      });
    }

    const user = userRows[0]!;

    // 3. Look up observation batch by batch_id
    const batchRows = await db
      .select()
      .from(observationBatches)
      .where(eq(observationBatches.id, batch_id))
      .limit(1);

    if (batchRows.length === 0) {
      return reply.status(404).send({
        error: 'batch_not_found',
        message: 'No observation batch found with the given batch_id',
      });
    }

    const batch = batchRows[0]!;

    // 4. Verify ownership
    if (batch.userId !== user.id) {
      return reply.status(403).send({
        error: 'forbidden',
        message: 'This batch does not belong to the given Soma DID',
      });
    }

    // 5. Fetch all observations in the batch
    const obsRows = await db
      .select()
      .from(observations)
      .where(eq(observations.batchId, batch_id));

    // Edge case: empty batch
    if (obsRows.length === 0) {
      return reply.status(200).send({ created: [], count: 0 });
    }

    // 6. Build KnowledgeEntry values for each observation
    const entries = obsRows.map((obs) => {
      const title = `${obs.observationType} at ${obs.observedAt.toISOString()}`;
      const content = JSON.stringify(obs.content);
      const embedding = stubEmbed(title + ' ' + content);

      return {
        entryType: obs.observationType,
        title,
        content,
        embedding,
        confidence: 0.3,
        tags: [obs.observationType],
        somaProvenance: {
          observation_id: obs.id,
          batch_id: batch.id,
          soma_did,
        },
        sourceObservationIds: [obs.id],
      };
    });

    // 7. Bulk-insert
    const inserted = await db
      .insert(knowledgeEntries)
      .values(entries)
      .returning();

    // 8. Return 201
    return reply.status(201).send({
      created: inserted.map((e) => ({
        id: e.id,
        entry_type: e.entryType,
        title: e.title,
      })),
      count: inserted.length,
    });
  });
}
