import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { cosineDistance } from 'drizzle-orm/sql/functions/vector';
import { users, knowledgeEntries } from '../db/schema/index.js';
import { queryBodySchema } from '../lib/schemas.js';
import { stubEmbed } from '../lib/embeddings.js';
import { guardianAuth } from '../middleware/guardian-auth.js';

export async function queryRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/query', { preHandler: guardianAuth }, async (request, reply) => {
    // 1. Validate request body
    const parseResult = queryBodySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'validation_error',
        message: 'Request body validation failed',
        details: parseResult.error.errors,
      });
    }

    const { soma_did, query_text, limit: limitValue } = parseResult.data;
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

    // 3. Generate query embedding
    const queryEmbedding = stubEmbed(query_text);

    // 4. Run cosine distance query
    const rows = await db
      .select({
        id: knowledgeEntries.id,
        entryType: knowledgeEntries.entryType,
        title: knowledgeEntries.title,
        content: knowledgeEntries.content,
        confidence: knowledgeEntries.confidence,
        tags: knowledgeEntries.tags,
        somaProvenance: knowledgeEntries.somaProvenance,
        createdAt: knowledgeEntries.createdAt,
        distance: cosineDistance(knowledgeEntries.embedding, queryEmbedding),
      })
      .from(knowledgeEntries)
      .orderBy(cosineDistance(knowledgeEntries.embedding, queryEmbedding))
      .limit(limitValue);

    // 5. Map to response shape
    const results = rows.map((row) => ({
      id: row.id,
      entry_type: row.entryType,
      title: row.title,
      content: row.content,
      confidence: row.confidence,
      tags: row.tags,
      soma_provenance: row.somaProvenance,
      similarity: Math.max(0, 1 - Number(row.distance)),
      created_at: row.createdAt.toISOString(),
    }));

    // 6. Return 200
    return reply.status(200).send({ results });
  });
}
