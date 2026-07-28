import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema/index.js';
import { registerBodySchema } from '../lib/schemas.js';
import type { Db } from '../db/connection.js';

// Extend FastifyInstance to include the decorated db
declare module 'fastify' {
  interface FastifyInstance {
    db: Db;
  }
}

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/register', async (request, reply) => {
    // Validate request body
    const parseResult = registerBodySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'validation_error',
        message: 'Request body validation failed',
        details: parseResult.error.errors,
      });
    }

    const { soma_did, public_key, display_name } = parseResult.data;
    const db = request.server.db;

    // Check for existing user with the same soma_did
    const existing = await db
      .select()
      .from(users)
      .where(eq(users.somaDid, soma_did))
      .limit(1);

    if (existing.length > 0) {
      return reply.status(409).send({
        error: 'already_registered',
        message: 'A user with this Soma DID is already registered',
      });
    }

    // Insert new user
    const inserted = await db
      .insert(users)
      .values({
        somaDid: soma_did,
        publicKey: public_key,
        displayName: display_name ?? null,
      })
      .returning();

    const user = inserted[0];
    if (!user) {
      return reply.status(500).send({
        error: 'internal_error',
        message: 'Failed to create user',
      });
    }

    return reply.status(201).send({
      user: {
        id: user.id,
        soma_did: user.somaDid,
        public_key: user.publicKey,
        display_name: user.displayName,
        created_at: user.createdAt.toISOString(),
      },
    });
  });
}
