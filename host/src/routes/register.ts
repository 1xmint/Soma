import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema/index.js';
import { registerBodySchema } from '../lib/schemas.js';
import type { Db } from '../db/connection.js';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { didMatchesPublicKey } from '../lib/did.js';

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

    // A did:key identifier *is* its public key. Accepting a registration whose
    // supplied key differs from the one the identifier commits to would make
    // every later signature check depend on the registry being right, rather
    // than on mathematics — and would let anyone bind their own key to someone
    // else's identifier.
    let suppliedKey: Uint8Array;
    try {
      suppliedKey = getCryptoProvider().encoding.decodeBase64(public_key);
    } catch {
      return reply.status(400).send({
        error: 'public_key_invalid',
        message: 'public_key is not valid base64',
      });
    }

    if (!didMatchesPublicKey(soma_did, suppliedKey)) {
      return reply.status(400).send({
        error: 'did_key_mismatch',
        message:
          'soma_did must be a did:key identifier committing to the supplied public_key',
      });
    }

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
