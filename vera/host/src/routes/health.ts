import type { FastifyInstance } from 'fastify';

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get('/health', async (_request, reply) => {
    return reply.status(200).send({
      status: 'ok',
      service: 'vera-knowledge',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
    });
  });
}
