import { z } from 'zod';

export const registerBodySchema = z.object({
  soma_did: z.string().min(1),
  public_key: z.string().min(1),
  display_name: z.string().optional(),
});

export type RegisterBody = z.infer<typeof registerBodySchema>;

const observationItemSchema = z.object({
  type: z.string().min(1),
  content: z.record(z.unknown()),
  observed_at: z.string().min(1),
});

export const observationsBodySchema = z.object({
  soma_did: z.string().min(1),
  source_type: z.string().min(1),
  signature: z.string().min(1),
  observations: z.array(observationItemSchema).min(1),
});

export type ObservationsBody = z.infer<typeof observationsBodySchema>;
export type ObservationItem = z.infer<typeof observationItemSchema>;

export const aggregateBodySchema = z.object({
  soma_did: z.string().min(1),
  batch_id: z.string().uuid(),
});

export const queryBodySchema = z.object({
  soma_did: z.string().min(1),
  query_text: z.string().min(1),
  limit: z.number().int().min(1).max(20).default(5),
});

export type AggregateBody = z.infer<typeof aggregateBodySchema>;
export type QueryBody = z.infer<typeof queryBodySchema>;
