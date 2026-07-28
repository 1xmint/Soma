import { pgTable, uuid, text, jsonb, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';
import { users } from './users.js';

export const observationBatches = pgTable(
  'observation_batches',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id),
    // Client-generated, carried inside the signature. The uniqueness index
    // below is what actually prevents replay: a timestamp window alone allows
    // unlimited replay inside the window, and this alone would require the
    // index to be retained forever. See SIGNING-SPEC.md.
    batchId: text('batch_id').notNull(),
    somaSignature: text('soma_signature').notNull(),
    signedPayloadHash: text('signed_payload_hash').notNull(),
    sourceType: text('source_type').notNull(),
    submittedAt: timestamp('submitted_at', { withTimezone: true }).notNull(),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    // Scoped per user: two identities may independently choose the same
    // batch_id without either being able to block the other.
    userBatchUnique: uniqueIndex('observation_batches_user_batch_idx').on(
      table.userId,
      table.batchId,
    ),
  }),
);

export const observations = pgTable('observations', {
  id: uuid('id').primaryKey().defaultRandom(),
  batchId: uuid('batch_id').notNull().references(() => observationBatches.id),
  observationType: text('observation_type').notNull(),
  content: jsonb('content').notNull(),
  observedAt: timestamp('observed_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type ObservationBatch = typeof observationBatches.$inferSelect;
export type NewObservationBatch = typeof observationBatches.$inferInsert;

export type Observation = typeof observations.$inferSelect;
export type NewObservation = typeof observations.$inferInsert;
