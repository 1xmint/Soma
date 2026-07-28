import { pgTable, uuid, text, real, jsonb, timestamp, vector } from 'drizzle-orm/pg-core';
import { users } from './users.js';

export const knowledgeEntries = pgTable('knowledge_entries', {
  id: uuid('id').primaryKey().defaultRandom(),
  sourceObservationIds: uuid('source_observation_ids').array().notNull(),
  entryType: text('entry_type').notNull(),
  title: text('title').notNull(),
  content: text('content').notNull(),
  embedding: vector('embedding', { dimensions: 1536 }),
  confidence: real('confidence').notNull().default(0.0),
  tags: text('tags').array(),
  somaProvenance: jsonb('soma_provenance').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const teachingEntries = pgTable('teaching_entries', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id),
  teachingType: text('teaching_type').notNull(),
  content: jsonb('content').notNull(),
  targetKnowledgeId: uuid('target_knowledge_id').references(() => knowledgeEntries.id),
  somaSignature: text('soma_signature').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type KnowledgeEntry = typeof knowledgeEntries.$inferSelect;
export type NewKnowledgeEntry = typeof knowledgeEntries.$inferInsert;

export type TeachingEntry = typeof teachingEntries.$inferSelect;
export type NewTeachingEntry = typeof teachingEntries.$inferInsert;
