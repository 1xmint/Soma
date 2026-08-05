/**
 * Vera observation batch envelope — v1.
 *
 * Implements SIGNING-SPEC.md. See that document for why each field exists;
 * this file is only the mechanism.
 *
 * Mirrored into host/src/lib/envelope.ts. The two copies are kept honest by
 * the shared conformance vectors, not by being the same file.
 */

import { canonicalize } from './canonicalize.js';

export const OBSERVATION_BATCH_DOMAIN = 'somavera:vera-observation-batch:v1\n';
export const OBSERVATION_BATCH_SCHEMA = 'somavera.vera-observation-batch.v1';

/** Exactly the fields an envelope may carry. Order here is irrelevant;
 *  canonicalization sorts. Presence is what matters. */
export const ENVELOPE_FIELDS = [
  'batch_id',
  'observations',
  'schema_version',
  'soma_did',
  'source_type',
  'submitted_at',
] as const;

export interface ObservationEnvelope {
  batch_id: string;
  observations: unknown[];
  schema_version: string;
  soma_did: string;
  source_type: string;
  submitted_at: string;
}

export class EnvelopeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

const BATCH_ID = /^[0-9a-f]{32}$/;
// RFC 3339 UTC, second precision, Z suffix, no fractional part. Deliberately
// narrow: every accepted spelling is one more way two implementations can
// produce different bytes for the same instant.
const SUBMITTED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** Format an instant the one way this profile permits. */
export function formatSubmittedAt(when: Date): string {
  return `${when.toISOString().slice(0, 19)}Z`;
}

/**
 * Validate an envelope's shape.
 *
 * Unknown fields are rejected rather than ignored. Ignoring them lets a future
 * version's meaning pass an older host that does not understand it, and lets an
 * intermediary attach unsigned data that a careless reader might trust.
 */
export function assertValidEnvelope(value: unknown): asserts value is ObservationEnvelope {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new EnvelopeError('envelope_invalid', 'envelope must be a JSON object');
  }
  const record = value as Record<string, unknown>;

  const present = Object.keys(record).sort();
  const expected = [...ENVELOPE_FIELDS].sort();
  if (present.length !== expected.length || present.some((k, i) => k !== expected[i])) {
    throw new EnvelopeError(
      'envelope_fields_invalid',
      `envelope must carry exactly [${expected.join(', ')}], received [${present.join(', ')}]`,
    );
  }

  if (record['schema_version'] !== OBSERVATION_BATCH_SCHEMA) {
    throw new EnvelopeError('schema_version_unsupported', 'schema_version is not v1');
  }
  if (typeof record['batch_id'] !== 'string' || !BATCH_ID.test(record['batch_id'])) {
    throw new EnvelopeError('batch_id_invalid', 'batch_id must be 32 lowercase hex characters');
  }
  if (typeof record['soma_did'] !== 'string' || record['soma_did'].length === 0) {
    throw new EnvelopeError('soma_did_invalid', 'soma_did must be a non-empty string');
  }
  if (typeof record['source_type'] !== 'string' || record['source_type'].length === 0) {
    throw new EnvelopeError('source_type_invalid', 'source_type must be a non-empty string');
  }
  if (typeof record['submitted_at'] !== 'string' || !SUBMITTED_AT.test(record['submitted_at'])) {
    throw new EnvelopeError(
      'submitted_at_invalid',
      'submitted_at must be RFC 3339 UTC with second precision and a Z suffix',
    );
  }
  if (!Array.isArray(record['observations']) || record['observations'].length === 0) {
    throw new EnvelopeError('observations_invalid', 'observations must be a non-empty array');
  }
}

/**
 * The exact bytes a signature covers.
 *
 * Always computed from a parsed envelope, never from received bytes. A sender
 * that emits non-canonical JSON is not rejected for that alone: the canonical
 * form is the identity of the content.
 */
export function signedBytes(envelope: ObservationEnvelope): Uint8Array {
  return new TextEncoder().encode(OBSERVATION_BATCH_DOMAIN + canonicalize(envelope));
}
