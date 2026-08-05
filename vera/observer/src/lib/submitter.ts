/**
 * Submission client — signs and POSTs observation batches to a Vera host.
 *
 * Signing contract: SIGNING-SPEC.md, v1.
 *   signed bytes = "somavera:vera-observation-batch:v1\n" || canonical_json(envelope)
 *   algorithm    = Ed25519 via getCryptoProvider().signing.sign()
 *   encoding     = Base64 via getCryptoProvider().encoding.encodeBase64()
 *
 * The v0 contract signed JSON.stringify(observations): no domain separation,
 * no canonicalization, and it left source_type unauthenticated even though
 * provenance is the point of the system. It is gone, not deprecated — both
 * ends live in this repository and ship together, so there is no window in
 * which a v0 sender meets a v1 host.
 *
 * HTTP contract:
 *   POST /v1/observations
 *   Body: { envelope, signature }
 *   Success: 201 created, or 200 when the batch_id was already accepted
 *   Errors:  400 (bad envelope), 403 (bad signature or stale), 404 (unknown DID)
 */

import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { randomBytes } from 'node:crypto';
import type { ObservationItem } from './types.js';
import type { SomaIdentity } from './identity.js';
import {
  OBSERVATION_BATCH_SCHEMA,
  assertValidEnvelope,
  formatSubmittedAt,
  signedBytes,
  type ObservationEnvelope,
} from './envelope.js';

// ---- Types ----

export interface SubmitterConfig {
  veraKnowledgeUrl: string;
  identity: SomaIdentity;
  sourceType?: string;
}

export interface SubmitSuccess {
  success: true;
  batchId: string;
}

export interface SubmitFailure {
  success: false;
  error: string;
  statusCode: number;
}

export type SubmitResult = SubmitSuccess | SubmitFailure;

// Shape returned by vera-knowledge on 201
interface VeraKnowledgeBatchResponse {
  batch: {
    id: string;
    user_id: string;
    source_type: string;
    observation_count: number;
    created_at: string;
  };
}

// ---- Public API ----

/**
 * Sign and POST a batch of observations to vera-knowledge.
 *
 * On 201: returns { success: true, batchId: <UUID> }
 * On 400/403/404/5xx: returns { success: false, error: <message>, statusCode: <N> }
 * On network error: returns { success: false, error: <message>, statusCode: 0 }
 */
export async function submitObservations(
  config: SubmitterConfig,
  observations: ObservationItem[]
): Promise<SubmitResult> {
  if (observations.length === 0) {
    return { success: false, error: 'no observations to submit', statusCode: 0 };
  }

  const provider = getCryptoProvider();
  const { identity, veraKnowledgeUrl, sourceType = 'git' } = config;

  // batch_id is random, not a hash of the content: two honest batches with
  // identical observations must remain distinguishable, and a content hash
  // would make an honest resubmission indistinguishable from a replay.
  const envelope: ObservationEnvelope = {
    batch_id: randomBytes(16).toString('hex'),
    observations,
    schema_version: OBSERVATION_BATCH_SCHEMA,
    soma_did: identity.somaDid,
    source_type: sourceType,
    submitted_at: formatSubmittedAt(new Date()),
  };

  // Validate before signing. Signing something this end would itself reject on
  // receipt produces a batch no host can accept and no operator can diagnose.
  try {
    assertValidEnvelope(envelope);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `envelope invalid: ${message}`, statusCode: 0 };
  }

  let signature: string;
  try {
    signature = provider.encoding.encodeBase64(
      provider.signing.sign(signedBytes(envelope), identity.secretKey),
    );
  } catch (err: unknown) {
    // Canonicalization rejects rather than repairs, so an observation carrying
    // a lone surrogate or an unsafe integer fails here. That is the design:
    // better an unsent batch than a signature over silently rewritten data.
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `not canonicalizable: ${message}`, statusCode: 0 };
  }

  const body = { envelope, signature };

  let response: Response;
  try {
    response = await fetch(`${veraKnowledgeUrl}/v1/observations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `network error: ${message}`, statusCode: 0 };
  }

  // 200 means this batch_id was already accepted. A retry after a network
  // timeout must not be punished, so replay is idempotent rather than fatal.
  if (response.status === 201 || response.status === 200) {
    let data: VeraKnowledgeBatchResponse;
    try {
      data = (await response.json()) as VeraKnowledgeBatchResponse;
    } catch {
      return { success: false, error: 'invalid JSON in 201 response', statusCode: 201 };
    }
    return { success: true, batchId: data.batch.id };
  }

  // Error path: parse body for a message if available
  let errorMessage: string;
  try {
    const errBody = (await response.json()) as Record<string, unknown>;
    errorMessage = typeof errBody['error'] === 'string'
      ? errBody['error']
      : typeof errBody['message'] === 'string'
        ? errBody['message']
        : `HTTP ${response.status}`;
  } catch {
    errorMessage = `HTTP ${response.status}`;
  }

  // Map known status codes to canonical error strings
  if (response.status === 404) {
    errorMessage = errorMessage === `HTTP ${response.status}` ? 'user_not_found' : errorMessage;
  } else if (response.status === 403) {
    errorMessage = errorMessage === `HTTP ${response.status}` ? 'signature_invalid' : errorMessage;
  }

  return { success: false, error: errorMessage, statusCode: response.status };
}
