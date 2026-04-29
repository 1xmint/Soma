/**
 * Submission client — signs and POSTs observation batches to vera-knowledge.
 *
 * Signing contract (must match veraAI/src/lib/soma-verify.ts):
 *   signed payload = JSON.stringify(observations)  (the ObservationItem array)
 *   algorithm      = Ed25519 via getCryptoProvider().signing.sign()
 *   encoding       = Base64 via getCryptoProvider().encoding.encodeBase64()
 *
 * HTTP contract (must match veraAI/src/routes/observations.ts):
 *   POST /v1/observations
 *   Body: { soma_did, source_type, signature, observations }
 *   Success: 201 { batch: { id, user_id, source_type, observation_count, created_at } }
 *   Errors:  400 (bad body), 403 (bad signature), 404 (user not found)
 */

import { getCryptoProvider } from 'soma-heart/crypto-provider';
import type { ObservationItem } from './types.js';
import type { SomaIdentity } from './identity.js';

// ---- Types ----

export interface SubmitterConfig {
  veraKnowledgeUrl: string;
  identity: SomaIdentity;
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
  const { identity, veraKnowledgeUrl } = config;

  // Sign exactly: JSON.stringify(observations) — the array, not the full body
  const signedPayload = JSON.stringify(observations);
  const payloadBytes = new TextEncoder().encode(signedPayload);
  const signatureBytes = provider.signing.sign(payloadBytes, identity.secretKey);
  const signature = provider.encoding.encodeBase64(signatureBytes);

  const body = {
    soma_did: identity.somaDid,
    source_type: 'git',
    signature,
    observations,
  };

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

  if (response.status === 201) {
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
