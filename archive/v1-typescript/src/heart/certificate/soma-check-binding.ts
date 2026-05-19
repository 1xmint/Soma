// Soma Check evidence binding helper (Slice 8).
//
// Binds Soma Check-style freshness receipt outputs into certificate-local
// claim and evidence reference shapes per spec section 13. This helper
// constructs references only; it does NOT verify Soma Check receipts,
// decide pricing, route providers, or carry payment rail semantics.
//
// Accepted v0.1 vocabulary used:
//   claim:    freshness_receipt
//   evidence: receipt_reference, hash_commitment,
//             request_response_transcript_hash (optional)

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

// -- Input types ------------------------------------------------------------

export interface SomaCheckReceiptInput {
  /** Soma Check receipt reference (hash or opaque identifier). */
  readonly receipt_reference: string;
  /** Content hash commitment from the Soma Check response. */
  readonly content_hash: string;
  /** Whether the Soma Check freshness result indicated unchanged content. */
  readonly unchanged: boolean;
  /** Request/response transcript hash, if available. */
  readonly transcript_hash?: string;
  /** Caller-supplied opaque metadata (e.g. provider-advertised terms). */
  readonly metadata?: Readonly<Record<string, string>>;
}

// -- Output types -----------------------------------------------------------

export interface FreshnessClaimBinding {
  readonly kind: 'freshness_receipt';
  readonly receipt_reference: string;
  readonly content_hash: string;
  readonly unchanged: boolean;
}

export interface EvidenceReferenceBinding {
  readonly kind: string;
  readonly reference: string;
}

export interface SomaCheckBindingOk {
  readonly bound: true;
  readonly claim: FreshnessClaimBinding;
  readonly evidence_references: readonly EvidenceReferenceBinding[];
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface SomaCheckBindingFail {
  readonly bound: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export type SomaCheckBindingResult = SomaCheckBindingOk | SomaCheckBindingFail;

// -- Binding ----------------------------------------------------------------

export function bindSomaCheckEvidence(
  input: SomaCheckReceiptInput,
): SomaCheckBindingResult {
  if (!input.receipt_reference) {
    return {
      bound: false,
      failureMode: FAILURE_MODES.EVIDENCE_MISSING,
      detail: 'receipt_reference is required',
    };
  }

  if (!input.content_hash) {
    return {
      bound: false,
      failureMode: FAILURE_MODES.EVIDENCE_MISSING,
      detail: 'content_hash is required',
    };
  }

  const claim: FreshnessClaimBinding = {
    kind: 'freshness_receipt',
    receipt_reference: input.receipt_reference,
    content_hash: input.content_hash,
    unchanged: input.unchanged,
  };

  const evidence: EvidenceReferenceBinding[] = [
    { kind: 'receipt_reference', reference: input.receipt_reference },
    { kind: 'hash_commitment', reference: input.content_hash },
  ];

  if (input.transcript_hash) {
    evidence.push({
      kind: 'request_response_transcript_hash',
      reference: input.transcript_hash,
    });
  }

  const result: SomaCheckBindingOk = {
    bound: true,
    claim,
    evidence_references: evidence,
  };

  if (input.metadata && Object.keys(input.metadata).length > 0) {
    return { ...result, metadata: input.metadata };
  }

  return result;
}
