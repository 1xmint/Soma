// Payment rail evidence binding helper (Slice 9).
//
// Binds rail-agnostic payment receipt references into certificate-local
// claim and evidence reference shapes per spec section 14. This helper
// constructs references only; it does NOT verify payment receipts,
// execute payments, decide pricing, route providers, or define rail
// semantics. Rail names and references are opaque caller-supplied
// metadata; no rail is special-cased.
//
// Accepted v0.1 vocabulary used:
//   claim:    payment_receipt_reference
//   evidence: payment_rail_receipt_reference

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

// -- Input types ------------------------------------------------------------

export interface PaymentRailReceiptInput {
  /** Opaque receipt reference from the payment rail. */
  readonly receipt_reference: string;
  /** Opaque rail name. Carried in output metadata only. */
  readonly rail_name?: string;
  /** Caller-supplied opaque metadata (e.g. provider-advertised terms). */
  readonly metadata?: Readonly<Record<string, string>>;
}

// -- Output types -----------------------------------------------------------

export interface PaymentClaimBinding {
  readonly kind: 'payment_receipt_reference';
  readonly receipt_reference: string;
}

export interface PaymentEvidenceBinding {
  readonly kind: 'payment_rail_receipt_reference';
  readonly reference: string;
}

export interface PaymentRailBindingOk {
  readonly bound: true;
  readonly claim: PaymentClaimBinding;
  readonly evidence_references: readonly [PaymentEvidenceBinding];
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface PaymentRailBindingFail {
  readonly bound: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export type PaymentRailBindingResult =
  | PaymentRailBindingOk
  | PaymentRailBindingFail;

// -- Binding ----------------------------------------------------------------

export function bindPaymentRailEvidence(
  input: PaymentRailReceiptInput,
): PaymentRailBindingResult {
  if (!input.receipt_reference) {
    return {
      bound: false,
      failureMode: FAILURE_MODES.EVIDENCE_MISSING,
      detail: 'receipt_reference is required',
    };
  }

  const claim: PaymentClaimBinding = {
    kind: 'payment_receipt_reference',
    receipt_reference: input.receipt_reference,
  };

  const evidence: PaymentEvidenceBinding = {
    kind: 'payment_rail_receipt_reference',
    reference: input.receipt_reference,
  };

  // Merge rail_name into metadata. Caller-supplied metadata takes precedence:
  // if metadata already contains rail_name, preserve the caller's value.
  let merged: Record<string, string> | undefined;
  if (input.rail_name || (input.metadata && Object.keys(input.metadata).length > 0)) {
    merged = {};
    if (input.rail_name) {
      merged.rail_name = input.rail_name;
    }
    if (input.metadata) {
      Object.assign(merged, input.metadata);
    }
  }

  const result: PaymentRailBindingOk = {
    bound: true,
    claim,
    evidence_references: [evidence],
  };

  if (merged && Object.keys(merged).length > 0) {
    return { ...result, metadata: merged };
  }

  return result;
}
