import { describe, it, expect } from 'vitest';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import {
  bindPaymentRailEvidence,
  type PaymentRailReceiptInput,
} from '../../../src/heart/certificate/payment-rail-binding.js';

// -- Successful bindings ----------------------------------------------------

describe('payment rail evidence binding - success', () => {
  it('binds a rail-agnostic payment receipt reference', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc123',
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.claim).toEqual({
      kind: 'payment_receipt_reference',
      receipt_reference: 'receipt-abc123',
    });
    expect(result.evidence_references).toEqual([
      { kind: 'payment_rail_receipt_reference', reference: 'receipt-abc123' },
    ]);
    expect(result.metadata).toBeUndefined();
  });

  it('carries rail_name as metadata only, not on claim or evidence', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-xyz',
      rail_name: 'x402',
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    // Claim and evidence have no rail_name field.
    expect(result.claim).toEqual({
      kind: 'payment_receipt_reference',
      receipt_reference: 'receipt-xyz',
    });
    expect(result.evidence_references).toEqual([
      { kind: 'payment_rail_receipt_reference', reference: 'receipt-xyz' },
    ]);
    // rail_name is in metadata.
    expect(result.metadata).toEqual({ rail_name: 'x402' });
  });

  it('carries caller-supplied metadata without affecting claim/evidence', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      metadata: {
        provider_terms: 'some-opaque-terms-ref',
        amount: '0.001',
        asset: 'USDC',
      },
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata).toEqual({
      provider_terms: 'some-opaque-terms-ref',
      amount: '0.001',
      asset: 'USDC',
    });
    expect(result.claim).toEqual({
      kind: 'payment_receipt_reference',
      receipt_reference: 'receipt-abc',
    });
    expect(result.evidence_references).toHaveLength(1);
  });

  it('merges rail_name into metadata alongside caller metadata', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      rail_name: 'lightning',
      metadata: { bolt11: 'lnbc100n1...' },
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata).toEqual({
      rail_name: 'lightning',
      bolt11: 'lnbc100n1...',
    });
  });

  it('preserves caller metadata rail_name over input rail_name', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      rail_name: 'x402',
      metadata: { rail_name: 'caller-override' },
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata!.rail_name).toBe('caller-override');
  });

  it('omits metadata when empty object and no rail_name provided', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      metadata: {},
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata).toBeUndefined();
  });
});

// -- Non-x402 fixture (mandatory per readiness doc) -------------------------

describe('payment rail evidence binding - non-x402 rail fixture', () => {
  it('binds a non-x402 rail receipt with identical structure', () => {
    const lightning: PaymentRailReceiptInput = {
      receipt_reference: 'lnbc-preimage-deadbeef',
      rail_name: 'lightning',
      metadata: { bolt11: 'lnbc100n1...' },
    };
    const result = bindPaymentRailEvidence(lightning);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.claim).toEqual({
      kind: 'payment_receipt_reference',
      receipt_reference: 'lnbc-preimage-deadbeef',
    });
    expect(result.evidence_references[0]).toEqual({
      kind: 'payment_rail_receipt_reference',
      reference: 'lnbc-preimage-deadbeef',
    });
    expect(result.metadata).toEqual({
      rail_name: 'lightning',
      bolt11: 'lnbc100n1...',
    });
  });

  it('binds a plain fixture rail with no rail_name', () => {
    const fixture: PaymentRailReceiptInput = {
      receipt_reference: 'test-fixture-receipt-001',
    };
    const result = bindPaymentRailEvidence(fixture);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.claim).toEqual({
      kind: 'payment_receipt_reference',
      receipt_reference: 'test-fixture-receipt-001',
    });
    expect(result.metadata).toBeUndefined();
  });
});

// -- Fail-closed on missing required fields ---------------------------------

describe('payment rail evidence binding - fail closed', () => {
  it('rejects missing receipt_reference with evidence-missing', () => {
    const input: PaymentRailReceiptInput = {
      receipt_reference: '',
    };
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
      expect(result.detail).toMatch(/receipt_reference/);
    }
  });

  it('rejects undefined receipt_reference (malformed runtime input)', () => {
    const input = {} as unknown as PaymentRailReceiptInput;
    const result = bindPaymentRailEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
    }
  });
});

// -- Vocabulary correctness -------------------------------------------------

describe('payment rail evidence binding - vocabulary', () => {
  it('uses only accepted v0.1 claim kind (payment_receipt_reference)', () => {
    const result = bindPaymentRailEvidence({
      receipt_reference: 'receipt-abc',
    });
    expect(result.bound).toBe(true);
    if (!result.bound) return;
    expect(result.claim.kind).toBe('payment_receipt_reference');
  });

  it('uses only accepted v0.1 evidence kind (payment_rail_receipt_reference)', () => {
    const result = bindPaymentRailEvidence({
      receipt_reference: 'receipt-abc',
    });
    expect(result.bound).toBe(true);
    if (!result.bound) return;
    expect(result.evidence_references[0].kind).toBe(
      'payment_rail_receipt_reference',
    );
  });
});

// -- Boundary discipline ----------------------------------------------------

describe('payment rail evidence binding - boundary', () => {
  it('metadata does not affect claim/evidence structure', () => {
    const withMeta: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      metadata: { amount: '50', currency: 'USD' },
    };
    const withoutMeta: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
    };

    const r1 = bindPaymentRailEvidence(withMeta);
    const r2 = bindPaymentRailEvidence(withoutMeta);
    expect(r1.bound).toBe(true);
    expect(r2.bound).toBe(true);
    if (r1.bound && r2.bound) {
      expect(r1.claim).toEqual(r2.claim);
      expect(r1.evidence_references).toEqual(r2.evidence_references);
    }
  });

  it('rail_name does not affect claim/evidence structure', () => {
    const withRail: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
      rail_name: 'x402',
    };
    const withoutRail: PaymentRailReceiptInput = {
      receipt_reference: 'receipt-abc',
    };

    const r1 = bindPaymentRailEvidence(withRail);
    const r2 = bindPaymentRailEvidence(withoutRail);
    expect(r1.bound).toBe(true);
    expect(r2.bound).toBe(true);
    if (r1.bound && r2.bound) {
      expect(r1.claim).toEqual(r2.claim);
      expect(r1.evidence_references).toEqual(r2.evidence_references);
    }
  });
});

// -- Core has zero x402 imports (lint check) --------------------------------

describe('payment rail evidence binding - no x402 dependency', () => {
  it('source file does not import x402', async () => {
    const { readFileSync } = await import('node:fs');
    const { resolve } = await import('node:path');
    const source = readFileSync(
      resolve(__dirname, '../../../src/heart/certificate/payment-rail-binding.ts'),
      'utf8',
    );
    expect(source).not.toMatch(/import.*x402/i);
    expect(source).not.toMatch(/require.*x402/i);
  });
});
