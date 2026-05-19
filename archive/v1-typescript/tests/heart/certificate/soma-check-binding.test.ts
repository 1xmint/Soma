import { describe, it, expect } from 'vitest';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import {
  bindSomaCheckEvidence,
  type SomaCheckReceiptInput,
} from '../../../src/heart/certificate/soma-check-binding.js';

// -- Successful bindings ----------------------------------------------------

describe('soma check evidence binding - success', () => {
  it('binds unchanged/freshness receipt with receipt_reference and hash_commitment', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc123',
      content_hash: 'sha256-deadbeef',
      unchanged: true,
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.claim.kind).toBe('freshness_receipt');
    expect(result.claim.receipt_reference).toBe('receipt-abc123');
    expect(result.claim.content_hash).toBe('sha256-deadbeef');
    expect(result.claim.unchanged).toBe(true);

    expect(result.evidence_references).toHaveLength(2);
    expect(result.evidence_references[0]).toEqual({
      kind: 'receipt_reference',
      reference: 'receipt-abc123',
    });
    expect(result.evidence_references[1]).toEqual({
      kind: 'hash_commitment',
      reference: 'sha256-deadbeef',
    });
    expect(result.metadata).toBeUndefined();
  });

  it('binds changed-result/fetch receipt (unchanged: false)', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-new456',
      content_hash: 'sha256-newcontent',
      unchanged: false,
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.claim.unchanged).toBe(false);
    expect(result.claim.kind).toBe('freshness_receipt');
    expect(result.evidence_references).toHaveLength(2);
  });

  it('includes transcript hash when provided', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: 'sha256-abc',
      unchanged: true,
      transcript_hash: 'transcript-sha256-xyz',
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.evidence_references).toHaveLength(3);
    expect(result.evidence_references[2]).toEqual({
      kind: 'request_response_transcript_hash',
      reference: 'transcript-sha256-xyz',
    });
  });

  it('carries caller-supplied metadata without affecting validity', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: 'sha256-abc',
      unchanged: true,
      metadata: {
        provider_terms: 'x402:some-term-ref',
        custom_field: 'arbitrary-value',
      },
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata).toEqual({
      provider_terms: 'x402:some-term-ref',
      custom_field: 'arbitrary-value',
    });
    // Metadata does not change the claim or evidence structure.
    expect(result.claim.kind).toBe('freshness_receipt');
    expect(result.evidence_references).toHaveLength(2);
  });

  it('omits metadata when empty object is provided', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: 'sha256-abc',
      unchanged: false,
      metadata: {},
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(true);
    if (!result.bound) return;

    expect(result.metadata).toBeUndefined();
  });
});

// -- Fail-closed on missing required fields ---------------------------------

describe('soma check evidence binding - fail closed', () => {
  it('rejects missing receipt_reference with evidence-missing', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: '',
      content_hash: 'sha256-abc',
      unchanged: true,
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
      expect(result.detail).toMatch(/receipt_reference/);
    }
  });

  it('rejects missing content_hash with evidence-missing', () => {
    const input: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: '',
      unchanged: true,
    };
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
      expect(result.detail).toMatch(/content_hash/);
    }
  });

  it('rejects undefined receipt_reference (malformed runtime input)', () => {
    const input = {
      content_hash: 'sha256-abc',
      unchanged: true,
    } as unknown as SomaCheckReceiptInput;
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
    }
  });

  it('rejects undefined content_hash (malformed runtime input)', () => {
    const input = {
      receipt_reference: 'receipt-abc',
      unchanged: true,
    } as unknown as SomaCheckReceiptInput;
    const result = bindSomaCheckEvidence(input);
    expect(result.bound).toBe(false);
    if (!result.bound) {
      expect(result.failureMode).toBe(FAILURE_MODES.EVIDENCE_MISSING);
    }
  });
});

// -- Vocabulary correctness -------------------------------------------------

describe('soma check evidence binding - vocabulary', () => {
  const validInput: SomaCheckReceiptInput = {
    receipt_reference: 'receipt-abc',
    content_hash: 'sha256-abc',
    unchanged: true,
    transcript_hash: 'transcript-xyz',
  };

  it('uses only accepted v0.1 claim kind (freshness_receipt)', () => {
    const result = bindSomaCheckEvidence(validInput);
    expect(result.bound).toBe(true);
    if (!result.bound) return;
    expect(result.claim.kind).toBe('freshness_receipt');
  });

  it('uses only accepted v0.1 evidence kinds', () => {
    const result = bindSomaCheckEvidence(validInput);
    expect(result.bound).toBe(true);
    if (!result.bound) return;
    const kinds = result.evidence_references.map((e) => e.kind);
    const acceptedKinds = new Set([
      'receipt_reference',
      'hash_commitment',
      'request_response_transcript_hash',
    ]);
    for (const k of kinds) {
      expect(acceptedKinds.has(k)).toBe(true);
    }
  });
});

// -- Boundary discipline ----------------------------------------------------

describe('soma check evidence binding - boundary', () => {
  it('metadata does not affect binding validity', () => {
    const withMeta: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: 'sha256-abc',
      unchanged: true,
      metadata: { price: '0.001', rail: 'x402' },
    };
    const withoutMeta: SomaCheckReceiptInput = {
      receipt_reference: 'receipt-abc',
      content_hash: 'sha256-abc',
      unchanged: true,
    };

    const r1 = bindSomaCheckEvidence(withMeta);
    const r2 = bindSomaCheckEvidence(withoutMeta);
    expect(r1.bound).toBe(true);
    expect(r2.bound).toBe(true);
    if (r1.bound && r2.bound) {
      expect(r1.claim).toEqual(r2.claim);
      expect(r1.evidence_references).toEqual(r2.evidence_references);
    }
  });
});
