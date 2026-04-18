import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import {
  signReceipt,
  verifyReceipt,
  receiptCanonical,
  EVIDENCE_SUMMARY_MAX,
  type ReceiptPayload,
} from '../../src/heart/reception-receipt.js';

const crypto = getCryptoProvider();

function makeVerifier() {
  const kp = crypto.signing.generateKeyPair();
  return kp;
}

function makePayload(overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  return {
    verifierId: 'did:soma:verifier123',
    requestId: 'req-abc-456',
    heartDid: 'did:soma:agent789',
    capabilityClass: 'tool:db',
    outcome: 'pass',
    timestamp: 1_700_000_000_000,
    evidenceSummary: 'Agent presented valid HMAC chain with 3 heartbeats.',
    ...overrides,
  };
}

describe('reception-receipt', () => {
  it('sign and verify roundtrip passes', () => {
    const kp = makeVerifier();
    const payload = makePayload();
    const signed = signReceipt(payload, kp.secretKey, kp.publicKey);

    expect(verifyReceipt(signed)).toBe(true);
  });

  it('tampered payload fails verification', () => {
    const kp = makeVerifier();
    const signed = signReceipt(makePayload(), kp.secretKey, kp.publicKey);

    const tampered = {
      ...signed,
      payload: { ...signed.payload, outcome: 'fail' as const },
    };

    expect(verifyReceipt(tampered)).toBe(false);
  });

  it('tampered signature fails verification', () => {
    const kp = makeVerifier();
    const signed = signReceipt(makePayload(), kp.secretKey, kp.publicKey);

    const tampered = { ...signed, signature: signed.signature.slice(0, -4) + 'AAAA' };
    expect(verifyReceipt(tampered)).toBe(false);
  });

  it('oversized evidenceSummary is rejected at sign time', () => {
    const kp = makeVerifier();
    const oversized = makePayload({ evidenceSummary: 'x'.repeat(EVIDENCE_SUMMARY_MAX + 1) });

    expect(() => signReceipt(oversized, kp.secretKey, kp.publicKey)).toThrow(
      /evidenceSummary too long/,
    );
  });

  it('exactly 512 chars is accepted', () => {
    const kp = makeVerifier();
    const boundary = makePayload({ evidenceSummary: 'x'.repeat(EVIDENCE_SUMMARY_MAX) });
    const signed = signReceipt(boundary, kp.secretKey, kp.publicKey);
    expect(verifyReceipt(signed)).toBe(true);
  });

  it('canonical serialization is stable across two calls with identical input', () => {
    const payload = makePayload();
    expect(receiptCanonical(payload)).toBe(receiptCanonical(payload));
  });

  it('canonical serialization is deterministic regardless of property insertion order', () => {
    const a = makePayload();
    // Construct an equivalent object with keys in a different order
    const b: ReceiptPayload = {
      timestamp: a.timestamp,
      outcome: a.outcome,
      verifierId: a.verifierId,
      evidenceSummary: a.evidenceSummary,
      capabilityClass: a.capabilityClass,
      heartDid: a.heartDid,
      requestId: a.requestId,
    };
    expect(receiptCanonical(a)).toBe(receiptCanonical(b));
  });

  it('wrong key fails verification', () => {
    const kp = makeVerifier();
    const otherKp = makeVerifier();
    const signed = signReceipt(makePayload(), kp.secretKey, kp.publicKey);

    const withWrongKey = { ...signed, signerPublicKey: crypto.encoding.encodeBase64(otherKp.publicKey) };
    expect(verifyReceipt(withWrongKey)).toBe(false);
  });

  it('all outcome values are accepted', () => {
    const kp = makeVerifier();
    for (const outcome of ['pass', 'fail', 'inconclusive'] as const) {
      const signed = signReceipt(makePayload({ outcome }), kp.secretKey, kp.publicKey);
      expect(verifyReceipt(signed)).toBe(true);
    }
  });
});
