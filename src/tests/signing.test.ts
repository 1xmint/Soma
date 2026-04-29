/**
 * Signing tests — verify that our Ed25519 signing path matches the
 * server-side verification path used by vera-knowledge (soma-verify.ts).
 *
 * The server verifies like this:
 *   provider.signing.verify(payloadBytes, signatureBytes, publicKeyBytes)
 * where payload = JSON.stringify(observations) and signature is base64-decoded.
 *
 * We confirm round-trip compatibility here without running a live server.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { getCryptoProvider } from 'soma-heart/crypto-provider';

describe('Ed25519 signing — vera-knowledge compatibility', () => {
  test('sign + verify round-trips correctly (same key)', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();

    const payload = JSON.stringify([
      { type: 'git_commit', content: { commit_hash: 'a'.repeat(40) }, observed_at: '2026-01-01T00:00:00Z' },
    ]);

    const payloadBytes = new TextEncoder().encode(payload);
    const signatureBytes = provider.signing.sign(payloadBytes, keyPair.secretKey);

    // Verify using same path as server (soma-verify.ts)
    const valid = provider.signing.verify(payloadBytes, signatureBytes, keyPair.publicKey);
    assert.ok(valid, 'Signature should verify with the matching public key');
  });

  test('signature is base64-encodeable and 64 bytes when decoded', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();

    const payload = JSON.stringify([{ type: 'git_commit', content: {}, observed_at: '2026-01-01T00:00:00Z' }]);
    const payloadBytes = new TextEncoder().encode(payload);
    const signatureBytes = provider.signing.sign(payloadBytes, keyPair.secretKey);
    const signatureB64 = provider.encoding.encodeBase64(signatureBytes);

    // Must be a non-empty string (base64)
    assert.ok(typeof signatureB64 === 'string' && signatureB64.length > 0, 'Signature should be a non-empty base64 string');

    // Decoded must be 64 bytes (Ed25519 signature size)
    const decoded = provider.encoding.decodeBase64(signatureB64);
    assert.equal(decoded.length, 64, 'Decoded signature must be 64 bytes');
  });

  test('wrong key fails verification', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();
    const wrongKeyPair = provider.signing.generateKeyPair();

    const payload = JSON.stringify([{ type: 'git_commit', content: {}, observed_at: '2026-01-01T00:00:00Z' }]);
    const payloadBytes = new TextEncoder().encode(payload);
    const signatureBytes = provider.signing.sign(payloadBytes, keyPair.secretKey);

    // Verify with the WRONG public key — must fail
    const valid = provider.signing.verify(payloadBytes, signatureBytes, wrongKeyPair.publicKey);
    assert.ok(!valid, 'Signature should NOT verify with a different public key');
  });

  test('tampered payload fails verification', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();

    const original = JSON.stringify([{ type: 'git_commit', content: { x: 1 }, observed_at: '2026-01-01T00:00:00Z' }]);
    const tampered = JSON.stringify([{ type: 'git_commit', content: { x: 2 }, observed_at: '2026-01-01T00:00:00Z' }]);

    const originalBytes = new TextEncoder().encode(original);
    const tamperedBytes = new TextEncoder().encode(tampered);
    const signatureBytes = provider.signing.sign(originalBytes, keyPair.secretKey);

    // Verify tampered payload against original signature — must fail
    const valid = provider.signing.verify(tamperedBytes, signatureBytes, keyPair.publicKey);
    assert.ok(!valid, 'Signature should NOT verify against a tampered payload');
  });

  test('public key is 32 bytes', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();
    assert.equal(keyPair.publicKey.length, 32, 'Ed25519 public key must be 32 bytes');
  });

  test('base64 encode/decode round-trips public key correctly', () => {
    const provider = getCryptoProvider();
    const keyPair = provider.signing.generateKeyPair();
    const encoded = provider.encoding.encodeBase64(keyPair.publicKey);
    const decoded = provider.encoding.decodeBase64(encoded);
    assert.deepEqual(decoded, keyPair.publicKey, 'Base64 round-trip should preserve public key bytes');
  });
});
