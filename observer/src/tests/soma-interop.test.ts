import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { didFromPublicKey, didMatchesPublicKey, fingerprintFromPublicKey, publicKeyFromDid } from '../lib/did.js';

/**
 * Interop with Soma, against fixed vectors Soma produced.
 *
 * Vera and Soma implement base58btc, multicodec tagging and Ed25519 verification
 * separately. Porting an algorithm faithfully and agreeing byte-for-byte are
 * different claims, and only the second one lets a Soma agent and a Vera
 * observer be the same identity.
 *
 * The values are fixed rather than generated here. A test that generates its own
 * input on both sides proves only that one implementation agrees with itself.
 */
const vectors = JSON.parse(
  readFileSync('../conformance/soma-identity-vectors.json', 'utf8'),
) as {
  vectors: {
    name: string;
    did: string;
    public_key_multibase: string;
    public_key_length_bytes: number;
    message_utf8: string;
    signature_base64: string;
  }[];
  reject: { name: string; did: string; reason: string }[];
};

test('vera recovers the key a soma did:key commits to', () => {
  for (const v of vectors.vectors) {
    const key = publicKeyFromDid(v.did);
    assert.equal(key.length, v.public_key_length_bytes, v.name);
    assert.equal(didFromPublicKey(key), v.did, 'the DID must re-derive from the recovered key');
    assert.equal(fingerprintFromPublicKey(key), v.public_key_multibase);
    assert.ok(didMatchesPublicKey(v.did, key));
  }
});

// The point of self-certifying identifiers: a signature made by Soma verifies
// under a key Vera derived from the identifier alone, with no registry, no
// network, and nothing to trust in between.
test('vera verifies a signature soma produced, using only the DID', () => {
  const provider = getCryptoProvider();

  for (const v of vectors.vectors) {
    const key = publicKeyFromDid(v.did);
    const message = new TextEncoder().encode(v.message_utf8);
    const signature = provider.encoding.decodeBase64(v.signature_base64);

    assert.ok(
      provider.signing.verify(message, signature, key),
      `${v.name}: a signature soma made did not verify under the key vera derived`,
    );
  }
});

test('a tampered message does not verify against the soma signature', () => {
  const provider = getCryptoProvider();
  const v = vectors.vectors[0]!;
  const key = publicKeyFromDid(v.did);
  const signature = provider.encoding.decodeBase64(v.signature_base64);

  assert.ok(
    !provider.signing.verify(new TextEncoder().encode(`${v.message_utf8}x`), signature, key),
  );
});

test('identifiers that commit to no key are refused', () => {
  for (const r of vectors.reject) {
    assert.throws(() => publicKeyFromDid(r.did), Error, r.name);
    assert.equal(didMatchesPublicKey(r.did, new Uint8Array(32)), false);
  }
});
