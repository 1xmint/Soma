/**
 * Soma identity module.
 *
 * Provides the SomaIdentity type and helpers for loading or generating
 * Ed25519 key pairs for signing observation batches submitted to
 * vera-knowledge.
 *
 * Uses getCryptoProvider() from soma-heart/crypto-provider so the same
 * algorithm implementation is used both here and in the server-side
 * verification path.
 */

import { getCryptoProvider } from 'soma-heart/crypto-provider';
import { didFromPublicKey } from './did.js';

// ---- Types ----

export interface SomaIdentity {
  /** The user's Soma DID, e.g. "did:soma:..." */
  somaDid: string;
  /** Base64-encoded Ed25519 public key (32 bytes) */
  publicKeyB64: string;
  /** Raw Ed25519 secret key (64 bytes: seed || publicKey) */
  secretKey: Uint8Array;
}

export interface IdentityConfig {
  /** The user's registered Soma DID */
  somaDid: string;
  /** Base64-encoded Ed25519 public key */
  publicKeyB64: string;
  /** Base64-encoded Ed25519 secret key */
  secretKeyB64: string;
}

// ---- Public API ----

/**
 * Load a SomaIdentity from an explicit config object.
 * Use this for production identities loaded from environment variables or
 * a config file.
 */
export function loadIdentity(config: IdentityConfig): SomaIdentity {
  const provider = getCryptoProvider();
  const secretKey = provider.encoding.decodeBase64(config.secretKeyB64);
  return {
    somaDid: config.somaDid,
    publicKeyB64: config.publicKeyB64,
    secretKey,
  };
}

/**
 * Generate a fresh Ed25519 keypair and test DID.
 * FOR TESTING ONLY — the resulting identity is not registered with vera-knowledge.
 */
export function generateTestIdentity(): SomaIdentity {
  const provider = getCryptoProvider();
  const keyPair = provider.signing.generateKeyPair();
  const publicKeyB64 = provider.encoding.encodeBase64(keyPair.publicKey);
  // Self-certifying, and byte-compatible with Soma. The previous form,
  // did:soma:test-<random>, had no relationship to the key: it could not
  // interoperate with Soma, and it let any key be bound to any identifier.
  const somaDid = didFromPublicKey(keyPair.publicKey);
  return {
    somaDid,
    publicKeyB64,
    secretKey: keyPair.secretKey,
  };
}
