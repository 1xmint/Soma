/**
 * Persistence — encrypt a heart's state to disk and rehydrate it later.
 *
 * A heart is valuable: it holds the signing key that IS the agent's identity,
 * the credentials that let it compute, the heartbeat chain that records its
 * history. When the process dies, all of that vanishes. Persistence lets an
 * operator save the heart at shutdown and reload it on boot — same DID, same
 * credentials, continuous heartbeat chain.
 *
 * State is protected with a password-derived key (PBKDF2-SHA256) and the
 * crypto provider's symmetric encryption (default: XSalsa20-Poly1305).
 *
 * Format (JSON):
 *   {
 *     v: 1,
 *     kdf: "pbkdf2-sha256",
 *     iterations: 210000,
 *     saltB64: "...",
 *     nonceB64: "...",
 *     ciphertextB64: "...",
 *     alg: "xsalsa20-poly1305"
 *   }
 *
 * Sessions are NOT persisted — they are ephemeral by design. Rehydrating a
 * heart does not resume its conversations; those must be reestablished.
 */

import { pbkdf2Sync } from 'node:crypto';
import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../core/crypto-provider.js';
import type { GenomeCommitment } from '../core/genome.js';
import type { Heartbeat } from './heartbeat.js';
import type { RevocationEvent } from './revocation.js';
import type { LineageCertificate } from './lineage.js';

// ─── Constants ──────────────────────────────────────────────────────────────

/** OWASP 2023 recommendation for PBKDF2-SHA256. */
const DEFAULT_PBKDF2_ITERATIONS = 210_000;
const PBKDF2_SALT_LENGTH = 16;
const DERIVED_KEY_LENGTH = 32;

// ─── Types ──────────────────────────────────────────────────────────────────

/** Encrypted credential as stored in the vault. */
export interface SerializedCredential {
  name: string;
  nonceB64: string;
  ciphertextB64: string;
}

/** The subset of heart state that survives serialization. */
export interface HeartState {
  /** Format version for forward compatibility. */
  version: 1;
  /** Genome commitment (public). */
  genome: GenomeCommitment;
  /** Signing key pair — base64-encoded for JSON. */
  signingKey: {
    publicKeyB64: string;
    secretKeyB64: string;
  };
  /** Model config. */
  modelId: string;
  modelBaseUrl: string;
  /** Data source configs (headers with auth keys are in credentials). */
  dataSources: Array<{
    name: string;
    url: string;
    headers?: Record<string, string>;
  }>;
  /** Credential vault contents (already encrypted with key derived from signingKey). */
  credentials: SerializedCredential[];
  /** Global heartbeat chain contents. */
  heartbeats: Heartbeat[];
  /** Revocations this heart is aware of. */
  revocations: RevocationEvent[];
  /** Lineage chain this heart carries, if any. */
  lineageChain?: LineageCertificate[];
  /** Root DID of the lineage, if any. */
  lineageRootDid?: string;
  /** When this state was captured. */
  savedAt: number;
}

/** Encrypted blob format — what gets written to disk. */
export interface EncryptedBlob {
  v: 1;
  kdf: 'pbkdf2-sha256';
  iterations: number;
  saltB64: string;
  nonceB64: string;
  ciphertextB64: string;
  alg: string;
}

// ─── Encryption ─────────────────────────────────────────────────────────────

function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Uint8Array {
  return new Uint8Array(
    pbkdf2Sync(password, Buffer.from(salt), iterations, DERIVED_KEY_LENGTH, 'sha256'),
  );
}

/**
 * Encrypt a HeartState with a password.
 * Returns a JSON string safe to write to disk.
 */
export function serializeHeart(
  state: HeartState,
  password: string,
  opts?: { iterations?: number; provider?: CryptoProvider },
): string {
  if (!password || password.length === 0) {
    throw new Error('password required for heart serialization');
  }
  const p = opts?.provider ?? getCryptoProvider();
  const iterations = opts?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;

  const salt = p.random.randomBytes(PBKDF2_SALT_LENGTH);
  const key = deriveKeyFromPassword(password, salt, iterations);
  const nonce = p.random.randomBytes(p.encryption.nonceLength);

  const plaintext = p.encoding.decodeUTF8(JSON.stringify(state));
  const ciphertext = p.encryption.encrypt(plaintext, nonce, key);

  // Wipe the key from memory
  key.fill(0);

  const blob: EncryptedBlob = {
    v: 1,
    kdf: 'pbkdf2-sha256',
    iterations,
    saltB64: p.encoding.encodeBase64(salt),
    nonceB64: p.encoding.encodeBase64(nonce),
    ciphertextB64: p.encoding.encodeBase64(ciphertext),
    alg: p.encryption.algorithmId,
  };

  return JSON.stringify(blob);
}

/**
 * Decrypt a serialized heart blob and return the HeartState.
 * Throws on wrong password or tampered blob.
 */
export function loadHeartState(
  blob: string,
  password: string,
  opts?: { provider?: CryptoProvider },
): HeartState {
  const p = opts?.provider ?? getCryptoProvider();

  let parsed: EncryptedBlob;
  try {
    parsed = JSON.parse(blob);
  } catch {
    throw new Error('invalid heart blob: not JSON');
  }

  if (parsed.v !== 1) {
    throw new Error(`unsupported heart blob version: ${parsed.v}`);
  }
  if (parsed.kdf !== 'pbkdf2-sha256') {
    throw new Error(`unsupported KDF: ${parsed.kdf}`);
  }
  if (parsed.alg !== p.encryption.algorithmId) {
    throw new Error(
      `blob encrypted with ${parsed.alg}, provider uses ${p.encryption.algorithmId}`,
    );
  }

  const salt = p.encoding.decodeBase64(parsed.saltB64);
  const nonce = p.encoding.decodeBase64(parsed.nonceB64);
  const ciphertext = p.encoding.decodeBase64(parsed.ciphertextB64);

  const key = deriveKeyFromPassword(password, salt, parsed.iterations);
  const plaintext = p.encryption.decrypt(ciphertext, nonce, key);
  key.fill(0);

  if (plaintext === null) {
    throw new Error('decryption failed: wrong password or tampered blob');
  }

  const stateJson = p.encoding.encodeUTF8(plaintext);
  const state: HeartState = JSON.parse(stateJson);

  if (state.version !== 1) {
    throw new Error(`unsupported heart state version: ${state.version}`);
  }

  return state;
}

// ─── Helpers for SignKeyPair roundtrip ──────────────────────────────────────

export function signKeyPairToJson(
  kp: SignKeyPair,
  provider?: CryptoProvider,
): { publicKeyB64: string; secretKeyB64: string } {
  const p = provider ?? getCryptoProvider();
  return {
    publicKeyB64: p.encoding.encodeBase64(kp.publicKey),
    secretKeyB64: p.encoding.encodeBase64(kp.secretKey),
  };
}

export function signKeyPairFromJson(
  json: { publicKeyB64: string; secretKeyB64: string },
  provider?: CryptoProvider,
): SignKeyPair {
  const p = provider ?? getCryptoProvider();
  return {
    publicKey: p.encoding.decodeBase64(json.publicKeyB64),
    secretKey: p.encoding.decodeBase64(json.secretKeyB64),
  };
}
