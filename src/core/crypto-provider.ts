/**
 * Cryptographic agility layer — abstract interfaces for all crypto operations.
 *
 * The protocol depends on properties (signing, encryption, hashing) not
 * specific algorithms. Like TLS cipher suites — the protocol works regardless
 * of which suite is negotiated.
 *
 * Default provider uses Ed25519 / X25519 / NaCl secretbox / SHA-256.
 * Operators can swap in post-quantum algorithms by providing a custom provider.
 */

import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = naclUtil;
import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

// ─── Algorithm-agnostic key pair types ───────────────────────────────────────

/** A signing key pair (e.g. Ed25519, Dilithium). */
export interface SignKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** A key-exchange key pair (e.g. X25519, Kyber). */
export interface BoxKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ─── Provider interfaces ─────────────────────────────────────────────────────

/** Digital signature operations. */
export interface SigningProvider {
  /** Algorithm identifier (e.g. "ed25519", "dilithium3"). */
  readonly algorithmId: string;
  /** Multicodec prefix for DID encoding. Ed25519 = [0xed, 0x01]. */
  readonly multicodecPrefix: Uint8Array;
  /** Generate a new signing key pair. */
  generateKeyPair(): SignKeyPair;
  /** Produce a detached signature. */
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  /** Verify a detached signature. */
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

/** Ephemeral key exchange (Diffie-Hellman or KEM). */
export interface KeyExchangeProvider {
  readonly algorithmId: string;
  /** Generate an ephemeral key pair for a single session. */
  generateKeyPair(): BoxKeyPair;
  /** Derive a shared secret from remote public key + local secret key. */
  deriveSharedKey(remotePublicKey: Uint8Array, localSecretKey: Uint8Array): Uint8Array;
}

/** Authenticated symmetric encryption. */
export interface SymmetricEncryptionProvider {
  readonly algorithmId: string;
  /** Required nonce length in bytes. */
  readonly nonceLength: number;
  /** Encrypt plaintext with nonce and key. Returns ciphertext with auth tag. */
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  /** Decrypt ciphertext. Returns null if authentication fails (tampered). */
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null;
}

/** Cryptographic hashing. */
export interface HashingProvider {
  readonly algorithmId: string;
  /** Hash a string, return hex digest. */
  hash(data: string): string;
  /**
   * HKDF key derivation (RFC 5869).
   *
   * `info` is REQUIRED and must be a domain-specific label unique to the
   * calling context (e.g. "soma-vault/v1", "soma-seed-nonce/v1"). Two
   * derivations with the same `ikm` but different `info` MUST produce
   * independent keys. This is the protection against cross-context key
   * reuse — omitting or reusing `info` defeats the entire purpose.
   *
   * `salt` is optional; when omitted, HKDF uses a zero-filled hash block
   * per RFC 5869 §2.2.
   */
  deriveKey(ikm: Uint8Array, length: number, info: string, salt?: Uint8Array): Uint8Array;
}

/** Binary ↔ string encoding. */
export interface EncodingProvider {
  encodeBase64(bytes: Uint8Array): string;
  decodeBase64(str: string): Uint8Array;
  encodeUTF8(bytes: Uint8Array): string;
  decodeUTF8(str: string): Uint8Array;
}

/** HMAC (keyed hash for message authentication). */
export interface HmacProvider {
  readonly algorithmId: string;
  /** Compute HMAC of message with key. Returns hex digest. */
  compute(key: Uint8Array, message: string): string;
  /** Verify HMAC. Constant-time comparison. */
  verify(key: Uint8Array, message: string, expectedHmac: string): boolean;
}

/** Cryptographically secure random bytes. */
export interface RandomProvider {
  randomBytes(length: number): Uint8Array;
}

// ─── Combined provider ──────────────────────────────────────────────────────

/**
 * Complete cryptographic provider — all algorithms needed by the protocol.
 *
 * Pass a custom provider to swap algorithms without touching the protocol.
 * Every crypto-using function accepts an optional provider parameter;
 * if omitted, the global default provider is used.
 */
export interface CryptoProvider {
  readonly signing: SigningProvider;
  readonly keyExchange: KeyExchangeProvider;
  readonly encryption: SymmetricEncryptionProvider;
  readonly hashing: HashingProvider;
  readonly hmac: HmacProvider;
  readonly encoding: EncodingProvider;
  readonly random: RandomProvider;
}

// ─── Default NaCl / SHA-256 provider ─────────────────────────────────────────

const naclSigning: SigningProvider = {
  algorithmId: "ed25519",
  multicodecPrefix: new Uint8Array([0xed, 0x01]),

  generateKeyPair(): SignKeyPair {
    const kp = nacl.sign.keyPair();
    return { publicKey: kp.publicKey, secretKey: kp.secretKey };
  },

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return nacl.sign.detached(message, secretKey);
  },

  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    return nacl.sign.detached.verify(message, signature, publicKey);
  },
};

const naclKeyExchange: KeyExchangeProvider = {
  algorithmId: "x25519",

  generateKeyPair(): BoxKeyPair {
    const kp = nacl.box.keyPair();
    return { publicKey: kp.publicKey, secretKey: kp.secretKey };
  },

  deriveSharedKey(remotePublicKey: Uint8Array, localSecretKey: Uint8Array): Uint8Array {
    return nacl.box.before(remotePublicKey, localSecretKey);
  },
};

const naclEncryption: SymmetricEncryptionProvider = {
  algorithmId: "xsalsa20-poly1305",
  nonceLength: nacl.secretbox.nonceLength,

  encrypt(plaintext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
    return nacl.secretbox(plaintext, nonce, key);
  },

  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null {
    return nacl.secretbox.open(ciphertext, nonce, key);
  },
};

const sha256Hashing: HashingProvider = {
  algorithmId: "sha-256",

  hash(data: string): string {
    return createHash("sha256").update(data).digest("hex");
  },

  deriveKey(ikm: Uint8Array, length: number, info: string, salt?: Uint8Array): Uint8Array {
    if (!info || info.length === 0) {
      throw new Error("deriveKey: info is required and must be non-empty (domain separation)");
    }
    if (length <= 0 || length > 8160) {
      // RFC 5869 §2.3: HKDF-Expand output ≤ 255 * HashLen (32 for SHA-256)
      throw new Error(`deriveKey: length must be in 1..8160, got ${length}`);
    }
    const effectiveSalt = salt ?? new Uint8Array(32);
    const infoBytes = new TextEncoder().encode(info);
    const out = hkdfSync("sha256", ikm, effectiveSalt, infoBytes, length);
    return new Uint8Array(out);
  },
};

const base64Encoding: EncodingProvider = {
  encodeBase64(bytes: Uint8Array): string {
    return encodeBase64(bytes);
  },
  decodeBase64(str: string): Uint8Array {
    return decodeBase64(str);
  },
  encodeUTF8(bytes: Uint8Array): string {
    return encodeUTF8(bytes);
  },
  decodeUTF8(str: string): Uint8Array {
    return decodeUTF8(str);
  },
};

const sha256Hmac: HmacProvider = {
  algorithmId: "hmac-sha256",

  compute(key: Uint8Array, message: string): string {
    return createHmac("sha256", key).update(message).digest("hex");
  },

  verify(key: Uint8Array, message: string, expectedHmac: string): boolean {
    const actual = this.compute(key, message);
    const a = Buffer.from(actual, "hex");
    const b = Buffer.from(expectedHmac, "hex");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  },
};

const naclRandom: RandomProvider = {
  randomBytes(length: number): Uint8Array {
    return nacl.randomBytes(length);
  },
};

/** The default provider: Ed25519 + X25519 + XSalsa20-Poly1305 + SHA-256 + HMAC-SHA256. */
export const DEFAULT_PROVIDER: CryptoProvider = {
  signing: naclSigning,
  keyExchange: naclKeyExchange,
  encryption: naclEncryption,
  hashing: sha256Hashing,
  hmac: sha256Hmac,
  encoding: base64Encoding,
  random: naclRandom,
};

// ─── Global provider management ─────────────────────────────────────────────

let _provider: CryptoProvider = DEFAULT_PROVIDER;

/** Get the current global crypto provider. */
export function getCryptoProvider(): CryptoProvider {
  return _provider;
}

/** Set the global crypto provider (call once at startup). */
export function setCryptoProvider(provider: CryptoProvider): void {
  _provider = provider;
}

/** Reset the global provider to the default NaCl/SHA-256 suite. */
export function resetCryptoProvider(): void {
  _provider = DEFAULT_PROVIDER;
}
