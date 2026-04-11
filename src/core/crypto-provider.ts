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
import {
  createHash,
  createHmac,
  hkdfSync,
  timingSafeEqual,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";

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

// Ed25519 via node:crypto native. We keep the tweetnacl wire format for keys
// (32-byte raw public key, 64-byte secret key = seed || publicKey) so existing
// stored keys and signatures remain interoperable. Internally we wrap the
// 32-byte seed / public key in the fixed PKCS8 / SPKI prefixes Node expects.
//
// Why: tweetnacl is pure JS and its verify path is not constant-time in the
// same way as libsodium/OpenSSL. Node Ed25519 sits on OpenSSL and is the
// sanctioned primitive for production signing.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function seedToPkcs8(seed: Uint8Array): Buffer {
  return Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
}
function pubkeyToSpki(pub: Uint8Array): Buffer {
  return Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pub)]);
}

const ed25519Signing: SigningProvider = {
  algorithmId: "ed25519",
  multicodecPrefix: new Uint8Array([0xed, 0x01]),

  generateKeyPair(): SignKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" });
    const pubRaw = new Uint8Array(spki.subarray(spki.length - 32));
    const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
    const seed = pkcs8.subarray(pkcs8.length - 32);
    const secretKey = new Uint8Array(64);
    secretKey.set(seed, 0);
    secretKey.set(pubRaw, 32);
    return { publicKey: pubRaw, secretKey };
  },

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== 64 && secretKey.length !== 32) {
      throw new Error(`ed25519 sign: secretKey must be 32 or 64 bytes, got ${secretKey.length}`);
    }
    const seed = secretKey.length === 64 ? secretKey.subarray(0, 32) : secretKey;
    const keyObj = createPrivateKey({
      key: seedToPkcs8(seed),
      format: "der",
      type: "pkcs8",
    });
    const sig = cryptoSign(null, Buffer.from(message), keyObj);
    return new Uint8Array(sig);
  },

  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    try {
      const keyObj = createPublicKey({
        key: pubkeyToSpki(publicKey),
        format: "der",
        type: "spki",
      });
      return cryptoVerify(null, Buffer.from(message), keyObj, Buffer.from(signature));
    } catch {
      return false;
    }
  },
};

const naclKeyExchange: KeyExchangeProvider = {
  algorithmId: "x25519",

  generateKeyPair(): BoxKeyPair {
    const kp = nacl.box.keyPair();
    return { publicKey: kp.publicKey, secretKey: kp.secretKey };
  },

  /**
   * X25519 ECDH with defensive low-order-point checks.
   *
   * RFC 7748 §6.1 warns that X25519 inputs drawn from the eight low-order
   * points on Curve25519 collapse the shared secret to zero regardless of
   * the local secret. A peer who supplies such a public key can force a
   * predictable session key. `nacl.box.before` does not filter them.
   *
   * Defense in depth:
   *   1. Reject wrong-length remote keys.
   *   2. Reject the all-zero remote key (the most trivial low-order point).
   *   3. Compute the shared secret, then reject it if it is all-zero —
   *      this catches the remaining seven low-order points at the cost of
   *      the scalar-mult we already had to perform.
   */
  deriveSharedKey(remotePublicKey: Uint8Array, localSecretKey: Uint8Array): Uint8Array {
    if (remotePublicKey.length !== 32) {
      throw new Error(`x25519 deriveSharedKey: remote public key must be 32 bytes, got ${remotePublicKey.length}`);
    }
    if (localSecretKey.length !== 32) {
      throw new Error(`x25519 deriveSharedKey: local secret key must be 32 bytes, got ${localSecretKey.length}`);
    }
    let allZero = true;
    for (let i = 0; i < 32; i++) {
      if (remotePublicKey[i] !== 0) { allZero = false; break; }
    }
    if (allZero) {
      throw new Error("x25519 deriveSharedKey: remote public key is all-zero (low-order point rejected)");
    }
    const shared = nacl.box.before(remotePublicKey, localSecretKey);
    let sharedZero = true;
    for (let i = 0; i < shared.length; i++) {
      if (shared[i] !== 0) { sharedZero = false; break; }
    }
    if (sharedZero) {
      throw new Error("x25519 deriveSharedKey: derived shared secret is zero (low-order point rejected)");
    }
    return shared;
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
  signing: ed25519Signing,
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
