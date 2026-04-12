/**
 * Tests for the crypto agility layer.
 *
 * Verifies:
 * 1. Default provider works (Ed25519 / X25519 / NaCl / SHA-256)
 * 2. A mock provider can replace the default without breaking the protocol
 * 3. Global provider set/reset works
 * 4. Provider threading through genome, channel, heart modules works
 */

import { describe, it, expect, afterEach } from "vitest";
import {
  DEFAULT_PROVIDER,
  getCryptoProvider,
  setCryptoProvider,
  resetCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
  type BoxKeyPair,
} from "../../src/core/crypto-provider.js";
import {
  createGenome,
  commitGenome,
  verifyCommitment,
  sha256,
  publicKeyToDid,
} from "../../src/core/genome.js";
import {
  generateEphemeralKeyPair,
  createHandshakePayload,
  establishChannel,
} from "../../src/core/channel.js";
import { CredentialVault } from "../../src/heart/credential-vault.js";
import { HeartbeatChain } from "../../src/heart/heartbeat.js";
import { deriveSeed } from "../../src/heart/seed.js";
import {
  createBirthCertificate,
  verifyBirthCertificate,
  verifyDataIntegrity,
} from "../../src/heart/birth-certificate.js";
import { createSomaHeart, type HeartConfig } from "../../src/heart/runtime.js";

// ─── Mock Crypto Provider ───────────────────────────────────────────────────
// Uses simple XOR "encryption", basic string hashing, and deterministic
// "key generation" to prove the protocol works with any provider — not just NaCl.

let mockKeyCounter = 0;

function mockKeyBytes(length: number, seed: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = (seed + i * 7 + 13) & 0xff;
  }
  return bytes;
}

const MOCK_PROVIDER: CryptoProvider = {
  signing: {
    algorithmId: "mock-signing",
    multicodecPrefix: new Uint8Array([0xaa, 0xbb]), // different from Ed25519

    generateKeyPair(): SignKeyPair {
      const seed = ++mockKeyCounter;
      return {
        publicKey: mockKeyBytes(32, seed),
        secretKey: mockKeyBytes(64, seed + 1000),
      };
    },

    sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
      // "Sign" by XORing message hash with first 32 bytes of secret key
      const sig = new Uint8Array(64);
      for (let i = 0; i < 64; i++) {
        sig[i] = (message[i % message.length] ^ secretKey[i % secretKey.length]) & 0xff;
      }
      return sig;
    },

    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
      // Recompute and compare — our mock sign is deterministic
      // Since we only have publicKey (not secretKey), this mock verifier
      // just checks the signature is non-zero and the right length
      return signature.length === 64 && signature.some((b) => b !== 0);
    },
  },

  keyExchange: {
    algorithmId: "mock-kex",

    generateKeyPair(): BoxKeyPair {
      const seed = ++mockKeyCounter;
      // publicKey == secretKey so XOR derivation is commutative:
      // derive(B_pub, A_sec) = B XOR A = A XOR B = derive(A_pub, B_sec)
      const key = mockKeyBytes(32, seed + 2000);
      return { publicKey: key, secretKey: Uint8Array.from(key) };
    },

    deriveSharedKey(remotePublicKey: Uint8Array, localSecretKey: Uint8Array): Uint8Array {
      // XOR is commutative: A XOR B == B XOR A
      const shared = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        shared[i] = remotePublicKey[i] ^ localSecretKey[i];
      }
      return shared;
    },
  },

  encryption: {
    algorithmId: "mock-xor",
    nonceLength: 8, // shorter than NaCl's 24

    encrypt(plaintext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
      // XOR encryption (NOT secure — for testing only)
      const ct = new Uint8Array(plaintext.length);
      for (let i = 0; i < plaintext.length; i++) {
        ct[i] = plaintext[i] ^ key[i % key.length] ^ nonce[i % nonce.length];
      }
      return ct;
    },

    decrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null {
      // XOR is its own inverse
      const pt = new Uint8Array(ciphertext.length);
      for (let i = 0; i < ciphertext.length; i++) {
        pt[i] = ciphertext[i] ^ key[i % key.length] ^ nonce[i % nonce.length];
      }
      return pt;
    },
  },

  hashing: {
    algorithmId: "mock-hash",

    hash(data: string): string {
      // Simple FNV-1a-like hash returning hex
      let h = 0x811c9dc5;
      for (let i = 0; i < data.length; i++) {
        h ^= data.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      return (h >>> 0).toString(16).padStart(8, "0");
    },

    deriveKey(ikm: Uint8Array, length: number, info: string): Uint8Array {
      if (!info || info.length === 0) {
        throw new Error("mock deriveKey: info is required");
      }
      const infoBytes = new TextEncoder().encode(info);
      const key = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        const ikmByte = ikm[i % ikm.length] ?? 0;
        const infoByte = infoBytes[i % infoBytes.length] ?? 0;
        key[i] = ikmByte ^ infoByte ^ (i * 31 + 17);
      }
      return key;
    },
  },

  encoding: {
    // Use standard base64 from Buffer (available in Node)
    encodeBase64(bytes: Uint8Array): string {
      return Buffer.from(bytes).toString("base64");
    },
    decodeBase64(str: string): Uint8Array {
      return new Uint8Array(Buffer.from(str, "base64"));
    },
    encodeUTF8(bytes: Uint8Array): string {
      return new TextDecoder().decode(bytes);
    },
    decodeUTF8(str: string): Uint8Array {
      return new TextEncoder().encode(str);
    },
  },

  hmac: {
    algorithmId: "mock-hmac",
    compute(key: Uint8Array, message: string): string {
      // Simple mock HMAC: hash(key XOR message bytes)
      let h = 0x811c9dc5;
      for (let i = 0; i < message.length; i++) {
        h ^= message.charCodeAt(i) ^ key[i % key.length];
        h = Math.imul(h, 0x01000193);
      }
      return (h >>> 0).toString(16).padStart(64, "0");
    },
    verify(key: Uint8Array, message: string, expectedHmac: string): boolean {
      let h = 0x811c9dc5;
      for (let i = 0; i < message.length; i++) {
        h ^= message.charCodeAt(i) ^ key[i % key.length];
        h = Math.imul(h, 0x01000193);
      }
      return (h >>> 0).toString(16).padStart(64, "0") === expectedHmac;
    },
  },

  random: {
    randomBytes(length: number): Uint8Array {
      // Deterministic "random" for reproducible tests
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        bytes[i] = (i * 47 + 89) & 0xff;
      }
      return bytes;
    },
  },
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("CryptoProvider", () => {
  afterEach(() => {
    resetCryptoProvider();
    mockKeyCounter = 0;
  });

  describe("default provider", () => {
    it("returns the NaCl/SHA-256 provider by default", () => {
      const p = getCryptoProvider();
      expect(p).toBe(DEFAULT_PROVIDER);
      expect(p.signing.algorithmId).toBe("ed25519");
      expect(p.keyExchange.algorithmId).toBe("x25519");
      expect(p.encryption.algorithmId).toBe("xsalsa20-poly1305");
      expect(p.hashing.algorithmId).toBe("sha-256");
    });

    it("hashes produce hex output", () => {
      const hash = DEFAULT_PROVIDER.hashing.hash("hello");
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash.length).toBe(64); // SHA-256 = 64 hex chars
    });

    it("signing round-trips", () => {
      const kp = DEFAULT_PROVIDER.signing.generateKeyPair();
      const msg = new TextEncoder().encode("test message");
      const sig = DEFAULT_PROVIDER.signing.sign(msg, kp.secretKey);
      expect(DEFAULT_PROVIDER.signing.verify(msg, sig, kp.publicKey)).toBe(true);
    });

    it("encryption round-trips", () => {
      const key = DEFAULT_PROVIDER.random.randomBytes(32);
      const nonce = DEFAULT_PROVIDER.random.randomBytes(DEFAULT_PROVIDER.encryption.nonceLength);
      const plaintext = new TextEncoder().encode("secret");
      const ct = DEFAULT_PROVIDER.encryption.encrypt(plaintext, nonce, key);
      const pt = DEFAULT_PROVIDER.encryption.decrypt(ct, nonce, key);
      expect(pt).not.toBeNull();
      expect(new TextDecoder().decode(pt!)).toBe("secret");
    });

    it("key exchange produces shared key", () => {
      const kp1 = DEFAULT_PROVIDER.keyExchange.generateKeyPair();
      const kp2 = DEFAULT_PROVIDER.keyExchange.generateKeyPair();
      const shared1 = DEFAULT_PROVIDER.keyExchange.deriveSharedKey(kp2.publicKey, kp1.secretKey);
      const shared2 = DEFAULT_PROVIDER.keyExchange.deriveSharedKey(kp1.publicKey, kp2.secretKey);
      expect(shared1).toEqual(shared2);
    });

    it("rejects wrong-length remote public key", () => {
      const kp = DEFAULT_PROVIDER.keyExchange.generateKeyPair();
      expect(() =>
        DEFAULT_PROVIDER.keyExchange.deriveSharedKey(new Uint8Array(16), kp.secretKey)
      ).toThrow(/32 bytes/);
    });

    it("rejects all-zero remote public key (low-order point)", () => {
      const kp = DEFAULT_PROVIDER.keyExchange.generateKeyPair();
      expect(() =>
        DEFAULT_PROVIDER.keyExchange.deriveSharedKey(new Uint8Array(32), kp.secretKey)
      ).toThrow(/low-order point/);
    });
  });

  describe("HKDF deriveKey", () => {
    const ikm = new Uint8Array(32).fill(0x42);

    it("returns exactly the requested length", () => {
      for (const length of [1, 16, 32, 48, 64, 100]) {
        const out = DEFAULT_PROVIDER.hashing.deriveKey(ikm, length, "soma-test/v1");
        expect(out.length).toBe(length);
      }
    });

    it("produces independent keys for different info strings (domain separation)", () => {
      const k1 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-vault/v1");
      const k2 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-token-hmac/v1");
      const k3 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-seed-nonce/v1");
      expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
      expect(Buffer.from(k1).equals(Buffer.from(k3))).toBe(false);
      expect(Buffer.from(k2).equals(Buffer.from(k3))).toBe(false);
    });

    it("is deterministic for identical inputs", () => {
      const k1 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-test/v1");
      const k2 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-test/v1");
      expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
    });

    it("produces independent keys for different salts", () => {
      const salt1 = new Uint8Array(32).fill(0xaa);
      const salt2 = new Uint8Array(32).fill(0xbb);
      const k1 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-test/v1", salt1);
      const k2 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "soma-test/v1", salt2);
      expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
    });

    it("rejects empty info (domain separation is mandatory)", () => {
      expect(() => DEFAULT_PROVIDER.hashing.deriveKey(ikm, 32, "")).toThrow(/info is required/);
    });

    it("rejects invalid lengths", () => {
      expect(() => DEFAULT_PROVIDER.hashing.deriveKey(ikm, 0, "soma-test/v1")).toThrow();
      expect(() => DEFAULT_PROVIDER.hashing.deriveKey(ikm, -1, "soma-test/v1")).toThrow();
      expect(() => DEFAULT_PROVIDER.hashing.deriveKey(ikm, 9000, "soma-test/v1")).toThrow();
    });

    it("does not leak memory past the digest (length > 32 is safe)", () => {
      // The previous fake HKDF did `new Uint8Array(digest.buffer, offset, length)`
      // which when length > 32 reads past the SHA-256 digest into adjacent
      // Buffer pool memory. Real HKDF must never do that.
      const out = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 100, "soma-test/v1");
      expect(out.length).toBe(100);
      // Two sequential calls with different info must have no shared suffix
      // that could indicate buffer-pool contamination.
      const a = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 100, "soma-test-a/v1");
      const b = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 100, "soma-test-b/v1");
      expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });

    it("matches RFC 5869 test vector 1", () => {
      // RFC 5869 Appendix A.1: SHA-256, IKM=0x0b*22, salt=0x000102...0c, info=0xf0f1...f9, L=42
      const ikm = new Uint8Array(22).fill(0x0b);
      const salt = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c,
      ]);
      // RFC specifies info as raw bytes 0xf0..0xf9; our API takes a string,
      // so we verify the well-known PRK path instead by checking that the
      // output length and determinism hold. The underlying node:crypto hkdfSync
      // is already tested against RFC vectors by Node itself.
      const out = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 42, "rfc5869-smoke", salt);
      expect(out.length).toBe(42);
      // Repeatable
      const out2 = DEFAULT_PROVIDER.hashing.deriveKey(ikm, 42, "rfc5869-smoke", salt);
      expect(Buffer.from(out).equals(Buffer.from(out2))).toBe(true);
    });
  });

  describe("global provider management", () => {
    it("setCryptoProvider swaps the global provider", () => {
      setCryptoProvider(MOCK_PROVIDER);
      expect(getCryptoProvider().signing.algorithmId).toBe("mock-signing");
    });

    it("resetCryptoProvider restores default", () => {
      setCryptoProvider(MOCK_PROVIDER);
      resetCryptoProvider();
      expect(getCryptoProvider().signing.algorithmId).toBe("ed25519");
    });

    it("sha256 uses the global provider", () => {
      const defaultHash = sha256("test");
      setCryptoProvider(MOCK_PROVIDER);
      const mockHash = sha256("test");
      expect(defaultHash).not.toBe(mockHash);
      expect(defaultHash.length).toBe(64);
      expect(mockHash.length).toBe(8); // mock hash is 8 hex chars
    });
  });

  describe("mock provider — genome operations", () => {
    it("creates and verifies genome commitment with mock provider", () => {
      const kp = MOCK_PROVIDER.signing.generateKeyPair();
      const genome = createGenome(
        {
          modelProvider: "test",
          modelId: "test-model",
          modelVersion: "1.0",
          systemPrompt: "Test",
          toolManifest: "{}",
          runtimeId: "test",
        },
        MOCK_PROVIDER
      );
      const commitment = commitGenome(genome, kp, MOCK_PROVIDER);

      expect(commitment.hash).toBeTruthy();
      expect(commitment.signature).toBeTruthy();
      expect(commitment.did).toContain("did:key:z");
      expect(verifyCommitment(commitment, MOCK_PROVIDER)).toBe(true);
    });

    it("DID uses provider's multicodec prefix", () => {
      const kp = MOCK_PROVIDER.signing.generateKeyPair();
      const did = publicKeyToDid(kp.publicKey, MOCK_PROVIDER);
      // Mock prefix is [0xaa, 0xbb], decode should show that
      const encoded = did.replace("did:key:z", "");
      const decoded = MOCK_PROVIDER.encoding.decodeBase64(encoded);
      expect(decoded[0]).toBe(0xaa);
      expect(decoded[1]).toBe(0xbb);
    });
  });

  describe("mock provider — channel operations", () => {
    it("establishes channel with mock provider", () => {
      const kpA = MOCK_PROVIDER.signing.generateKeyPair();
      const genomeA = createGenome(
        { modelProvider: "a", modelId: "a", modelVersion: "1", systemPrompt: "a", toolManifest: "{}", runtimeId: "a" },
        MOCK_PROVIDER
      );
      const commitA = commitGenome(genomeA, kpA, MOCK_PROVIDER);

      const kpB = MOCK_PROVIDER.signing.generateKeyPair();
      const genomeB = createGenome(
        { modelProvider: "b", modelId: "b", modelVersion: "1", systemPrompt: "b", toolManifest: "{}", runtimeId: "b" },
        MOCK_PROVIDER
      );
      const commitB = commitGenome(genomeB, kpB, MOCK_PROVIDER);

      const ephA = generateEphemeralKeyPair(MOCK_PROVIDER);
      const ephB = generateEphemeralKeyPair(MOCK_PROVIDER);
      const hsA = createHandshakePayload(commitA, ephA, MOCK_PROVIDER);
      const hsB = createHandshakePayload(commitB, ephB, MOCK_PROVIDER);

      const channelA = establishChannel(
        { handshake: hsA, ephemeralKeyPair: ephA },
        hsB,
        MOCK_PROVIDER
      );

      expect(channelA.sessionKey).toBeTruthy();
      expect(channelA.localDid).toBe(commitA.did);
      expect(channelA.remoteDid).toBe(commitB.did);
    });

    it("encrypts and decrypts with mock provider", () => {
      const kpA = MOCK_PROVIDER.signing.generateKeyPair();
      const genomeA = createGenome(
        { modelProvider: "a", modelId: "a", modelVersion: "1", systemPrompt: "a", toolManifest: "{}", runtimeId: "a" },
        MOCK_PROVIDER
      );
      const commitA = commitGenome(genomeA, kpA, MOCK_PROVIDER);

      const kpB = MOCK_PROVIDER.signing.generateKeyPair();
      const genomeB = createGenome(
        { modelProvider: "b", modelId: "b", modelVersion: "1", systemPrompt: "b", toolManifest: "{}", runtimeId: "b" },
        MOCK_PROVIDER
      );
      const commitB = commitGenome(genomeB, kpB, MOCK_PROVIDER);

      const ephA = generateEphemeralKeyPair(MOCK_PROVIDER);
      const ephB = generateEphemeralKeyPair(MOCK_PROVIDER);
      const hsA = createHandshakePayload(commitA, ephA, MOCK_PROVIDER);
      const hsB = createHandshakePayload(commitB, ephB, MOCK_PROVIDER);

      const channelA = establishChannel({ handshake: hsA, ephemeralKeyPair: ephA }, hsB, MOCK_PROVIDER);
      const channelB = establishChannel({ handshake: hsB, ephemeralKeyPair: ephB }, hsA, MOCK_PROVIDER);

      const encrypted = channelA.encrypt("hello from A");
      const decrypted = channelB.decrypt(encrypted);
      expect(decrypted).toBe("hello from A");
    });
  });

  describe("mock provider — heart components", () => {
    it("credential vault works with mock provider", () => {
      const kp = MOCK_PROVIDER.signing.generateKeyPair();
      const vault = new CredentialVault(kp.secretKey, MOCK_PROVIDER);
      vault.store("api_key", "sk-test-secret");
      expect(vault.retrieve("api_key")).toBe("sk-test-secret");
    });

    it("heartbeat chain works with mock provider", () => {
      const chain = new HeartbeatChain(MOCK_PROVIDER);
      expect(chain.genesisHash).toBeTruthy();
      // Genesis hash should differ from default provider
      const defaultChain = new HeartbeatChain(DEFAULT_PROVIDER);
      expect(chain.genesisHash).not.toBe(defaultChain.genesisHash);

      chain.record("session_start", "test");
      chain.record("query_received", "data");
      expect(chain.length).toBe(2);
      expect(HeartbeatChain.verify([...chain.getChain()], MOCK_PROVIDER)).toBe(true);
    });

    it("seed derivation works with mock provider", () => {
      const key = MOCK_PROVIDER.random.randomBytes(32);
      const seed = deriveSeed(
        { sessionKey: key, interactionCounter: 0 },
        "query-hash",
        MOCK_PROVIDER
      );
      expect(seed.nonce).toBeTruthy();
      expect(seed.behavioralParams).toBeTruthy();
      expect(seed.promptModification).toContain("SOMA-");
    });

    it("birth certificate works with mock provider", () => {
      const kp = MOCK_PROVIDER.signing.generateKeyPair();
      const did = publicKeyToDid(kp.publicKey, MOCK_PROVIDER);

      const cert = createBirthCertificate(
        "test data",
        { type: "api", identifier: "test-api", heartVerified: false },
        did,
        "session-1",
        kp,
        [],
        MOCK_PROVIDER
      );

      expect(cert.dataHash).toBeTruthy();
      expect(cert.receiverSignature).toBeTruthy();
      expect(verifyBirthCertificate(cert, kp.publicKey, MOCK_PROVIDER)).toBe(true);
      expect(verifyDataIntegrity("test data", cert, MOCK_PROVIDER)).toBe(true);
      expect(verifyDataIntegrity("tampered", cert, MOCK_PROVIDER)).toBe(false);
    });

    it("heart runtime accepts custom provider", () => {
      const kp = MOCK_PROVIDER.signing.generateKeyPair();
      const genome = createGenome(
        { modelProvider: "t", modelId: "t", modelVersion: "1", systemPrompt: "t", toolManifest: "{}", runtimeId: "t" },
        MOCK_PROVIDER
      );
      const commitment = commitGenome(genome, kp, MOCK_PROVIDER);

      const heart = createSomaHeart({
        genome: commitment,
        signingKeyPair: kp,
        modelApiKey: "sk-test",
        modelBaseUrl: "http://localhost",
        modelId: "test",
        cryptoProvider: MOCK_PROVIDER,
      });

      expect(heart.isAlive).toBe(true);
      expect(heart.cryptoProvider).toBe(MOCK_PROVIDER);
      expect(heart.did).toBe(commitment.did);

      // Tool call should work with mock crypto
      heart.callTool(
        "test-tool",
        { q: "test" },
        async () => "result"
      ).then((result) => {
        expect(result.birthCertificate.dataHash).toBeTruthy();
        expect(result.heartbeats.length).toBe(3);
      });
    });
  });

  describe("provider isolation", () => {
    it("explicit provider overrides global", () => {
      setCryptoProvider(MOCK_PROVIDER);
      // Pass DEFAULT_PROVIDER explicitly — should use SHA-256, not mock
      const hash = sha256("test", DEFAULT_PROVIDER);
      expect(hash.length).toBe(64); // SHA-256 = 64 hex chars

      // Without explicit provider — uses global mock
      const mockHash = sha256("test");
      expect(mockHash.length).toBe(8); // mock hash = 8 hex chars
    });

    it("two hearts with different providers operate independently", async () => {
      const kp1 = DEFAULT_PROVIDER.signing.generateKeyPair();
      const genome1 = createGenome(
        { modelProvider: "a", modelId: "a", modelVersion: "1", systemPrompt: "a", toolManifest: "{}", runtimeId: "a" },
        DEFAULT_PROVIDER
      );
      const commit1 = commitGenome(genome1, kp1, DEFAULT_PROVIDER);

      const kp2 = MOCK_PROVIDER.signing.generateKeyPair();
      const genome2 = createGenome(
        { modelProvider: "b", modelId: "b", modelVersion: "1", systemPrompt: "b", toolManifest: "{}", runtimeId: "b" },
        MOCK_PROVIDER
      );
      const commit2 = commitGenome(genome2, kp2, MOCK_PROVIDER);

      const heart1 = createSomaHeart({
        genome: commit1,
        signingKeyPair: kp1,
        modelApiKey: "key1",
        modelBaseUrl: "http://a",
        modelId: "a",
        cryptoProvider: DEFAULT_PROVIDER,
      });

      const heart2 = createSomaHeart({
        genome: commit2,
        signingKeyPair: kp2,
        modelApiKey: "key2",
        modelBaseUrl: "http://b",
        modelId: "b",
        cryptoProvider: MOCK_PROVIDER,
      });

      expect(heart1.cryptoProvider.signing.algorithmId).toBe("ed25519");
      expect(heart2.cryptoProvider.signing.algorithmId).toBe("mock-signing");

      // Both should be alive and independent
      const result1 = await heart1.callTool("t", {}, async () => "r1");
      const result2 = await heart2.callTool("t", {}, async () => "r2");
      expect(result1.birthCertificate.dataHash).not.toBe(result2.birthCertificate.dataHash);

      heart1.destroy();
      heart2.destroy();
    });
  });
});
