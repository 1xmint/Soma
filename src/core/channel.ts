import {
  getCryptoProvider,
  type CryptoProvider,
  type BoxKeyPair,
} from "./crypto-provider.js";
import { type GenomeCommitment, verifyCommitment } from "./genome.js";

// Re-export key pair type for consumers
export type { BoxKeyPair };

// --- Types ---

/** Material presented during handshake — identity + ephemeral key for session. */
export interface HandshakePayload {
  did: string;
  genomeCommitment: GenomeCommitment;
  ephemeralPublicKey: string; // base64-encoded public key
}

/** An established encrypted channel between two agents. */
export interface Channel {
  localDid: string;
  remoteDid: string;
  localGenomeCommitment: GenomeCommitment;
  remoteGenomeCommitment: GenomeCommitment;
  /** The shared session key — used by the heart seed mechanism. */
  sessionKey: Uint8Array;
  /** Encrypt a plaintext message for the remote party. */
  encrypt(plaintext: string): EncryptedMessage;
  /** Decrypt a message from the remote party. */
  decrypt(message: EncryptedMessage): string;
}

export interface EncryptedMessage {
  nonce: string;    // base64
  ciphertext: string; // base64
}

// --- Handshake ---

/** Generate an ephemeral key pair for a single session — forward secrecy. */
export function generateEphemeralKeyPair(provider?: CryptoProvider): BoxKeyPair {
  return (provider ?? getCryptoProvider()).keyExchange.generateKeyPair();
}

/** Build the handshake payload an agent presents to initiate a channel. */
export function createHandshakePayload(
  genomeCommitment: GenomeCommitment,
  ephemeralKeyPair: BoxKeyPair,
  provider?: CryptoProvider
): HandshakePayload {
  const p = provider ?? getCryptoProvider();
  return {
    did: genomeCommitment.did,
    genomeCommitment,
    ephemeralPublicKey: p.encoding.encodeBase64(ephemeralKeyPair.publicKey),
  };
}

/**
 * Establish a channel from two handshake payloads.
 *
 * Both sides:
 * 1. Verify the other's genome commitment signature
 * 2. Derive a shared session key via key exchange
 * 3. All subsequent traffic is authenticated-encrypted
 *
 * A proxy between A and B cannot decrypt, read, or inject — reduced to a dumb pipe.
 */
export function establishChannel(
  local: {
    handshake: HandshakePayload;
    ephemeralKeyPair: BoxKeyPair;
  },
  remoteHandshake: HandshakePayload,
  provider?: CryptoProvider
): Channel {
  const p = provider ?? getCryptoProvider();

  // Step 1: Verify the remote party's genome commitment
  if (!verifyCommitment(remoteHandshake.genomeCommitment, p)) {
    throw new Error("Remote genome commitment verification failed");
  }

  // Step 2: Verify the remote DID matches its genome commitment
  if (remoteHandshake.did !== remoteHandshake.genomeCommitment.did) {
    throw new Error("Remote DID does not match genome commitment");
  }

  // Step 3: Derive shared session key via key exchange
  const remoteEphemeralKey = p.encoding.decodeBase64(remoteHandshake.ephemeralPublicKey);
  const sharedKey = p.keyExchange.deriveSharedKey(remoteEphemeralKey, local.ephemeralKeyPair.secretKey);

  // Step 4: Return a channel object with encrypt/decrypt using the shared key
  return {
    localDid: local.handshake.did,
    remoteDid: remoteHandshake.did,
    localGenomeCommitment: local.handshake.genomeCommitment,
    remoteGenomeCommitment: remoteHandshake.genomeCommitment,
    sessionKey: sharedKey,

    encrypt(plaintext: string): EncryptedMessage {
      const nonce = p.random.randomBytes(p.encryption.nonceLength);
      const messageBytes = p.encoding.decodeUTF8(plaintext);
      const ciphertext = p.encryption.encrypt(messageBytes, nonce, sharedKey);
      return {
        nonce: p.encoding.encodeBase64(nonce),
        ciphertext: p.encoding.encodeBase64(ciphertext),
      };
    },

    decrypt(message: EncryptedMessage): string {
      const nonce = p.encoding.decodeBase64(message.nonce);
      const ciphertext = p.encoding.decodeBase64(message.ciphertext);
      const plaintext = p.encryption.decrypt(ciphertext, nonce, sharedKey);
      if (plaintext === null) {
        throw new Error("Decryption failed — message tampered or wrong key");
      }
      return p.encoding.encodeUTF8(plaintext);
    },
  };
}
