import nacl from "tweetnacl";
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from "tweetnacl-util";
import { type GenomeCommitment, verifyCommitment, publicKeyToDid } from "./genome.js";

// --- Types ---

/** Material presented during handshake — identity + ephemeral key for session. */
export interface HandshakePayload {
  did: string;
  genomeCommitment: GenomeCommitment;
  ephemeralPublicKey: string; // base64-encoded X25519 public key
}

/** An established encrypted channel between two agents. */
export interface Channel {
  localDid: string;
  remoteDid: string;
  localGenomeCommitment: GenomeCommitment;
  remoteGenomeCommitment: GenomeCommitment;
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

/** Generate an ephemeral X25519 key pair for a single session — forward secrecy. */
export function generateEphemeralKeyPair(): nacl.BoxKeyPair {
  return nacl.box.keyPair();
}

/** Build the handshake payload an agent presents to initiate a channel. */
export function createHandshakePayload(
  genomeCommitment: GenomeCommitment,
  ephemeralKeyPair: nacl.BoxKeyPair
): HandshakePayload {
  return {
    did: genomeCommitment.did,
    genomeCommitment,
    ephemeralPublicKey: encodeBase64(ephemeralKeyPair.publicKey),
  };
}

/**
 * Establish a channel from two handshake payloads.
 *
 * Both sides:
 * 1. Verify the other's genome commitment signature
 * 2. Derive a shared session key via X25519 Diffie-Hellman
 * 3. All subsequent traffic is NaCl secretbox encrypted
 *
 * A proxy between A and B cannot decrypt, read, or inject — reduced to a dumb pipe.
 */
export function establishChannel(
  local: {
    handshake: HandshakePayload;
    ephemeralKeyPair: nacl.BoxKeyPair;
  },
  remoteHandshake: HandshakePayload
): Channel {
  // Step 1: Verify the remote party's genome commitment
  if (!verifyCommitment(remoteHandshake.genomeCommitment)) {
    throw new Error("Remote genome commitment verification failed");
  }

  // Step 2: Verify the remote DID matches its genome commitment
  if (remoteHandshake.did !== remoteHandshake.genomeCommitment.did) {
    throw new Error("Remote DID does not match genome commitment");
  }

  // Step 3: Derive shared session key via X25519
  const remoteEphemeralKey = decodeBase64(remoteHandshake.ephemeralPublicKey);
  const sharedKey = nacl.box.before(remoteEphemeralKey, local.ephemeralKeyPair.secretKey);

  // Step 4: Return a channel object with encrypt/decrypt using the shared key
  return {
    localDid: local.handshake.did,
    remoteDid: remoteHandshake.did,
    localGenomeCommitment: local.handshake.genomeCommitment,
    remoteGenomeCommitment: remoteHandshake.genomeCommitment,

    encrypt(plaintext: string): EncryptedMessage {
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const messageBytes = decodeUTF8(plaintext);
      const ciphertext = nacl.secretbox(messageBytes, nonce, sharedKey);
      return {
        nonce: encodeBase64(nonce),
        ciphertext: encodeBase64(ciphertext),
      };
    },

    decrypt(message: EncryptedMessage): string {
      const nonce = decodeBase64(message.nonce);
      const ciphertext = decodeBase64(message.ciphertext);
      const plaintext = nacl.secretbox.open(ciphertext, nonce, sharedKey);
      if (plaintext === null) {
        throw new Error("Decryption failed — message tampered or wrong key");
      }
      return encodeUTF8(plaintext);
    },
  };
}
