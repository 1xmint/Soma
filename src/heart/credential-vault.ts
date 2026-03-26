/**
 * The credential vault — holds API keys and tool credentials encrypted at rest.
 *
 * Like a cell's nucleus protecting DNA — credentials are only accessible
 * through the heart's execution methods. No public getter exists outside
 * the heart module. The credentials never leave the heart.
 */

import { createHash } from "node:crypto";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from "tweetnacl-util";

interface EncryptedCredential {
  nonce: string; // base64
  ciphertext: string; // base64
}

export class CredentialVault {
  private readonly encryptionKey: Uint8Array;
  private readonly credentials: Map<string, EncryptedCredential> = new Map();

  constructor(signingSecretKey: Uint8Array) {
    // Derive a 32-byte encryption key from the signing secret key via SHA-256.
    // The signing key is 64 bytes (Ed25519); we need 32 for NaCl secretbox.
    const hash = createHash("sha256").update(signingSecretKey).digest();
    this.encryptionKey = new Uint8Array(hash);
  }

  /** Store a credential encrypted at rest. */
  store(name: string, value: string): void {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const plaintext = decodeUTF8(value);
    const ciphertext = nacl.secretbox(plaintext, nonce, this.encryptionKey);
    this.credentials.set(name, {
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(ciphertext),
    });
  }

  /**
   * Retrieve a credential — only callable from within the heart module.
   * @internal
   */
  retrieve(name: string): string {
    const encrypted = this.credentials.get(name);
    if (!encrypted) {
      throw new Error(`Credential not found: ${name}`);
    }
    const nonce = decodeBase64(encrypted.nonce);
    const ciphertext = decodeBase64(encrypted.ciphertext);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, this.encryptionKey);
    if (plaintext === null) {
      throw new Error(`Failed to decrypt credential: ${name}`);
    }
    return encodeUTF8(plaintext);
  }

  /** Check if a credential exists. */
  has(name: string): boolean {
    return this.credentials.has(name);
  }

  /** List credential names (not values). */
  names(): string[] {
    return Array.from(this.credentials.keys());
  }

  /** Securely wipe all credentials from memory. */
  destroy(): void {
    this.encryptionKey.fill(0);
    this.credentials.clear();
  }
}
