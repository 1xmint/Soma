/**
 * The credential vault — holds API keys and tool credentials encrypted at rest.
 *
 * Like a cell's nucleus protecting DNA — credentials are only accessible
 * through the heart's execution methods. No public getter exists outside
 * the heart module. The credentials never leave the heart.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from "../core/crypto-provider.js";

interface EncryptedCredential {
  nonce: string; // base64
  ciphertext: string; // base64
}

export class CredentialVault {
  private readonly encryptionKey: Uint8Array;
  private readonly credentials: Map<string, EncryptedCredential> = new Map();
  private readonly provider: CryptoProvider;

  constructor(signingSecretKey: Uint8Array, provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
    // Derive a 32-byte encryption key from the signing secret key.
    this.encryptionKey = this.provider.hashing.deriveKey(signingSecretKey, 32);
  }

  /** Store a credential encrypted at rest. */
  store(name: string, value: string): void {
    const { encryption, encoding, random } = this.provider;
    const nonce = random.randomBytes(encryption.nonceLength);
    const plaintext = encoding.decodeUTF8(value);
    const ciphertext = encryption.encrypt(plaintext, nonce, this.encryptionKey);
    this.credentials.set(name, {
      nonce: encoding.encodeBase64(nonce),
      ciphertext: encoding.encodeBase64(ciphertext),
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
    const { encryption, encoding } = this.provider;
    const nonce = encoding.decodeBase64(encrypted.nonce);
    const ciphertext = encoding.decodeBase64(encrypted.ciphertext);
    const plaintext = encryption.decrypt(ciphertext, nonce, this.encryptionKey);
    if (plaintext === null) {
      throw new Error(`Failed to decrypt credential: ${name}`);
    }
    return encoding.encodeUTF8(plaintext);
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
