import { getCryptoProvider } from 'soma-heart/crypto-provider';

/**
 * Verify a Soma Ed25519 signature over exact payload bytes.
 *
 * Takes bytes rather than a string deliberately. The signed payload is a domain
 * prefix concatenated with canonical JSON; handing this function a string and
 * letting it encode would put a second encoding step between what the caller
 * computed and what is verified, which is precisely where a byte-exact scheme
 * goes quietly wrong.
 *
 * @param payload      - The exact bytes that were signed
 * @param signatureB64 - Base64-encoded Ed25519 signature (64 bytes)
 * @param publicKeyB64 - Base64-encoded Ed25519 public key (32 bytes)
 * @returns true if the signature is valid, false otherwise
 */
export function verifySignature(
  payload: Uint8Array,
  signatureB64: string,
  publicKeyB64: string,
): boolean {
  try {
    const provider = getCryptoProvider();
    const payloadBytes = payload;
    const signatureBytes = provider.encoding.decodeBase64(signatureB64);
    const publicKeyBytes = provider.encoding.decodeBase64(publicKeyB64);
    return provider.signing.verify(payloadBytes, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
}
