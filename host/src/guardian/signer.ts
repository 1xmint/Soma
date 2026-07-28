import { getCryptoProvider } from 'soma-heart/crypto-provider';
import type { GuardianConfig, SignedRequestHeaders } from './types.js';
import { ShareBoundaryPolicy } from './policy.js';

export interface GuardianSigner {
  /**
   * Build the three signed request headers for the given method/path/body.
   *
   * Policy is checked BEFORE signing. If the policy denies the action,
   * this method throws — the request is never signed and never sent.
   */
  signRequest(method: string, path: string, body: unknown): SignedRequestHeaders;
}

/**
 * Create a guardian signer bound to a config and policy.
 *
 * All crypto uses getCryptoProvider() from soma-heart/crypto-provider.
 * Nonce generation uses the Web Crypto global (crypto.getRandomValues),
 * which is available in Node.js ≥ 19 and is not a signing operation.
 */
export function createGuardianSigner(
  config: GuardianConfig,
  policy: ShareBoundaryPolicy,
): GuardianSigner {
  return {
    signRequest(method: string, path: string, body: unknown): SignedRequestHeaders {
      // Policy check FIRST — throws if denied, never reaches signing
      policy.checkOrThrow(path);

      const provider = getCryptoProvider();

      // Generate a 16-byte (32 hex char) nonce via Web Crypto global
      const nonceBytes = new Uint8Array(16);
      crypto.getRandomValues(nonceBytes);
      const nonce = Array.from(nonceBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const timestamp = new Date().toISOString();

      // Canonical signing input — must match server reconstruction exactly
      const signingInput = JSON.stringify({ method, path, body, timestamp, nonce });

      const inputBytes = new TextEncoder().encode(signingInput);
      const signatureBytes = provider.signing.sign(inputBytes, config.secretKey);
      const signature = provider.encoding.encodeBase64(signatureBytes);

      return {
        'x-guardian-signature': signature,
        'x-guardian-timestamp': timestamp,
        'x-guardian-nonce': nonce,
      };
    },
  };
}
