/**
 * Configuration for a local guardian instance.
 * secretKey is held in memory only — never serialised.
 */
export interface GuardianConfig {
  somaDid: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * The three HTTP headers that constitute a signed request envelope.
 */
export interface SignedRequestHeaders {
  'x-guardian-signature': string;
  'x-guardian-timestamp': string;
  'x-guardian-nonce': string;
}

/**
 * Day 0 share boundary policy.
 * The guardian checks these flags BEFORE signing any request.
 */
export interface SharePolicy {
  allowAggregate: boolean;
  allowQuery: boolean;
}

/**
 * Portable export of guardian identity + policy.
 * secretKey is intentionally excluded.
 */
export interface GuardianExportBundle {
  version: 1;
  soma_did: string;
  /** Base64-encoded Ed25519 public key */
  public_key: string;
  policy: SharePolicy;
  exported_at: string; // ISO 8601
}
