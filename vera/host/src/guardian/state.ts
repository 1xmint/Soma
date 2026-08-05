import { getCryptoProvider } from 'soma-heart/crypto-provider';
import type { GuardianConfig, GuardianExportBundle, SharePolicy } from './types.js';

/**
 * GuardianState: holds the guardian's config and policy in one place.
 *
 * exportBundle() produces a portable JSON snapshot for inspection or
 * backup. The secret key is NEVER included in the export.
 */
export class GuardianState {
  constructor(
    private readonly config: GuardianConfig,
    private readonly policy: SharePolicy,
  ) {}

  exportBundle(): GuardianExportBundle {
    const provider = getCryptoProvider();
    return {
      version: 1,
      soma_did: this.config.somaDid,
      public_key: provider.encoding.encodeBase64(this.config.publicKey),
      policy: { ...this.policy },
      exported_at: new Date().toISOString(),
    };
  }
}
