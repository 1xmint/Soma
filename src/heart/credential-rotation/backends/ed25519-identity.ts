/**
 * Ed25519IdentityBackend — the first production CredentialBackend.
 *
 * Wraps `KeyHistory` from `src/heart/key-rotation.ts` as the underlying
 * KERI-style pre-rotation log. The backend owns the private keys; the
 * `KeyHistory` owns the public chain. Together they satisfy:
 *
 *   - Invariant 2 (session credentials always derived, never imported):
 *     the backend mints every keypair with the active crypto provider; it
 *     refuses to accept externally-supplied secret material.
 *   - Invariant 9 + L1 (pre-rotation with full manifest commitment):
 *     the controller checks the manifest commitment; KeyHistory independently
 *     checks the key digest. Either layer rejecting fails the rotation.
 *   - Invariant 7 (backend isolation): the backend exposes no cross-backend
 *     state. Callers who want the public chain call `getKeyHistoryEvents`.
 *
 * Secret-key handling in Node is best-effort; `zeroize` overwrites the
 * Uint8Array when the backend revokes a credential. Node's GC and V8's
 * copy-during-compaction mean this is not a hard guarantee, but it removes
 * secrets from long-lived references and shortens the exfiltration window
 * on heap dumps.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../../../core/crypto-provider.js';
import { KeyHistory, type RotationEvent as KeriRotationEvent } from '../../key-rotation.js';
import { computeManifestCommitment } from '../controller.js';
import type {
  AlgorithmSuite,
  Credential,
  CredentialBackend,
  CredentialClass,
} from '../types.js';

// ─── Per-credential secret material (private to the backend) ────────────────

interface StoredSecret {
  credentialId: string;
  identityId: string;
  keyPair: SignKeyPair;
  expiresAt: number;
  revoked: boolean;
}

// ─── Per-identity rotation plumbing ────────────────────────────────────────

interface IdentityPlumbing {
  history: KeyHistory;
  /**
   * The keypair that the *current* rotation event pre-committed to as the
   * next key. Retained until the next rotation consumes it, at which point
   * it becomes the new current and a fresh `pendingNext` is generated.
   */
  pendingNext: SignKeyPair;
  /** Live credential id for the current top of the chain. */
  currentCredentialId: string;
  /** TTL inherited from inception, reused on rotation. */
  ttlMs: number;
}

// ─── Backend ────────────────────────────────────────────────────────────────

export class Ed25519IdentityBackend implements CredentialBackend {
  readonly backendId: string;
  readonly algorithmSuite: AlgorithmSuite = 'ed25519';
  readonly class: CredentialClass = 'A';
  private readonly provider: CryptoProvider;
  private readonly secrets = new Map<string, StoredSecret>();
  private readonly plumbing = new Map<string, IdentityPlumbing>();
  private counter = 0;

  constructor(opts: { backendId: string; provider?: CryptoProvider } = { backendId: 'ed25519-identity' }) {
    this.backendId = opts.backendId;
    this.provider = opts.provider ?? getCryptoProvider();
  }

  async issueCredential(args: {
    identityId: string;
    issuedAt: number;
    ttlMs: number;
  }): Promise<Credential> {
    if (this.plumbing.has(args.identityId)) {
      throw new Error(
        `ed25519-identity backend: identity ${args.identityId} already inceptioned`,
      );
    }
    const inceptionKeyPair = this.provider.signing.generateKeyPair();
    const nextKeyPair = this.provider.signing.generateKeyPair();

    const { history } = KeyHistory.incept({
      inceptionSecretKey: inceptionKeyPair.secretKey,
      inceptionPublicKey: inceptionKeyPair.publicKey,
      nextPublicKey: nextKeyPair.publicKey,
      provider: this.provider,
    });

    const credential = this.mintCredentialEntry({
      identityId: args.identityId,
      keyPair: inceptionKeyPair,
      issuedAt: args.issuedAt,
      ttlMs: args.ttlMs,
      nextPublicKey: nextKeyPair.publicKey,
    });

    this.plumbing.set(args.identityId, {
      history,
      pendingNext: nextKeyPair,
      currentCredentialId: credential.credentialId,
      ttlMs: args.ttlMs,
    });

    return credential;
  }

  async revealNextCredential(oldCredentialId: string): Promise<Credential> {
    const oldSecret = this.requireLive(oldCredentialId);
    const plumb = this.plumbing.get(oldSecret.identityId);
    if (!plumb) {
      throw new Error(
        `ed25519-identity backend: missing plumbing for ${oldSecret.identityId}`,
      );
    }
    // Promote the pre-committed next key to "current"; generate the new next.
    const promotedKeyPair = plumb.pendingNext;
    const newNextKeyPair = this.provider.signing.generateKeyPair();

    // Append the rotation event to the KeyHistory. This is the second layer
    // of pre-rotation enforcement — KeyHistory throws if the promoted public
    // key does not match the digest committed in the prior event.
    plumb.history.rotate({
      currentSecretKey: promotedKeyPair.secretKey,
      currentPublicKey: promotedKeyPair.publicKey,
      nextPublicKey: newNextKeyPair.publicKey,
    });

    const now = Date.now();
    const credential = this.mintCredentialEntry({
      identityId: oldSecret.identityId,
      keyPair: promotedKeyPair,
      issuedAt: now,
      ttlMs: plumb.ttlMs,
      nextPublicKey: newNextKeyPair.publicKey,
    });

    plumb.pendingNext = newNextKeyPair;
    plumb.currentCredentialId = credential.credentialId;
    return credential;
  }

  async signWithCredential(
    credentialId: string,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    const stored = this.requireLive(credentialId);
    return this.provider.signing.sign(message, stored.keyPair.secretKey);
  }

  async verifyWithCredential(
    credentialId: string,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    const stored = this.secrets.get(credentialId);
    if (!stored || stored.revoked) return false;
    return this.provider.signing.verify(
      message,
      signature,
      stored.keyPair.publicKey,
    );
  }

  async verifyWithManifest(
    manifest: { publicKey: Uint8Array },
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    return this.provider.signing.verify(message, signature, manifest.publicKey);
  }

  async revokeCredential(credentialId: string): Promise<void> {
    const stored = this.secrets.get(credentialId);
    if (!stored) return;
    stored.revoked = true;
    // Best-effort zeroize of secret-key bytes. See file header for caveats.
    stored.keyPair.secretKey.fill(0);
  }

  // ─── Public-chain introspection (for anchoring / gossip / verifiers) ─────

  /**
   * Return the KeyHistory events for an identity. Consumers publish these
   * to the pulse tree or gossip them to verifiers. This is the *only*
   * cross-boundary output of the backend — public chain state, no secrets.
   */
  getKeyHistoryEvents(identityId: string): readonly KeriRotationEvent[] {
    const plumb = this.plumbing.get(identityId);
    if (!plumb) throw new Error(`unknown identity: ${identityId}`);
    return plumb.history.getEvents();
  }

  /** Current top-of-chain credential id, or null if the identity is unknown. */
  getCurrentCredentialId(identityId: string): string | null {
    return this.plumbing.get(identityId)?.currentCredentialId ?? null;
  }

  // ─── Internals ───────────────────────────────────────────────────────────

  private mintCredentialEntry(args: {
    identityId: string;
    keyPair: SignKeyPair;
    issuedAt: number;
    ttlMs: number;
    nextPublicKey: Uint8Array;
  }): Credential {
    const nextManifestCommitment = computeManifestCommitment(
      {
        backendId: this.backendId,
        algorithmSuite: this.algorithmSuite,
        publicKey: args.nextPublicKey,
      },
      this.provider,
    );
    this.counter += 1;
    const credentialId = `${this.backendId}:${args.identityId}:${this.counter}`;
    const credential: Credential = {
      credentialId,
      identityId: args.identityId,
      backendId: this.backendId,
      algorithmSuite: this.algorithmSuite,
      class: this.class,
      publicKey: args.keyPair.publicKey,
      issuedAt: args.issuedAt,
      expiresAt: args.issuedAt + args.ttlMs,
      nextManifestCommitment,
    };
    this.secrets.set(credentialId, {
      credentialId,
      identityId: args.identityId,
      keyPair: args.keyPair,
      expiresAt: credential.expiresAt,
      revoked: false,
    });
    return credential;
  }

  private requireLive(credentialId: string): StoredSecret {
    const stored = this.secrets.get(credentialId);
    if (!stored) throw new Error(`unknown credential: ${credentialId}`);
    if (stored.revoked) throw new Error(`credential revoked: ${credentialId}`);
    return stored;
  }
}
