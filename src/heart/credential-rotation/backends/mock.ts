/**
 * MockCredentialBackend — in-memory Ed25519 backend for tests and benches.
 *
 * Mints fresh Ed25519 keypairs via the active crypto provider, retains the
 * secret material in a per-backend Map, and pre-generates the *next* keypair
 * at each mint so pre-rotation (invariant 9) is always one step ahead.
 *
 * Not suitable for production — secrets live in plain process memory. The
 * real `ed25519-identity` backend (follow-up commit) will wrap `KeyHistory`
 * and store secrets in the heart's signing backend.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../../../core/crypto-provider.js';
import { computeManifestCommitment } from '../controller.js';
import type {
  AlgorithmSuite,
  Credential,
  CredentialBackend,
  CredentialClass,
} from '../types.js';

interface StoredCredential {
  credential: Credential;
  keyPair: SignKeyPair;
  /** Pre-generated next keypair, revealed on rotation. */
  next: {
    keyPair: SignKeyPair;
    ttlMs: number;
  };
  revoked: boolean;
}

export class MockCredentialBackend implements CredentialBackend {
  readonly backendId: string;
  readonly algorithmSuite: AlgorithmSuite = 'ed25519';
  readonly class: CredentialClass;
  private readonly provider: CryptoProvider;
  private readonly store = new Map<string, StoredCredential>();
  private counter = 0;

  constructor(opts: {
    backendId: string;
    class?: CredentialClass;
    provider?: CryptoProvider;
  }) {
    this.backendId = opts.backendId;
    this.class = opts.class ?? 'A';
    this.provider = opts.provider ?? getCryptoProvider();
  }

  async issueCredential(args: {
    identityId: string;
    issuedAt: number;
    ttlMs: number;
  }): Promise<Credential> {
    const keyPair = this.provider.signing.generateKeyPair();
    const nextKeyPair = this.provider.signing.generateKeyPair();
    const nextManifestCommitment = computeManifestCommitment(
      {
        backendId: this.backendId,
        algorithmSuite: this.algorithmSuite,
        publicKey: nextKeyPair.publicKey,
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
      publicKey: keyPair.publicKey,
      issuedAt: args.issuedAt,
      expiresAt: args.issuedAt + args.ttlMs,
      nextManifestCommitment,
    };

    this.store.set(credentialId, {
      credential,
      keyPair,
      next: { keyPair: nextKeyPair, ttlMs: args.ttlMs },
      revoked: false,
    });
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
    const stored = this.store.get(credentialId);
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

  async revealNextCredential(oldCredentialId: string): Promise<Credential> {
    const stored = this.requireLive(oldCredentialId);
    const { keyPair } = stored.next;
    // Pre-generate the credential-after-next so we stay one step ahead.
    const nextNextKeyPair = this.provider.signing.generateKeyPair();
    const nextManifestCommitment = computeManifestCommitment(
      {
        backendId: this.backendId,
        algorithmSuite: this.algorithmSuite,
        publicKey: nextNextKeyPair.publicKey,
      },
      this.provider,
    );

    this.counter += 1;
    const credentialId = `${this.backendId}:${stored.credential.identityId}:${this.counter}`;
    const now = Date.now();
    const credential: Credential = {
      credentialId,
      identityId: stored.credential.identityId,
      backendId: this.backendId,
      algorithmSuite: this.algorithmSuite,
      class: this.class,
      publicKey: keyPair.publicKey,
      issuedAt: now,
      expiresAt: now + stored.next.ttlMs,
      nextManifestCommitment,
    };

    this.store.set(credentialId, {
      credential,
      keyPair,
      next: { keyPair: nextNextKeyPair, ttlMs: stored.next.ttlMs },
      revoked: false,
    });
    return credential;
  }

  async revokeCredential(credentialId: string): Promise<void> {
    const stored = this.store.get(credentialId);
    if (stored) stored.revoked = true;
  }

  // ─── Test-only hooks ─────────────────────────────────────────────────────

  /** Force a mismatching "next" key so pre-rotation validation fires. */
  sabotagePreRotation(credentialId: string): void {
    const stored = this.requireLive(credentialId);
    stored.next.keyPair = this.provider.signing.generateKeyPair();
  }

  private requireLive(credentialId: string): StoredCredential {
    const stored = this.store.get(credentialId);
    if (!stored) throw new Error(`unknown credential: ${credentialId}`);
    if (stored.revoked) throw new Error(`credential revoked: ${credentialId}`);
    return stored;
  }
}
