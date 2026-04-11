/**
 * MockCredentialBackend — in-memory Ed25519 backend for tests and benches.
 *
 * Mints fresh Ed25519 keypairs via the active crypto provider, retains the
 * secret material in a per-backend Map, and pre-generates the *next* keypair
 * at each mint so pre-rotation (invariant 9) is always one step ahead.
 *
 * Rotation is transactional via the stage/commit/abort protocol: a staged
 * credential is materialised in the store so the controller can collect
 * its first proof-of-possession, but `abortStagedRotation` removes it and
 * zeroises its secret bytes, so a rejected rotation never leaves the
 * backend in a forward-advanced state.
 *
 * Not suitable for production — secrets live in plain process memory. The
 * production `Ed25519IdentityBackend` (`./ed25519-identity.ts`) wraps a
 * KeyHistory log and follows the same stage/commit/abort discipline.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../../../core/crypto-provider.js';
import { computeManifestCommitment } from '../controller.js';
import {
  StagedRotationConflict,
  type AlgorithmSuite,
  type Credential,
  type CredentialBackend,
  type CredentialClass,
} from '../types.js';

interface StoredCredential {
  credential: Credential;
  keyPair: SignKeyPair;
  revoked: boolean;
}

interface MockIdentity {
  identityId: string;
  /** Live (committed) credential id. */
  currentCredentialId: string;
  /** Pre-generated next keypair — committed digest matches this. */
  nextKeyPair: SignKeyPair;
  /** TTL inherited from inception, reused on rotation. */
  ttlMs: number;
  /**
   * If a rotation has been staged but not yet committed, the credentialId
   * of the staged credential and the next-next keypair we generated for
   * it. `commitStagedRotation` promotes these; `abortStagedRotation` rolls
   * them back.
   */
  staged:
    | {
        credentialId: string;
        nextNextKeyPair: SignKeyPair;
      }
    | null;
}

export class MockCredentialBackend implements CredentialBackend {
  readonly backendId: string;
  readonly algorithmSuite: AlgorithmSuite = 'ed25519';
  readonly class: CredentialClass;
  private readonly provider: CryptoProvider;
  private readonly store = new Map<string, StoredCredential>();
  private readonly identities = new Map<string, MockIdentity>();
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
    if (this.identities.has(args.identityId)) {
      throw new Error(
        `mock backend: identity ${args.identityId} already inceptioned`,
      );
    }
    const keyPair = this.provider.signing.generateKeyPair();
    const nextKeyPair = this.provider.signing.generateKeyPair();
    const credential = this.mintEntry({
      identityId: args.identityId,
      keyPair,
      nextPublicKey: nextKeyPair.publicKey,
      issuedAt: args.issuedAt,
      ttlMs: args.ttlMs,
    });

    this.identities.set(args.identityId, {
      identityId: args.identityId,
      currentCredentialId: credential.credentialId,
      nextKeyPair,
      ttlMs: args.ttlMs,
      staged: null,
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

  async stageNextCredential(args: {
    identityId: string;
    oldCredentialId: string;
    issuedAt: number;
  }): Promise<Credential> {
    const ident = this.requireIdentity(args.identityId);
    if (ident.staged) {
      throw new StagedRotationConflict(args.identityId);
    }
    if (ident.currentCredentialId !== args.oldCredentialId) {
      throw new Error(
        `mock backend: oldCredentialId ${args.oldCredentialId} does not match current ${ident.currentCredentialId}`,
      );
    }
    const promotedKeyPair = ident.nextKeyPair;
    const nextNextKeyPair = this.provider.signing.generateKeyPair();
    const credential = this.mintEntry({
      identityId: args.identityId,
      keyPair: promotedKeyPair,
      nextPublicKey: nextNextKeyPair.publicKey,
      issuedAt: args.issuedAt,
      ttlMs: ident.ttlMs,
    });
    ident.staged = {
      credentialId: credential.credentialId,
      nextNextKeyPair,
    };
    return credential;
  }

  async commitStagedRotation(identityId: string): Promise<void> {
    const ident = this.requireIdentity(identityId);
    if (!ident.staged) {
      throw new Error(`mock backend: no staged rotation for ${identityId}`);
    }
    ident.currentCredentialId = ident.staged.credentialId;
    ident.nextKeyPair = ident.staged.nextNextKeyPair;
    ident.staged = null;
  }

  async abortStagedRotation(identityId: string): Promise<void> {
    const ident = this.identities.get(identityId);
    if (!ident || !ident.staged) return;
    // Drop the staged credential entry. We do NOT zero its secretKey here —
    // that keypair is the same bytes as `ident.nextKeyPair` (the
    // pre-committed next key), and the old credential's manifest commitment
    // is still bound to that public key, so a retry must still be able to
    // sign with it.
    this.store.delete(ident.staged.credentialId);
    // The next-next keypair was freshly generated for this stage and is
    // not referenced by any live credential — safe to zeroise.
    ident.staged.nextNextKeyPair.secretKey.fill(0);
    ident.staged = null;
  }

  async revokeCredential(credentialId: string): Promise<void> {
    const stored = this.store.get(credentialId);
    if (!stored) return;
    stored.revoked = true;
    stored.keyPair.secretKey.fill(0);
  }

  async discardIdentity(identityId: string): Promise<void> {
    const ident = this.identities.get(identityId);
    if (!ident) return;
    if (ident.staged) {
      await this.abortStagedRotation(identityId);
    }
    for (const [credId, stored] of this.store) {
      if (stored.credential.identityId === identityId) {
        stored.keyPair.secretKey.fill(0);
        this.store.delete(credId);
      }
    }
    ident.nextKeyPair.secretKey.fill(0);
    this.identities.delete(identityId);
  }

  // ─── Test-only hooks ─────────────────────────────────────────────────────

  /**
   * @internal — test-only. Replaces the pre-committed next keypair so the
   * next `stageNextCredential` call returns a credential whose manifest
   * does NOT match the prior commitment, exercising the L1 check.
   */
  sabotagePreRotation(credentialId: string): void {
    const stored = this.requireLive(credentialId);
    const ident = this.requireIdentity(stored.credential.identityId);
    ident.nextKeyPair = this.provider.signing.generateKeyPair();
  }

  // ─── Internals ───────────────────────────────────────────────────────────

  private mintEntry(args: {
    identityId: string;
    keyPair: SignKeyPair;
    nextPublicKey: Uint8Array;
    issuedAt: number;
    ttlMs: number;
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
    this.store.set(credentialId, {
      credential,
      keyPair: args.keyPair,
      revoked: false,
    });
    return credential;
  }

  private requireLive(credentialId: string): StoredCredential {
    const stored = this.store.get(credentialId);
    if (!stored) throw new Error(`unknown credential: ${credentialId}`);
    if (stored.revoked) throw new Error(`credential revoked: ${credentialId}`);
    return stored;
  }

  private requireIdentity(identityId: string): MockIdentity {
    const ident = this.identities.get(identityId);
    if (!ident) throw new Error(`unknown identity: ${identityId}`);
    return ident;
  }
}
