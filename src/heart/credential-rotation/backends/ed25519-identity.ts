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
 * Rotation is transactional via the stage/commit/abort protocol:
 *   - `stageNextCredential` allocates a staged credential entry and a new
 *     "next-next" keypair, but does NOT call `KeyHistory.rotate` yet.
 *   - `commitStagedRotation` advances the KeyHistory chain and promotes
 *     the staged credential to current. This is the only place where
 *     durable chain state mutates.
 *   - `abortStagedRotation` drops the staged credential entry and zeroes
 *     the freshly-generated next-next secret. The pre-committed `pendingNext`
 *     keypair is NOT zeroised — the old credential's manifest commitment
 *     is still bound to it, so a retried rotation must still be able to
 *     sign with it.
 *
 * Secret-key handling in Node is best-effort; `revokeCredential` overwrites
 * the Uint8Array. V8's GC and copy-during-compaction mean this is not a
 * hard guarantee, but it removes secrets from long-lived references and
 * shortens the exfiltration window on heap dumps.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from '../../../core/crypto-provider.js';
import { KeyHistory, type RotationEvent as KeriRotationEvent } from '../../key-rotation.js';
import { computeManifestCommitment } from '../controller.js';
import {
  StagedRotationConflict,
  type AlgorithmSuite,
  type Credential,
  type CredentialBackend,
  type CredentialClass,
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
   * next key. On stage, this becomes the new current on commit. Until
   * committed, it must NOT be zeroised — the old credential's manifest
   * commitment is bound to its public key, and the backend must be able
   * to sign with it on a retry.
   */
  pendingNext: SignKeyPair;
  /** Live credential id for the current top of the chain. */
  currentCredentialId: string;
  /** TTL inherited from inception, reused on rotation. */
  ttlMs: number;
  /**
   * If a rotation is staged but not yet committed, the metadata we need
   * to either promote it (commit) or roll it back (abort).
   */
  staged:
    | {
        credentialId: string;
        /** New "next-next" keypair — freshly generated, safe to zeroise on abort. */
        newNextKeyPair: SignKeyPair;
      }
    | null;
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

  constructor(
    opts: { backendId: string; provider?: CryptoProvider } = {
      backendId: 'ed25519-identity',
    },
  ) {
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
      staged: null,
    });

    return credential;
  }

  async stageNextCredential(args: {
    identityId: string;
    oldCredentialId: string;
    issuedAt: number;
  }): Promise<Credential> {
    const plumb = this.requirePlumbing(args.identityId);
    if (plumb.staged) {
      throw new StagedRotationConflict(args.identityId);
    }
    if (plumb.currentCredentialId !== args.oldCredentialId) {
      throw new Error(
        `ed25519-identity backend: oldCredentialId ${args.oldCredentialId} does not match current ${plumb.currentCredentialId}`,
      );
    }
    // The promoted keypair is the pre-committed next from the live chain.
    const promotedKeyPair = plumb.pendingNext;
    // Fresh next-next for the chain after we commit.
    const newNextKeyPair = this.provider.signing.generateKeyPair();

    const credential = this.mintCredentialEntry({
      identityId: args.identityId,
      keyPair: promotedKeyPair,
      issuedAt: args.issuedAt,
      ttlMs: plumb.ttlMs,
      nextPublicKey: newNextKeyPair.publicKey,
    });

    plumb.staged = {
      credentialId: credential.credentialId,
      newNextKeyPair,
    };
    return credential;
  }

  async commitStagedRotation(identityId: string): Promise<void> {
    const plumb = this.requirePlumbing(identityId);
    const staged = plumb.staged;
    if (!staged) {
      throw new Error(
        `ed25519-identity backend: no staged rotation for ${identityId}`,
      );
    }
    // This is the only place the KeyHistory chain advances. If it throws
    // (e.g. KeyHistory's independent pre-rotation digest check fails), the
    // catch in the controller will call abortStagedRotation and we stay
    // consistent.
    plumb.history.rotate({
      currentSecretKey: plumb.pendingNext.secretKey,
      currentPublicKey: plumb.pendingNext.publicKey,
      nextPublicKey: staged.newNextKeyPair.publicKey,
    });

    plumb.pendingNext = staged.newNextKeyPair;
    plumb.currentCredentialId = staged.credentialId;
    plumb.staged = null;
  }

  async abortStagedRotation(identityId: string): Promise<void> {
    const plumb = this.plumbing.get(identityId);
    if (!plumb || !plumb.staged) return;
    const staged = plumb.staged;
    // Drop the staged credential entry. Do NOT zeroise its secretKey —
    // that buffer is `plumb.pendingNext.secretKey`, which is still bound
    // to the prior credential's manifest commitment and must remain
    // signable for a retried rotation.
    this.secrets.delete(staged.credentialId);
    // The next-next keypair was freshly generated for this stage and no
    // live credential references it — safe to zeroise.
    staged.newNextKeyPair.secretKey.fill(0);
    plumb.staged = null;
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
    // Best-effort zeroise of secret-key bytes. See file header for caveats.
    // This is safe on a committed credential because, by the time a caller
    // reaches revoke, a successful rotation has already moved `pendingNext`
    // to the NEW keypair — the bytes we're zeroing are not shared with
    // any live credential.
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

  private requirePlumbing(identityId: string): IdentityPlumbing {
    const plumb = this.plumbing.get(identityId);
    if (!plumb) throw new Error(`unknown identity: ${identityId}`);
    return plumb;
  }
}
