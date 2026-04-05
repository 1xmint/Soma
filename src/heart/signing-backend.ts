/**
 * Signing backends — pluggable where the secret key *lives*.
 *
 * Everywhere else in soma-heart, "signing key" means a `Uint8Array` — the
 * raw 64-byte Ed25519 secret key, in process memory. That's fine for dev
 * and for operators who accept software-only key storage. It's not fine
 * for anyone who needs hardware-backed keys: YubiHSM, AWS KMS, Ledger,
 * Apple Secure Enclave, TPM, etc. On those backends the secret key NEVER
 * leaves the device — callers pass a key handle and the device signs.
 *
 * This module defines the narrow interface that lets those backends slot
 * in without modifying the dozens of call sites that already consume
 * `Uint8Array` secret keys. Think of it as the "signing socket" into
 * which operators plug a hardware device.
 *
 * Design:
 *   - `SigningKeyHandle`: opaque reference {publicKey, backendId, keyId}.
 *     `publicKey` is always revealed (not secret); `keyId` is whatever the
 *     backend uses to locate the private material (slot number, URI,
 *     derivation path, etc.).
 *   - `SigningBackend.sign(handle, message) → Promise<Uint8Array>`.
 *     Async because most hardware backends are network or IPC round-trips.
 *   - `InProcessBackend`: holds raw Uint8Array secret keys in a Map keyed
 *     by keyId. Matches current default behavior. Useful in tests.
 *   - `DelegatedBackend`: wraps a caller-supplied `signDelegate` function
 *     — the escape hatch for arbitrary external signers.
 *
 * This does NOT change anything else in soma-heart. Call sites that want
 * backend-pluggable signing call `backend.sign(handle, msg)`; call sites
 * that want the classic `Uint8Array` path keep working unchanged. Both
 * paths produce standard Ed25519 signatures verified the same way.
 *
 * Non-goals:
 *   - Key *generation* on the HSM: backends expose `generateKey` optionally,
 *     but soma doesn't require it (many HSMs provision keys out-of-band).
 *   - Touch/pinpad UX: the delegate function owns UX. Backends that need a
 *     user tap just block in `sign()` until confirmed.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Opaque reference to a signing key that may live outside this process.
 * `publicKey` is always known; `keyId` is whatever the backend uses.
 */
export interface SigningKeyHandle {
  /** Raw public key bytes (always revealed). */
  publicKey: Uint8Array;
  /** Which backend owns this handle. */
  backendId: string;
  /** Backend-specific key identifier (slot, URI, derivation path, etc.). */
  keyId: string;
}

/** A backend that can sign messages using keys it owns. */
export interface SigningBackend {
  /** Unique id for this backend (matches `SigningKeyHandle.backendId`). */
  readonly backendId: string;
  /**
   * Sign `message` using the private key referenced by `handle`.
   * Async because HSMs, remote signers, and hardware wallets are round-trips.
   */
  sign(
    handle: SigningKeyHandle,
    message: Uint8Array,
  ): Promise<Uint8Array> | Uint8Array;
  /**
   * Verify a signature. Stateless — does not require access to private keys.
   * Backends may forward to the underlying crypto provider.
   */
  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean;
  /** List handles this backend knows about (may be partial / remote-paginated). */
  listHandles?(): Promise<SigningKeyHandle[]> | SigningKeyHandle[];
  /** Optional: generate a new key pair inside the backend. */
  generateKey?(
    opts?: { keyId?: string },
  ): Promise<SigningKeyHandle> | SigningKeyHandle;
  /** Optional: export the private key (HSMs typically refuse). */
  exportSecretKey?(
    handle: SigningKeyHandle,
  ): Promise<Uint8Array> | Uint8Array;
}

// ─── InProcessBackend — software keys in memory ─────────────────────────────

/**
 * Reference backend: holds raw secret keys in a JS Map. Matches the current
 * default soma-heart behavior. Useful as a drop-in for tests and dev, and
 * as a baseline for comparison with hardware backends.
 */
export class InProcessBackend implements SigningBackend {
  readonly backendId = 'in-process';
  private readonly keys = new Map<
    string,
    { publicKey: Uint8Array; secretKey: Uint8Array }
  >();
  private readonly provider: CryptoProvider;
  private counter = 0;

  constructor(provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
  }

  /** Import an existing key pair under a chosen keyId. */
  importKey(
    keyId: string,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ): SigningKeyHandle {
    this.keys.set(keyId, { publicKey, secretKey });
    return { publicKey, backendId: this.backendId, keyId };
  }

  generateKey(opts?: { keyId?: string }): SigningKeyHandle {
    const kp = this.provider.signing.generateKeyPair();
    const keyId = opts?.keyId ?? `key-${++this.counter}`;
    this.keys.set(keyId, {
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
    });
    return {
      publicKey: kp.publicKey,
      backendId: this.backendId,
      keyId,
    };
  }

  sign(handle: SigningKeyHandle, message: Uint8Array): Uint8Array {
    if (handle.backendId !== this.backendId) {
      throw new Error(
        `handle belongs to ${handle.backendId}, not ${this.backendId}`,
      );
    }
    const entry = this.keys.get(handle.keyId);
    if (!entry) {
      throw new Error(`unknown keyId: ${handle.keyId}`);
    }
    return this.provider.signing.sign(message, entry.secretKey);
  }

  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean {
    return this.provider.signing.verify(message, signature, publicKey);
  }

  listHandles(): SigningKeyHandle[] {
    return Array.from(this.keys.entries()).map(([keyId, { publicKey }]) => ({
      publicKey,
      backendId: this.backendId,
      keyId,
    }));
  }

  exportSecretKey(handle: SigningKeyHandle): Uint8Array {
    const entry = this.keys.get(handle.keyId);
    if (!entry) throw new Error(`unknown keyId: ${handle.keyId}`);
    // Return a copy so callers can't mutate internal state.
    return entry.secretKey.slice();
  }

  /** Remove a key from the backend (useful for key rotation cleanup). */
  deleteKey(keyId: string): boolean {
    return this.keys.delete(keyId);
  }
}

// ─── DelegatedBackend — escape hatch for arbitrary external signers ────────

/**
 * Callback-shaped backend. Wraps an arbitrary async signer (YubiHSM CLI,
 * Ledger BLE, AWS KMS, Fireblocks, etc.) so it fits the `SigningBackend`
 * interface. The delegate function is authoritative — this class never
 * touches secret material.
 */
export class DelegatedBackend implements SigningBackend {
  readonly backendId: string;
  private readonly signDelegate: (
    handle: SigningKeyHandle,
    message: Uint8Array,
  ) => Promise<Uint8Array>;
  private readonly provider: CryptoProvider;
  private readonly handles = new Map<string, SigningKeyHandle>();

  constructor(opts: {
    backendId: string;
    sign: (
      handle: SigningKeyHandle,
      message: Uint8Array,
    ) => Promise<Uint8Array>;
    handles?: readonly SigningKeyHandle[];
    provider?: CryptoProvider;
  }) {
    this.backendId = opts.backendId;
    this.signDelegate = opts.sign;
    this.provider = opts.provider ?? getCryptoProvider();
    for (const h of opts.handles ?? []) {
      if (h.backendId !== this.backendId) {
        throw new Error(
          `handle backend ${h.backendId} does not match ${this.backendId}`,
        );
      }
      this.handles.set(h.keyId, h);
    }
  }

  async sign(
    handle: SigningKeyHandle,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    if (handle.backendId !== this.backendId) {
      throw new Error(
        `handle belongs to ${handle.backendId}, not ${this.backendId}`,
      );
    }
    const sig = await this.signDelegate(handle, message);
    // Paranoid check: the delegate returned a signature that verifies
    // against the advertised public key. Protects against a broken /
    // misconfigured delegate returning garbage.
    if (!this.verify(message, sig, handle.publicKey)) {
      throw new Error(
        'delegated backend returned signature that does not verify',
      );
    }
    return sig;
  }

  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean {
    return this.provider.signing.verify(message, signature, publicKey);
  }

  listHandles(): SigningKeyHandle[] {
    return Array.from(this.handles.values());
  }

  /** Register a new handle (e.g. after discovering a key on the device). */
  registerHandle(handle: SigningKeyHandle): void {
    if (handle.backendId !== this.backendId) {
      throw new Error(
        `handle backend ${handle.backendId} does not match ${this.backendId}`,
      );
    }
    this.handles.set(handle.keyId, handle);
  }
}

// ─── BackendRegistry — select backend by handle.backendId ──────────────────

/**
 * Convenience registry so callers can sign with "whatever backend the
 * handle belongs to" without a switch statement at every call site.
 */
export class BackendRegistry {
  private readonly backends = new Map<string, SigningBackend>();

  register(backend: SigningBackend): void {
    if (this.backends.has(backend.backendId)) {
      throw new Error(`backend already registered: ${backend.backendId}`);
    }
    this.backends.set(backend.backendId, backend);
  }

  get(backendId: string): SigningBackend {
    const b = this.backends.get(backendId);
    if (!b) throw new Error(`no backend registered: ${backendId}`);
    return b;
  }

  has(backendId: string): boolean {
    return this.backends.has(backendId);
  }

  /** Sign via whichever backend owns this handle. */
  async sign(
    handle: SigningKeyHandle,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    const backend = this.get(handle.backendId);
    return backend.sign(handle, message);
  }

  /** Verify — any backend will do (verification is stateless). */
  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean {
    // Pick the first registered backend (verify is stateless, doesn't
    // matter which one). If none, use the default provider.
    const first = this.backends.values().next().value as
      | SigningBackend
      | undefined;
    if (first) return first.verify(message, signature, publicKey);
    return getCryptoProvider().signing.verify(message, signature, publicKey);
  }

  size(): number {
    return this.backends.size;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Derive the DID for a signing key handle. */
export function handleToDid(
  handle: SigningKeyHandle,
  provider?: CryptoProvider,
): string {
  return publicKeyToDid(handle.publicKey, provider);
}
