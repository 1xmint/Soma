/**
 * DID method flexibility — pluggable identifier schemes.
 *
 * The rest of soma-heart deals in `did:key` identifiers by default:
 * the DID IS the public key (prefix-encoded), so there's no resolution
 * step. That's fine for agents minting their own keys, but it doesn't
 * cover three things operators keep asking about:
 *
 *   1. `did:web:example.com` — a domain controls the key, the agent
 *      proves "I belong to example.com" by controlling what's served
 *      at example.com/.well-known/did.json. Useful for branded agents.
 *   2. `did:pkh:eip155:1:0xABC…` — a blockchain account controls the
 *      key. Useful when the agent is already a wallet on some chain.
 *   3. Custom / in-house DID methods that resolve to keys via whatever
 *      mechanism the operator has (corporate directory, KMS, etc.).
 *
 * This module defines a narrow `DidMethod` interface and a registry,
 * so soma doesn't have to know how any specific method resolves —
 * it just asks "give me the verification keys for this DID."
 *
 * Built-in methods:
 *   - DidKeyMethod: resolution is sync and key-is-the-identifier.
 *     Matches existing behavior exactly.
 *   - DidWebMethod: resolution fetches the did:web document over HTTPS.
 *     HTTP is pluggable, so tests can inject a stub fetcher.
 *   - DidPkhMethod: format-only. Parses chain + account from the DID
 *     but cannot resolve a key from the DID alone — caller supplies
 *     an out-of-band key binding (e.g. from a prior on-chain signature).
 *
 * This does NOT change any existing call sites. Code that wants
 * multi-method support constructs a `DidMethodRegistry` and calls
 * `registry.resolve(did)`; code that only cares about `did:key`
 * continues to use `publicKeyToDid`/`didToPublicKey` unchanged.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from './crypto-provider.js';
import { publicKeyToDid, didToPublicKey } from './genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** One verification key attached to a DID document. */
export interface DidVerificationKey {
  /** Raw public key bytes. */
  publicKey: Uint8Array;
  /** Signing algorithm id (matches SigningProvider.algorithmId). */
  algorithmId: string;
  /** Optional purpose hint (authentication, assertion, keyAgreement). */
  purpose?: 'authentication' | 'assertion' | 'keyAgreement';
  /** Optional stable id within the document (e.g. "#key-1"). */
  keyId?: string;
}

/** Minimal DID document — just enough to verify signatures. */
export interface DidDocument {
  did: string;
  verificationKeys: DidVerificationKey[];
  /** Method-specific metadata (e.g. chain/account for did:pkh). */
  metadata?: Readonly<Record<string, unknown>>;
}

/** Pluggable DID method implementation. */
export interface DidMethod {
  /** Method name segment (e.g. "key", "web", "pkh"). */
  readonly methodName: string;
  /** Does this DID belong to this method? */
  matches(did: string): boolean;
  /**
   * Resolve a DID to its verification material. Always async for interface
   * uniformity — sync methods just return `Promise.resolve(doc)`.
   */
  resolve(did: string): Promise<DidDocument>;
}

/** A DID method that can mint new identifiers from a public key. */
export interface MintableDidMethod extends DidMethod {
  /**
   * Construct a DID for the given public key (+ method-specific opts).
   * Throws if the method cannot identify this kind of key.
   */
  identify(
    publicKey: Uint8Array,
    opts?: Record<string, unknown>,
  ): string;
}

// ─── DidMethodRegistry ──────────────────────────────────────────────────────

/**
 * Registry of DID methods. Consumers register the methods they trust,
 * then `resolve(did)` dispatches by prefix matching.
 */
export class DidMethodRegistry {
  private readonly methods = new Map<string, DidMethod>();

  register(method: DidMethod): void {
    if (this.methods.has(method.methodName)) {
      throw new Error(`DID method already registered: ${method.methodName}`);
    }
    this.methods.set(method.methodName, method);
  }

  get(methodName: string): DidMethod {
    const m = this.methods.get(methodName);
    if (!m) throw new Error(`no DID method registered: ${methodName}`);
    return m;
  }

  has(methodName: string): boolean {
    return this.methods.has(methodName);
  }

  /** Find the method that claims to match this DID. */
  forDid(did: string): DidMethod {
    for (const method of this.methods.values()) {
      if (method.matches(did)) return method;
    }
    throw new Error(`no registered DID method matches: ${did}`);
  }

  /** Resolve a DID through whichever registered method claims it. */
  async resolve(did: string): Promise<DidDocument> {
    return this.forDid(did).resolve(did);
  }

  list(): string[] {
    return Array.from(this.methods.keys()).sort();
  }

  size(): number {
    return this.methods.size;
  }
}

// ─── Method: did:key ────────────────────────────────────────────────────────

/**
 * Self-referential DID method: the identifier IS the public key.
 * Zero network I/O, zero external state. Resolution is a pure decode.
 */
export class DidKeyMethod implements MintableDidMethod {
  readonly methodName = 'key';
  private readonly provider: CryptoProvider;

  constructor(provider?: CryptoProvider) {
    this.provider = provider ?? getCryptoProvider();
  }

  matches(did: string): boolean {
    return did.startsWith('did:key:');
  }

  identify(publicKey: Uint8Array): string {
    return publicKeyToDid(publicKey, this.provider);
  }

  async resolve(did: string): Promise<DidDocument> {
    const publicKey = didToPublicKey(did, this.provider);
    return {
      did,
      verificationKeys: [
        {
          publicKey,
          algorithmId: this.provider.signing.algorithmId,
          purpose: 'authentication',
          keyId: '#key-1',
        },
      ],
    };
  }
}

// ─── Method: did:web ────────────────────────────────────────────────────────

/** Shape of the DID document we expect at /.well-known/did.json. */
export interface DidWebDocumentJson {
  id?: string;
  verificationMethod?: {
    id?: string;
    type?: string;
    controller?: string;
    publicKeyMultibase?: string;
    publicKeyBase64?: string;
    publicKeyBase58?: string;
  }[];
  authentication?: unknown[];
  assertionMethod?: unknown[];
  keyAgreement?: unknown[];
}

/** Pluggable HTTP fetcher — inject a stub in tests, real fetch in prod. */
export type DidWebFetcher = (url: string) => Promise<DidWebDocumentJson>;

/**
 * `did:web:example.com` → https://example.com/.well-known/did.json
 * `did:web:example.com:users:alice` →
 *   https://example.com/users/alice/did.json
 *
 * Fetcher is pluggable so this module doesn't pull in a fetch dep and
 * tests can stub it. Public keys are expected in `publicKeyBase64`
 * (soma convention) — multibase/base58 fields are rejected.
 */
export class DidWebMethod implements DidMethod {
  readonly methodName = 'web';
  private readonly fetcher: DidWebFetcher;
  private readonly provider: CryptoProvider;

  constructor(fetcher: DidWebFetcher, provider?: CryptoProvider) {
    this.fetcher = fetcher;
    this.provider = provider ?? getCryptoProvider();
  }

  matches(did: string): boolean {
    return did.startsWith('did:web:');
  }

  /** Convert `did:web:example.com:users:alice` → full URL. */
  static didToUrl(did: string): string {
    if (!did.startsWith('did:web:')) {
      throw new Error(`not a did:web: ${did}`);
    }
    const rest = did.slice('did:web:'.length);
    // Per spec: colons become path slashes; if no path, append /.well-known
    const segments = rest.split(':').map((s) => decodeURIComponent(s));
    if (segments.length === 0 || segments[0] === '') {
      throw new Error(`did:web missing domain: ${did}`);
    }
    const domain = segments[0];
    if (segments.length === 1) {
      return `https://${domain}/.well-known/did.json`;
    }
    const path = segments.slice(1).join('/');
    return `https://${domain}/${path}/did.json`;
  }

  async resolve(did: string): Promise<DidDocument> {
    if (!this.matches(did)) {
      throw new Error(`not a did:web: ${did}`);
    }
    const url = DidWebMethod.didToUrl(did);
    const doc = await this.fetcher(url);
    if (doc.id !== undefined && doc.id !== did) {
      throw new Error(
        `did:web document id mismatch: expected ${did}, got ${doc.id}`,
      );
    }
    const keys: DidVerificationKey[] = [];
    for (const vm of doc.verificationMethod ?? []) {
      const pkB64 = vm.publicKeyBase64;
      if (!pkB64) continue; // skip keys we can't decode
      let publicKey: Uint8Array;
      try {
        publicKey = this.provider.encoding.decodeBase64(pkB64);
      } catch {
        continue;
      }
      keys.push({
        publicKey,
        algorithmId: vm.type ?? 'ed25519',
        purpose: 'authentication',
        keyId: vm.id,
      });
    }
    return { did, verificationKeys: keys };
  }
}

// ─── Method: did:pkh ────────────────────────────────────────────────────────

/** Parsed chain + account from a did:pkh. CAIP-10 format. */
export interface PkhIdentifier {
  /** Namespace (e.g. "eip155" for EVM chains, "solana"). */
  chainNamespace: string;
  /** Network reference (e.g. "1" for Ethereum mainnet). */
  chainReference: string;
  /** Account address as the chain expects it. */
  account: string;
}

/**
 * `did:pkh:<caip-10>` — blockchain account identifiers.
 * Parse/format only. A did:pkh doesn't reveal the public key by itself
 * (EVM addresses are hash(pk), Solana addresses ARE pks but without
 * algorithm metadata). Callers pass an optional `keyBinder` to attach
 * verification keys out-of-band.
 */
export class DidPkhMethod implements DidMethod {
  readonly methodName = 'pkh';
  private readonly keyBinder?: (pkh: PkhIdentifier) => DidVerificationKey[];

  constructor(
    keyBinder?: (pkh: PkhIdentifier) => DidVerificationKey[],
  ) {
    this.keyBinder = keyBinder;
  }

  matches(did: string): boolean {
    return did.startsWith('did:pkh:');
  }

  static parse(did: string): PkhIdentifier {
    if (!did.startsWith('did:pkh:')) {
      throw new Error(`not a did:pkh: ${did}`);
    }
    const rest = did.slice('did:pkh:'.length);
    const parts = rest.split(':');
    if (parts.length !== 3) {
      throw new Error(
        `did:pkh expects 3 segments (<namespace>:<reference>:<account>), got: ${did}`,
      );
    }
    const [chainNamespace, chainReference, account] = parts;
    if (!chainNamespace || !chainReference || !account) {
      throw new Error(`did:pkh has empty segments: ${did}`);
    }
    return { chainNamespace, chainReference, account };
  }

  static format(id: PkhIdentifier): string {
    return `did:pkh:${id.chainNamespace}:${id.chainReference}:${id.account}`;
  }

  async resolve(did: string): Promise<DidDocument> {
    const id = DidPkhMethod.parse(did);
    const keys = this.keyBinder ? this.keyBinder(id) : [];
    return {
      did,
      verificationKeys: keys,
      metadata: {
        chainNamespace: id.chainNamespace,
        chainReference: id.chainReference,
        account: id.account,
      },
    };
  }
}

// ─── Default registry ───────────────────────────────────────────────────────

/**
 * Convenience: registry pre-populated with DidKeyMethod. Callers add
 * did:web and did:pkh as needed (they require a fetcher/keyBinder).
 */
export function createDefaultDidRegistry(
  provider?: CryptoProvider,
): DidMethodRegistry {
  const registry = new DidMethodRegistry();
  registry.register(new DidKeyMethod(provider));
  return registry;
}

// ─── Helper: verify signature via DID resolution ────────────────────────────

/**
 * Resolve `did`, then check whether `signature` over `message` verifies
 * against any of the returned verification keys. Returns the matching
 * key on success, or null on failure.
 */
export async function verifySignatureViaDid(
  did: string,
  message: Uint8Array,
  signature: Uint8Array,
  registry: DidMethodRegistry,
  provider?: CryptoProvider,
): Promise<DidVerificationKey | null> {
  const p = provider ?? getCryptoProvider();
  const doc = await registry.resolve(did);
  for (const vk of doc.verificationKeys) {
    try {
      if (p.signing.verify(message, signature, vk.publicKey)) {
        return vk;
      }
    } catch {
      // continue — try next key
    }
  }
  return null;
}
