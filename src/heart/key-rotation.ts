/**
 * Key rotation — KERI-style pre-rotation with forward digest commitments.
 *
 * Keys are assumed static in the rest of the protocol: delegations, sessions,
 * and revocations are all signed by a stable keypair whose public key IS the
 * identifier (did:key). In reality keys must rotate — scheduled (hygiene) or
 * reactive (suspected compromise). This module closes audit limit #6 by
 * giving each identity an append-only, hash-chained `KeyHistory` that
 * records rotations as signed events, with each event pre-committing to
 * the digest of the NEXT public key.
 *
 * Why pre-rotation:
 *   If each rotation event only revealed the new key, an attacker who stole
 *   the current key could rotate to their OWN key, taking over the
 *   identity. Pre-rotation defeats this: the NEXT key's digest is committed
 *   in the CURRENT event, signed by the current key. An attacker who steals
 *   the current key cannot produce a new key matching the pre-committed
 *   digest without the pre-image (they would need to have stolen the next
 *   key too, which at time of commitment did not yet exist in signing use).
 *
 * Identity stability:
 *   `identity` is the did:key of the INCEPTION public key. It never changes.
 *   Verifiers always speak to a single identity; current signing key is
 *   resolved from the chain.
 *
 * Event shape:
 *   - `inception` (sequence=0): signed by inception key, commits to
 *     digest(next_public_key).
 *   - `rotation` (sequence>0): signed by the key whose digest was committed
 *     as `nextKeyDigest` in the previous event, commits to digest of a new
 *     next key.
 *
 * Verifiers that hold a `KeyHistory` for an identity can answer
 * `currentPublicKey(identity)` by reading the tip of the chain.
 * Distribution of histories (gossip, registry, on-chain anchoring) is out of
 * scope here — same transport question as revocations.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export type RotationEventType = 'inception' | 'rotation';

/** One link in the key history chain. */
export interface RotationEvent {
  /** Stable identity (did:key of inception public key). */
  identity: string;
  /** Position in the chain. Inception = 0. */
  sequence: number;
  /** Event type. */
  eventType: RotationEventType;
  /** Hash of the previous event, or genesis hash for inception. */
  previousEventHash: string;
  /** Base64 public key that signs THIS event. */
  currentPublicKey: string;
  /** Hash of the next public key (pre-commitment). */
  nextKeyDigest: string;
  /** When this event was issued. */
  timestamp: number;
  /** Anti-replay nonce. */
  nonce: string;
  /** Self-hash of all fields above + signature. */
  hash: string;
  /** Signature over canonical payload, by `currentPublicKey`'s secret key. */
  signature: string;
}

export type KeyHistoryVerification =
  | { valid: true }
  | { valid: false; reason: string };

// ─── Constants ──────────────────────────────────────────────────────────────

const GENESIS_INPUT_PREFIX = 'soma-key-history:genesis:';
const KEY_DIGEST_DOMAIN = 'soma-key-digest:';

// ─── KeyHistory ─────────────────────────────────────────────────────────────

/** Append-only, hash-chained, pre-rotated key history for one identity. */
export class KeyHistory {
  private readonly events: RotationEvent[] = [];
  private readonly provider: CryptoProvider;
  readonly identity: string;
  readonly genesisHash: string;

  private constructor(
    identity: string,
    provider: CryptoProvider,
  ) {
    this.provider = provider;
    this.identity = identity;
    this.genesisHash = provider.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${identity}`,
    );
  }

  /**
   * Create a new KeyHistory with an inception event. Commits to the next
   * key's digest — caller MUST retain `nextKeyPair` until the next rotation.
   */
  static incept(opts: {
    inceptionSecretKey: Uint8Array;
    inceptionPublicKey: Uint8Array;
    nextPublicKey: Uint8Array;
    provider?: CryptoProvider;
  }): { history: KeyHistory; event: RotationEvent } {
    const p = opts.provider ?? getCryptoProvider();
    const identity = publicKeyToDid(opts.inceptionPublicKey, p);
    const history = new KeyHistory(identity, p);

    const currentPublicKeyB64 = p.encoding.encodeBase64(opts.inceptionPublicKey);
    const nextKeyDigest = computeKeyDigest(
      p.encoding.encodeBase64(opts.nextPublicKey),
      p,
    );
    const nonce = p.encoding.encodeBase64(p.random.randomBytes(12));

    const payload = {
      identity,
      sequence: 0,
      eventType: 'inception' as const,
      previousEventHash: history.genesisHash,
      currentPublicKey: currentPublicKeyB64,
      nextKeyDigest,
      timestamp: Date.now(),
      nonce,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = p.signing.sign(signingInput, opts.inceptionSecretKey);
    const signatureB64 = p.encoding.encodeBase64(signature);
    const hash = computeEventHash(payload, signatureB64, p);

    const event: RotationEvent = {
      ...payload,
      hash,
      signature: signatureB64,
    };
    history.events.push(event);
    return { history, event };
  }

  /**
   * Rotate to the pre-committed next key, committing to a new next key.
   * `currentSecretKey` MUST correspond to the public key whose digest was
   * committed in the previous event (otherwise append fails).
   */
  rotate(opts: {
    currentSecretKey: Uint8Array;
    currentPublicKey: Uint8Array;
    nextPublicKey: Uint8Array;
  }): RotationEvent {
    if (this.events.length === 0) {
      throw new Error('cannot rotate: history has no inception event');
    }
    const prior = this.events[this.events.length - 1];
    const currentPublicKeyB64 = this.provider.encoding.encodeBase64(
      opts.currentPublicKey,
    );

    // Check that the provided current key matches the previous event's
    // pre-committed nextKeyDigest. This is the heart of pre-rotation.
    const providedDigest = computeKeyDigest(currentPublicKeyB64, this.provider);
    if (providedDigest !== prior.nextKeyDigest) {
      throw new Error(
        'cannot rotate: currentPublicKey does not match prior event nextKeyDigest',
      );
    }

    const nextKeyDigest = computeKeyDigest(
      this.provider.encoding.encodeBase64(opts.nextPublicKey),
      this.provider,
    );
    const nonce = this.provider.encoding.encodeBase64(
      this.provider.random.randomBytes(12),
    );

    const payload = {
      identity: this.identity,
      sequence: this.events.length,
      eventType: 'rotation' as const,
      previousEventHash: prior.hash,
      currentPublicKey: currentPublicKeyB64,
      nextKeyDigest,
      timestamp: Date.now(),
      nonce,
    };

    const signingInput = new TextEncoder().encode(canonicalJson(payload));
    const signature = this.provider.signing.sign(
      signingInput,
      opts.currentSecretKey,
    );
    const signatureB64 = this.provider.encoding.encodeBase64(signature);
    const hash = computeEventHash(payload, signatureB64, this.provider);

    const event: RotationEvent = {
      ...payload,
      hash,
      signature: signatureB64,
    };
    this.events.push(event);
    return event;
  }

  /** Tip event's public key, or inception key if never rotated. */
  get currentPublicKey(): string {
    if (this.events.length === 0) {
      throw new Error('empty key history');
    }
    return this.events[this.events.length - 1].currentPublicKey;
  }

  /** Number of events in the chain. */
  get length(): number {
    return this.events.length;
  }

  /** Read-only snapshot. */
  getEvents(): readonly RotationEvent[] {
    return this.events;
  }

  /** Verify this history's chain integrity. */
  verify(): KeyHistoryVerification {
    return KeyHistory.verifyChain(this.events, this.identity, this.provider);
  }

  /**
   * Replace contents with an imported chain. Leaves history untouched on
   * failure. Identity must match.
   */
  replaceWith(events: RotationEvent[]): KeyHistoryVerification {
    const check = KeyHistory.verifyChain(events, this.identity, this.provider);
    if (!check.valid) return check;
    this.events.length = 0;
    this.events.push(...events);
    return { valid: true };
  }

  // ─── Static verification ──────────────────────────────────────────────────

  /**
   * Verify a standalone key history chain. Checks:
   *   1. Non-empty: first event is inception (sequence=0).
   *   2. Identity consistent across all events.
   *   3. Monotonic sequence.
   *   4. Inception's previousEventHash == genesis hash for identity.
   *   5. Each subsequent event's previousEventHash == prior event's hash.
   *   6. Each event's currentPublicKey matches prior nextKeyDigest
   *      (inception excluded — its public key must match the identity).
   *   7. Each event's signature verifies with currentPublicKey.
   *   8. Each event's hash correctly computed.
   */
  static verifyChain(
    events: readonly RotationEvent[],
    expectedIdentity: string,
    provider?: CryptoProvider,
  ): KeyHistoryVerification {
    const p = provider ?? getCryptoProvider();
    if (events.length === 0) {
      return { valid: false, reason: 'empty chain' };
    }

    const genesisHash = p.hashing.hash(
      `${GENESIS_INPUT_PREFIX}${expectedIdentity}`,
    );

    for (let i = 0; i < events.length; i++) {
      const e = events[i];

      if (e.identity !== expectedIdentity) {
        return { valid: false, reason: `event ${i} identity mismatch` };
      }
      if (e.sequence !== i) {
        return { valid: false, reason: `event ${i} sequence=${e.sequence}` };
      }
      if (i === 0 && e.eventType !== 'inception') {
        return { valid: false, reason: 'first event must be inception' };
      }
      if (i > 0 && e.eventType !== 'rotation') {
        return { valid: false, reason: `event ${i} must be rotation` };
      }

      const expectedPrev = i === 0 ? genesisHash : events[i - 1].hash;
      if (e.previousEventHash !== expectedPrev) {
        return { valid: false, reason: `event ${i} previousEventHash broken` };
      }

      // Pre-rotation check: current key's digest must match prior event's
      // nextKeyDigest (except inception, where the key must derive the identity).
      if (i === 0) {
        const pubKey = p.encoding.decodeBase64(e.currentPublicKey);
        const derivedIdentity = publicKeyToDid(pubKey, p);
        if (derivedIdentity !== expectedIdentity) {
          return {
            valid: false,
            reason: 'inception currentPublicKey does not derive identity',
          };
        }
      } else {
        const digest = computeKeyDigest(e.currentPublicKey, p);
        if (digest !== events[i - 1].nextKeyDigest) {
          return {
            valid: false,
            reason: `event ${i} currentPublicKey does not match prior nextKeyDigest`,
          };
        }
      }

      // Signature check
      const { hash, signature, ...payload } = e;
      const signingInput = new TextEncoder().encode(canonicalJson(payload));
      const sigBytes = p.encoding.decodeBase64(signature);
      const pubKey = p.encoding.decodeBase64(e.currentPublicKey);
      if (!p.signing.verify(signingInput, sigBytes, pubKey)) {
        return { valid: false, reason: `event ${i} bad signature` };
      }

      const expectedHash = computeEventHash(payload, signature, p);
      if (hash !== expectedHash) {
        return { valid: false, reason: `event ${i} hash mismatch` };
      }
    }

    return { valid: true };
  }

  /**
   * Resolve the current active public key (base64) for an identity from a
   * verified history. Caller SHOULD call `verifyChain` first; this method
   * only reads the tip.
   */
  static currentPublicKey(events: readonly RotationEvent[]): string {
    if (events.length === 0) throw new Error('empty history');
    return events[events.length - 1].currentPublicKey;
  }
}

// ─── Internals ──────────────────────────────────────────────────────────────

export function computeKeyDigest(
  publicKeyB64: string,
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  return p.hashing.hash(`${KEY_DIGEST_DOMAIN}${publicKeyB64}`);
}

function computeEventHash(
  payload: Omit<RotationEvent, 'hash' | 'signature'>,
  signatureB64: string,
  provider: CryptoProvider,
): string {
  return provider.hashing.hash(
    `${canonicalJson(payload)}|${signatureB64}`,
  );
}
