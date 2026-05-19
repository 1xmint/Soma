/**
 * Mutual session proof-of-possession.
 *
 * Single-sided `proof-of-possession.ts` proves *one* party holds their key
 * (a delegation holder answering a verifier's challenge). That's fine for
 * an asymmetric relationship — one side presents credentials, the other
 * checks them. But when two hearts establish a session with each other
 * (subtask dispatch, peer negotiation, A2A calls), both sides need to
 * authenticate. Otherwise the verifier-side of a one-sided PoP exchange
 * could itself be a man-in-the-middle: it learns who you are, you never
 * confirm who it is.
 *
 * Protocol — three-message handshake:
 *   1. A sends `SessionInit`: {sessionId, nonceA, initiatorDid, initiatorPublicKey, purpose}.
 *   2. B replies `SessionAccept`: init echoed, adds nonceB + responderDid +
 *      responderPublicKey, signs canonical(init || accept_payload).
 *   3. A verifies B's signature, signs the *same transcript*, replies `SessionConfirm`.
 *   4. B verifies A's signature.
 *
 * After both signatures verify against the DIDs, each side has a proof
 * that the counterparty holds the key for the DID they advertised. The
 * `transcriptHash` is a stable SHA-256 both parties can bind into later
 * operations (receipts, heartbeats) so every follow-up message is
 * traceable to this specific session.
 *
 * Replay protection: nonces are 32 random bytes each, fresh per session.
 * The transcript includes `initiatedAt` (and optionally `ttlMs`) so
 * verifiers can reject stale handshakes. Sessions are one-shot: once
 * confirmed, the transcriptHash is the session identifier — don't reuse.
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';
import {
  verifyDidBinding,
  type DidMethodRegistry,
} from '../core/did-method.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** Initiator's opening message — includes their nonce + identity claim. */
export interface SessionInit {
  sessionId: string;
  initiatorDid: string;
  initiatorPublicKey: string;
  nonceA: string;
  purpose: string;
  initiatedAt: number;
  ttlMs: number | null;
}

/** Responder's reply — includes their nonce, identity, and signature over transcript. */
export interface SessionAccept {
  sessionId: string;
  responderDid: string;
  responderPublicKey: string;
  nonceB: string;
  acceptedAt: number;
  /** Base64 signature by responder over canonical(transcriptPayload). */
  responderSignature: string;
}

/** Initiator's closing message — signs the *same* transcript as the responder. */
export interface SessionConfirm {
  sessionId: string;
  confirmedAt: number;
  /** Base64 signature by initiator over canonical(transcriptPayload). */
  initiatorSignature: string;
}

/** A successfully verified mutual session — both sides proven. */
export interface SessionBindings {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  nonceA: string;
  nonceB: string;
  purpose: string;
  initiatedAt: number;
  acceptedAt: number;
  confirmedAt: number;
  /** SHA-256 hex of canonical transcript, stable across both parties. */
  transcriptHash: string;
}

export type SessionVerification =
  | { valid: true; bindings: SessionBindings }
  | { valid: false; reason: string };

// ─── Transcript (the bytes both parties sign) ───────────────────────────────

/**
 * The canonical payload that both parties must sign. Contains EVERY field
 * from init + the two new fields from accept. Keeps order deterministic so
 * A's signature and B's signature attest to the same transcript.
 */
function buildTranscriptPayload(
  init: SessionInit,
  acceptNonce: string,
  responderDid: string,
  responderPublicKey: string,
  acceptedAt: number,
) {
  return {
    protocol: 'soma-mutual-session/1',
    sessionId: init.sessionId,
    initiatorDid: init.initiatorDid,
    initiatorPublicKey: init.initiatorPublicKey,
    responderDid,
    responderPublicKey,
    nonceA: init.nonceA,
    nonceB: acceptNonce,
    purpose: init.purpose,
    initiatedAt: init.initiatedAt,
    acceptedAt,
    ttlMs: init.ttlMs,
  };
}

function hashTranscript(
  payload: ReturnType<typeof buildTranscriptPayload>,
  p: CryptoProvider,
): string {
  return p.hashing.hash(canonicalJson(payload));
}

// ─── Step 1: Initiator proposes ─────────────────────────────────────────────

export function initiateSession(opts: {
  initiatorDid: string;
  initiatorPublicKey: string;
  purpose: string;
  ttlMs?: number | null;
  provider?: CryptoProvider;
}): SessionInit {
  const p = opts.provider ?? getCryptoProvider();
  return {
    sessionId: `sess-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    initiatorDid: opts.initiatorDid,
    initiatorPublicKey: opts.initiatorPublicKey,
    nonceA: p.encoding.encodeBase64(p.random.randomBytes(32)),
    purpose: opts.purpose,
    initiatedAt: Date.now(),
    ttlMs: opts.ttlMs ?? null,
  };
}

// ─── Step 2: Responder accepts (signs transcript) ───────────────────────────

export function acceptSession(opts: {
  init: SessionInit;
  responderDid: string;
  responderPublicKey: string;
  responderSigningKey: Uint8Array;
  provider?: CryptoProvider;
}): SessionAccept {
  const p = opts.provider ?? getCryptoProvider();

  // Sanity check: caller passed a matching DID/public key.
  const pubBytes = p.encoding.decodeBase64(opts.responderPublicKey);
  const derivedDid = publicKeyToDid(pubBytes, p);
  if (derivedDid !== opts.responderDid) {
    throw new Error('responderDid does not match responderPublicKey');
  }

  const nonceB = p.encoding.encodeBase64(p.random.randomBytes(32));
  const acceptedAt = Date.now();
  const payload = buildTranscriptPayload(
    opts.init,
    nonceB,
    opts.responderDid,
    opts.responderPublicKey,
    acceptedAt,
  );
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const signature = p.signing.sign(signingInput, opts.responderSigningKey);
  return {
    sessionId: opts.init.sessionId,
    responderDid: opts.responderDid,
    responderPublicKey: opts.responderPublicKey,
    nonceB,
    acceptedAt,
    responderSignature: p.encoding.encodeBase64(signature),
  };
}

// ─── Step 3: Initiator confirms (verifies B, then signs same transcript) ───

export function confirmSession(opts: {
  init: SessionInit;
  accept: SessionAccept;
  initiatorSigningKey: Uint8Array;
  provider?: CryptoProvider;
}): SessionConfirm {
  const p = opts.provider ?? getCryptoProvider();

  // Guard: session id must match.
  if (opts.init.sessionId !== opts.accept.sessionId) {
    throw new Error('session id mismatch between init and accept');
  }

  // Verify the responder's signature BEFORE committing to anything.
  const payload = buildTranscriptPayload(
    opts.init,
    opts.accept.nonceB,
    opts.accept.responderDid,
    opts.accept.responderPublicKey,
    opts.accept.acceptedAt,
  );
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const responderSigBytes = p.encoding.decodeBase64(
    opts.accept.responderSignature,
  );
  const responderPubBytes = p.encoding.decodeBase64(opts.accept.responderPublicKey);
  if (!p.signing.verify(signingInput, responderSigBytes, responderPubBytes)) {
    throw new Error('responder signature invalid');
  }
  // Verify the DID matches the public key B claimed.
  if (opts.accept.responderDid !== publicKeyToDid(responderPubBytes, p)) {
    throw new Error('responderDid does not match responderPublicKey');
  }

  const signature = p.signing.sign(signingInput, opts.initiatorSigningKey);
  return {
    sessionId: opts.init.sessionId,
    confirmedAt: Date.now(),
    initiatorSignature: p.encoding.encodeBase64(signature),
  };
}

// ─── Step 4: Either party verifies the completed mutual session ────────────

export function verifyMutualSession(opts: {
  init: SessionInit;
  accept: SessionAccept;
  confirm: SessionConfirm;
  /** Current time for freshness check (defaults to Date.now()). */
  now?: number;
  /** Maximum age allowed for the handshake (ms). Optional. */
  maxAgeMs?: number;
  provider?: CryptoProvider;
  /**
   * Optional DID method registry for non-did:key identities (did:web, did:pkh).
   * When absent, falls back to did:key binding semantics.
   */
  registry?: DidMethodRegistry;
}): SessionVerification {
  const p = opts.provider ?? getCryptoProvider();
  const now = opts.now ?? Date.now();

  // 1. Session ids agree.
  if (
    opts.init.sessionId !== opts.accept.sessionId ||
    opts.init.sessionId !== opts.confirm.sessionId
  ) {
    return { valid: false, reason: 'session id mismatch' };
  }

  // 2. Timestamp ordering: init ≤ accept ≤ confirm.
  if (opts.accept.acceptedAt < opts.init.initiatedAt) {
    return { valid: false, reason: 'accept precedes init' };
  }
  if (opts.confirm.confirmedAt < opts.accept.acceptedAt) {
    return { valid: false, reason: 'confirm precedes accept' };
  }

  // 3. TTL check from init.ttlMs (if set).
  if (opts.init.ttlMs !== null) {
    if (now - opts.init.initiatedAt > opts.init.ttlMs) {
      return { valid: false, reason: 'session TTL expired' };
    }
  }

  // 4. Caller-supplied freshness check.
  if (opts.maxAgeMs !== undefined) {
    if (now - opts.init.initiatedAt > opts.maxAgeMs) {
      return { valid: false, reason: 'handshake too old' };
    }
  }

  // 5. DIDs match public keys on both sides.
  let initiatorPubBytes: Uint8Array;
  let responderPubBytes: Uint8Array;
  try {
    initiatorPubBytes = p.encoding.decodeBase64(opts.init.initiatorPublicKey);
    responderPubBytes = p.encoding.decodeBase64(opts.accept.responderPublicKey);
  } catch {
    return { valid: false, reason: 'malformed public key' };
  }
  const initBinding = verifyDidBinding(
    opts.init.initiatorDid,
    initiatorPubBytes,
    opts.registry,
    p,
  );
  if (!initBinding.bound) {
    return {
      valid: false,
      reason: `initiatorDid does not match initiatorPublicKey: ${initBinding.reason}`,
    };
  }
  const respBinding = verifyDidBinding(
    opts.accept.responderDid,
    responderPubBytes,
    opts.registry,
    p,
  );
  if (!respBinding.bound) {
    return {
      valid: false,
      reason: `responderDid does not match responderPublicKey: ${respBinding.reason}`,
    };
  }

  // 7. Both signatures verify over the same transcript.
  const payload = buildTranscriptPayload(
    opts.init,
    opts.accept.nonceB,
    opts.accept.responderDid,
    opts.accept.responderPublicKey,
    opts.accept.acceptedAt,
  );
  const signingInput = new TextEncoder().encode(canonicalJson(payload));
  const respSig = p.encoding.decodeBase64(opts.accept.responderSignature);
  if (!p.signing.verify(signingInput, respSig, responderPubBytes)) {
    return { valid: false, reason: 'responder signature invalid' };
  }
  const initSig = p.encoding.decodeBase64(opts.confirm.initiatorSignature);
  if (!p.signing.verify(signingInput, initSig, initiatorPubBytes)) {
    return { valid: false, reason: 'initiator signature invalid' };
  }

  return {
    valid: true,
    bindings: {
      sessionId: opts.init.sessionId,
      initiatorDid: opts.init.initiatorDid,
      responderDid: opts.accept.responderDid,
      nonceA: opts.init.nonceA,
      nonceB: opts.accept.nonceB,
      purpose: opts.init.purpose,
      initiatedAt: opts.init.initiatedAt,
      acceptedAt: opts.accept.acceptedAt,
      confirmedAt: opts.confirm.confirmedAt,
      transcriptHash: hashTranscript(payload, p),
    },
  };
}

// ─── Helper: compute transcript hash without running full verify ───────────

/**
 * Compute the canonical transcript hash for an (init, accept) pair. Both
 * parties should get the same value. Useful as a session identifier for
 * binding downstream operations.
 */
export function computeTranscriptHash(
  init: SessionInit,
  accept: SessionAccept,
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  const payload = buildTranscriptPayload(
    init,
    accept.nonceB,
    accept.responderDid,
    accept.responderPublicKey,
    accept.acceptedAt,
  );
  return hashTranscript(payload, p);
}
