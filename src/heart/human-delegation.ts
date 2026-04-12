/**
 * HumanDelegation — session-scoped consent from a human to an agent.
 *
 * Context: in practice most "agents" are humans prompting an LLM that runs
 * in a harness under the human's paid credentials. The durable, liability-
 * bearing identity is the *human*; the agent is ephemeral — born when the
 * harness starts a session, dead when the session ends. We need a primitive
 * that binds the agent's ephemeral DID to the human's durable DID under a
 * bounded capability envelope, with a cryptographic trail strong enough for
 * Nova to replay and attribute liability.
 *
 * Design:
 *   - Reuses the existing `Caveat` vocabulary from `delegation.ts` — a
 *     HumanDelegation is *not* a new caveat language, it's a bundling of
 *     the existing ones with a bound issuer (human) and subject (agent
 *     ephemeral session key).
 *   - Attestation verification is PLUGGABLE. Soma stays agnostic: it does
 *     not ship a WebAuthn parser, an Apple Secure Enclave verifier, or a
 *     hardware SSH key validator. Callers (e.g. ClawNet) pre-verify the
 *     attestation payload and pass in an `AttestationVerifier` that returns
 *     a verdict. This keeps Soma free of browser/platform dependencies and
 *     preserves the protocol-purity rule: Soma has zero ClawNet knowledge.
 *   - Canonical signing input uses `domainSigningInput` under the
 *     `soma/human-delegation/v1` domain, so a signature over a
 *     HumanDelegation payload cannot be replayed as any other Soma
 *     signature.
 *   - The issuing signing key is the human's *current* credential — if the
 *     human's credential rotates mid-session, the HumanDelegation remains
 *     valid against the lineage chain as long as the named `humanCredentialId`
 *     is still resolvable.
 *
 * Heartbeat:
 *   A well-formed consent ceremony emits two heartbeat events:
 *     - `consent_required` — when the heart asks the human authenticator
 *     - `consent_granted`  — when the human returns a signed HumanDelegation
 *   Both are defined in `heartbeat.ts` so sense-observer sees them without
 *   any new plumbing. This module only constructs and verifies the
 *   payload; it does not record heartbeat events itself — callers compose
 *   that through `HeartRuntime` (PR-B).
 *
 * See `internal/active/session-mode-and-ceremony.md` in the claw-net repo
 * for the full architectural blueprint (§7.1 covers this module).
 */

import { domainSigningInput } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import {
  verifyDidBinding,
  type DidMethodRegistry,
} from '../core/did-method.js';
import type { Caveat } from './delegation.js';

const HUMAN_DELEGATION_DOMAIN = 'soma/human-delegation/v1';

/** Ceremony tier achieved at the moment the human approved. */
export type CeremonyTier = 'L0' | 'L1' | 'L2' | 'L3';

/**
 * Opaque attestation payload produced by the human's authenticator.
 *
 * Soma does not parse this. A caller that trusts WebAuthn passes the raw
 * `clientDataJSON || authenticatorData || signature` through; a caller
 * that trusts Apple DeviceCheck passes its own blob. The only thing Soma
 * requires is that an `AttestationVerifier` can return a yes/no verdict
 * that also reports which ceremony tier was achieved.
 */
export interface HumanAttestation {
  /**
   * Scheme identifier. `'webauthn'`, `'ssh-hardware'`, `'platform-bio'`,
   * `'mock'` (tests), or any caller-defined string. The verifier switches
   * on this.
   */
  kind: string;
  /** Opaque bytes — verifier-specific encoding. */
  payload: Uint8Array;
  /**
   * The challenge hash that was shown to the authenticator. MUST equal
   * `computeChallengeHash(envelope, sessionId, agentEphemeralPubkey)`
   * computed independently by the verifier. Prevents replay across
   * sessions.
   */
  challengeHash: Uint8Array;
}

/**
 * Pluggable attestation verifier. Implementations live outside Soma.
 * Pure function — no I/O — so the verification path stays
 * deterministic and unit-testable. Return `{ ok: true, tier }` to
 * accept, anything else to reject.
 */
export type AttestationVerifier = (
  attestation: HumanAttestation,
  context: {
    sessionId: string;
    envelopeHash: Uint8Array;
    agentEphemeralPubkey: Uint8Array;
  },
) => { ok: true; tier: CeremonyTier } | { ok: false; reason: string };

/** The signed consent payload. */
export interface HumanDelegation {
  version: typeof HUMAN_DELEGATION_DOMAIN;
  sessionId: string;
  humanDid: string;
  humanCredentialId: string;
  humanPublicKey: string;              // base64 of the issuing credential's pubkey
  agentEphemeralDid: string;
  agentEphemeralPublicKey: string;     // base64
  envelope: Caveat[];
  issuedAt: number;
  expiresAt: number;
  ceremonyTier: CeremonyTier;
  attestation: HumanAttestation;
  signature: string;                   // base64 Ed25519 (or provider-default)
}

// ─── Canonicalization helpers ───────────────────────────────────────────────

/**
 * Compute the challenge hash a human authenticator must sign over.
 *
 * Binds the authenticator signature to the exact (envelope, session,
 * agent pubkey) tuple so the signed attestation cannot be lifted into a
 * different session or a broader envelope.
 */
export function computeChallengeHash(
  envelope: Caveat[],
  sessionId: string,
  agentEphemeralPubkey: Uint8Array,
  provider?: CryptoProvider,
): Uint8Array {
  const p = provider ?? getCryptoProvider();
  const envelopeBytes = new TextEncoder().encode(JSON.stringify(envelope));
  const sessionBytes = new TextEncoder().encode(sessionId);
  const combined = new Uint8Array(
    envelopeBytes.length + 1 + sessionBytes.length + 1 + agentEphemeralPubkey.length,
  );
  let offset = 0;
  combined.set(envelopeBytes, offset);
  offset += envelopeBytes.length;
  combined[offset++] = 0;
  combined.set(sessionBytes, offset);
  offset += sessionBytes.length;
  combined[offset++] = 0;
  combined.set(agentEphemeralPubkey, offset);
  const digest = p.hashing.hash(
    p.encoding.encodeBase64(combined),
  );
  return p.encoding.decodeBase64(digest);
}

function hashEnvelope(
  envelope: Caveat[],
  provider: CryptoProvider,
): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(envelope));
  const digest = provider.hashing.hash(provider.encoding.encodeBase64(bytes));
  return provider.encoding.decodeBase64(digest);
}

// ─── Creation ───────────────────────────────────────────────────────────────

/**
 * Build a signed HumanDelegation. This is the payload the heart hands back
 * to the harness after a successful consent ceremony; the harness then
 * presents it on every subsequent in-session call.
 *
 * The caller is responsible for:
 *   - Having already verified the human authenticator's attestation (via
 *     an `AttestationVerifier`) — this function trusts its inputs.
 *   - Providing the human's *current* signing key. Rotation policy lives
 *     in the CredentialRotationController, not here.
 */
export function createHumanDelegation(opts: {
  sessionId: string;
  humanDid: string;
  humanCredentialId: string;
  humanPublicKey: string;          // base64
  humanSigningKey: Uint8Array;     // raw bytes
  agentEphemeralDid: string;
  agentEphemeralPublicKey: string; // base64
  envelope: Caveat[];
  issuedAt: number;
  expiresAt: number;
  ceremonyTier: CeremonyTier;
  attestation: HumanAttestation;
  provider?: CryptoProvider;
}): HumanDelegation {
  if (opts.expiresAt <= opts.issuedAt) {
    throw new Error('HumanDelegation: expiresAt must be after issuedAt');
  }
  const p = opts.provider ?? getCryptoProvider();

  const payload = {
    version: HUMAN_DELEGATION_DOMAIN as typeof HUMAN_DELEGATION_DOMAIN,
    sessionId: opts.sessionId,
    humanDid: opts.humanDid,
    humanCredentialId: opts.humanCredentialId,
    humanPublicKey: opts.humanPublicKey,
    agentEphemeralDid: opts.agentEphemeralDid,
    agentEphemeralPublicKey: opts.agentEphemeralPublicKey,
    envelope: opts.envelope,
    issuedAt: opts.issuedAt,
    expiresAt: opts.expiresAt,
    ceremonyTier: opts.ceremonyTier,
    attestation: {
      kind: opts.attestation.kind,
      payload: p.encoding.encodeBase64(opts.attestation.payload),
      challengeHash: p.encoding.encodeBase64(opts.attestation.challengeHash),
    },
  };

  const signingInput = domainSigningInput(HUMAN_DELEGATION_DOMAIN, payload);
  const signature = p.signing.sign(signingInput, opts.humanSigningKey);

  return {
    version: HUMAN_DELEGATION_DOMAIN,
    sessionId: opts.sessionId,
    humanDid: opts.humanDid,
    humanCredentialId: opts.humanCredentialId,
    humanPublicKey: opts.humanPublicKey,
    agentEphemeralDid: opts.agentEphemeralDid,
    agentEphemeralPublicKey: opts.agentEphemeralPublicKey,
    envelope: opts.envelope,
    issuedAt: opts.issuedAt,
    expiresAt: opts.expiresAt,
    ceremonyTier: opts.ceremonyTier,
    attestation: opts.attestation,
    signature: p.encoding.encodeBase64(signature),
  };
}

// ─── Verification ───────────────────────────────────────────────────────────

export type HumanDelegationVerification =
  | { valid: true; tier: CeremonyTier }
  | { valid: false; reason: string };

/**
 * Verify a HumanDelegation end-to-end:
 *   1. Ed25519 signature over the canonical payload under the human's
 *      stated public key.
 *   2. The human's DID actually binds to that public key (via the
 *      DID method registry — supports did:key, did:web, did:pkh).
 *   3. The attestation payload, under an injected verifier, passes and
 *      reports a tier at least as high as the claimed `ceremonyTier`.
 *   4. The attestation's challenge hash matches the independently-
 *      computed hash for this (envelope, session, agent key) tuple.
 *   5. `now` is within `[issuedAt, expiresAt]`.
 *
 * Returns the accepted ceremony tier on success, which callers can use
 * to gate actions that require higher tiers. Pure — no I/O beyond what
 * the DID method registry does during binding.
 */
export function verifyHumanDelegation(
  d: HumanDelegation,
  attestationVerifier: AttestationVerifier,
  now: number,
  opts?: {
    provider?: CryptoProvider;
    registry?: DidMethodRegistry;
  },
): HumanDelegationVerification {
  const p = opts?.provider ?? getCryptoProvider();

  if (d.version !== HUMAN_DELEGATION_DOMAIN) {
    return { valid: false, reason: `unknown version ${d.version}` };
  }
  if (now < d.issuedAt) {
    return { valid: false, reason: 'issued in the future' };
  }
  if (now >= d.expiresAt) {
    return { valid: false, reason: 'expired' };
  }

  // 1. Reconstruct signing payload and verify the signature.
  const { signature, ...rest } = d;
  const payload = {
    ...rest,
    attestation: {
      kind: d.attestation.kind,
      payload: p.encoding.encodeBase64(d.attestation.payload),
      challengeHash: p.encoding.encodeBase64(d.attestation.challengeHash),
    },
  };
  const signingInput = domainSigningInput(HUMAN_DELEGATION_DOMAIN, payload);
  const sigBytes = p.encoding.decodeBase64(signature);
  const humanPubKey = p.encoding.decodeBase64(d.humanPublicKey);
  if (!p.signing.verify(signingInput, sigBytes, humanPubKey)) {
    return { valid: false, reason: 'invalid signature over HumanDelegation' };
  }

  // 2. DID binding — the stated humanDid must resolve to that pubkey.
  const binding = verifyDidBinding(d.humanDid, humanPubKey, opts?.registry, p);
  if (!binding.bound) {
    return {
      valid: false,
      reason: `humanDid does not bind to humanPublicKey: ${binding.reason}`,
    };
  }

  // 3. Challenge hash independently recomputed — prevents replay of
  //    an attestation from a different session or envelope.
  const agentPub = p.encoding.decodeBase64(d.agentEphemeralPublicKey);
  const expectedChallenge = computeChallengeHash(
    d.envelope,
    d.sessionId,
    agentPub,
    p,
  );
  if (!constantTimeEqual(expectedChallenge, d.attestation.challengeHash)) {
    return {
      valid: false,
      reason: 'attestation challenge hash mismatch',
    };
  }

  // 4. Attestation verifier (plug-in) — reports actual tier achieved.
  const envelopeHash = hashEnvelope(d.envelope, p);
  const attResult = attestationVerifier(d.attestation, {
    sessionId: d.sessionId,
    envelopeHash,
    agentEphemeralPubkey: agentPub,
  });
  if (!attResult.ok) {
    return { valid: false, reason: `attestation rejected: ${attResult.reason}` };
  }

  // Callers may claim a tier the authenticator didn't actually reach —
  // reject that case rather than silently downgrading, so policy gates
  // that require L2+ can trust the claimed tier.
  if (tierRank(attResult.tier) < tierRank(d.ceremonyTier)) {
    return {
      valid: false,
      reason: `claimed tier ${d.ceremonyTier} exceeds attested ${attResult.tier}`,
    };
  }

  return { valid: true, tier: attResult.tier };
}

function tierRank(tier: CeremonyTier): number {
  switch (tier) {
    case 'L0':
      return 0;
    case 'L1':
      return 1;
    case 'L2':
      return 2;
    case 'L3':
      return 3;
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
