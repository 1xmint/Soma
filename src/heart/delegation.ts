/**
 * Delegation — macaroons-style capability tokens with caveats.
 *
 * A delegation is a signed token from issuer to subject granting a set of
 * capabilities under a set of caveats (time bounds, budget, audience, etc.).
 * Delegations are CHAINABLE: a holder can attenuate by adding more caveats,
 * but NEVER broaden scope. Chain verification checks that every link's
 * caveats monotonically narrow the previous.
 *
 * Delegations are bearer-adjacent: they name a subject DID, and the subject
 * must be able to sign a proof-of-possession to use them. Unlike classic
 * macaroons, we bind to a DID rather than pure HMAC chains, which is
 * cleaner in a world where every actor already has a keypair.
 *
 * Typical flow:
 *   A has capability X
 *   A delegates X to B with caveat "budget: 1000 credits"
 *   B delegates X to C with additional caveat "expires: tomorrow"
 *   C tries to use X → chain verified: signed by A → B → C, all caveats hold
 */

import { domainSigningInput } from '../core/canonicalize.js';

const DELEGATION_DOMAIN = 'soma/delegation/v1';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';
import {
  verifyDidBinding,
  type DidMethodRegistry,
} from '../core/did-method.js';
import {
  checkKeyEffective,
  type HistoricalKeyLookup,
} from './historical-key-lookup.js';

// ─── Caveat Types ───────────────────────────────────────────────────────────

/** A caveat is a condition that must hold for the delegation to be valid. */
export type Caveat =
  | { kind: 'expires-at'; timestamp: number }
  | { kind: 'not-before'; timestamp: number }
  | { kind: 'audience'; did: string }
  | { kind: 'budget'; credits: number }
  | { kind: 'max-invocations'; count: number }
  | { kind: 'capabilities'; allow: string[] }
  | { kind: 'custom'; key: string; value: string }
  // ─── soma-capabilities/1.1 additions ───
  /**
   * Invocation requires a fresh StepUpAttestation that matches the
   * invoker, achieves at least `minTier`, and is no older than
   * `maxAgeMs` (if set) at check time. Verifiers that do not understand
   * this caveat kind fail closed (the `default:` arm rejects).
   */
  | {
      kind: 'requires-stepup';
      minTier: number;
      /** Optional freshness bound in milliseconds. Omit for no bound. */
      maxAgeMs?: number;
    }
  /**
   * Invocation is only valid for one of the listed hosts. Hosts are
   * exact string matches; use multiple entries for multiple hosts. No
   * glob or regex — keep the matching surface small.
   */
  | { kind: 'host-allowlist'; hosts: string[] }
  /**
   * Invocation is only valid when the command argv matches one of the
   * listed patterns. Patterns are either exact argv arrays or a prefix
   * spec `{ prefix: string[] }` that matches if the invoked argv starts
   * with the listed prefix elements. Shell interpolation is NEVER
   * applied — matching is over literal argv.
   */
  | {
      kind: 'command-allowlist';
      patterns: Array<{ exact: string[] } | { prefix: string[] }>;
    }
  /**
   * Invocation must occur within one of the listed time windows. Each
   * window is `{ startHour, endHour }` in UTC (0-23). A window that
   * wraps midnight is expressed as `startHour > endHour`.
   */
  | {
      kind: 'time-window';
      windows: Array<{ startHourUtc: number; endHourUtc: number }>;
    };

// ─── Delegation Type ────────────────────────────────────────────────────────

export interface Delegation {
  /** Opaque ID — used for revocation. */
  id: string;
  /** DID of the issuer (who is granting). */
  issuerDid: string;
  /** DID of the subject (who receives). */
  subjectDid: string;
  /** Capabilities being granted (before caveats restrict them). */
  capabilities: string[];
  /** Caveats that must all hold for use. */
  caveats: Caveat[];
  /** When this delegation was issued. */
  issuedAt: number;
  /** Random nonce to prevent replay. */
  nonce: string;
  /** If this attenuates a previous delegation, its ID. */
  parentId: string | null;
  /** Base64-encoded Ed25519 signature by the issuer. */
  signature: string;
  /** Base64-encoded public key of the issuer (for verification). */
  issuerPublicKey: string;
}

/** Context at verification time — who's invoking, what they want, spend so far. */
export interface InvocationContext {
  /** DID invoking the delegation (the holder/subject using the token). */
  invokerDid: string;
  /**
   * DID of the service/resource being invoked (the VERIFIER's own identity).
   * Required if the delegation has an `audience` caveat. If absent when the
   * caveat is present, validation FAILS CLOSED — this closes audit limit #8
   * where audience caveats could be silently ignored.
   */
  audienceDid?: string;
  /** Capability being exercised. */
  capability: string;
  /** Credits being spent on this invocation. */
  creditsSpent?: number;
  /** Cumulative credits spent across all invocations of this delegation. */
  cumulativeCreditsSpent?: number;
  /** Number of prior invocations (for max-invocations caveat). */
  invocationCount?: number;
  /** Current time (defaults to Date.now()). */
  now?: number;

  // ─── soma-capabilities/1.1 additions ───

  /**
   * Host being targeted by the invocation. Required if the delegation
   * has a `host-allowlist` caveat — absence fails closed.
   */
  host?: string;
  /**
   * Command argv being invoked, as a literal array. Required if the
   * delegation has a `command-allowlist` caveat — absence fails closed.
   */
  commandArgv?: string[];
  /**
   * A pre-verified step-up attestation. Presence is required if the
   * delegation has a `requires-stepup` caveat. The verifier MUST have
   * already verified the attestation's signature and action-digest
   * binding BEFORE placing it here — this caveat check only compares
   * tier and age. See `verifyStepUpAttestation` in `stepup.ts`.
   */
  stepUpAttestation?: {
    subjectDid: string;
    tierAchieved: number;
    /** Unix ms when the heart accepted and counter-signed the attestation. */
    acceptedAt: number;
  };
}

// ─── Creation ───────────────────────────────────────────────────────────────

export function createDelegation(opts: {
  issuerDid: string;
  issuerPublicKey: string;
  issuerSigningKey: Uint8Array;
  subjectDid: string;
  capabilities: string[];
  caveats?: Caveat[];
  parentId?: string | null;
  provider?: CryptoProvider;
}): Delegation {
  const p = opts.provider ?? getCryptoProvider();
  const nonce = p.encoding.encodeBase64(p.random.randomBytes(16));

  const payload = {
    id: `dg-${p.encoding.encodeBase64(p.random.randomBytes(12))}`,
    issuerDid: opts.issuerDid,
    subjectDid: opts.subjectDid,
    capabilities: opts.capabilities,
    caveats: opts.caveats ?? [],
    issuedAt: Date.now(),
    nonce,
    parentId: opts.parentId ?? null,
    issuerPublicKey: opts.issuerPublicKey,
  };

  const signingInput = domainSigningInput(DELEGATION_DOMAIN, payload);
  const signature = p.signing.sign(signingInput, opts.issuerSigningKey);

  return {
    ...payload,
    signature: p.encoding.encodeBase64(signature),
  };
}

/**
 * Attenuate an existing delegation — subject narrows capability/caveats for
 * someone else. The new delegation's scope can ONLY be a subset of the parent.
 */
export function attenuateDelegation(opts: {
  parent: Delegation;
  newSubjectDid: string;
  newSubjectSigningKey: Uint8Array;
  newSubjectPublicKey: string;
  additionalCaveats?: Caveat[];
  narrowedCapabilities?: string[];
  provider?: CryptoProvider;
}): Delegation {
  const caps = opts.narrowedCapabilities ?? opts.parent.capabilities;
  // Ensure attenuation: every new cap must have been in parent
  for (const cap of caps) {
    if (!opts.parent.capabilities.includes(cap)) {
      throw new Error(`Cannot attenuate: ${cap} not in parent delegation`);
    }
  }

  // Derive the attenuator's DID from their public key (they become the issuer)
  const p = opts.provider ?? getCryptoProvider();
  const pubKeyBytes = p.encoding.decodeBase64(opts.newSubjectPublicKey);
  const attenuatorDid = publicKeyToDid(pubKeyBytes, p);

  return createDelegation({
    issuerDid: attenuatorDid,
    issuerPublicKey: opts.newSubjectPublicKey,
    issuerSigningKey: opts.newSubjectSigningKey,
    subjectDid: opts.newSubjectDid,
    capabilities: caps,
    caveats: [...opts.parent.caveats, ...(opts.additionalCaveats ?? [])],
    parentId: opts.parent.id,
    provider: opts.provider,
  });
}

// ─── Verification ───────────────────────────────────────────────────────────

export type DelegationVerification =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a delegation's signature + integrity (NOT caveats against context).
 *
 * When `lookup` is provided, the verifier additionally confirms that the
 * issuer's public key was effective at the delegation's `issuedAt` timestamp
 * via the rotation subsystem. If the key is not found or was not effective,
 * the delegation is rejected (fail-closed). When `lookup` is omitted,
 * existing behavior is preserved (backward-compatible).
 */
export function verifyDelegationSignature(
  del: Delegation,
  provider?: CryptoProvider,
  registry?: DidMethodRegistry,
  lookup?: HistoricalKeyLookup,
): DelegationVerification {
  const p = provider ?? getCryptoProvider();
  const { signature, ...payload } = del;
  const signingInput = domainSigningInput(DELEGATION_DOMAIN, payload);
  const sigBytes = p.encoding.decodeBase64(signature);
  const issuerPubKey = p.encoding.decodeBase64(del.issuerPublicKey);

  if (!p.signing.verify(signingInput, sigBytes, issuerPubKey)) {
    return { valid: false, reason: 'invalid signature' };
  }

  const binding = verifyDidBinding(del.issuerDid, issuerPubKey, registry, p);
  if (!binding.bound) {
    return {
      valid: false,
      reason: `issuerDid does not match issuerPublicKey: ${binding.reason}`,
    };
  }

  // Rotation-aware key validity check (opt-in).
  if (lookup) {
    let result;
    try {
      result = lookup.resolve(issuerPubKey, del.issuedAt);
    } catch {
      return { valid: false, reason: 'key lookup failed: resolver threw' };
    }
    const check = checkKeyEffective(result, del.issuedAt);
    if (!check.effective) {
      return { valid: false, reason: check.reason };
    }
  }

  return { valid: true };
}

/**
 * Check caveats against an invocation context.
 */
export function checkCaveats(
  del: Delegation,
  ctx: InvocationContext,
): DelegationVerification {
  const now = ctx.now ?? Date.now();

  // Capability check: is the invoked capability in the delegation?
  if (!del.capabilities.includes(ctx.capability)) {
    // Check wildcards
    const hasWildcard = del.capabilities.some((cap) => {
      if (cap === '*') return true;
      if (cap.endsWith(':*') && ctx.capability.startsWith(cap.slice(0, -1))) return true;
      return false;
    });
    if (!hasWildcard) {
      return { valid: false, reason: `capability ${ctx.capability} not granted` };
    }
  }

  // Iterate caveats
  for (const cav of del.caveats) {
    switch (cav.kind) {
      case 'expires-at':
        if (now > cav.timestamp) return { valid: false, reason: 'expired' };
        break;
      case 'not-before':
        if (now < cav.timestamp) return { valid: false, reason: 'not yet valid' };
        break;
      case 'audience':
        // Fail closed: if the caveat names an audience but the verifier
        // didn't declare its own identity, we cannot safely accept.
        if (ctx.audienceDid === undefined) {
          return {
            valid: false,
            reason: `audience caveat present but ctx.audienceDid not provided (fail-closed)`,
          };
        }
        if (ctx.audienceDid !== cav.did) {
          return { valid: false, reason: `audience mismatch: expected ${cav.did}` };
        }
        break;
      case 'budget': {
        const spent = ctx.cumulativeCreditsSpent ?? 0;
        const thisCall = ctx.creditsSpent ?? 0;
        if (spent + thisCall > cav.credits) {
          return { valid: false, reason: `budget exhausted (${spent + thisCall}/${cav.credits})` };
        }
        break;
      }
      case 'max-invocations':
        if ((ctx.invocationCount ?? 0) >= cav.count) {
          return { valid: false, reason: `max invocations reached (${cav.count})` };
        }
        break;
      case 'capabilities':
        if (!cav.allow.includes(ctx.capability)) {
          const hasWc = cav.allow.some((c) => {
            if (c === '*') return true;
            if (c.endsWith(':*') && ctx.capability.startsWith(c.slice(0, -1))) return true;
            return false;
          });
          if (!hasWc) return { valid: false, reason: `caveat narrows capability: ${ctx.capability} not allowed` };
        }
        break;
      case 'custom':
        // Custom caveats are opaque — caller must handle
        break;

      // ─── soma-capabilities/1.1 ───

      case 'requires-stepup': {
        const att = ctx.stepUpAttestation;
        if (att === undefined) {
          return {
            valid: false,
            reason: 'requires-stepup caveat present but no stepUpAttestation in ctx (fail-closed)',
          };
        }
        if (att.subjectDid !== ctx.invokerDid) {
          return { valid: false, reason: 'stepUp attestation subject does not match invoker' };
        }
        if (att.tierAchieved < cav.minTier) {
          return {
            valid: false,
            reason: `stepUp tier ${att.tierAchieved} below required ${cav.minTier}`,
          };
        }
        if (cav.maxAgeMs !== undefined && now - att.acceptedAt > cav.maxAgeMs) {
          return { valid: false, reason: 'stepUp attestation too old' };
        }
        break;
      }

      case 'host-allowlist': {
        if (ctx.host === undefined) {
          return {
            valid: false,
            reason: 'host-allowlist caveat present but ctx.host not provided (fail-closed)',
          };
        }
        if (!cav.hosts.includes(ctx.host)) {
          return { valid: false, reason: `host ${ctx.host} not in allowlist` };
        }
        break;
      }

      case 'command-allowlist': {
        const argv = ctx.commandArgv;
        if (argv === undefined) {
          return {
            valid: false,
            reason: 'command-allowlist caveat present but ctx.commandArgv not provided (fail-closed)',
          };
        }
        const matches = cav.patterns.some((pattern) => {
          if ('exact' in pattern) {
            if (pattern.exact.length !== argv.length) return false;
            return pattern.exact.every((v, i) => v === argv[i]);
          }
          if (pattern.prefix.length > argv.length) return false;
          return pattern.prefix.every((v, i) => v === argv[i]);
        });
        if (!matches) {
          return { valid: false, reason: `command ${JSON.stringify(argv)} does not match any allowed pattern` };
        }
        break;
      }

      case 'time-window': {
        const hourUtc = new Date(now).getUTCHours();
        const inWindow = cav.windows.some((w) => {
          if (w.startHourUtc <= w.endHourUtc) {
            return hourUtc >= w.startHourUtc && hourUtc < w.endHourUtc;
          }
          // Wraps midnight (e.g. 22..06).
          return hourUtc >= w.startHourUtc || hourUtc < w.endHourUtc;
        });
        if (!inWindow) {
          return { valid: false, reason: `current hour ${hourUtc}Z not in any allowed time window` };
        }
        break;
      }

      default: {
        // Exhaustiveness + fail-closed on unknown caveat kinds.
        const _exhaustive: never = cav;
        void _exhaustive;
        return { valid: false, reason: `unknown caveat kind (fail-closed)` };
      }
    }
  }

  return { valid: true };
}

/**
 * Full verification: signature + caveats + subject matches invoker.
 */
export function verifyDelegation(
  del: Delegation,
  ctx: InvocationContext,
  provider?: CryptoProvider,
  registry?: DidMethodRegistry,
  lookup?: HistoricalKeyLookup,
): DelegationVerification {
  const sigCheck = verifyDelegationSignature(del, provider, registry, lookup);
  if (!sigCheck.valid) return sigCheck;

  if (del.subjectDid !== ctx.invokerDid) {
    return { valid: false, reason: 'invoker is not the delegation subject' };
  }

  return checkCaveats(del, ctx);
}
