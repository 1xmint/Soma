/**
 * HumanSession — bounded, consumable handle around a verified HumanDelegation.
 *
 * A HumanDelegation is the *signed consent payload*. A HumanSession is the
 * *runtime handle* that tracks what the agent has spent, how many calls
 * it has made, and whether the envelope has been exhausted or exceeded.
 * Separating the two matters because:
 *
 *   - The delegation is immutable — once the human signs it, its envelope
 *     is fixed.
 *   - The session mutates on every action (budget drains, invocation
 *     counter ticks, escalation flips).
 *
 * This module is pure in-memory. Persistence, IPC, and the HTTP surface
 * are the caller's problem — we only ship the state machine and the
 * enforcement primitives. That keeps it trivially unit-testable.
 *
 * Envelope enforcement is *strict* by default: a budget overdraft or
 * hitting max-invocations terminates the session. Callers who want
 * soft-limit behavior can wrap the registry.
 *
 * Cross-ref: `internal/active/session-mode-and-ceremony.md` §7.3.
 */

import type { Caveat } from './delegation.js';
import type {
  AttestationVerifier,
  CeremonyTier,
  HumanDelegation,
} from './human-delegation.js';
import { verifyHumanDelegation } from './human-delegation.js';
import type {
  ActionClass,
  CeremonyPolicy,
} from './ceremony-policy.js';
import { createCeremonyPolicy } from './ceremony-policy.js';
import type { CryptoProvider } from '../core/crypto-provider.js';
import type { DidMethodRegistry } from '../core/did-method.js';

export type SessionStatus =
  | 'active'
  | 'expired'
  | 'revoked'
  | 'budget-exhausted'
  | 'invocations-exhausted';

export interface HumanSession {
  sessionId: string;
  humanDid: string;
  agentEphemeralDid: string;
  tier: CeremonyTier;
  status: SessionStatus;
  startedAt: number;
  expiresAt: number;
  /** Remaining budget if a `budget` caveat was set, else null (unbounded). */
  remainingCredits: number | null;
  /** Remaining invocations if `max-invocations` was set, else null. */
  remainingInvocations: number | null;
  delegation: HumanDelegation;
}

export interface InvokeRequest {
  actionClass: ActionClass;
  /** Credits this action will consume. Must be ≥ 0. */
  cost?: number;
  /** Optional host the action targets — checked against host-allowlist. */
  host?: string;
  now: number;
}

export type InvokeResult =
  | { ok: true; session: HumanSession }
  | { ok: false; reason: string; session: HumanSession };

function initialBudget(envelope: Caveat[]): number | null {
  const caveat = envelope.find((c) => c.kind === 'budget');
  return caveat && caveat.kind === 'budget' ? caveat.credits : null;
}

function initialInvocations(envelope: Caveat[]): number | null {
  const caveat = envelope.find((c) => c.kind === 'max-invocations');
  return caveat && caveat.kind === 'max-invocations' ? caveat.count : null;
}

function hostAllowed(envelope: Caveat[], host: string | undefined): boolean {
  const caveat = envelope.find((c) => c.kind === 'host-allowlist');
  if (!caveat || caveat.kind !== 'host-allowlist') return true;
  if (!host) return false;
  return caveat.hosts.includes(host);
}

/**
 * In-process registry of active HumanSessions.
 *
 * Not thread-safe across worker threads — Soma runtimes are single-
 * threaded per heart by design. A multi-process deployment needs its
 * own coordination layer on top (that's a ClawNet concern, not Soma's).
 */
export class HumanSessionRegistry {
  private readonly sessions = new Map<string, HumanSession>();
  private readonly policy: CeremonyPolicy;
  private readonly verifier: AttestationVerifier;
  private readonly provider: CryptoProvider | undefined;
  private readonly registry: DidMethodRegistry | undefined;

  constructor(opts: {
    attestationVerifier: AttestationVerifier;
    policy?: CeremonyPolicy;
    provider?: CryptoProvider;
    didRegistry?: DidMethodRegistry;
  }) {
    this.verifier = opts.attestationVerifier;
    this.policy = opts.policy ?? createCeremonyPolicy();
    this.provider = opts.provider;
    this.registry = opts.didRegistry;
  }

  /**
   * Verify + open a session from a signed HumanDelegation. Fails closed
   * on signature, attestation, or envelope errors. Idempotent by
   * `sessionId` — re-opening an already-active session returns the
   * existing handle rather than double-counting the envelope.
   */
  open(delegation: HumanDelegation, now: number): InvokeResult {
    const existing = this.sessions.get(delegation.sessionId);
    if (existing) return { ok: true, session: existing };

    const verification = verifyHumanDelegation(delegation, this.verifier, now, {
      provider: this.provider,
      registry: this.registry,
    });
    if (!verification.valid) {
      return {
        ok: false,
        reason: verification.reason,
        session: {
          sessionId: delegation.sessionId,
          humanDid: delegation.humanDid,
          agentEphemeralDid: delegation.agentEphemeralDid,
          tier: delegation.ceremonyTier,
          status: 'revoked',
          startedAt: now,
          expiresAt: delegation.expiresAt,
          remainingCredits: initialBudget(delegation.envelope),
          remainingInvocations: initialInvocations(delegation.envelope),
          delegation,
        },
      };
    }

    const session: HumanSession = {
      sessionId: delegation.sessionId,
      humanDid: delegation.humanDid,
      agentEphemeralDid: delegation.agentEphemeralDid,
      tier: verification.tier,
      status: 'active',
      startedAt: now,
      expiresAt: delegation.expiresAt,
      remainingCredits: initialBudget(delegation.envelope),
      remainingInvocations: initialInvocations(delegation.envelope),
      delegation,
    };
    this.sessions.set(delegation.sessionId, session);
    return { ok: true, session };
  }

  get(sessionId: string): HumanSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Attempt an in-session action. Walks the envelope caveats + policy
   * engine and, on success, mutates the session counters atomically.
   * On failure returns a reason string and leaves counters unchanged.
   */
  invoke(sessionId: string, req: InvokeRequest): InvokeResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`HumanSessionRegistry.invoke: unknown session ${sessionId}`);
    }

    if (session.status !== 'active') {
      return { ok: false, reason: `session ${session.status}`, session };
    }

    if (req.now >= session.expiresAt) {
      session.status = 'expired';
      return { ok: false, reason: 'session expired', session };
    }

    const decision = this.policy(req.actionClass, session.tier);
    if (!decision.ok) {
      return { ok: false, reason: decision.reason ?? 'policy denied', session };
    }

    if (!hostAllowed(session.delegation.envelope, req.host)) {
      return {
        ok: false,
        reason: `host '${req.host ?? '<none>'}' not in host-allowlist`,
        session,
      };
    }

    const cost = req.cost ?? 0;
    if (cost < 0) {
      return { ok: false, reason: 'negative cost', session };
    }

    if (session.remainingCredits !== null && cost > session.remainingCredits) {
      session.status = 'budget-exhausted';
      return {
        ok: false,
        reason: `budget overdraft: need ${cost}, have ${session.remainingCredits}`,
        session,
      };
    }

    if (session.remainingInvocations !== null && session.remainingInvocations <= 0) {
      session.status = 'invocations-exhausted';
      return { ok: false, reason: 'max-invocations reached', session };
    }

    if (session.remainingCredits !== null) {
      session.remainingCredits -= cost;
    }
    if (session.remainingInvocations !== null) {
      session.remainingInvocations -= 1;
      if (session.remainingInvocations === 0) {
        session.status = 'invocations-exhausted';
      }
    }

    return { ok: true, session };
  }

  revoke(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    session.status = 'revoked';
    return true;
  }

  /** Drop terminated sessions — call from a periodic sweep. */
  prune(now: number): number {
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.status !== 'active' || now >= session.expiresAt) {
        this.sessions.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    return this.sessions.size;
  }
}
