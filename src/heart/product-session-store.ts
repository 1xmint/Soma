/**
 * ProductSessionStore — in-memory server-side truth for ProductSessions.
 *
 * The store is the authoritative lookup target for opaque session tokens.
 * The flow: client presents token → server validates MAC/expiry →
 * server resolves `claims.sid` against this store → match against live
 * session → proceed or reject.
 *
 * Design:
 *   - Pure in-memory Map — no database, no persistence, no HTTP.
 *   - Single-threaded by design (same as HumanSessionRegistry).
 *   - Fail-closed: missing, expired, and revoked sessions return `undefined`
 *     or an explicit rejection.
 *   - Update-in-place for step-up elevation and decay — the stored session
 *     is always the source of truth.
 *   - Prune sweeps remove expired and revoked sessions to bound growth.
 *
 * This module is deliberately narrow. Persistent storage, multi-process
 * coordination, and HTTP middleware are the caller's concern.
 *
 * Cross-ref:
 *   - `product-session.ts` — ProductSession type, issuance, elevation, decay
 *   - `product-session.ts` — opaque token mint/validate/match
 *   - `human-session.ts` — HumanSessionRegistry (same pattern)
 */

import type { ProductSession } from './product-session.js';

/**
 * In-memory store for server-side ProductSession records.
 *
 * Not thread-safe across worker threads — Soma runtimes are single-
 * threaded per heart by design. A multi-process deployment needs its
 * own coordination layer on top.
 */
export class ProductSessionStore {
  private readonly sessions = new Map<string, ProductSession>();

  /** Store a newly issued ProductSession. Overwrites if sessionId already exists. */
  put(session: ProductSession): void {
    this.sessions.set(session.sessionId, session);
  }

  /**
   * Look up a ProductSession by sessionId.
   *
   * Returns `undefined` if the session does not exist.
   * Does NOT check expiry or revocation — the caller should use
   * `matchTokenToSession` or check `revocationState`/`expiresAt` explicitly.
   * This is intentional: the store is a dumb lookup; policy is the caller's job.
   */
  get(sessionId: string): ProductSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Check whether a session exists in the store.
   */
  has(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  /**
   * Replace a stored ProductSession with an updated version.
   *
   * Used after step-up elevation (`elevateProductSession`) or decay
   * (`decayProductSession`) to keep the store in sync with the latest
   * session state.
   *
   * Returns `false` if the sessionId is not in the store (nothing to update).
   * The new session's `sessionId` must match the old one — this is a safety
   * check against accidentally swapping sessions.
   */
  update(session: ProductSession): boolean {
    if (!this.sessions.has(session.sessionId)) return false;
    this.sessions.set(session.sessionId, session);
    return true;
  }

  /**
   * Revoke a session by sessionId.
   *
   * Sets `revocationState` to `'revoked'` on the stored session. Returns
   * `false` if the session does not exist or is already revoked.
   *
   * The session remains in the store after revocation — it will be cleaned
   * up by `prune`. This is intentional: immediate deletion would turn
   * "token for revoked session" into "token for unknown session", losing
   * the ability to distinguish the two failure modes.
   */
  revoke(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (session.revocationState === 'revoked') return false;

    // ProductSession is treated as immutable in the pure functions, but
    // the store is the mutable truth layer. Replace with a revoked copy.
    this.sessions.set(sessionId, {
      ...session,
      revocationState: 'revoked',
    });
    return true;
  }

  /**
   * Remove expired and revoked sessions to bound memory growth.
   *
   * Call from a periodic sweep or after batch operations. Returns the
   * number of sessions removed.
   */
  prune(now?: number): number {
    const ts = now ?? Date.now();
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.revocationState === 'revoked' || ts >= session.expiresAt) {
        this.sessions.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  /**
   * Revoke all sessions for a given accountId.
   *
   * Used when an account is compromised, deleted, or needs a full
   * session reset. Returns the number of sessions revoked.
   */
  revokeByAccount(accountId: string): number {
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (session.accountId === accountId && session.revocationState !== 'revoked') {
        this.sessions.set(id, { ...session, revocationState: 'revoked' });
        count += 1;
      }
    }
    return count;
  }

  /**
   * Revoke all active sessions whose deviceBinding references the given factorId.
   *
   * Used when a factor is compromised or deregistered — sessions that
   * derive their authority from that factor must not continue. Sessions
   * with `deviceBinding === null` (e.g. adapter-bridge) are never matched.
   *
   * Returns the number of sessions revoked.
   */
  revokeByFactor(factorId: string): number {
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (
        session.deviceBinding?.factorId === factorId &&
        session.revocationState !== 'revoked'
      ) {
        this.sessions.set(id, { ...session, revocationState: 'revoked' });
        count += 1;
      }
    }
    return count;
  }

  /**
   * Revoke all active sessions whose `somaIdentityBinding` matches the
   * given DID. Catches sessions that carry an identity reference but may
   * not have a formal account binding in the binding store.
   *
   * Returns the number of sessions revoked.
   */
  revokeByIdentity(somaIdentityDid: string): number {
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (
        session.somaIdentityBinding === somaIdentityDid &&
        session.revocationState !== 'revoked'
      ) {
        this.sessions.set(id, { ...session, revocationState: 'revoked' });
        count += 1;
      }
    }
    return count;
  }

  /**
   * Get all active (non-revoked, non-expired) sessions for an account.
   *
   * Useful for session management UIs ("you have 3 active sessions").
   */
  getByAccount(accountId: string, now?: number): ProductSession[] {
    const ts = now ?? Date.now();
    const result: ProductSession[] = [];
    for (const session of this.sessions.values()) {
      if (
        session.accountId === accountId &&
        session.revocationState === 'active' &&
        ts < session.expiresAt
      ) {
        result.push(session);
      }
    }
    return result;
  }

  /** Number of sessions currently in the store (including revoked/expired). */
  get size(): number {
    return this.sessions.size;
  }

  /** Remove all sessions. */
  clear(): void {
    this.sessions.clear();
  }
}
