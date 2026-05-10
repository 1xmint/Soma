/**
 * IdentityRecoveryCoordinator — state machine for identity freeze and
 * recovery ceremonies.
 *
 * Runtime states: nominal (no ceremony record) | frozen | pending | verifying.
 * "restored" is a completion outcome recorded in the ceremony log; the
 * runtime returns to nominal (ceremony record deleted).
 *
 * The coordinator tracks recovery state and provides `isFrozen` checks
 * that HeartRuntime consults before issuing any new authority. It does
 * NOT own session invalidation — the caller (HeartRuntime.freezeIdentity)
 * composes coordinator state registration with invalidateIdentitySessions.
 *
 * Persistence seam: all state goes through the `RecoveryStore` interface.
 * The first implementation is in-memory; durable backends implement the
 * same three-method interface.
 */

// ─── Recovery Ceremony State ─────────────────────────────────────────────────

export type RecoveryCeremonyState = 'frozen' | 'pending' | 'verifying';

export interface RecoveryCeremony {
  readonly id: string;
  readonly identityDid: string;
  state: RecoveryCeremonyState;
  readonly frozenAt: number;
  /** When recovery evidence was first submitted (null while frozen). */
  initiatedAt: number | null;
  /** The recovery evidence type (null while frozen). */
  evidenceType: string | null;
  /** When the time-lock expires (null if not yet pending or no lock). */
  timeLockExpiresAt: number | null;
  /** When this ceremony was cancelled (null if active). */
  cancelledAt: number | null;
  /** When this ceremony completed successfully (null if active). */
  completedAt: number | null;
}

// ─── Persistence Seam ────────────────────────────────────────────────────────

/**
 * Storage interface for recovery ceremony state.
 *
 * Implementations must provide:
 *   - get: look up by identity DID (at most one active ceremony per identity)
 *   - put: upsert a ceremony record
 *   - delete: remove the record (on completion → return to nominal)
 *
 * The in-memory implementation below is the default. Durable backends
 * (database, encrypted file, etc.) implement the same interface.
 */
export interface RecoveryStore {
  get(identityDid: string): RecoveryCeremony | undefined;
  put(ceremony: RecoveryCeremony): void;
  delete(identityDid: string): boolean;
}

// ─── In-Memory Store ─────────────────────────────────────────────────────────

export class InMemoryRecoveryStore implements RecoveryStore {
  private readonly ceremonies = new Map<string, RecoveryCeremony>();

  get(identityDid: string): RecoveryCeremony | undefined {
    return this.ceremonies.get(identityDid);
  }

  put(ceremony: RecoveryCeremony): void {
    this.ceremonies.set(ceremony.identityDid, ceremony);
  }

  delete(identityDid: string): boolean {
    return this.ceremonies.delete(identityDid);
  }
}

// ─── Coordinator Result Types ────────────────────────────────────────────────

export interface FreezeResult {
  ceremonyId: string;
}

export interface RecoveryStatusResult {
  identityDid: string;
  state: RecoveryCeremonyState;
  ceremonyId: string;
  frozenAt: number;
  initiatedAt: number | null;
  evidenceType: string | null;
  timeLockExpiresAt: number | null;
  cancelledAt: number | null;
}

// ─── Coordinator ─────────────────────────────────────────────────────────────

export class IdentityRecoveryCoordinator {
  private readonly store: RecoveryStore;
  private readonly clock: () => number;

  constructor(
    store: RecoveryStore,
    opts?: { now?: () => number },
  ) {
    this.store = store;
    this.clock = opts?.now ?? (() => Date.now());
  }

  // ─── Freeze Gate ─────────────────────────────────────────────────────────

  /**
   * Returns true if the identity has an active recovery ceremony
   * (frozen, pending, or verifying). This is the gate check that
   * HeartRuntime calls before every authority-establishing flow.
   */
  isFrozen(identityDid: string): boolean {
    return this.store.get(identityDid) !== undefined;
  }

  // ─── Status Query ────────────────────────────────────────────────────────

  getStatus(identityDid: string): RecoveryStatusResult | null {
    const c = this.store.get(identityDid);
    if (!c) return null;
    return {
      identityDid: c.identityDid,
      state: c.state,
      ceremonyId: c.id,
      frozenAt: c.frozenAt,
      initiatedAt: c.initiatedAt,
      evidenceType: c.evidenceType,
      timeLockExpiresAt: c.timeLockExpiresAt,
      cancelledAt: c.cancelledAt,
    };
  }

  // ─── Freeze ──────────────────────────────────────────────────────────────

  /**
   * Register an identity as frozen. This is the state-tracking half of
   * the freeze operation. The caller (HeartRuntime.freezeIdentity) is
   * responsible for also running invalidateIdentitySessions.
   *
   * @throws if the identity is already frozen.
   */
  freezeIdentity(identityDid: string, opts?: { now?: number }): FreezeResult {
    const existing = this.store.get(identityDid);
    if (existing) {
      throw new Error(
        `identity ${identityDid} is already in recovery state '${existing.state}' (ceremony ${existing.id})`,
      );
    }

    const now = opts?.now ?? this.clock();
    const ceremonyId = `recovery-${now}-${identityDid.slice(-8)}`;

    this.store.put({
      id: ceremonyId,
      identityDid,
      state: 'frozen',
      frozenAt: now,
      initiatedAt: null,
      evidenceType: null,
      timeLockExpiresAt: null,
      cancelledAt: null,
      completedAt: null,
    });

    return { ceremonyId };
  }

  // ─── State Transitions (for future recovery slices) ──────────────────────

  /**
   * Advance a frozen identity to pending — recovery evidence has been
   * submitted and the time-lock starts counting.
   *
   * @throws if the identity is not in 'frozen' state.
   */
  initiatePending(
    identityDid: string,
    evidenceType: string,
    timeLockMs: number,
    opts?: { now?: number },
  ): RecoveryCeremony {
    const c = this.store.get(identityDid);
    if (!c) {
      throw new Error(`identity ${identityDid} is not frozen`);
    }
    if (c.state !== 'frozen') {
      throw new Error(
        `cannot initiate recovery: identity ${identityDid} is in '${c.state}' state, expected 'frozen'`,
      );
    }

    const now = opts?.now ?? this.clock();

    c.state = 'pending';
    c.initiatedAt = now;
    c.evidenceType = evidenceType;
    c.timeLockExpiresAt = now + timeLockMs;
    c.cancelledAt = null;

    this.store.put(c);
    return { ...c };
  }

  /**
   * Cancel a pending recovery — reverts to frozen.
   *
   * Used when an original authenticator asserts during the time-lock
   * (stolen seed detection) or when an operator explicitly cancels.
   *
   * @returns true if cancelled, false if not in pending state.
   */
  cancelRecovery(identityDid: string, opts?: { now?: number }): boolean {
    const c = this.store.get(identityDid);
    if (!c || c.state !== 'pending') return false;

    const now = opts?.now ?? this.clock();

    c.state = 'frozen';
    c.cancelledAt = now;
    c.initiatedAt = null;
    c.evidenceType = null;
    c.timeLockExpiresAt = null;

    this.store.put(c);
    return true;
  }

  /**
   * Advance a pending ceremony to verifying — time-lock has expired,
   * evidence is being re-validated, new authenticators are enrolling.
   *
   * @throws if the identity is not in 'pending' state or time-lock has
   *         not yet expired.
   */
  advanceToVerifying(identityDid: string, opts?: { now?: number }): RecoveryCeremony {
    const c = this.store.get(identityDid);
    if (!c) {
      throw new Error(`identity ${identityDid} has no active recovery ceremony`);
    }
    if (c.state !== 'pending') {
      throw new Error(
        `cannot advance to verifying: identity ${identityDid} is in '${c.state}' state, expected 'pending'`,
      );
    }

    const now = opts?.now ?? this.clock();

    if (c.timeLockExpiresAt !== null && now < c.timeLockExpiresAt) {
      throw new Error(
        `time-lock has not expired for ${identityDid}: ${c.timeLockExpiresAt - now}ms remaining`,
      );
    }

    c.state = 'verifying';
    this.store.put(c);
    return { ...c };
  }

  /**
   * Complete a recovery ceremony — identity returns to nominal.
   *
   * Deletes the ceremony record from the store. The ceremony itself
   * is captured in heartbeat events, not in the coordinator's state.
   *
   * @returns the completed ceremony snapshot for heartbeat recording.
   * @throws if the identity is not in 'verifying' state.
   */
  completeRecovery(identityDid: string, opts?: { now?: number }): RecoveryCeremony {
    const c = this.store.get(identityDid);
    if (!c) {
      throw new Error(`identity ${identityDid} has no active recovery ceremony`);
    }
    if (c.state !== 'verifying') {
      throw new Error(
        `cannot complete recovery: identity ${identityDid} is in '${c.state}' state, expected 'verifying'`,
      );
    }

    const now = opts?.now ?? this.clock();
    const snapshot: RecoveryCeremony = {
      ...c,
      completedAt: now,
    };

    this.store.delete(identityDid);
    return snapshot;
  }
}
