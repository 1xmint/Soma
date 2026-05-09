/**
 * ProductAccountBinding — canonical binding between a product account
 * and a Soma root identity.
 *
 * Decision 1: 1:1 primary binding — one humanDid per product account.
 * One Soma identity MAY back multiple accounts across different product
 * shells. Multi-identity binding is explicitly deferred.
 *
 * The binding is the product's view onto the identity. If the account
 * is deleted, the Soma identity persists. If the identity is
 * compromised, the account is compromised — the identity IS the root.
 *
 * Cross-ref:
 *   - docs/proposals/soma-human-identity-binding-and-attestation.md §4.4
 *   - docs/proposals/soma-backed-login-session-authority-architecture.md Decision 1
 */

// ─── Binding Type ────────────────────────────────────────────────────────────

/**
 * How the account was bound to the identity.
 *
 *   - `primary`: direct binding during onboarding or identity creation.
 *   - `delegated`: bound via a delegation chain (e.g. an agent bound
 *     the account on behalf of the human).
 *   - `guardian-mediated`: bound via a guardian recovery ceremony.
 */
export type BindingType = 'primary' | 'delegated' | 'guardian-mediated';

// ─── Product Account Binding ─────────────────────────────────────────────────

export interface ProductAccountBinding {
  /** Product-level account identifier (e.g. HeyVera account ID). */
  accountId: string;
  /** The Soma root identity DID this account is bound to. */
  somaIdentityDid: string;
  /** How the binding was established. */
  bindingType: BindingType;
  /** Unix ms when the binding was created. */
  boundAt: number;
  /** Unix ms when the binding was dissolved, or null if active. */
  unboundAt: number | null;
}

// ─── Binding Store ───────────────────────────────────────────────────────────

/**
 * In-memory store for ProductAccountBinding records.
 *
 * Enforces the 1:1 primary binding invariant: one active binding per
 * account. One Soma identity can back multiple accounts (cross-shell).
 *
 * Same in-memory / no-persistence pattern as ProductSessionStore.
 * Durable storage is the caller's concern.
 */
export class ProductAccountBindingStore {
  private readonly bindings = new Map<string, ProductAccountBinding>();

  /**
   * Bind a product account to a Soma identity.
   *
   * Throws if the account already has an active binding — unbind first,
   * or use `rebind` for an atomic unbind-and-bind.
   */
  bind(
    input: {
      accountId: string;
      somaIdentityDid: string;
      bindingType: BindingType;
    },
    now?: number,
  ): ProductAccountBinding {
    const existing = this.bindings.get(input.accountId);
    if (existing && existing.unboundAt === null) {
      throw new Error(
        `account ${input.accountId} already bound to ${existing.somaIdentityDid}`,
      );
    }

    const binding: ProductAccountBinding = {
      ...input,
      boundAt: now ?? Date.now(),
      unboundAt: null,
    };

    this.bindings.set(input.accountId, binding);
    return { ...binding };
  }

  /** Look up a binding by account ID (active or unbound). */
  get(accountId: string): ProductAccountBinding | undefined {
    const b = this.bindings.get(accountId);
    return b ? { ...b } : undefined;
  }

  /** Look up the active binding for an account. Returns undefined if unbound. */
  getActive(accountId: string): ProductAccountBinding | undefined {
    const b = this.bindings.get(accountId);
    return b && b.unboundAt === null ? { ...b } : undefined;
  }

  /**
   * Dissolve an active binding. Returns false if the account has no
   * active binding.
   */
  unbind(accountId: string, now?: number): boolean {
    const b = this.bindings.get(accountId);
    if (!b || b.unboundAt !== null) return false;
    this.bindings.set(accountId, { ...b, unboundAt: now ?? Date.now() });
    return true;
  }

  /**
   * Atomic unbind-and-bind: dissolve the old binding (if any) and
   * create a new one in one operation.
   */
  rebind(
    accountId: string,
    newIdentityDid: string,
    bindingType: BindingType,
    now?: number,
  ): ProductAccountBinding {
    const ts = now ?? Date.now();
    this.unbind(accountId, ts);
    return this.bind(
      { accountId, somaIdentityDid: newIdentityDid, bindingType },
      ts,
    );
  }

  /**
   * Get all active bindings for a Soma identity (across product shells).
   * Returns defensive copies.
   */
  getByIdentity(somaIdentityDid: string): ProductAccountBinding[] {
    return [...this.bindings.values()]
      .filter(
        (b) => b.somaIdentityDid === somaIdentityDid && b.unboundAt === null,
      )
      .map((b) => ({ ...b }));
  }

  /** Total bindings in the store (including unbound). */
  get size(): number {
    return this.bindings.size;
  }

  /** Count of currently active bindings. */
  get activeCount(): number {
    let count = 0;
    for (const b of this.bindings.values()) {
      if (b.unboundAt === null) count++;
    }
    return count;
  }

  clear(): void {
    this.bindings.clear();
  }
}
