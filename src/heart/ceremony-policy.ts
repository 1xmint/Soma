/**
 * CeremonyPolicy — maps (action class → required ceremony tier).
 *
 * The policy engine is a pure lookup layer that decides *which tier of
 * human consent* an action needs before a HumanDelegation can authorize
 * it. It has no crypto, no I/O, no state — it's a function of the
 * action class and the policy config, nothing else. This keeps the gate
 * auditable, unit-testable, and trivially configurable by callers.
 *
 * Why a separate primitive:
 *   - HumanDelegation (human-delegation.ts) answers "did the human
 *     consent to this envelope?"
 *   - CeremonyPolicy answers "does this envelope and tier actually
 *     authorize *this specific action*?"
 *   These are orthogonal questions. Bundling them would couple crypto
 *   verification to policy config churn — the policy changes far more
 *   often than the delegation format does.
 *
 * Action classes (not action names): we intentionally gate on *classes*
 * rather than specific endpoints or tools. The policy should not grow
 * linearly with the number of endpoints — that's how real-world policy
 * engines become unmaintainable. Classes are coarse and stable:
 *
 *   - 'read'         — observational, side-effect-free calls
 *   - 'write'        — mutates non-financial state
 *   - 'spend'        — moves money, credits, or other counted resources
 *   - 'deploy'       — changes running code or infrastructure
 *   - 'admin'        — policy changes, key rotation, escrow resolution
 *
 * Callers can extend the class set through the `custom` map if they
 * need finer granularity (e.g. HeyDATA adding `'voice-call'`). The
 * default policy is opinionated: `read` needs L0, `write` needs L1,
 * `spend` and `deploy` need L2, `admin` needs L3. Override with the
 * `PolicyOverrides` argument.
 *
 * Cross-ref: `internal/active/session-mode-and-ceremony.md` §7.4.
 */

import type { CeremonyTier } from './human-delegation.js';

/** Canonical action classes understood by the default policy. */
export type ActionClass = 'read' | 'write' | 'spend' | 'deploy' | 'admin' | string; // custom classes flow through the map

/** Mapping from action class to required tier. */
export type PolicyMap = Record<string, CeremonyTier>;

export const DEFAULT_CEREMONY_POLICY: PolicyMap = {
  read: 'L0',
  write: 'L1',
  spend: 'L2',
  deploy: 'L2',
  admin: 'L3',
};

export interface PolicyOverrides {
  /**
   * Replacement or extension map merged over `DEFAULT_CEREMONY_POLICY`. Unknown
   * classes that aren't in the merged map default to `unknownClassTier`.
   */
  overrides?: PolicyMap;
  /**
   * Tier required for action classes not present in the merged map.
   * Defaults to `'L2'` — fail-safe: an unrecognized class is treated as
   * high-risk rather than silently allowed.
   */
  unknownClassTier?: CeremonyTier;
}

export interface PolicyDecision {
  ok: boolean;
  requiredTier: CeremonyTier;
  actualTier: CeremonyTier;
  reason?: string;
}

function tierRank(t: CeremonyTier): number {
  return { L0: 0, L1: 1, L2: 2, L3: 3 }[t];
}

/**
 * Build a reusable policy function. The returned function is pure:
 * same inputs → same output, no closures over mutable state.
 */
export function createCeremonyPolicy(opts?: PolicyOverrides) {
  const merged: PolicyMap = { ...DEFAULT_CEREMONY_POLICY, ...(opts?.overrides ?? {}) };
  const unknownTier: CeremonyTier = opts?.unknownClassTier ?? 'L2';

  return function decide(actionClass: ActionClass, attestedTier: CeremonyTier): PolicyDecision {
    const required = merged[actionClass] ?? unknownTier;
    const ok = tierRank(attestedTier) >= tierRank(required);
    if (ok) {
      return { ok: true, requiredTier: required, actualTier: attestedTier };
    }
    return {
      ok: false,
      requiredTier: required,
      actualTier: attestedTier,
      reason: `action class '${actionClass}' requires ${required} but session is ${attestedTier}`,
    };
  };
}

export type CeremonyPolicy = ReturnType<typeof createCeremonyPolicy>;
