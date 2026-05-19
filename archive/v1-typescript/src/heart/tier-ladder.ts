/**
 * Tier Ladder — deployment-configurable policy mapping factor combinations
 * to tier numbers.
 *
 * The tier ladder is the piece of step-up that's deployment-specific. A
 * solo developer running a personal heart and a regulated enterprise
 * running a corporate heart both use the same FactorRegistry and StepUp
 * primitives, but they disagree on what "tier 2" means — the developer
 * might accept a single Touch ID, the enterprise might require a hardware
 * security key plus a co-approval from a second human.
 *
 * The ladder is pure config data: an ordered list of tier rules, each
 * naming a numeric tier and a boolean predicate over the factor assertion
 * context. Evaluation walks the ladder from highest tier to lowest and
 * returns the first rule whose predicate passes. If nothing passes, tier
 * 0 is returned (the minimum, "anonymous" tier).
 *
 * Predicates are a small algebra: leaf checks against the factor type,
 * hardware-attested flag, user-verification flag, registration count,
 * distinct-device count, and composition via `and` / `or` / `not`. This
 * is deliberately smaller than a full Rego/OPA policy — we optimize for
 * being auditable in a single sitting rather than expressive.
 *
 * New predicate kinds can be added without breaking existing ladders: a
 * deployment that doesn't use a new kind will never encounter it, and
 * verifiers that don't understand a new kind fail closed (return 0).
 */

// ─── Evaluation Input ───────────────────────────────────────────────────────

/**
 * Context passed to the ladder evaluator. Built by the step-up service
 * from the FactorRegistry and the current assertion.
 */
export interface TierEvalInput {
  /** Factor type that produced the current assertion. */
  factorType: string;
  /**
   * Tier the factor's own verifier reports. This is the factor's claim
   * about its inherent strength (e.g., a WebAuthn verifier might report
   * tier 2 for hardware-attested roaming authenticators). Ladder rules
   * can cap or raise this.
   */
  factorTier: number;
  /** Subject the assertion was produced for. */
  subjectDid: string;
  /** True if the assertion included a user-verification (biometric/PIN) flag. */
  hasUserVerification: boolean;
  /** True if the factor has a hardware attestation (e.g., FIDO2 AAGUID verified). */
  hasHardwareAttestation: boolean;
  /**
   * Active (non-revoked) factors registered to the subject. Used by
   * `registered-count` and `distinct-device-count` predicates to reason
   * about what else the subject has available.
   */
  registeredActive: Array<{
    factorType: string;
    factorId: string;
    metadata: Record<string, string>;
  }>;
}

// ─── Predicate Algebra ──────────────────────────────────────────────────────

export type TierPredicate =
  /** Factor type of the current assertion is in the allowed set. */
  | { kind: 'factor-type'; types: string[] }
  /** Factor's self-reported tier is at least `tier`. */
  | { kind: 'min-factor-tier'; tier: number }
  /** Current assertion had a user-verification flag. */
  | { kind: 'user-verification' }
  /** Factor has a hardware attestation. */
  | { kind: 'hardware-attested' }
  /**
   * Subject has at least `count` active registered factors. Optionally
   * restricted to a type.
   */
  | { kind: 'registered-count'; count: number; factorType?: string }
  /**
   * Subject has at least `count` distinct devices registered (counted by
   * `metadata.deviceId` if present, else by `factorId`).
   */
  | { kind: 'distinct-device-count'; count: number }
  /** All sub-predicates must hold. */
  | { kind: 'and'; of: TierPredicate[] }
  /** At least one sub-predicate must hold. */
  | { kind: 'or'; of: TierPredicate[] }
  /** Negation. */
  | { kind: 'not'; of: TierPredicate };

export interface TierRule {
  /** Numeric tier this rule grants when its predicate passes. */
  tier: number;
  /** Predicate that must hold to grant this tier. */
  when: TierPredicate;
  /** Human-readable label for logs / audit trails. */
  label?: string;
}

/**
 * A tier ladder is an ordered list of rules. Evaluation walks from
 * highest tier to lowest and returns the first match. Order of rules
 * with the same tier is evaluation order.
 */
export type TierLadder = TierRule[];

// ─── Evaluation ─────────────────────────────────────────────────────────────

/**
 * Check a predicate against an eval input. Unknown predicate kinds fail
 * closed (return false).
 */
export function checkPredicate(
  pred: TierPredicate,
  input: TierEvalInput,
): boolean {
  switch (pred.kind) {
    case 'factor-type':
      return pred.types.includes(input.factorType);

    case 'min-factor-tier':
      return input.factorTier >= pred.tier;

    case 'user-verification':
      return input.hasUserVerification;

    case 'hardware-attested':
      return input.hasHardwareAttestation;

    case 'registered-count': {
      const filtered = pred.factorType
        ? input.registeredActive.filter((f) => f.factorType === pred.factorType)
        : input.registeredActive;
      return filtered.length >= pred.count;
    }

    case 'distinct-device-count': {
      const seen = new Set<string>();
      for (const f of input.registeredActive) {
        seen.add(f.metadata.deviceId ?? f.factorId);
      }
      return seen.size >= pred.count;
    }

    case 'and':
      return pred.of.every((p) => checkPredicate(p, input));

    case 'or':
      return pred.of.some((p) => checkPredicate(p, input));

    case 'not':
      return !checkPredicate(pred.of, input);

    default: {
      // Exhaustiveness guard — new predicate kinds fail closed.
      const _exhaustive: never = pred;
      void _exhaustive;
      return false;
    }
  }
}

/**
 * Evaluate a tier ladder. Returns the highest tier whose predicate
 * passes, or 0 if none.
 */
export function evaluateLadder(
  ladder: TierLadder,
  input: TierEvalInput,
): number {
  const sorted = [...ladder].sort((a, b) => b.tier - a.tier);
  for (const rule of sorted) {
    if (checkPredicate(rule.when, input)) {
      return rule.tier;
    }
  }
  return 0;
}

/**
 * Evaluate a ladder and return the matching rule (not just the number).
 * Useful for audit logs — "tier 2 granted because rule 'hardware-key-with-uv' passed".
 */
export function evaluateLadderDetailed(
  ladder: TierLadder,
  input: TierEvalInput,
): { tier: number; rule: TierRule | null } {
  const sorted = [...ladder].sort((a, b) => b.tier - a.tier);
  for (const rule of sorted) {
    if (checkPredicate(rule.when, input)) {
      return { tier: rule.tier, rule };
    }
  }
  return { tier: 0, rule: null };
}

// ─── Default Ladders ────────────────────────────────────────────────────────

/**
 * The default ladder shipped with Soma. Sensible for developer setups:
 *
 *   Tier 0: anything — no factor required (read-only, no secrets at risk)
 *   Tier 1: any WebAuthn assertion with user verification — routine ops
 *   Tier 2: WebAuthn UV from a hardware-attested authenticator, OR two
 *           distinct devices registered with at least one UV assertion
 *   Tier 3: Tier 2 AND hardware-attested — destructive / irreversible ops
 *
 * Enterprises and paranoid deployments override with their own ladder.
 */
export const DEFAULT_LADDER: TierLadder = [
  {
    tier: 3,
    label: 'hardware-attested-with-uv',
    when: {
      kind: 'and',
      of: [
        { kind: 'hardware-attested' },
        { kind: 'user-verification' },
        { kind: 'distinct-device-count', count: 2 },
      ],
    },
  },
  {
    tier: 2,
    label: 'hardware-or-two-devices',
    when: {
      kind: 'or',
      of: [
        {
          kind: 'and',
          of: [
            { kind: 'hardware-attested' },
            { kind: 'user-verification' },
          ],
        },
        {
          kind: 'and',
          of: [
            { kind: 'user-verification' },
            { kind: 'distinct-device-count', count: 2 },
          ],
        },
      ],
    },
  },
  {
    tier: 1,
    label: 'webauthn-uv',
    when: {
      kind: 'and',
      of: [
        {
          kind: 'factor-type',
          types: ['webauthn-platform', 'webauthn-roaming'],
        },
        { kind: 'user-verification' },
      ],
    },
  },
  {
    tier: 0,
    label: 'any',
    when: { kind: 'or', of: [] }, // Always false alone, but tier 0 is the floor anyway.
  },
];

/**
 * Paranoid ladder for "extremist security" deployments. Requires hardware
 * attestation for any tier above 0 and multi-device for tier 3.
 */
export const PARANOID_LADDER: TierLadder = [
  {
    tier: 3,
    label: 'hardware-uv-multi-device',
    when: {
      kind: 'and',
      of: [
        { kind: 'hardware-attested' },
        { kind: 'user-verification' },
        { kind: 'distinct-device-count', count: 3 },
      ],
    },
  },
  {
    tier: 2,
    label: 'hardware-uv-two-device',
    when: {
      kind: 'and',
      of: [
        { kind: 'hardware-attested' },
        { kind: 'user-verification' },
        { kind: 'distinct-device-count', count: 2 },
      ],
    },
  },
  {
    tier: 1,
    label: 'hardware-uv',
    when: {
      kind: 'and',
      of: [
        { kind: 'hardware-attested' },
        { kind: 'user-verification' },
      ],
    },
  },
];
