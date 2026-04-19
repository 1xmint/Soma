/**
 * Delegation Chain Verification — SOMA-CAPABILITIES-SPEC.md steps 6-7.
 *
 * Walks a delegation chain from leaf to root, verifying at each link:
 *   - Cryptographic signature integrity (with optional HistoricalKeyLookup)
 *   - Subject-issuer linkage (child.issuerDid === parent.subjectDid)
 *   - Monotonic capability attenuation (child caps ⊆ parent caps)
 *   - Monotonic caveat accumulation (child caveats ⊇ parent caveats)
 *   - Revocation status via RevocationRegistry
 *
 * Fails closed: unknown errors, unresolvable parents, broken invariants
 * all produce typed failure results — never thrown exceptions.
 *
 * @module
 */

import type { CryptoProvider } from '../core/crypto-provider.js';
import type { DidMethodRegistry } from '../core/did-method.js';
import type { HistoricalKeyLookup } from './historical-key-lookup.js';
import type { RevocationRegistry } from './revocation.js';
import {
  verifyDelegationSignature,
  type Delegation,
  type Caveat,
} from './delegation.js';

// ─── Result Types ───────────────────────────────────────────────────────────

/** Successful chain verification result. */
export interface ChainVerificationSuccess {
  readonly valid: true;
  /** The verified chain, ordered leaf-first (index 0 = leaf, last = root). */
  readonly chain: readonly Delegation[];
}

/** Failed chain verification result. */
export interface ChainVerificationFailure {
  readonly valid: false;
  /** Human-readable reason for failure. */
  readonly reason: string;
  /** Index in the chain array where verification failed (0 = leaf). */
  readonly failedAtIndex: number;
}

/** Result of verifying a delegation chain. */
export type ChainVerificationResult =
  | ChainVerificationSuccess
  | ChainVerificationFailure;

// ─── Options ────────────────────────────────────────────────────────────────

/** Options for chain verification. */
export interface ChainVerificationOptions {
  /** Crypto provider override (defaults to global). */
  provider?: CryptoProvider;
  /** DID method registry for non-did:key methods. */
  registry?: DidMethodRegistry;
  /** Rotation-aware key lookup for historical key verification. */
  lookup?: HistoricalKeyLookup;
  /**
   * Maximum allowed chain depth. Verifiers SHOULD cap depth to bound work
   * and prevent DoS. Recommended: 16. Default: 16.
   */
  maxDepth?: number;
}

/** Default maximum chain depth (per SOMA-CAPABILITIES-SPEC.md §Security). */
const DEFAULT_MAX_DEPTH = 16;

// ─── Capability Subset Checking ─────────────────────────────────────────────

/**
 * Check whether a single capability string is granted by a set of
 * parent capabilities, respecting wildcard matching.
 *
 * Matching rules (per SOMA-CAPABILITIES-SPEC.md §Capability Strings):
 *   - `*` matches any capability.
 *   - `<prefix>:*` matches anything starting with `<prefix>:`.
 *   - Exact string match otherwise.
 */
function isCapabilityGranted(
  cap: string,
  parentCaps: readonly string[],
): boolean {
  for (const parent of parentCaps) {
    if (parent === '*') return true;
    if (parent === cap) return true;
    if (
      parent.endsWith(':*') &&
      cap.startsWith(parent.slice(0, -1))
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Check that child capabilities are a subset of parent capabilities.
 * Every child capability must be granted by at least one parent capability.
 *
 * Returns `undefined` if the subset relationship holds, or a reason string
 * describing the first broadening violation found.
 */
function checkCapabilitySubset(
  childCaps: readonly string[],
  parentCaps: readonly string[],
): string | undefined {
  for (const cap of childCaps) {
    if (!isCapabilityGranted(cap, parentCaps)) {
      return `capability "${cap}" not granted by parent`;
    }
  }
  return undefined;
}

// ─── Caveat Superset Checking ───────────────────────────────────────────────

/**
 * Canonical JSON representation of a caveat for equality comparison.
 * Uses sorted keys and deterministic serialization so that structurally
 * equivalent caveats compare equal regardless of property order.
 */
function canonicalCaveat(c: Caveat): string {
  return JSON.stringify(c, Object.keys(c).sort());
}

/**
 * Check that the child's caveats are a superset of the parent's caveats.
 * Per SOMA-CAPABILITIES-SPEC.md §Attenuation Rules: a child copies all
 * parent caveats unchanged and may add more. Every parent caveat must
 * appear in the child.
 *
 * Returns `undefined` if the superset relationship holds, or a reason
 * string describing the first missing parent caveat.
 */
function checkCaveatSuperset(
  childCaveats: readonly Caveat[],
  parentCaveats: readonly Caveat[],
): string | undefined {
  const childSet = new Set(childCaveats.map(canonicalCaveat));
  for (const pc of parentCaveats) {
    if (!childSet.has(canonicalCaveat(pc))) {
      return `parent caveat ${JSON.stringify(pc)} not present in child`;
    }
  }
  return undefined;
}

// ─── Chain Verification ─────────────────────────────────────────────────────

/**
 * Verify a delegation chain from leaf to root.
 *
 * The chain array is ordered **leaf-first**: `chain[0]` is the delegation
 * being exercised, `chain[chain.length - 1]` is the root (parentId === null).
 *
 * At each link, the function verifies:
 *   1. Cryptographic signature (via {@link verifyDelegationSignature})
 *   2. Subject-issuer linkage (child.issuerDid === parent.subjectDid)
 *   3. Capability attenuation (child caps ⊆ parent caps)
 *   4. Caveat accumulation (child caveats ⊇ parent caveats)
 *   5. Revocation status (via RevocationRegistry.isRevoked)
 *
 * Fails closed: any error — signature failure, broken linkage, broadened
 * scope, revoked link, or unexpected exception — produces a typed failure
 * result. No exceptions are thrown from verification paths.
 *
 * @param chain - Delegation chain, leaf-first. Must be non-empty.
 * @param revocationRegistry - Registry to check revocation at each link.
 * @param opts - Optional crypto provider, DID registry, key lookup, depth cap.
 * @returns Typed result: success with the verified chain, or failure with
 *          reason and the index where verification failed.
 */
export function verifyDelegationChain(
  chain: readonly Delegation[],
  revocationRegistry: RevocationRegistry,
  opts: ChainVerificationOptions = {},
): ChainVerificationResult {
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  // ── Empty chain rejection ──
  if (chain.length === 0) {
    return {
      valid: false,
      reason: 'empty chain',
      failedAtIndex: 0,
    };
  }

  // ── Depth cap ──
  if (chain.length > maxDepth) {
    return {
      valid: false,
      reason: `chain depth ${chain.length} exceeds maximum ${maxDepth}`,
      failedAtIndex: maxDepth,
    };
  }

  // ── Structural check: root must have null parentId ──
  const root = chain[chain.length - 1];
  if (root.parentId !== null) {
    return {
      valid: false,
      reason: 'chain root (last element) has non-null parentId — chain is incomplete',
      failedAtIndex: chain.length - 1,
    };
  }

  // ── Structural check: non-root links must have parentId ──
  for (let i = 0; i < chain.length - 1; i++) {
    if (chain[i].parentId === null) {
      return {
        valid: false,
        reason: `delegation at index ${i} has null parentId but is not the root`,
        failedAtIndex: i,
      };
    }
  }

  // ── Walk chain: verify each link ──
  try {
    for (let i = 0; i < chain.length; i++) {
      const del = chain[i];

      // 1. Signature verification
      const sigCheck = verifyDelegationSignature(
        del,
        opts.provider,
        opts.registry,
        opts.lookup,
      );
      if (!sigCheck.valid) {
        return {
          valid: false,
          reason: `signature verification failed at index ${i}: ${sigCheck.reason}`,
          failedAtIndex: i,
        };
      }

      // 2. Revocation check
      if (revocationRegistry.isRevoked(del.id)) {
        return {
          valid: false,
          reason: `delegation ${del.id} at index ${i} is revoked`,
          failedAtIndex: i,
        };
      }

      // 3. Chain linkage + attenuation (for non-root links)
      if (i < chain.length - 1) {
        const parent = chain[i + 1];

        // parentId linkage
        if (del.parentId !== parent.id) {
          return {
            valid: false,
            reason: `parentId mismatch at index ${i}: expected "${parent.id}", got "${del.parentId}"`,
            failedAtIndex: i,
          };
        }

        // Subject-issuer linkage: child was issued by parent's subject
        if (del.issuerDid !== parent.subjectDid) {
          return {
            valid: false,
            reason: `subject-issuer linkage broken at index ${i}: child.issuerDid (${del.issuerDid}) !== parent.subjectDid (${parent.subjectDid})`,
            failedAtIndex: i,
          };
        }

        // Capability attenuation: child caps ⊆ parent caps
        const capViolation = checkCapabilitySubset(
          del.capabilities,
          parent.capabilities,
        );
        if (capViolation !== undefined) {
          return {
            valid: false,
            reason: `capability broadening at index ${i}: ${capViolation}`,
            failedAtIndex: i,
          };
        }

        // Caveat accumulation: child caveats ⊇ parent caveats
        const cavViolation = checkCaveatSuperset(
          del.caveats,
          parent.caveats,
        );
        if (cavViolation !== undefined) {
          return {
            valid: false,
            reason: `caveat attenuation violation at index ${i}: ${cavViolation}`,
            failedAtIndex: i,
          };
        }
      }
    }
  } catch (err: unknown) {
    // Fail closed: unexpected errors produce typed failures.
    const message =
      err instanceof Error ? err.message : 'unknown verification error';
    return {
      valid: false,
      reason: `unexpected error during chain verification: ${message}`,
      failedAtIndex: 0,
    };
  }

  return {
    valid: true,
    chain,
  };
}
