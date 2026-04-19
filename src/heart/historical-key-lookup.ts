/**
 * HistoricalKeyLookup — rotation-aware key validity interface.
 *
 * This is the consumer-facing interface that verifier call sites use to
 * check whether a public key was effective at a given timestamp. It
 * bridges the gap between verifiers (which only know issuerDid +
 * issuerPublicKey + issuedAt) and the rotation subsystem (which tracks
 * credential lifecycles with effectiveFrom/effectiveUntil windows).
 *
 * Callers construct a lookup closure that binds identity context
 * externally — the verifier never needs to know about identityId,
 * credential chains, or rotation events. This keeps each verifier's
 * API surface minimal.
 *
 * The canonical adapter from CredentialRotationController is:
 *
 * ```ts
 * const lookup: HistoricalKeyLookup = {
 *   resolve(publicKey, timestamp) {
 *     return controller.lookupHistoricalCredential(identityId, {
 *       kind: 'publicKey',
 *       publicKey,
 *     });
 *   },
 * };
 * ```
 *
 * See also: CredentialRotationController.lookupHistoricalCredential
 * in credential-rotation/controller.ts, which is the primary backend
 * for this interface.
 */

// ─── Result types ───────────────────────────────────────────────────────────

/**
 * Successful lookup: the key was found in some credential chain.
 *
 * `effectiveFrom` is the timestamp when the credential became effective
 * (i.e. when its introducing rotation event reached `effective` status).
 * `null` means the event is still `pending` or `anchored` — the
 * credential has never been authoritative, and a verifier MUST reject.
 *
 * `effectiveUntil` is the timestamp when a superseding credential became
 * effective, closing this credential's validity window. `null` means the
 * credential is still current (no superseding event, or superseding event
 * not yet effective).
 */
export interface HistoricalKeyLookupHit {
  readonly found: true;
  readonly effectiveFrom: number | null;
  readonly effectiveUntil: number | null;
}

/**
 * Typed not-found. Verifiers MUST treat both reasons as "not effective
 * at the given timestamp" and fail closed.
 */
export interface HistoricalKeyLookupMiss {
  readonly found: false;
  readonly reason: 'unknown-identity' | 'credential-not-in-chain';
}

export type HistoricalKeyLookupResult =
  | HistoricalKeyLookupHit
  | HistoricalKeyLookupMiss;

// ─── Lookup interface ───────────────────────────────────────────────────────

/**
 * A rotation-aware key validity resolver.
 *
 * `resolve(publicKey, timestamp)` checks whether `publicKey` was effective
 * at `timestamp`. The caller binds identity context (e.g. identityId)
 * into the implementation at construction time.
 *
 * Verifiers use this to close the key-verifier gap: instead of trusting
 * an embedded issuerPublicKey at face value, they confirm via the
 * rotation subsystem that the key was actually authoritative when the
 * artifact (delegation, revocation, birth certificate, disclosure) was
 * issued.
 */
export interface HistoricalKeyLookup {
  resolve(
    publicKey: Uint8Array,
    timestamp: number,
  ): HistoricalKeyLookupResult;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Check whether a lookup result indicates the key was effective at the
 * given timestamp. Encapsulates the effectiveFrom/effectiveUntil window
 * check so each verifier doesn't repeat this logic.
 *
 * Returns `{ effective: true }` if the key was valid at `timestamp`, or
 * `{ effective: false, reason }` with a typed reason string.
 */
export function checkKeyEffective(
  result: HistoricalKeyLookupResult,
  timestamp: number,
): { effective: true } | { effective: false; reason: string } {
  if (!result.found) {
    return {
      effective: false,
      reason: result.reason === 'unknown-identity'
        ? 'key lookup failed: unknown identity'
        : 'key lookup failed: credential not in chain',
    };
  }

  // effectiveFrom === null means the credential's introducing event
  // never reached `effective` status. Fail closed.
  if (result.effectiveFrom === null) {
    return { effective: false, reason: 'credential not yet effective (pending/anchored)' };
  }

  // The credential became effective AFTER the artifact was issued.
  if (result.effectiveFrom > timestamp) {
    return { effective: false, reason: 'credential not yet effective at issuedAt' };
  }

  // effectiveUntil !== null means a superseding credential became
  // effective. If it became effective AT or BEFORE the artifact's
  // timestamp, this credential was already rotated out.
  if (result.effectiveUntil !== null && result.effectiveUntil <= timestamp) {
    return { effective: false, reason: 'credential rotated out before issuedAt' };
  }

  return { effective: true };
}
