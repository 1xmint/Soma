/**
 * Soma Check — conditional payment protocol (soma-check/1.0)
 *
 * The first conditional payment protocol for APIs. Agents check a content
 * hash before paying — if data hasn't changed, they pay nothing. Built on
 * the existing birth-certificate `dataHash`, so the primitive that proves
 * provenance also drives change detection.
 *
 * Headers:
 *   Request:  `If-Soma-Hash: <hash>` — agent's last-known hash for this resource
 *   Response: `X-Soma-Hash: <hash>` — current content hash
 *             `X-Soma-Protocol: soma-check/1.0`
 *
 * Flow:
 *   1. Agent calls an endpoint normally → gets response with X-Soma-Hash
 *   2. Agent stores hash, keyed by URL/resource
 *   3. Next time, agent sends If-Soma-Hash with the stored hash
 *   4. If server's current hash matches → { unchanged: true }, 0 cost
 *   5. If different → normal paid response with new hash
 *
 * Backward compatible: clients that don't send If-Soma-Hash pay normally.
 */

// ─── Protocol Constants ─────────────────────────────────────────────────────

export const SOMA_CHECK_PROTOCOL = 'soma-check/1.0';

export const SOMA_CHECK_HEADERS = {
  /** Request header — agent's last-known hash. */
  IF_SOMA_HASH: 'If-Soma-Hash',
  /** Response header — current content hash. */
  X_SOMA_HASH: 'X-Soma-Hash',
  /** Response header — protocol version marker. */
  X_SOMA_PROTOCOL: 'X-Soma-Protocol',
} as const;

// ─── Types ──────────────────────────────────────────────────────────────────

/** A Soma Check response body when data is unchanged (0-cost hit). */
export interface UnchangedResponse {
  unchanged: true;
  dataHash: string;
  /** ISO-8601 timestamp of when the hash was last computed. */
  cachedAt?: string;
  /** Whether the cached entry is still fresh (vs. stale-but-matching). */
  fresh?: boolean;
  /** Age of the cache entry in seconds. */
  age?: number;
  /** Protocol marker. */
  protocol: 'soma-check';
  creditsUsed?: 0;
}

/** Metadata describing a cached resource for a check response. */
export interface CheckMetadata {
  cachedAt?: string | Date;
  freshUntil?: string | Date;
  fresh?: boolean;
  age?: number;
}

// ─── Header Builders ────────────────────────────────────────────────────────

/**
 * Build the response headers a provider should emit on every call.
 * Agents use the `X-Soma-Hash` value in their next `If-Soma-Hash` request.
 */
export function buildSomaCheckResponseHeaders(dataHash: string): Record<string, string> {
  return {
    [SOMA_CHECK_HEADERS.X_SOMA_HASH]: dataHash,
    [SOMA_CHECK_HEADERS.X_SOMA_PROTOCOL]: SOMA_CHECK_PROTOCOL,
  };
}

/**
 * Build the request headers for a consumer sending `If-Soma-Hash`.
 */
export function buildSomaCheckRequestHeaders(lastKnownHash: string): Record<string, string> {
  return {
    [SOMA_CHECK_HEADERS.IF_SOMA_HASH]: lastKnownHash,
  };
}

// ─── Header Parsers ─────────────────────────────────────────────────────────

/**
 * Extract the `If-Soma-Hash` value from a request's headers.
 * Returns null if header is missing. Headers are read case-insensitively.
 */
export function extractIfSomaHash(
  headers: Record<string, string> | Headers | undefined | null,
): string | null {
  if (!headers) return null;
  const lookup = headerLookup(headers);
  return (
    lookup('if-soma-hash') ??
    lookup('If-Soma-Hash') ??
    null
  );
}

/**
 * Extract the current `X-Soma-Hash` from a response's headers.
 * Consumers store this to send back as `If-Soma-Hash` on next call.
 */
export function extractSomaHash(
  headers: Record<string, string> | Headers | undefined | null,
): string | null {
  if (!headers) return null;
  const lookup = headerLookup(headers);
  return (
    lookup('x-soma-hash') ??
    lookup('X-Soma-Hash') ??
    null
  );
}

/** Check whether a response was served via Soma Check (carries protocol header). */
export function isSomaCheckResponse(
  headers: Record<string, string> | Headers | undefined | null,
): boolean {
  if (!headers) return false;
  const lookup = headerLookup(headers);
  const protocol = lookup('x-soma-protocol') ?? lookup('X-Soma-Protocol');
  return typeof protocol === 'string' && protocol.startsWith('soma-check/');
}

// ─── Provider-Side Helpers ──────────────────────────────────────────────────

/**
 * Given a cached data hash and an incoming request's `If-Soma-Hash` header,
 * decide whether the provider should respond with `unchanged: true` (0 cost)
 * instead of doing the full paid fetch.
 *
 * Returns null if there's no match (caller should proceed with normal flow).
 */
export function shouldRespondUnchanged(
  incomingHash: string | null,
  currentHash: string | null,
): boolean {
  if (!incomingHash || !currentHash) return false;
  return incomingHash === currentHash;
}

/**
 * Build the response body for a cache hit where hash hasn't changed.
 * The caller is responsible for setting the response headers separately
 * via `buildSomaCheckResponseHeaders(dataHash)`.
 */
export function buildUnchangedResponse(
  dataHash: string,
  meta?: CheckMetadata,
): UnchangedResponse {
  const cachedAt =
    meta?.cachedAt instanceof Date ? meta.cachedAt.toISOString() : meta?.cachedAt;
  const body: UnchangedResponse = {
    unchanged: true,
    dataHash,
    protocol: 'soma-check',
    creditsUsed: 0,
  };
  if (cachedAt) body.cachedAt = cachedAt;
  if (typeof meta?.fresh === 'boolean') body.fresh = meta.fresh;
  if (typeof meta?.age === 'number') body.age = meta.age;
  return body;
}

// ─── Consumer-Side Helpers ──────────────────────────────────────────────────

/**
 * In-memory hash store keyed by URL/resource.
 * For production use, persist this to disk or a small KV store.
 */
export class SomaCheckHashStore {
  private readonly hashes = new Map<string, string>();

  get(key: string): string | undefined {
    return this.hashes.get(key);
  }

  set(key: string, hash: string): void {
    this.hashes.set(key, hash);
  }

  has(key: string): boolean {
    return this.hashes.has(key);
  }

  delete(key: string): boolean {
    return this.hashes.delete(key);
  }

  clear(): void {
    this.hashes.clear();
  }

  size(): number {
    return this.hashes.size;
  }

  entries(): IterableIterator<[string, string]> {
    return this.hashes.entries();
  }
}

// ─── Internals ──────────────────────────────────────────────────────────────

function headerLookup(
  headers: Record<string, string> | Headers,
): (name: string) => string | null {
  if (typeof (headers as Headers).get === 'function') {
    return (name: string) => (headers as Headers).get(name);
  }
  const lowered: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers as Record<string, string>)) {
    lowered[k.toLowerCase()] = v;
  }
  return (name: string) => lowered[name.toLowerCase()] ?? null;
}
