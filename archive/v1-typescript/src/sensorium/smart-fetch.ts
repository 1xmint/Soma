/**
 * smartFetch — consumer-side Soma Check helper.
 *
 * Drop-in replacement for `fetch()` that automatically:
 *   1. Stores the `X-Soma-Hash` from every response
 *   2. Sends `If-Soma-Hash` on subsequent calls to the same URL
 *   3. Returns cached content when the server responds `{ unchanged: true }`
 *
 * When data hasn't changed, the response body is replayed from the consumer's
 * local cache — zero provider cost, zero parsing overhead.
 *
 * @example
 * ```ts
 * import { createSmartFetch } from "soma-sense";
 *
 * const sfetch = createSmartFetch();
 *
 * // First call — normal paid fetch
 * const r1 = await sfetch("https://api.example.com/price?symbol=BTC");
 * const price1 = await r1.json();
 *
 * // Second call — sends If-Soma-Hash automatically
 * // If unchanged, returns the cached body with { unchanged: true, dataHash, ... }
 * const r2 = await sfetch("https://api.example.com/price?symbol=BTC");
 * if (r2.somaCheck?.unchanged) {
 *   // Zero-cost: use cached body
 *   const price2 = r2.somaCheck.cachedBody;
 * }
 * ```
 */

import {
  SOMA_CHECK_HEADERS,
  buildSomaCheckRequestHeaders,
  extractSomaHash,
  SomaCheckHashStore,
} from '../core/soma-check.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SmartFetchConfig {
  /** Custom hash store — defaults to in-memory `SomaCheckHashStore`. */
  hashStore?: SomaCheckHashStore;
  /**
   * Override the underlying fetch implementation. Defaults to globalThis.fetch.
   * Useful for testing or custom transports.
   */
  fetchImpl?: typeof fetch;
  /**
   * Cache body keyed by URL — when server responds `unchanged: true`,
   * return the cached body from this store. Defaults to an in-memory Map.
   */
  bodyCache?: Map<string, unknown>;
  /** Callback invoked whenever Soma Check saves a request (0-cost hit). */
  onSaved?: (url: string, dataHash: string) => void;
}

export interface SomaCheckMeta {
  /** True if the server responded with `unchanged: true` and we served from cache. */
  unchanged: boolean;
  /** The current dataHash as known to the server. */
  dataHash: string | null;
  /** The cached body, if `unchanged` is true. */
  cachedBody?: unknown;
  /** Age of the server's cached entry, if provided. */
  age?: number;
  /** Whether the server's cached entry was still fresh. */
  fresh?: boolean;
}

/** A `Response` augmented with Soma Check metadata. */
export interface SmartResponse extends Response {
  somaCheck?: SomaCheckMeta;
}

// ─── Key Normalization ──────────────────────────────────────────────────────

/**
 * Normalize a URL to a stable cache key — strips trailing slashes and
 * orders query params so `?a=1&b=2` and `?b=2&a=1` hit the same entry.
 */
export function hashKeyForUrl(url: string): string {
  try {
    const u = new URL(url);
    // Sort query params for stable keying
    const params = Array.from(u.searchParams.entries()).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    const search =
      params.length > 0
        ? '?' + params.map(([k, v]) => `${k}=${v}`).join('&')
        : '';
    const path = u.pathname.replace(/\/+$/, '') || '/';
    return `${u.protocol}//${u.host}${path}${search}`;
  } catch {
    // Not a full URL — return as-is
    return url;
  }
}

// ─── smartFetch Factory ─────────────────────────────────────────────────────

/**
 * Create a smart fetch function with its own hash store + body cache.
 * Multiple callers can share a single instance, or create separate ones.
 */
export function createSmartFetch(config: SmartFetchConfig = {}) {
  const hashStore = config.hashStore ?? new SomaCheckHashStore();
  const bodyCache = config.bodyCache ?? new Map<string, unknown>();
  const fetchImpl =
    config.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);

  if (!fetchImpl) {
    throw new Error(
      'smartFetch: no fetch implementation available. Provide `fetchImpl` in config or use in a fetch-enabled environment.',
    );
  }

  return async function smartFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<SmartResponse> {
    const url = typeof input === 'string' ? input : input.toString();
    const cacheKey = hashKeyForUrl(url);

    // Inject If-Soma-Hash if we have a stored hash for this URL
    const lastHash = hashStore.get(cacheKey);
    const headers = new Headers(init?.headers);
    if (lastHash) {
      const { [SOMA_CHECK_HEADERS.IF_SOMA_HASH]: hashHeader } =
        buildSomaCheckRequestHeaders(lastHash);
      headers.set(SOMA_CHECK_HEADERS.IF_SOMA_HASH, hashHeader);
    }

    const response = (await fetchImpl(input as any, {
      ...init,
      headers,
    })) as SmartResponse;

    // Read current hash from response headers and update store
    const currentHash = extractSomaHash(response.headers);
    if (currentHash) {
      hashStore.set(cacheKey, currentHash);
    }

    // If status is 200 and body is JSON with `unchanged: true`, serve cached
    if (response.ok && currentHash === lastHash && lastHash) {
      const cloned = response.clone();
      try {
        const body = (await cloned.json()) as any;
        if (body && body.unchanged === true) {
          const cached = bodyCache.get(cacheKey);
          response.somaCheck = {
            unchanged: true,
            dataHash: currentHash,
            cachedBody: cached,
            age: typeof body.age === 'number' ? body.age : undefined,
            fresh: typeof body.fresh === 'boolean' ? body.fresh : undefined,
          };
          config.onSaved?.(url, currentHash);
          return response;
        }
      } catch {
        // Not JSON or malformed — fall through
      }
    }

    // Cache the body for next time (so a future `unchanged` response can replay it)
    if (response.ok) {
      const cloned = response.clone();
      try {
        const body = await cloned.json();
        bodyCache.set(cacheKey, body);
        response.somaCheck = {
          unchanged: false,
          dataHash: currentHash,
        };
      } catch {
        // Non-JSON body — skip body caching but still expose hash meta
        response.somaCheck = {
          unchanged: false,
          dataHash: currentHash,
        };
      }
    }

    return response;
  };
}

/**
 * Default shared smart fetch — convenient for quick use but all callers
 * in a process share one cache. For isolation, use `createSmartFetch()`.
 */
export const smartFetch = createSmartFetch();
