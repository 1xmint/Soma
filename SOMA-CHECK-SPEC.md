# Soma Check — Conditional Payment Protocol

**Version:** `soma-check/1.0`
**Status:** Draft
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

## Motivation

Every production API payment protocol today — x402, ACP, AP2, L402 — charges unconditionally. An agent that polls a "BTC price" endpoint once per minute pays for 1,440 responses per day even though the price is only stale for, say, 30 seconds at a time. The other 23+ hours of payments are wasted on bytes the agent already holds.

**The ask:** a standardized way for a provider to tell a paying caller "nothing has changed since your last call, here's the hash, don't pay me" — without bespoke per-provider caching contracts.

Soma Check is that primitive. It reuses the content hash that Soma's birth certificates already publish (`dataHash`), so there is no additional signing cost: the hash that proves *provenance* is the same hash that drives *change detection*.

## Non-Goals

- **Replacing x402.** Soma Check is a **companion** to x402 (or any other payment protocol). It does not mint payments, does not handle settlement, and does not define wallet semantics.
- **Proving data is true.** Soma Check proves a content hash — not data correctness. A malicious provider can return `unchanged: true` for stale data; the resulting hash mismatch on eventual refetch is the accountability signal.
- **Full HTTP caching.** Soma Check is one header, one response shape. It does not replace `ETag` + `If-None-Match` (though it resembles them at the surface) because ETags do not carry cryptographic provenance and are not paywall-aware.

## Protocol

### Headers

| Header | Direction | Meaning |
|--------|-----------|---------|
| `If-Soma-Hash: <hash>` | Request | The caller's last-known hash for this resource |
| `X-Soma-Hash: <hash>` | Response | The provider's current content hash |
| `X-Soma-Protocol: soma-check/1.0` | Response | Protocol marker |

Hash values are opaque strings — providers SHOULD use lowercase hex SHA-256, but callers MUST treat them as opaque. The cryptographic binding comes from Soma birth certificates that carry the same `dataHash`.

### Flow

```
┌────────────┐                                   ┌────────────┐
│   Agent    │                                   │  Provider  │
└─────┬──────┘                                   └──────┬─────┘
      │                                                 │
      │  1. POST /endpoint (normal call, no hash)       │
      │ ───────────────────────────────────────────►    │
      │                                                 │
      │  2. 200 OK + body + X-Soma-Hash: abc123         │
      │ ◄───────────────────────────────────────────    │
      │                                                 │
      │     [agent stores hash keyed by resource]       │
      │                                                 │
      │  3. POST /endpoint + If-Soma-Hash: abc123       │
      │ ───────────────────────────────────────────►    │
      │                                                 │
      │  4a. If hash matches current:                   │
      │      200 OK + { unchanged: true, ... }          │
      │         + X-Soma-Hash: abc123                   │
      │         + 0 credits charged                     │
      │      OR                                         │
      │  4b. If hash differs or no cached entry:        │
      │      normal paid response + X-Soma-Hash: new    │
      │ ◄───────────────────────────────────────────    │
      │                                                 │
```

### Free Hash Probe (optional)

Providers MAY expose a dedicated hash endpoint for cheap freshness probes without a full call:

```
GET /endpoint/check

200 OK
{
  "dataHash": "abc123...",
  "cachedAt": "2026-04-04T12:00:00Z",
  "freshUntil": "2026-04-04T12:05:00Z",
  "fresh": true,
  "age": 42
}
```

This endpoint MUST be free (0 credits). It is syntactic sugar — the same information is available via `X-Soma-Hash` on a normal call.

### Unchanged Response Body

When `If-Soma-Hash` matches the provider's current hash, the response body SHOULD be:

```json
{
  "unchanged": true,
  "dataHash": "abc123...",
  "cachedAt": "2026-04-04T12:00:00Z",
  "fresh": true,
  "age": 42,
  "creditsUsed": 0,
  "protocol": "soma-check"
}
```

Providers MAY include additional fields (e.g. `requestId`, `endpointId`). Callers MUST tolerate unknown fields.

### Response Status Codes

| Code | Meaning |
|------|---------|
| `200 OK` | Normal response OR `unchanged: true` payload |
| `402 Payment Required` | Payment needed (standard x402) — Soma Check does not override |
| `400 Bad Request` | Malformed `If-Soma-Hash` (e.g. non-string, over 256 chars) |

Soma Check does NOT use `304 Not Modified` — the response is a full JSON body because callers may rely on the shape to detect a cache hit without inspecting headers.

## Semantics

### Idempotency & Pricing

- A request carrying `If-Soma-Hash` with a matching hash MUST NOT be billed.
- A request carrying `If-Soma-Hash` with a non-matching hash MUST be billed as a normal call.
- A request carrying no `If-Soma-Hash` MUST be treated as a normal call (backward compatible).

### Cache Invalidation

- Providers MUST update their published hash whenever the underlying data changes.
- Providers MAY publish a hash that includes TTL-within-hash (e.g. hash over `data + freshWindow`), but the default is hash over content only.
- Agents MUST NOT assume that `unchanged: true` implies data freshness — if an agent needs absolute freshness, it can send a request without `If-Soma-Hash`.

### Hash Collisions

Soma Check relies on SHA-256-sized hashes. Collision risk is negligible. Providers MUST NOT shorten hashes below 16 hex chars (64 bits); below that, targeted collisions become feasible.

### Compatibility with Soma Provenance

When Soma Check is combined with Soma birth certificates:
- `X-Soma-Hash` value MUST equal the `dataHash` in the accompanying birth certificate.
- Changing the cache without updating the birth certificate is a protocol violation and forfeits provenance guarantees.

## Implementation

### Provider (soma-heart)

```typescript
import {
  extractIfSomaHash,
  shouldRespondUnchanged,
  buildSomaCheckResponseHeaders,
  buildUnchangedResponse,
} from 'soma-heart';

app.post('/endpoint', (req, res) => {
  const incomingHash = extractIfSomaHash(req.headers);
  const currentHash = cache.getHash(req.url);

  // Always emit Soma Check response headers
  const headers = buildSomaCheckResponseHeaders(currentHash);
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);

  if (shouldRespondUnchanged(incomingHash, currentHash)) {
    return res.json(buildUnchangedResponse(currentHash, {
      cachedAt: cache.getCachedAt(req.url),
      age: cache.getAge(req.url),
      fresh: true,
    }));
  }

  // Normal paid flow...
});
```

### Consumer (soma-sense)

```typescript
import { createSmartFetch } from 'soma-sense';

const sfetch = createSmartFetch();

// First call — normal paid fetch
const r1 = await sfetch('https://api.example.com/price?symbol=BTC');
const price1 = await r1.json();

// Second call — sends If-Soma-Hash automatically
const r2 = await sfetch('https://api.example.com/price?symbol=BTC');
if (r2.somaCheck?.unchanged) {
  // Zero-cost: use cached body
  const price2 = r2.somaCheck.cachedBody;
}
```

## Relationship to Existing Standards

| Standard | Relationship |
|----------|--------------|
| **x402** | Orthogonal. x402 moves money; Soma Check decides whether money should move. |
| **HTTP ETag / If-None-Match** | Surface-similar, different semantics. ETag is a server-chosen opaque token; Soma Check hash is a content-addressed SHA-256 that matches a birth certificate. ETag has no payment semantics. |
| **HTTP Cache-Control** | Complementary. Providers can use both. |
| **JSON-LD Verifiable Credentials** | Orthogonal. Soma Check does not mandate credential format; it standardises a hash protocol. |

## Security Considerations

**Hash spoofing:** A malicious provider could claim `unchanged: true` while serving stale data. Detection: caller periodically refetches without `If-Soma-Hash` and compares. If data changed but the hash matched, the provider's Soma birth certificate signature chain becomes evidence of the lie.

**Replay of cached bodies:** Soma Check does not sign the cached body held by the consumer — the consumer trusts its own cache. If the consumer's local storage is tampered with, Soma Check provides no protection (but this is out-of-scope; it's a local-machine concern).

**DoS via hash probes:** The optional free `/check` endpoint is rate-limit-appropriate but uncached-expensive. Providers SHOULD rate limit anonymous `/check` calls.

**Information leakage:** The response `X-Soma-Hash` reveals when data changes. This is usually desirable but can leak timing information. Providers that consider this sensitive should not implement Soma Check for those endpoints.

## Changelog

- **1.0** (2026-04-04) — Initial draft.
