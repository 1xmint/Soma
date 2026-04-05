# Soma Delegation — Scoped, Bounded, Auditable Agent Authority Transfer

**Version:** `soma-delegation/0.1`
**Status:** Draft
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

## Motivation

Multi-agent systems delegate authority. A parent agent spawns children; children spawn grandchildren. Today's standard practice across CrewAI, AutoGen, MetaGPT, and LangGraph is to hand children the parent's full API key. This is unsafe:

- **No blast radius control** — one rogue child can drain the parent's wallet.
- **No scope narrowing** — children inherit every permission their parent has.
- **No depth limits** — delegation chains grow unbounded.
- **No cascade revoke** — killing a parent does not kill descendants.
- **No intent declaration** — providers cannot distinguish a research agent from an attacker.

IETF `draft-klrc-aiagent-auth-01` is attempting to standardize agent auth but does not address scoped spend delegation. Soma Delegation fills that gap with a minimal, implementable primitive for agent-to-agent authority transfer.

This spec formalizes the HTTP wire protocol. It builds on Soma's library-level delegation primitives (macaroon-style capability tokens with caveats) and defines how they are expressed over HTTP: headers, status codes, response shape, and enforcement semantics.

## Non-Goals

- **Replacing OAuth 2.0 or OIDC.** Soma Delegation targets agent-to-agent authority transfer, not user-facing consent flows.
- **Defining payment settlement.** Spend caps declared here are enforced by the issuing server; actual settlement is handled by x402 or equivalent payment protocols.
- **Cross-issuer trust registry.** v0.1 assumes a single issuing server per chain. Cross-platform federation is out of scope (see Open Questions).

## Concepts

### Delegation Key

A secondary credential issued by a parent credential, bound to one or more constraints:

| Constraint | Meaning |
|------------|---------|
| `depth` | Current depth in the chain (root = 0) |
| `max_depth` | How many further delegations the child may issue |
| `scope` | Subset of parent's permissions (endpoints, methods, per-call cost) |
| `spend_cap_usd` | Total value child + descendants may consume |
| `branch_spend_cap_usd` | Per-immediate-child ceiling |
| `intent` | Signed declaration of purpose + data domain |
| `ttl` | Wall-clock expiry |
| `parent_id` | Cryptographic link to the issuing key |

### Cascade

A parent revocation invalidates all descendants recursively. A parent expiry expires all descendants. Cascades are enforced by the issuing server via BFS subtree traversal.

### Scope Narrowing

A child's scope MUST be a strict subset of its parent's. A child cannot grant itself permissions the parent lacks. Enforced at BOTH issue time AND serving time.

### Intent Declaration

A signed statement at key creation: "this delegation exists to perform task T with data domain D." Providers MAY use this for pricing, rate-limiting, or refusal. Intent is advisory — but it is signed, so misrepresentation is attributable.

## Protocol

### Delegation Key Structure

```json
{
  "key_id": "dlg_8f2a...",
  "parent_id": "dlg_3c1e... | root_xyz",
  "depth": 2,
  "max_depth": 3,
  "scope": {
    "endpoints": ["helius.rpc.*", "claw.solscan.*"],
    "methods": ["GET", "POST"],
    "max_cost_per_call_usd": 0.05
  },
  "spend_cap_usd": 10.00,
  "spend_used_usd": 2.43,
  "branch_spend_cap_usd": 2.00,
  "intent": {
    "declaration": "Research agent: summarize daily DeFi TVL changes on Solana",
    "data_domain": "public-chain-data",
    "ttl_hours": 24
  },
  "expires_at": "2026-04-06T18:00:00Z",
  "issued_at": "2026-04-05T18:00:00Z",
  "issued_by_sig": "ed25519:3f8a...",
  "revoked": false
}
```

### Request Headers

| Header | Required | Direction | Meaning |
|--------|----------|-----------|---------|
| `Authorization` | yes | Request | `Bearer <key_id>` |
| `X-Soma-Delegation-Chain` | no | Request | JSON array of ancestor key_ids (oldest first) |
| `X-Soma-Intent` | no | Request | Repeat of `intent.declaration` for quick policy match |

### Response Headers (successful delegated call)

The issuing server SHOULD attach these headers on responses when the caller is using a delegated key:

| Header | Value |
|--------|-------|
| `X-Soma-Delegation-Chain` | Comma-separated masked key_ids, leaf first |
| `X-Soma-Delegation-Depth` | Leaf's `depth` integer |
| `X-Soma-Delegation-Hops` | Number of delegation hops (chain length) |
| `X-Soma-Delegation-Root` | Masked root credential |
| `X-Soma-Delegation-Intent` | Leaf's `intent.declaration` (if set) |
| `X-Soma-Protocol` | `soma-delegation/0.1` |

Key IDs MUST be masked (first 4 + last 4 chars) to preserve least-privilege disclosure — upstream providers learn the shape of the chain without gaining credentials.

### Response Headers (on rejection)

| Header | Value |
|--------|-------|
| `X-Soma-Delegation-Error` | One of: `DEPTH_EXCEEDED`, `SCOPE_VIOLATION`, `SPEND_CAP_EXCEEDED`, `BRANCH_CAP_EXCEEDED`, `REVOKED`, `EXPIRED`, `INTENT_REJECTED` |

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `401 Unauthorized` | key_id unknown or revoked |
| `402 Payment Required` | Spend cap exhausted (x402 semantics) |
| `403 Forbidden` | Scope violation or intent rejection |
| `410 Gone` | Key expired |

## Semantics

### Depth

- Root keys have `depth = 0`.
- A delegation increments depth: `child.depth = parent.depth + 1`.
- If `child.depth > parent.max_depth`, delegation is **rejected**.
- `max_depth` MAY only decrease down a chain: `child.max_depth <= parent.max_depth - 1`.

### Scope Narrowing

For each scope dimension:

```
child.scope ⊆ parent.scope
```

Specifically:

- `child.scope.endpoints` is a subset (by glob) of `parent.scope.endpoints`.
- `child.scope.methods` is a subset of `parent.scope.methods`.
- `child.scope.max_cost_per_call_usd <= parent.scope.max_cost_per_call_usd`.

Issuance with broadened scope is **rejected at creation time**. Scope is ALSO enforced at serving time — calls that don't match the child's scope get `403 SCOPE_VIOLATION`.

### Spend Caps

Two caps apply simultaneously:

**Total cap (`spend_cap_usd`):** hard limit on this key's cumulative spend including all descendants. Enforced at every call: `spend_used_usd + call_cost <= spend_cap_usd`.

**Branch cap (`branch_spend_cap_usd`):** per-immediate-child ceiling. When this key issues a child, that child's `spend_cap_usd <= branch_spend_cap_usd`.

Both caps roll up: a grandchild's spend counts toward the parent's and grandparent's `spend_used_usd`.

### Cascade Revoke

When a key is revoked:

1. Its `revoked` flag flips to true.
2. All keys with `parent_id = revoked_key_id` are revoked (recursively).
3. Implementations SHOULD use a transaction or recursive SQL query for consistency.

Soma-compliant servers MUST refuse calls from any key in the revoked subtree.

### Intent Declaration

`intent.declaration` is a free-text description signed by the parent at creation.
`intent.data_domain` is a structured enum:

```
public-chain-data | private-user-data | model-output | training-data | other
```

Providers MAY:

- Price differently per intent (`data_domain = training-data` may carry premium).
- Rate-limit per intent (declared "production" keys get higher quota than "research").
- Refuse to serve certain intents (e.g., adversarial probing).

Intent is advisory — providers enforce their own policy. But intent is signed, so misrepresentation is attributable.

## Examples

### CrewAI-style three-level chain

```
Root (user)        depth=0, max_depth=3, spend_cap=$100, scope=*
  └─ Crew Manager  depth=1, max_depth=2, spend_cap=$50, branch_cap=$10
       └─ Researcher  depth=2, max_depth=0, spend_cap=$10, scope={read-only, public-data}
```

- If Researcher tries to spawn a child → rejected (`max_depth=0`).
- If Researcher exhausts $10 → no more calls.
- If user revokes Root → Crew Manager and Researcher instantly revoked.

### AutoGen-style peer spawning

```
Root (app)         depth=0, max_depth=2, spend_cap=$200
  ├─ Planner       depth=1, max_depth=1, spend_cap=$50, intent="plan execution"
  ├─ Executor A    depth=1, max_depth=0, spend_cap=$30, intent="run subtask"
  └─ Executor B    depth=1, max_depth=0, spend_cap=$30, intent="run subtask"
```

If Planner reaches `spend_cap=$50` first, Planner stops but Executors A/B still run until their own caps.

### Adversarial scenario — rogue child

```
Root             spend_cap=$100, branch_cap=$10
  └─ Child (rogue)  spend_cap=$10 ← capped by branch_cap
```

Child burns $10 in 1 minute trying to DOS parent's wallet. Parent's remaining $90 is safe because `branch_cap=$10` was enforced at child creation.

## Comparison with Prior Art

| Feature | IETF draft-klrc | OAuth 2.0 | Capability systems | **Soma Delegation** |
|---------|-----------------|-----------|--------------------|---------------------|
| Auth token | yes | yes | yes | yes |
| Scope narrowing | partial | yes (scopes) | yes | **yes (issue + serving)** |
| Depth limits | no | no | rare | **yes** |
| Spend caps | no | no | no | **yes** |
| Branch caps | no | no | no | **yes** |
| Cascade revoke | no | no | partial | **yes** |
| Intent declaration | no | no | no | **yes** |
| Wire format | TBD | HTTP Bearer | various | HTTP + `X-Soma-*` |

**Soma Delegation's contribution:** the first standard with **spend-bounded delegation + cascade revoke + intent declaration** as first-class primitives.

## Implementation

A reference implementation is live in [ClawNet](https://github.com/1xmint/claw-net) (production since 2026-Q1).

### Issuer API

```typescript
// Create a delegation
POST /v1/economy/keys/delegate
{
  "label": "research-swarm-1",
  "spendLimit": 100,
  "expiresInHours": 24,
  "permissions": ["invoke", "query"],
  "maxDepth": 2,
  "branchSpendLimit": 25,
  "intentDeclaration": "price-oracle polling for backtest analysis",
  "dataDomain": "public-chain-data",
  "scopeEndpointsGlob": ["helius.rpc.*", "coingecko.prices.*"],
  "scopeMethodsCsv": "GET,POST"
}
→ 201 { "ok": true, "childKey": "cn-..." }

// Walk the lineage
GET /v1/economy/keys/delegated/:childKey/chain
→ 200 { "protocol": "soma-delegation/0.1", "leaf": "cn-...", "root": "cn-...",
        "depth": 2, "hops": 3, "chain": [...] }

// Cascade revoke
DELETE /v1/economy/keys/delegated/:childKey
→ 200 { "ok": true, "cascade": true, "revokedCount": 7 }
```

### Enforcement at serving time

Every call to `POST /v1/endpoints/:id/call` performs:

1. Key resolution + spend cap check.
2. Scope check: endpoint matches `scope_endpoints_glob`, method in `scope_methods_csv`.
3. On success: attach `X-Soma-Delegation-*` headers to response.
4. On failure: `403 + X-Soma-Delegation-Error: SCOPE_VIOLATION`.

### Storage schema (reference)

```sql
CREATE TABLE delegated_keys (
  child_key TEXT PRIMARY KEY,
  parent_key TEXT NOT NULL,
  depth INTEGER NOT NULL DEFAULT 0,
  max_depth INTEGER NOT NULL DEFAULT 0,
  spend_limit INTEGER NOT NULL,
  spent INTEGER NOT NULL DEFAULT 0,
  branch_spend_limit INTEGER,
  intent_declaration TEXT,
  data_domain TEXT,
  scope_endpoints_glob TEXT, -- JSON array
  scope_methods_csv TEXT,
  expires_at TEXT,
  revoked_at TEXT,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_delegated_parent ON delegated_keys(parent_key);
```

## Open Questions

1. **Intent rejection:** should providers return the reason in headers or keep it opaque (security trade-off)?
2. **Scope glob syntax:** shell-glob, regex, or URI template? Leaning shell-glob for simplicity.
3. **Spend cap roll-up visibility:** should children see their parent's remaining cap, or only their own? Leaning own-only (least privilege).
4. **Cascade revoke performance:** at depth > 10 with fan-out > 100, recursive revoke may be slow. Consider lazy mark-and-sweep.
5. **Cross-platform delegation:** if Key A is issued by Soma issuer X and Key B is issued by Soma issuer Y, how do providers verify the chain? Requires cross-issuer trust registry.
6. **Key rotation:** if parent rotates its signing key, do children need re-issuance?

## Roadmap

- **v0.2** — formal glob-subset semantics, cross-issuer trust registry design.
- **v0.3** — reference client SDK in `@soma/delegation` npm package.
- **v1.0** — IETF submission as input to `draft-klrc-aiagent-auth` working group.

## License

CC BY 4.0 — implementations and derivative specs encouraged.
