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
| `parent_id` | Reference to the immediately-preceding link in a delegation chain. For a root delegation (`depth = 0`), this points at the root issuer's credential, whose authority is anchored in a stable `identityId` under ADR-0004 D2 (see `Rotation Interaction`). For a nested delegation (`depth ≥ 1`), this is the parent delegation's `key_id`, used for cascade-revoke traversal (see `Cascade Revoke`); nested `parent_id` values are delegation-chain pointers, not identity anchors. |

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

## Rotation Interaction

Delegation verification under **root issuer credential rotation** is normatively defined in this section. Before this section was added, Open Question 6 treated the interaction as undefined; this section closes it, supersedes any earlier "current-key-bound root issuer" reading of a root delegation's issuer reference, and is the Soma#24 / Gate 5 (Slice C) closure required by ADR-0004 D2.

**Scope.** This section applies to **root delegations** — a `depth = 0` delegation whose `parent_id` points at the root issuer's rotating credential. Nested delegations (`depth ≥ 1`) are out of scope here: they are signed by their parent delegation's subject key, and delegation subject keys do not rotate in v0.1 (see *What this section does NOT resolve* below). Cascade-revoke semantics (`parent_id` as delegation-chain pointer for nested links, BFS traversal over `delegated_keys.parent_key`) are unchanged by this section.

Per ADR-0004's Readiness Horizon, Gate 5 (this section) MUST precede Gate 6 (`soma-heart` package surface) and Gate 7 (first-consumer implementation unlock). Merging this section satisfies `SOMA-ROTATION-SPEC.md` §13.2's "until `SOMA-DELEGATION-SPEC.md` is updated" condition for the normative text; the residual operational precondition — a working historical-credential lookup plus the wire-schema alignment described below — remains a Gate 4 / Slice D readiness item and a separate docs-hygiene follow-up respectively, not Gate 5 blockers.

### Root-issuer identity binding (normative)

A **root delegation** binds to the root issuer's **stable identity anchor**, not to the specific credential that produced `issued_by_sig`. Concretely:

- For a root delegation, the issuer reference (carried on the wire by the field(s) described under *Wire-schema dependency* below, and by the `parent_id` field of the root link as a legacy shorthand) resolves to a stable `identityId` (`SOMA-ROTATION-SPEC.md` §2.1). An identity persists across credential rotations; the credential currently bound to that identity MAY change over time, but the identity anchor MUST NOT.
- A root delegation's `issued_by_sig` was produced at `issued_at` by the root issuer's **then-effective** credential. After a root-issuer rotation, that credential is no longer current, but the signature math still verifies against the credential's public key as it existed at issue time.
- Existing root delegations therefore remain valid without re-issuance across a root-issuer rotation, provided the root issuer's identity anchor is unchanged and the delegation is still within its own lifetime constraints (`ttl`, `expires_at`, `revoked`, spend caps). Nested descendants inherit this property transitively: their validity chain walks back to a root delegation that remains valid.
- Cascade revoke (§Cascade Revoke) is unaffected. `parent_id` continues to function as the delegation-chain parent pointer for BFS traversal over `delegated_keys.parent_key`; revoking a delegation still revokes only its own subtree, not every other delegation under the same root identity.

This matches ADR-0004 D2 for the root link of a delegation chain: root delegations bind to identity, not credentials. Nested delegations continue to bind to their parent delegation key as before.

### Why this required a verification-model amendment

The v0.1 spec historically described `parent_id` as a "cryptographic link to the issuing key" and a root delegation's `issued_by_sig` as a signature under the root issuer's current signing key. Taken literally, that reading breaks under rotation of the root issuer's credential: after such a rotation, "the root issuer's current signing key" is a different key than the one that produced the original `issued_by_sig`, and a naive verifier would reject a still-valid root delegation even though the identity that authorised it is unchanged.

A conforming verifier therefore cannot resolve the signing key of a root delegation by reading "whatever credential is current for the root issuer right now." It MUST resolve the credential that was effective when the root delegation was issued, and verify against that credential's public key. This rule applies only to the root link of a delegation chain; nested-delegation verification (against the parent delegation's non-rotating subject key) is unchanged.

### v0.1 verification mechanism (normative)

ADR-0004 D2 and `SOMA-ROTATION-SPEC.md` §13.3 enumerated three candidate mechanisms for identity-bound delegation verification:

1. **Historical archive** — retain superseded parent public keys so historic `issued_by_sig` values still verify after rotation.
2. **Cascade re-signing** — re-issue every descendant delegation on every parent rotation. ADR-0004 D2 rejected this as the default on availability grounds.
3. **Signature-scheme redesign** — replace ed25519-over-credential signatures with identity-based signatures, BLS aggregation, or threshold schemes.

**v0.1 adopts Mechanism 1 (historical archive).** Mechanisms 2 and 3 are not adopted in v0.1. A superseding ADR is required to change the mechanism. Mechanism 2 MAY be re-added later as a policy-level option for specific delegation classes without superseding Mechanism 1.

Mechanism 1 is the minimal v0.1 pick for a concrete reason: the historical archive it requires already exists in the rotation subsystem. `SOMA-ROTATION-SPEC.md` §10.2 requires every controller snapshot to carry the complete rotation event chain, and every rotation event (`RotationEvent` in `src/heart/credential-rotation/types.ts`) carries the `newCredential` that became effective at that event, including its `publicKey`. The full history of an identity's effective credentials is therefore already recoverable by walking the event chain. Mechanism 1 re-uses state the rotation spec already requires; no additional persistence, no new cryptography, and no new signing scheme are needed.

### Wire-schema dependency (normative)

The Conforming Verifier Rule below keys its historical-credential lookup on a tuple of `(identityId, issuer_credential_id)` or `(identityId, issuer_public_key)`. Neither `issuer_credential_id` nor `issuer_public_key` is a field carried today by §Protocol · Delegation Key Structure or by the reference SQL schema (§Storage schema) of this spec. A spec-conforming **root delegation** MUST therefore additionally carry one of:

- `issuer_credential_id` — a reference resolvable to a `RotationEvent.newCredential` under the root issuer's `identityId` in the rotation subsystem; or
- `issuer_public_key` — the root issuer's then-effective credential public key, base64-encoded, paired with the algorithm suite recorded on that credential.

The in-code Soma delegation primitive at `src/heart/delegation.ts` already carries `issuerPublicKey` (and its matching `signature`) per delegation, which satisfies the `issuer_public_key` option and is sufficient for Mechanism 1 today. Aligning the wire format at §Protocol · Delegation Key Structure and the reference SQL schema at §Storage schema with the in-code primitive — by adding the chosen field to the wire JSON and a matching column to `delegated_keys` — is the pre-existing docs-hygiene tech debt called out under *What this section does NOT resolve* below. Until that alignment lands, the Conforming Verifier Rule is implementable against the in-code primitive but NOT against a minimal spec-conforming wire message; a spec-only implementer MUST treat delegation-under-rotation as unshippable until the wire follow-up merges. This is a docs/code hygiene follow-up, not a Gate 5 blocker: OQ6 semantic closure (the choice of identity-binding + Mechanism 1) is independent of the field names used to carry the issuer reference.

### Conforming verifier rule (normative)

A conforming delegation verifier MUST, before accepting the `issued_by_sig` of a **root delegation** (the `depth = 0` link at the base of a delegation chain):

1. Resolve the root delegation's issuer reference to the root issuer's stable `identityId` anchor.
2. Consult the rotation subsystem's read-only historical-credential lookup (see *Slice D code contract* below) to locate the credential that produced `issued_by_sig`. The lookup key is the pair `(identityId, issuer_credential_id)` when the root delegation carries `issuer_credential_id`, or `(identityId, issuer_public_key)` when it carries `issuer_public_key` (see *Wire-schema dependency* above for field semantics). The verifier MUST NOT assume that the root issuer's *current* credential is the one that signed.
3. Confirm that the returned credential was `effective` at `issued_at`. A credential that was staged-but-not-yet-effective at `issued_at`, or that was already revoked before `issued_at`, MUST NOT satisfy this check.
4. Verify `issued_by_sig` against the returned credential's public key using the algorithm suite recorded on that credential (`AlgorithmSuite`, `SOMA-ROTATION-SPEC.md` §2.4).
5. Reject the root delegation if any step fails: unknown identity, no matching historical credential, credential not effective at `issued_at`, or signature verification failure.

This rule applies only to the root link. Verification of a nested delegation's `issued_by_sig` is against the parent delegation's subject key (recorded when that parent delegation was issued) and does not consult the rotation subsystem, because delegation subject keys do not rotate in v0.1.

Verifiers MUST fail closed on any rotation-subsystem lookup error for a root delegation. A verifier that cannot consult the rotation subsystem at all MUST NOT accept root delegations across root-issuer rotation; such a verifier MAY only accept root delegations whose `issued_by_sig` matches the root issuer's *current* credential, and MUST treat that narrower behaviour as a strict subset of this section's rules, not as a replacement for them.

### Slice D code contract (normative)

The rotation subsystem MUST expose, as part of Gate 4 / Slice D, a read-only **historical-credential lookup** that answers the membership question required by the Conforming Verifier Rule. The lookup:

- MUST accept a query keyed by `(identityId, credentialId)` or `(identityId, publicKey)`.
- MUST walk the event chain of the addressed identity (§4 of `SOMA-ROTATION-SPEC.md`) and return either the full `Credential` record (including `publicKey`, `algorithmSuite`, `issuedAt`, and the `effective`/`revoked` window in which it was authoritative), or a typed "not found" result if no such credential exists in that identity's event chain.
- MUST be a pure read over existing rotation state. It MUST NOT mutate the event chain, the accepted pool, any rate-limit bucket, or any snapshot.
- MUST NOT depend on the accepted-pool grace window (`SOMA-ROTATION-SPEC.md` §6). It MUST return historical credentials regardless of whether their accepted-pool entry has aged out, because the delegation verifier needs long-lived historical truth, not the short-lived verify-before-revoke window.
- MUST NOT cross identity boundaries. A lookup against `identityId` A MUST NOT return credentials that were effective under `identityId` B, even if a `credentialId` or `publicKey` happens to collide.

Until this lookup lands, no first-consumer integration MAY ship delegation-under-rotation as a supported path. This matches the conditional restriction in `SOMA-ROTATION-SPEC.md` §13.2.

### What this section does NOT resolve

- **Delegation wire-schema alignment.** The existing `parent_id`, `issued_by_sig`, and storage-schema fields in this spec predate ADR-0004 and do not carry an explicit issuer-public-key column in the reference SQL schema. Aligning the wire schema and the storage schema with the macaroon-style primitive in `src/heart/delegation.ts` (which embeds `issuerPublicKey` and `signature` directly on each delegation) is pre-existing tech debt and is out of scope for OQ6 closure. A separate docs-hygiene PR may formalise the alignment; that work is NOT a Slice C deliverable and NOT a Gate 5 blocker.
- **Cross-issuer delegation.** Delegations that cross issuing authorities are still tracked under Open Question 5 (cross-platform delegation). Identity-binding within a single issuer is resolved by this section; cross-issuer resolution depends on the cross-issuer trust registry, which is out of v0.1 scope.
- **Delegation-key rotation.** This section closes OQ6 for the case where a *parent credential* rotates. It does not address rotation of a delegation key itself. Delegation keys in v0.1 are expected to expire or be revoked, not rotated; rotating a delegation key is a superseding-ADR concern.

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
6. **Key rotation (CLOSED — Gate 5 / Slice C):** resolved by the `Rotation Interaction` section above. A root delegation binds to the root issuer's stable `identityId`, not to a specific credential; existing root delegations remain valid across a root-issuer rotation without re-issuance, and nested descendants inherit validity transitively. v0.1 adopts the historical-archive verification mechanism (ADR-0004 D2, Mechanism 1), which depends on a Slice D / Gate 4 historical-credential lookup contract and a separate wire-schema alignment follow-up (to carry an explicit `issuer_credential_id` or `issuer_public_key` on root delegations); both are documented in that section.

## Roadmap

- **v0.2** — formal glob-subset semantics, cross-issuer trust registry design.
- **v0.3** — reference client SDK in `@soma/delegation` npm package.
- **v1.0** — IETF submission as input to `draft-klrc-aiagent-auth` working group.

## License

CC BY 4.0 — implementations and derivative specs encouraged.
