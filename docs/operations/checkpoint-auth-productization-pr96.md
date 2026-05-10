# Checkpoint: Auth Productization — PR #96

**Date:** 2026-05-10
**Branch:** `feat/auth-slice-1-account-binding-login-challenge`
**PR:** https://github.com/1xmint/Soma/pull/96
**Commits:** 5 slices (c950ac4 → 5974334)
**Stats:** 10 files changed, +3,172 / -100 lines, 2,150 tests passing, clean build

---

## 1. What is now canonical

### Primitives landed (all tested, exported, type-safe)

| Primitive | Module | Slice | Contract |
|---|---|---|---|
| `ProductAccountBindingStore` | `product-account-binding.ts` | 1 | 1:1 account ↔ Soma identity binding. `bind`, `unbind`, `rebind`, `getByIdentity`. |
| `LoginChallengeService` | `login-challenge.ts` | 1, 2 | Challenge-response login with signed `LoginVerification`. Carries `LoginCeremonyEvidence` with proven factors. |
| `LoginCeremonyEvidence` / `ProvenFactor` | `login-challenge.ts` | 2 | Structured record of what was actually proven. Tier derived from proven factors only — enrolled-but-unused factors do not inflate. |
| `TierLadder` integration | `login-challenge.ts` → `tier-ladder.ts` | 2 | `evaluateLadder` drives tier from `TierEvalInput` where `registeredActive` = proven factors. |
| `DeviceBinding` from evidence | `runtime.ts` | 2 | Strongest proven factor determines `deviceTrustLevel`. `LOGIN_TRUST_TO_DEVICE_TRUST` mapping. |
| `migrateAdapterToSomaDirect` | `runtime.ts` | 3 | Binding-and-reissue (not in-place mutation). Validates adapter session, verifies login, authorizes binding, issues new soma-direct session, revokes old. `authOrigin` is immutable provenance. |
| `resolveProductSession` | `runtime.ts` | 4A | Request-safe session resolution. Decay + expiry + revocation enforced on every call. No scheduler dependency. |
| `unbindAccountAndRevokeSessions` | `runtime.ts` | 4A | Atomic unbind + session revocation cascade. |
| `invalidateFactorSessions` | `runtime.ts` | 4B | Direct factor invalidation. Revokes sessions where `deviceBinding.factorId` matches. Unrelated factors ignored. Adapter-bridge (null binding) unaffected. |
| `invalidateIdentitySessions` | `runtime.ts` | 5 | Identity-level invalidation. Routes through binding store + belt-and-suspenders `revokeByIdentity`. Unbinds accounts, revokes sessions, records heartbeat. |
| `ProductSessionStore` extensions | `product-session-store.ts` | 4A, 4B, 5 | `revokeByAccount`, `revokeByFactor`, `revokeByIdentity`. |

### Heartbeat event types added

`adapter_migration_completed`, `adapter_migration_denied`, `account_binding_unbound`, `factor_sessions_invalidated`, `identity_sessions_invalidated`

### Invariants enforced

- **Tier truth from ceremony, not inventory.** `registeredActive` in `TierEvalInput` is populated from `ProvenFactor[]`, never from `FactorRegistry` enrollment.
- **`authOrigin` is immutable provenance.** An adapter-bridge session remains `adapter-bridge` even when revoked, migrated-from, or invalidated. Audit trail is never rewritten.
- **Scheduler-free correctness.** Expiry, decay, and revocation are all enforced on the request path (`resolveProductSession` / `resolveProductSessionToken`). `prune()` is optional cleanup, not correctness.
- **No silent binding.** Adapter-to-direct migration requires explicit binding authorization. Binding conflicts are rejected, not overwritten.
- **Direct invalidation only.** Factor and identity invalidation are scoped to sessions that *currently* derive authority from the revoked factor/identity. No blanket kill-all.

---

## 2. What product layers can safely rely on

### Login and session issuance

A product server can now:
- Register factors via `FactorRegistry`
- Configure a `TierLadder` for deployment-specific tier policy
- Create a `LoginChallengeService` and run `verifyLogin` / `verifyMultiFactorLogin`
- Issue `ProductSession` from the `LoginVerification` via `issueProductSessionFromLogin`
- Issue adapter-bridge sessions via `issueAdapterBridgeSession` (capped at L1)
- Mint opaque tokens via `mintProductSessionToken`

### Request-path session resolution

For every protected request:
- `resolveProductSession(sessionId)` — if holding sessionId directly
- `resolveProductSessionToken(token)` — if holding opaque token

Both enforce expiry, decay, and revocation. The returned session's `currentAuthorityTier` is always the decayed truth.

### Session lifecycle operations

- **Step-up:** `elevateProductSession` (in-place tier elevation with decay window)
- **Unbind:** `unbindAccountAndRevokeSessions` (dissolve binding + revoke all account sessions)
- **Factor compromise:** `invalidateFactorSessions(factorId)` (revoke sessions backed by that factor)
- **Identity compromise:** `invalidateIdentitySessions(did, bindingStore)` (revoke all sessions for that identity across accounts)
- **Migration:** `migrateAdapterToSomaDirect` (adapter → soma-direct with new session)

### What product layers should NOT rely on yet

- Persistent storage — stores are in-memory; durable backends are caller-owned
- Recovery — no re-establishment ceremony after compromise invalidation
- HTTP middleware — cookie/header/CORS integration is product-layer
- Multi-identity binding — 1:1 only, multi-identity explicitly deferred
- Blanket factor policy — "subject has no valid factors left" is not implemented

---

## 3. What is explicitly deferred

| Item | Why deferred | Blocked on |
|---|---|---|
| Recovery ceremony | Requires guardian/escrow flow design, key reconstruction protocol | Key escrow architecture decision |
| Blanket factor-revocation policy | "All factors for a subject revoked" requires policy layer proving no valid factors remain | Multi-factor enrollment being a product requirement |
| Pre-step-up binding restoration | Downgrade instead of revoke when step-up factor is revoked | Requires `loginDeviceBinding` field on ProductSession |
| Product HTTP middleware | Cookie issuance, refresh tokens, CORS/CSP | Product-specific, not Soma core |
| Persistent storage adapters | Durable ProductSessionStore / BindingStore backends | Deployment architecture decision |
| Multi-identity binding | One Soma identity backing multiple accounts or vice versa | Product requirement clarity |
| Session transfer / federation | Cross-product-shell session portability | Commerce/rooms architecture |

---

## 4. Next Soma frontiers after auth

### 4a. Recovery

**What:** Re-establish identity and sessions after `invalidateIdentitySessions` has run. The identity is suspended — how does the human get back in?

**Depends on:** Key escrow (`splitSecret` / `reconstructSecret` already in soma-heart), guardian attestation flow, a new ceremony type that proves identity continuity without the compromised credential.

**Scope:** Recovery ceremony definition, `CredentialRotationController` integration for post-recovery key rotation, new `ProductSession` issuance from recovery evidence.

**Risk:** Medium. The escrow primitives exist; the ceremony design is the gap.

### 4b. Commerce / entitlements

**What:** Soma-backed payment authorization and entitlement enforcement. A `ProductSession` at a given tier gates access to paid features.

**Depends on:** Soma Check protocol (already landed: `buildSomaCheckRequestHeaders`, `SomaCheckHashStore`), spend receipts (`SpendLog`, `signSpendHead`), and a product-layer entitlement model.

**Scope:** Entitlement claims on ProductSession, spend-budget enforcement per session, receipt chain for payment proof.

**Risk:** Low for the Soma primitives (spend receipts exist). Medium for the product-layer entitlement model (HeyVera-specific).

### 4c. Secure rooms / custody

**What:** Multi-party session contexts where participants present mutual proof-of-possession and share authority within a bounded scope.

**Depends on:** Mutual session PoP (`initiateSession` / `acceptSession` / `confirmSession` already in soma-heart), delegation chains with caveats, threshold signing for shared custody.

**Scope:** Room session type, participant authority negotiation, custody key ceremony.

**Risk:** High. Multi-party coordination adds complexity. The primitives exist but the orchestration is novel.

---

## 5. Recommendation

**Close this lane. Open recovery as the next bounded target.**

PR #96 delivers a complete, tested, scheduler-free auth/session lifecycle substrate. Every invalidation path — expiry, decay, factor compromise, identity compromise, binding dissolution, adapter migration — has a canonical runtime method, heartbeat trail, and test coverage.

The product layer (HeyVera) can build login, session management, and authority enforcement on this substrate today. What it cannot do yet is recover from identity compromise — and that's the gap that will matter first in production.

Recovery is the natural next lane because:
1. It's the only path that re-enters the auth lifecycle after `invalidateIdentitySessions` runs
2. The escrow and rotation primitives already exist in soma-heart
3. It's bounded — a ceremony definition + runtime wiring, not open-ended architecture
4. Commerce and rooms both assume a working identity; recovery ensures the identity can survive

The auth lane should not retarget — its scope is complete. A new `s18-soma-recovery-ceremony` supervisor session is the right container for the next work.
