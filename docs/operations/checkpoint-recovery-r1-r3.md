# Checkpoint: Identity Recovery R1–R3

**Date:** 2026-05-10
**Branch:** `feat/auth-slice-1-account-binding-login-challenge`
**Commits:** `679e863` (R1), `07ae363` (R1 fix), `424dd58` (R2+R3), `c56b21f` (R3 fix)
**Tests:** 2,302 pass / 130 files / 0 failures

---

## 1. Canonical Recovery Guarantees

These guarantees are implemented, tested, and load-bearing. Future work must not weaken them.

1. **Recovery evidence starts the ceremony, not live authority.** Recovery factors (seeds, guardian approvals) prove possession or social trust. They never grant direct operational authority.

2. **Time-lock and cancellation are first-class.** Every recovery path enforces a configurable time-lock between evidence submission and verification advancement. Cancellation during the time-lock reverts to frozen, clears quorum state, and invalidates all outstanding challenges for that identity.

3. **Completion requires three gates (no exceptions):**
   - At least one non-recovery-seed authenticator enrolled
   - Non-empty `rotationEventHash` provided
   - `verifyRotation` callback configured AND returning true

4. **Product-account rebinding is deferred and explicit.** Recovery completion unfreezes accounts (clears coordinator freeze flags) but does NOT rebind product-account bindings. Dissolved bindings stay dissolved. The caller must explicitly rebind via `ProductAccountBindingStore.bind()`.

5. **Heartbeat audit events cover the full ceremony path.** Every state transition emits a typed heartbeat event with structured JSON data including identity DID, ceremony ID, timestamps, and evidence metadata.

6. **Domain separation prevents cross-protocol replay.** Each ceremony type uses distinct signing domains. Recovery-seed: `soma/recovery-challenge/v1` + `soma/recovery-evidence/v1`. Guardian: `soma/guardian-challenge/v1` + `soma/guardian-approval/v1`. Signatures under one domain do not verify under another.

7. **Replay protection is structural.** Consumed challenge IDs are tracked. Challenges cannot be resubmitted after consumption. Cancellation moves outstanding challenges into the consumed set.

---

## 2. Implemented Recovery Paths

### R1: Identity Freeze + State Machine

**Files:** `src/heart/recovery-coordinator.ts`, `src/heart/runtime.ts`

- `IdentityRecoveryCoordinator` with state machine: nominal → frozen → pending → verifying → nominal
- `RecoveryStore` persistence interface with `InMemoryRecoveryStore`
- `isFrozen()` / `isAccountFrozen()` gate checks consulted by runtime before every authority-establishing flow
- `HeartRuntime.freezeIdentity()` composes: collect bound accounts → register freeze → invalidate sessions → dissolve bindings → record `identity_frozen` heartbeat
- Six authority flows gated: `issueProductSession`, `issueAdapterBridgeSession`, `createHumanSession`, `migrateAdapterToSomaDirect`, plus adapter-bridge re-entry guard on frozen accounts
- Account-level freeze tracking via reverse index (accountId → identityDid)

### R2: Recovery-Seed Ceremony

**Files:** `src/heart/recovery-seed-ceremony.ts`, `tests/heart/recovery-seed-ceremony.test.ts` (46 tests)

- `RecoverySeedCeremonyService` — standalone service, not embedded in runtime
- Challenge-response protocol: heart issues signed `RecoveryChallenge`, seed holder signs payload under evidence domain
- Ed25519 signature verification against `FactorRegistry` registered `publicMaterial`
- `submitRecoveryEvidence()` verifies signature, advances coordinator frozen → pending, starts time-lock
- `advanceToVerifying()` enforces time-lock expiry
- `completeRecovery()` enforces all three completion gates
- `cancelRecovery()` reverts pending → frozen
- `pruneExpired()` housekeeping for outstanding challenges
- Factor `markUsed()` on successful evidence submission
- `CeremonyEventEmitter` pattern decouples from `HeartbeatChain`

### R3: Guardian Quorum Recovery

**Files:** `src/heart/guardian-recovery-ceremony.ts`, `tests/heart/guardian-recovery-ceremony.test.ts` (50 tests)

- `GuardianRecoveryCeremonyService` — standalone service, same pattern as R2
- Per-guardian challenge issuance bound to ceremony ID
- `resolveGuardianKey` callback resolves guardian DID → Ed25519 public key
- `getGuardianConfig` callback resolves identity → `GuardianConfig` (threshold + guardian list)
- `QuorumState` tracks approvals per identity; duplicate approvals from same guardian rejected
- Time-lock starts at quorum (M-th approval), not first approval
- Cancellation invalidates all outstanding challenges for the identity (moved to consumed set)
- `getQuorumStatus()` exposes current approval count, threshold, approving guardian DIDs
- Same three completion gates as R2
- Tested quorum edge cases: 1-of-1, 3-of-5, time-lock-starts-at-quorum

---

## 3. Canonical Completion Gates

Every recovery path (seed, guardian, any future path) must enforce these before returning to nominal:

| Gate | Check | Failure message |
|------|-------|-----------------|
| 1. Authenticator enrollment | `factorRegistry.listActive()` has at least one factor with type ≠ `recovery-seed` | `no non-recovery-seed authenticator enrolled` |
| 2. Rotation hash | `opts.rotationEventHash` is truthy | `credential rotation event hash required` |
| 3. Verified rotation | `config.verifyRotation` is defined AND returns `true` | `verifyRotation callback not configured` or `credential rotation verification failed` |

If any gate fails, the coordinator stays in `verifying` state (or earlier). The identity remains frozen.

---

## 4. Explicitly Deferred

| Item | Status | Notes |
|------|--------|-------|
| Runtime convenience methods | Deferred | `HeartRuntime.recoverViaSeed()` / `recoverViaGuardians()` — not required; ceremony services are standalone and directly usable |
| Guardian notification delivery | Deferred | Email/push/in-app challenge delivery is a product-layer concern, not a ceremony protocol concern |
| Durable quorum state | Deferred | `QuorumState` is in-memory; production persistence would follow the `RecoveryStore` pattern |
| Guardian rotation mid-ceremony | Deferred | Adding/removing guardians during an active ceremony is not supported; config is read at challenge/approval time |
| Automatic rebinding on completion | Rejected | Explicit design decision — rebinding is caller-owned |
| Multi-evidence recovery (seed + guardian hybrid) | Deferred | Both paths use the same coordinator; composing them would require a meta-ceremony layer |
| Recovery audit log export | Deferred | Heartbeat events exist; a structured export/query API is not built |

---

## 5. Recommended Next Slice

**R4 is not the highest-value next step.**

The ceremony services are standalone and complete. Runtime integration (R4) would add convenience methods but no new trust guarantees. The higher-value next moves are:

1. **Wire `verifyRotation` to `CredentialRotationController` in a real integration test.** The callback contract is defined but no test verifies end-to-end rotation → recovery completion with a real controller. This is the thinnest remaining trust seam.

2. **Recovery-aware login flow.** Post-recovery, the caller must explicitly rebind accounts and issue fresh sessions. A tested integration path (freeze → recover → rebind → login) would prove the product-layer contract works.

3. **R4 (runtime convenience)** becomes worthwhile only if HeartRuntime is the primary entry point for callers. If ceremony services are used directly, R4 is optional.

---

## 6. What Product Layers Can Safely Rely On

| Primitive | Stable? | API surface |
|-----------|---------|-------------|
| `IdentityRecoveryCoordinator` | Yes | `freezeIdentity`, `isFrozen`, `isAccountFrozen`, `initiatePending`, `cancelRecovery`, `advanceToVerifying`, `completeRecovery`, `getStatus` |
| `RecoverySeedCeremonyService` | Yes | `createRecoveryChallenge`, `submitRecoveryEvidence`, `cancelRecovery`, `advanceToVerifying`, `completeRecovery`, `pruneExpired`, `outstandingCount` |
| `GuardianRecoveryCeremonyService` | Yes | `createGuardianChallenge`, `submitGuardianApproval`, `cancelRecovery`, `advanceToVerifying`, `completeRecovery`, `getQuorumStatus`, `pruneExpired`, `outstandingCount` |
| `GuardianConfig` / `validateGuardianConfig` | Yes | Schema validation for guardian metadata |
| `RecoveryStore` interface | Yes | `get`, `put`, `delete` — any durable backend can implement |
| Heartbeat event types | Yes | `identity_frozen`, `recovery_initiated`, `recovery_cancelled`, `recovery_verifying`, `recovery_completed`, `guardian_approval_received` |
| Completion gate contract | Yes | Three gates, no fallback, `verifyRotation` required |
| Rebinding contract | Yes | Deferred/explicit — callers must `bind()` post-recovery |

Product layers (HeyVera, login flows, admin tools) can build recovery UIs and server-side handlers against these APIs. The coordinator and ceremony services are the stable interface; runtime convenience methods (if added later) would delegate to them.

---

## 7. Lane Recommendation

**This lane should retarget.** R1–R3 are complete and the recovery ceremony protocol is structurally closed. The remaining recovery work (integration tests, login flow wiring) belongs in a product-integration lane, not this ceremony-protocol lane.
