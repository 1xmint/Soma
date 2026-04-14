# Soma Rotation — Credential Rotation Protocol

**Version:** `soma-rotation/0.1`
**Status:** Draft
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

> v0.1 is a **narrow-assurance** rotation contract. It is non-independent
> single-witness for the first consumer — see §7. It does not specify
> break-glass, panic freeze, or M-of-N recovery; those are deferred to a
> future ADR. v0.1 is the minimum contract needed to ratify the existing
> `src/heart/credential-rotation/` subsystem per ADR-0004 and to unblock
> claw-net as first consumer.

## Motivation

Soma ships rotation code that behaves as if a normative spec exists.
`src/heart/credential-rotation/types.ts` cites "architecture doc §13c"
and "§14 L1-L3"; neither document exists in this repo. Two parallel
rotation subsystems coexist with no normative ruling on which is
canonical. `soma-heart` v0.3.0 already exposes
`./credential-rotation` as a public subpath while the normative
contract lives only in source comments. ClawNet has shadow-adopted
this surface via claw-net PR #30 and PR #31 (inert backend).

ADR-0004 resolved the seven decisions this spec is now normative on.
This document makes those decisions citable, testable, and
implementer-facing.

## Non-Goals

- **Break-glass ceremony.** Panic freeze, key quarantine, and
  operator-driven recovery after confirmed compromise are out of
  scope for v0.1. See §7.3 and ADR-0004 D4.
- **M-of-N witness quorum.** v0.1 is explicitly single-witness. See §7.
- **Delegation semantics under rotation.** This spec records the
  *intended* interaction only. Normative delegation behaviour under
  parent rotation is owned by `SOMA-DELEGATION-SPEC.md` and is closed
  by Slice C / Gate 5. See §13.
- **Unifying `src/heart/key-rotation.ts` with
  `src/heart/credential-rotation/`.** v0.1 names the canonical
  substrate but does not rewrite either.
- **Changing `CredentialBackend` interface shape.** v0.1 ratifies the
  existing interface. Interface evolution is a future ADR concern.
- **Post-quantum hybrid suites.** `ed25519+ml-dsa-65` and
  `secp256k1+ml-dsa-65` are reserved identifiers only; v0.1 normatively
  supports `ed25519` as the only in-allowlist suite.

## Terminology

| Term | Meaning |
|---|---|
| **Identity** | Long-lived anchor (`identityId`) that persists across rotations. |
| **Credential** | A keypair bound to an identity at a point in time. Rotates underneath the identity. |
| **Backend** | Pluggable implementation of the algorithm-specific half of the primitive: mint / sign / verify / stage / commit / abort / revoke / discard. |
| **Controller** | The generic `CredentialRotationController`. Enforces policy and invariants; holds no secret material. |
| **Manifest** | `(backendId, algorithmSuite, publicKey)` — the public description of a credential. |
| **Commitment** | A content-addressed digest over the *next* credential's manifest (L1). |
| **Rotation event** | Append-only signed record of a credential transition, lifecycle-tracked through `pending → anchored → witnessed → effective → revoked`. |
| **Staged rotation** | The window between `stageNextCredential` and `commitStagedRotation` / `abortStagedRotation`. |
| **Accepted pool** | Previously-effective credentials retained for a grace window so in-flight verifies do not fail on a clean rotation. |
| **Witness** | Any external observer that cosigns the anchoring root for a rotation event. See §7 for v0.1 assurance bound. |

## 1. Canonical Subsystem

`src/heart/credential-rotation/` is the **canonical consumer-facing**
rotation substrate. `src/heart/key-rotation.ts` is an internal
KERI-style log primitive. Downstream packages MUST NOT import
`key-rotation.ts` directly. A future ADR MAY use it as
`credential-rotation/`'s L1 log backend or deprecate it; v0.1 does
neither.

`soma-heart`'s `package.json` `exports` field surfaces
`./credential-rotation` as the public subpath. No other rotation
surface is normative.

## 2. Core Primitives

### 2.1 Identity

An identity is a stable anchor string (`identityId`) that persists
across rotations. The credential currently bound to an identity MAY
change over time; the identity itself MUST NOT. Audit history, birth
certificates, and downstream references (delegation `parent_id`, where
Slice C lands identity-binding) anchor on `identityId`, not on
`credentialId`.

### 2.2 Credential

A live credential is the tuple:

```
(credentialId, identityId, backendId, algorithmSuite, class,
 publicKey, issuedAt, expiresAt, nextManifestCommitment)
```

`credentialId` is unique within `(backendId, identityId)`. Secret
material never leaves the backend (invariant 2). The controller stores
only the public fields.

### 2.3 Credential Class

Exactly three classes are defined: `A`, `B`, `C`. See §9 for the
mechanism-vs-default boundary. Adding or removing a class is a
superseding-ADR change, not a configurable policy choice.

### 2.4 Algorithm Suite

`AlgorithmSuite` is one of:

```
ed25519 | ed25519+ml-dsa-65 | secp256k1 | secp256k1+ml-dsa-65
```

v0.1 normatively supports `ed25519` only. The three hybrid suites are
reserved identifiers. A backend declaring a hybrid suite MUST pass a
hybrid-verify test before a conforming controller MAY add it to any
`suiteAllowlist`. Controllers MUST reject rotation into a suite not
present in the allowlist at the time of the rotation event
(`SuiteDowngradeRejected`, invariant 1).

## 3. Pre-Rotation Commitment (L1)

Every credential MUST carry `nextManifestCommitment`, a
content-addressed digest over the manifest of the credential that
will replace it. This is L1.

### 3.1 Commitment Inputs

The commitment is computed over the *next* credential's full manifest:

```
manifest = (backendId, algorithmSuite, publicKey)
```

Committing the whole manifest (not just the public key) closes a
cross-suite confusion attack: an adversary who obtains a future
private key cannot reuse its public key under a different suite or
backend.

### 3.2 Canonical Encoding

The commitment input MUST be serialised as the ASCII string:

```
soma-manifest:<backendId>|<algorithmSuite>|<base64(publicKey)>
```

Where:

- `<backendId>` is the opaque backend id, as declared by the backend
  at registration time. It MUST NOT contain any byte that acts as a
  delimiter in this encoding — specifically the ASCII `|` (U+007C)
  and `:` (U+003A) separator bytes — and MUST NOT contain the NUL
  byte (U+0000). Backend registration and policy validation MUST
  reject any `backendId` carrying a prohibited byte before that
  backend is admitted to the `backendAllowlist`, so no malformed id
  can reach the commitment encoder (see §15).
- `<algorithmSuite>` is one of the `AlgorithmSuite` values listed in
  §2.4, transmitted verbatim.
- `<base64(publicKey)>` is the standard base64 (RFC 4648, with
  padding) encoding of the raw public key bytes as the backend
  exposes them.

The three `<backendId>` byte restrictions are not interchangeable and
have distinct rationales:

- **`|` (U+007C) — collision-critical.** `|` is the field separator
  between `<backendId>`, `<algorithmSuite>`, and `<base64(publicKey)>`
  in the v0.1 encoding. A `|` inside `<backendId>` makes the
  concatenation ambiguous at the byte level: two different
  `(backendId, algorithmSuite, publicKey)` triples can produce
  identical encoded input bytes, and therefore identical commitment
  digests. Rejecting `|` is required for commitment uniqueness under
  the current encoder.
- **`:` (U+003A) — prefix delimiter, reserved for canonicalization
  and forward-compatible encoding extensions.** `:` is the literal
  separator between the `soma-manifest` prefix and `<backendId>`.
  Under the v0.1 encoder alone a `:` inside `<backendId>` does not
  cause a byte-level collision, because the literal prefix
  `soma-manifest` contains no `:` and the first `:` in the input
  unambiguously terminates the prefix. `:` is nevertheless reserved
  so that a future, superseding encoding revision MAY introduce
  additional `:`-delimited prefix fields (for example, an explicit
  canonicalization-scheme version segment) without a backendId
  compatibility break. Rejecting `:` in v0.1 is forward-compatible
  encoding hygiene, not a v0.1 collision fix.
- **U+0000 — downstream canonicalization safety.** The NUL byte is
  not a structural delimiter in the v0.1 encoding. It is rejected so
  that any downstream consumer that treats the encoded input, a
  derived `backendId`, or a log line as a C string cannot be tricked
  into truncating at an embedded NUL, and so that the encoded input
  remains a clean printable-ASCII string end to end. This restriction
  is canonicalization hygiene, not a v0.1 collision fix.

The resulting ASCII string is hashed with the provider's canonical
hash (`sha256` for v0.1). The commitment stored on the current
credential is the hex digest of that hash, lowercase.

### 3.3 Test Vector Requirements

A conforming implementation MUST pass test vectors covering:

1. A fixed `(backendId, algorithmSuite, publicKey)` triple producing
   a known commitment digest.
2. A same-publicKey, different-`algorithmSuite` pair producing
   different digests (cross-suite distinguishability).
3. A same-publicKey, different-`backendId` pair producing different
   digests (cross-backend distinguishability).
4. Base64 padding correctness: a public key whose byte length is not
   a multiple of 3 MUST produce padded base64 in the commitment
   input.

Test vectors live under `tests/heart/credential-rotation/vectors/`
and are a Slice D acceptance criterion (see §15).

### 3.4 Verification on Rotate

At rotation time, the controller MUST recompute the new credential's
manifest commitment under §3.2 and compare it byte-for-byte to
`oldCredential.nextManifestCommitment`. A mismatch MUST raise
`PreRotationMismatch` (invariant 9) and MUST NOT advance any state.

## 4. Rotation Event Lifecycle

### 4.1 States

A rotation event moves through exactly these states:

```
pending → anchored → witnessed → effective → revoked
```

| State | Meaning |
|---|---|
| `pending` | Written to the local log; no pulse-tree anchor yet. |
| `anchored` | A pulse-tree root containing this event's hash has been published. |
| `witnessed` | At least one external witness cosignature has been recorded (see §7 for assurance bound). |
| `effective` | The new credential is now primary. In v0.1 single-witness, the first `witnessEvent` call advances `anchored → effective` directly. |
| `revoked` | Superseded by a later event. |

Only an `effective` credential MAY sign on behalf of the identity.
Any attempt to sign with a non-effective credential MUST raise
`NotYetEffective` (invariant 3).

### 4.2 Anchor-Before-Effect (L3)

L3 requires three conditions before an event is `effective`:

1. **Local log write** — the event is persisted to the controller's
   event chain.
2. **Pulse-tree anchor** — a pulse-tree root containing the event
   hash has been published.
3. **Witness** — at least one external witness cosignature has been
   recorded on the anchoring root. See §7 for the v0.1 assurance
   bound on what "witness" entails.

A conforming controller MUST NOT mutate `state.current` or install
the new credential until all three have occurred.

### 4.3 Signatures (L2)

Every non-inception rotation event MUST carry:

1. **Old-key signature** — a signature under the *outgoing*
   credential's secret key over the canonical event-signing input
   with role `rotation-sign`.
2. **New-key proof-of-possession** — a signature under the *incoming*
   credential's secret key over the canonical event-signing input
   with role `rotation-pop`, computed after the old-key signature is
   fixed so the PoP covers it.

Both signatures MUST be present at event hashing time (§4.4). A
controller verifying a rotation chain MUST verify both.

The canonical signing input uses domain separation of the form
`soma/credential-rotation/<role>/v1`, applied to the canonical JSON
encoding of the pre-event struct. Roles are fixed:
`inception-pop`, `rotation-sign`, `rotation-pop`.

### 4.4 Event Hashing

The content-addressed event hash is computed after both L2 signatures
are fixed, over the pre-event struct plus both signature fields, as:

```
sha256( "soma-rotation-event:" || canonicalJson(preEventWithSignatures) )
```

Public keys inside the event MUST be base64-encoded in the JSON so
the hashed bytes are deterministic across runtimes (see
`src/heart/credential-rotation/snapshot.ts` for the canonical wire
shape). The event hash is the lowercase hex digest.

### 4.5 Chain Linkage

Every event MUST link to its predecessor by `previousEventHash`. The
genesis predecessor hash is deterministic per `(identityId,
backendId)` and is computed as:

```
sha256( "soma-rotation-genesis:" || identityId || ":" || backendId )
```

Sequence numbers MUST be strictly monotonic; the genesis event has
`sequence = 0` and carries `oldCredentialId = null` and an empty
`oldKeySignature`.

### 4.6 Ratchet Anchor

Each event carries a `ratchetAnchor` mixed into the new credential's
derivation. It is computed as:

```
sha256( "soma-ratchet:" || previousAnchor || "|" || base64(newPublicKey) )
```

The genesis anchor is
`sha256("soma-ratchet-genesis:" || identityId)`. Ratchet-anchor
derivation is how v0.1 provides post-compromise security (invariant
10): an attacker who captures a credential's secret at time `t`
cannot derive the successor credential without also capturing the
controller's ratchet state at `t`.

### 4.7 Event Chain Retention (Normative)

An identity's rotation event chain is append-only and MUST NOT be
pruned, compacted, or truncated for the lifetime of the identity. A
conforming controller MUST retain every event from genesis through
the current tip, such that every credential the chain has ever made
`effective` — including revoked predecessors — remains recoverable
by walking the chain.

This applies to the runtime controller state, not only to serialised
snapshots. A controller that discarded historic events from
in-memory state but still serialised a complete chain into
`ControllerSnapshot` would violate this invariant: the §10.2
snapshot-completeness requirement is a consequence of runtime
retention, not a substitute for it.

Rationale: identity-bound delegation verification, as defined in
`SOMA-DELEGATION-SPEC.md` §Rotation Interaction, requires a
historical-credential lookup against the rotation subsystem. That
lookup's Slice D code contract is specified normatively in
`SOMA-DELEGATION-SPEC.md` §Rotation Interaction and lands alongside
the Gate 4 code reconciliation scoped by §15. It assumes the
rotation controller has every credential the chain has ever bound.
Pruning the chain would silently break identity-bound verification
of delegations issued under earlier credentials.

Retention is a structural controller constraint, not a runtime
detectable operation: no single `sign`, `rotate`, or `commit` call
raises an error when pruning occurs. A controller that implements
pruning is structurally non-conforming, and the reference assertion
is the historical-credential lookup required by
`SOMA-DELEGATION-SPEC.md` §Rotation Interaction's Slice D code
contract, landing under the §15 Gate 4 reconciliation.

## 5. Staged Rotation and Rollback

### 5.1 Stage / Commit / Abort

The `CredentialBackend` interface exposes three staging operations:

- `stageNextCredential({ identityId, oldCredentialId, issuedAt })` —
  reveals the public manifest of the next keypair so the controller
  can verify it matches the prior commitment (§3), but MUST NOT
  mutate durable chain state (history append, `current` pointer,
  etc.).
- `commitStagedRotation(identityId)` — appends to the backend's
  durable log, advances the current credential pointer, and
  generates the next-next keypair so pre-rotation stays one step
  ahead.
- `abortStagedRotation(identityId)` — drops the staged credential,
  zeroises any partial secret material it held, and leaves the
  backend in the exact state it was in before the stage call.
  MUST be idempotent: aborting when no rotation is staged is a
  no-op.

At most one rotation MAY be staged per identity at a time. A second
stage attempt against an identity with a staged rotation in flight
MUST raise `StagedRotationConflict`.

### 5.2 Rollback Invariant (Normative)

**Invariant (rollback, pre-durable-commit).** If any step between
`stageNextCredential` and the point at which
`commitStagedRotation` makes the new credential **externally
durable** throws, the controller state and the backend state MUST
both revert to the pre-stage state. No partial rotation MAY be
observable in either layer after the throw has propagated to the
caller.

This applies to every step the controller performs between staging
and committing, including but not limited to:

- commitment re-derivation and comparison (§3.4);
- suite allowlist check;
- derivation of the new ratchet anchor;
- old-key signing of the pre-event body;
- new-key proof-of-possession signing;
- event hashing.

Each of these substeps executes **before** the controller hands
control to `commitStagedRotation`, so no external observer has yet
seen a new `current` pointer, a new event-chain entry, or a new
ratchet anchor. A conforming controller MUST call
`backend.abortStagedRotation` on the affected identity when any of
the above throws. The original error MUST be preserved for the
caller; errors from `abortStagedRotation` MAY be suppressed by the
controller provided the abort was attempted.

Neither the event chain nor `state.current` may be mutated on a
throw path. A rollback leaves the identity with:

- its prior `current` credential intact and still `effective`;
- its prior event chain intact;
- its backend holding only the pre-stage secret material;
- its rate-limit bucket unchanged (the failed attempt does NOT
  consume a rotation slot — see §8.2).

**Commit-call failures are in scope for Slice D, not deferred.**
Once the controller calls `commitStagedRotation`, the recovery
shape on a thrown commit depends on the backend's atomicity and
abort semantics, which differ across durable-log implementations.
v0.1 does not prescribe a single normative recovery shape for a
commit-call failure, but it also does NOT silently defer the
question to an unnamed future ADR. Slice D (§15) MUST do one of:

1. Land a test that asserts a specific recovery shape for a failure
   thrown by `commitStagedRotation` on the reference backend — for
   example, that the backend commit is atomic so a thrown commit
   leaves the identity in the pre-stage state and the rotation is
   retriable, with the same observable properties as the pre-commit
   rollback above; OR
2. Explicitly constrain, in the Slice D PR, the set of failure
   modes the reference backend is permitted to produce from
   `commitStagedRotation` (e.g. "the reference backend's commit is
   infallible after staging succeeds; any error is an
   implementation bug") and document that constraint alongside the
   code.

Slice D MUST NOT ship a commit-call failure path whose recovery
shape is neither tested nor explicitly constrained. Any divergence
between the reference backend's observable commit-call behaviour
and this spec is a spec bug per §15, to be fixed by a follow-up
spec PR rather than by drifting the code.

### 5.3 Implementation Flexibility

The ADR does not pre-decide *how* the rollback invariant is
implemented. Acceptable strategies include a try/abort block around
the stage → sign → commit sequence, a controller-level transaction
boundary, or explicit revert calls. v0.1 does not require any
specific control-flow shape; it requires that a conforming
implementation satisfy the invariant under test.

### 5.4 Rollback Acceptance Test

Slice D MUST land a test in `tests/credential-rotation/` that:

1. Starts with an effective credential.
2. Forces a throw in each of the substeps enumerated in §5.2 by
   instrumenting either the backend or the controller's crypto
   provider.
3. Asserts that after the throw propagates, the identity is in the
   pre-stage state per §5.2 (same `current`, same event chain
   length, same ratchet anchor, no staged secret material in the
   backend).

This test is a Slice D acceptance criterion (see §15).

## 6. Verify-Before-Revoke and the Accepted Pool

Invariant 12 requires that a credential MUST NOT be revoked until
verify-before-revoke has succeeded: the controller must confirm that
the replacement credential is effective and that propagation of the
new `current` pointer has been acknowledged, before the old credential
becomes unusable.

After a clean rotation, the prior credential MUST be placed in the
identity's **accepted pool** with a grace window of
`challengePeriodMs` (§8.1). During the grace window:

- `verify()` MUST accept signatures from the pooled credential (so
  in-flight requests that pre-date the rotation do not fail).
- `sign()` MUST NOT use the pooled credential.
- Revocation MAY proceed once propagation is acknowledged *and* the
  grace window has elapsed. Premature revocation MUST raise
  `VerifyBeforeRevokeFailed`.

A credential's implicit revocation by a superseding rotation event
(§4.1 `revoked` state) is subject to the same verify-before-revoke
rule: the `revoked` status applies to the event lifecycle; the
credential is not considered fully retired until the accepted-pool
grace has elapsed.

## 7. Witness Quorum — v0.1 Assurance Bound

### 7.1 Single-Witness Mechanism

v0.1 normative behaviour is **single-witness**. The first
`witnessEvent(identityId, eventHash)` call on an `anchored` event
advances the event directly to `effective` and installs the new
credential as current. Additional `witnessEvent` calls on an already
`effective` event MAY increment an internal counter for future use by
multi-witness policies but MUST NOT cause any further state
transition.

### 7.2 Non-Independence Caveat (Normative)

In the first-consumer configuration (claw-net), the rotating identity
and the witness are not independent parties: the same operator
operates both the subject of rotation and the process that witnesses
the rotation event. v0.1 witnessing is therefore **non-independent
single-witness**.

A conforming v0.1 implementation MUST state this assurance bound in
its integration documentation. Implementations MUST NOT represent
v0.1 witnessing as equivalent to:

- M-of-N witness quorum across mutually-distrusting parties;
- independent third-party witnessing by an external operator;
- any threshold scheme providing Byzantine fault tolerance.

### 7.3 Threat Model Exclusions

v0.1 non-independent single-witness provides **no defence** against:

1. A fully-compromised operator environment where the attacker
   controls both the rotating controller and the witness process.
2. A targeted attacker who has captured the current signing key *and*
   the pre-committed next key (both L1 commitment and live keypair).
3. A byzantine witness process that cosigns arbitrary events without
   verification.

The v0.1 threat model MUST explicitly exclude these scenarios.
Higher-assurance configurations are a future-ADR concern tracked
under M-of-N.

### 7.4 Invariant 4 Disposition

Invariant 4 ("panic freeze requires M-of-N quorum") as declared in
`src/heart/credential-rotation/types.ts` is **dropped from the v0.1
normative set**. Slice D MUST update the `types.ts` header comment
to reflect this and MUST annotate `witnessEvent` as
single-witness-by-design for v0.1, with a pointer to this spec §7
and to the future ADR for M-of-N.

This deletion is normative: a v0.1 implementation does NOT have
invariant 4 in its contract.

### 7.5 Recovery Path Deferral

v0.1 defines no operator-facing recovery ceremony beyond the existing
`rotate()` + `revokeCredential()` primitives. Break-glass, panic
freeze, and M-of-N-authorised recovery are deferred to a future ADR
(ADR-0004 D4).

Deferral of the recovery path depends on both §5.2 (rollback
required) and §7.2 (single-witness assurance stated plainly). If a
future revision weakens either, the recovery-path deferral MUST be
re-opened.

`rotate()` is not a general compromise-recovery mechanism. It works
as a recovery path only under narrow conditions: the attacker holds
the current signing key but not the pre-committed next key, the
operator retains control of the backend and controller execution
path, and rotation execution is not itself blocked or corrupted.
Scenarios outside those bounds — next key also compromised, backend
unreachable, controller state inconsistent, operator unsure which
keys are compromised — are exactly what break-glass exists to
address, and are out of scope for v0.1.

## 8. Challenge Period and Rate Limiting

### 8.1 Challenge Period (Invariant 8)

Destructive operations (rotation, revocation) MUST be gated by a
per-controller challenge period. The controller rejects destructive
calls during the challenge window with `ChallengePeriodActive`. The
default value is 1 hour; the absolute floor is 15 minutes (see §9.2).

### 8.2 Rate Limit (Invariant 8)

`rotate()` MUST enforce a per-identity rotation rate limit against
`maxRotationsPerHour` with a token-bucket burst of `rotationBurst`.
Exceeded rates MUST raise `RateLimitExceeded`. The default is 10
rotations/hour with burst 3; the absolute floor is 2 rotations/hour
(see §9.2).

A failed rotation attempt (one that triggers rollback under §5.2)
MUST NOT consume a rotation slot. The rate-limit bucket is advanced
only when a rotation successfully commits.

Only `rotate()` is rate-limited; `incept` and adoption paths are not.

## 9. Policy Model — Mechanism vs. Default

### 9.1 Normative Mechanism

The following elements of the policy model are **normative
mechanism**:

- Exactly three credential classes (`A | B | C`) exist. Adding or
  removing classes beyond `A | B | C` requires a superseding ADR.
- Each class carries a per-class TTL policy (`defaultMs`, `floorMs`).
  The per-class `floorMs` field is **operator-configured** at policy
  construction time. A conforming controller MUST enforce
  `defaultMs >= floorMs` within each class. v0.1 does NOT define an
  absolute protocol-wide minimum for per-class `floorMs` itself —
  raising any per-class floor to an absolute protocol floor is a
  future-ADR concern (see §16).
- The controller carries two **protocol-wide floors** on
  `challengePeriodMs` and `maxRotationsPerHour` that apply
  regardless of class. See §9.2.
- The policy carries a `backendAllowlist` (invariant 6) and a
  `suiteAllowlist` (invariant 1).

### 9.2 Normative Floors

v0.1 normatively defines exactly two **absolute protocol-wide floors**.
Consumers MAY raise them; consumers MUST NOT lower them. A conforming
controller MUST reject a `ControllerPolicy` whose values are below
either of these floors.

| Floor | Value |
|---|---|
| `POLICY_FLOORS.challengePeriodMs` | 15 minutes |
| `POLICY_FLOORS.maxRotationsPerHour` | 2 |

These are the only fields carried by the `POLICY_FLOORS` constant in
`src/heart/credential-rotation/types.ts`, and they are the only floors
the controller rejects below-threshold values for in `validatePolicy`
(`src/heart/credential-rotation/controller.ts`).

**Per-class TTL floors are not protocol-wide floors in v0.1.** The
reference policy ships `DEFAULT_TTL_POLICY.A.floorMs` = 60s,
`DEFAULT_TTL_POLICY.B.floorMs` = 5min, and
`DEFAULT_TTL_POLICY.C.floorMs` = 60min. These are the values the
reference policy ships with — they are shipped defaults, not absolute
protocol floors. An operator constructing a `ControllerPolicy` MAY
declare different per-class `floorMs` values; the controller enforces
only the relative `defaultMs >= floorMs` rule within each class
(§9.1). Operator-declared class floors are not checked against an
absolute minimum by v0.1.

### 9.3 Non-Normative Defaults

The concrete values inside `DEFAULT_TTL_POLICY` (`defaultMs` per
class) and `DEFAULT_POLICY` (`challengePeriodMs`, `maxRotationsPerHour`,
`rotationBurst`, initial `suiteAllowlist`, etc.) are a **starting
set**, not normative values. Consumers MAY tighten them; conformance
does not depend on the exact defaults.

The distinction is: the *shape* of the policy (fields, classes,
floors existing) is normative; the *numbers* above the floors are
policy choices.

## 10. Snapshot and Wire Contracts

### 10.1 Snapshot Version

Snapshots carry an explicit `version` field. v0.1 uses
`SNAPSHOT_VERSION = 1`. A controller loading a snapshot with a
version it does not support MUST fail closed with a clear error.
Versions are not silently migrated.

### 10.2 Snapshot Invariants (Normative)

A snapshot MUST preserve everything required for a restored
controller to keep producing L1/L2/L3-correct events for every
identity it holds. Specifically, a `ControllerSnapshot` MUST carry:

- the full `ControllerPolicy`;
- for every identity: the complete event chain, the current
  credential id (or `null`), the accepted-pool entries with their
  grace-until timestamps, the ratchet anchor, the rotation
  timestamp window used for rate limiting, and the challenge-period
  unlock timestamp (if set).

The in-memory shapes hold `Uint8Array` in a few places (public keys).
The wire format MUST base64-encode those fields so the signed bytes
and the hashed bytes round-trip deterministically across runtimes.
Wire types are defined in `src/heart/credential-rotation/snapshot.ts`
(`CredentialWire`, `RotationEventWire`, `IdentityStateSnapshot`,
`ControllerSnapshot`).

### 10.3 Mid-Stage Prohibition (Normative)

A backend MUST refuse to produce a snapshot while any identity it
holds has a staged rotation in flight. Callers MUST commit or abort
every staged rotation before snapshotting. This MUST be enforced at
the backend layer, not left to the caller.

Rationale: snapshotting a mid-stage state would serialise a
non-committed credential, and restoring such a snapshot would
resurrect it without going through the stage → verify → commit
sequence, bypassing §5.2 rollback semantics.

### 10.4 Backend Snapshots

Backend snapshot formats are backend-specific and carry their own
`version` field. The controller snapshot and backend snapshots MUST
be bundled by the caller when persisted; the controller does NOT
snapshot backend internal state.

Each backend's snapshot MUST preserve all secret material required
to continue serving an identity after restore. Callers are
responsible for encrypting the bundled snapshot before writing it to
durable storage.

## 11. Error Taxonomy

All controller-enforced violations MUST be `InvariantViolation`
subclasses. The set defined by v0.1 is:

| Error | Invariant | Raised when |
|---|---|---|
| `SuiteDowngradeRejected` | 1 | Rotation would adopt a credential whose `algorithmSuite` is not in the `suiteAllowlist`. |
| `CredentialExpired` | 2 | `sign()` is called on an expired `state.current`. |
| `NotYetEffective` | 3 | `sign()` is called while no effective credential exists, or `rotate()` is called while the tip event is not yet effective. |
| `BackendNotAllowlisted` | 6 | An operation references a backend not in the `backendAllowlist`. |
| `DuplicateBackend` | 7 | A backend is registered twice. |
| `RateLimitExceeded` | 8 | `rotate()` exceeds the per-identity rate limit. |
| `ChallengePeriodActive` | 8 | A destructive operation is attempted during an active challenge window. |
| `PreRotationMismatch` | 9 | The new credential's re-derived manifest commitment does not match the prior commitment. |
| `StagedRotationConflict` | 9 | Stage is called against an identity that already has a staged rotation in flight. |
| `VerifyBeforeRevokeFailed` | 12 | Revocation is attempted before propagation is acknowledged or the accepted-pool grace has elapsed. |

No invariant-4 error exists in v0.1 (see §7.4). Implementations MUST
NOT invent additional `InvariantViolation` subclasses without a
superseding ADR; backend-specific errors MUST use their own error
base classes.

## 12. Threat Model (v0.1)

The v0.1 threat model is scoped to the assurances v0.1 actually
provides. An operator deploying a conforming v0.1 implementation
MUST write a threat model that:

1. States the non-independence of the witness explicitly (§7.2).
2. Excludes fully-compromised operator environments (§7.3).
3. Excludes attackers who have captured both the current and
   pre-committed next keys.
4. Declares that compromise recovery is limited to clean-key
   scenarios and that break-glass is not part of v0.1 (§7.5).
5. Declares that post-quantum suites are reserved identifiers only
   in v0.1 and that `ed25519` is the only active suite.

Integration documentation in downstream repos MUST link back to this
section and MUST NOT claim assurances beyond it.

## 13. Delegation Interaction

### 13.1 Intended Interaction (Non-Normative Here)

ADR-0004 D2 accepted identity-binding: delegations bind to a stable
identity anchor (`identityId`), not to the credential that issued
them. When a parent credential rotates, existing delegation keys are
intended to remain valid without re-issuance, provided the parent's
`identityId` is unchanged and the new credential has reached
`effective`.

This section records the *intended* interaction only. The normative
rule lives in `SOMA-DELEGATION-SPEC.md`, which currently documents
key-binding (`parent_id` as "Cryptographic link to the issuing key";
`issued_by_sig` signed under the parent's current signing key at
issue time). Converting that spec to identity-binding is a
**verification-model redesign**, not a one-line edit, and is out of
scope for this document.

Identity-bound verification in turn depends on the event chain
retention invariant (§4.7): the historical-credential lookup
specified by `SOMA-DELEGATION-SPEC.md` §Rotation Interaction's
Slice D code contract (landing under the §15 Gate 4 reconciliation)
assumes the rotation controller has retained every credential the
chain has ever made `effective`.

### 13.2 Normative Dependency (Normative)

`SOMA-ROTATION-SPEC.md` v0.1 does NOT define delegation verification
under parent rotation. Normative delegation-under-rotation semantics
live in `SOMA-DELEGATION-SPEC.md` §Rotation Interaction, which
closed Open Question 6 as of Slice C / Gate 5 by adopting
identity-binding with Mechanism 1 (historical archive). See that
section's *Conforming verifier rule* and *Slice D code contract* for
the authoritative rules.

Requirements on implementations of this spec:

- The rotation controller MUST NOT attempt to reason about
  delegation children during rotation; delegation verification is
  owned by the delegation subsystem, which consumes the
  historical-credential lookup this subsystem exposes as a Gate 4 /
  Slice D deliverable (see §15 and §14 invariant 13).
- First-consumer integration MUST NOT ship delegation-under-rotation
  as a supported path until that historical-credential lookup lands.
  This is the residual operational precondition on Gate 7
  (first-consumer unlock) per ADR-0004's Readiness Horizon;
  `SOMA-DELEGATION-SPEC.md` §Rotation Interaction states the same
  rule from the delegation side.
- The residual illustrative-wire / reference-SQL alignment item
  called out under `SOMA-DELEGATION-SPEC.md` §Rotation Interaction's
  *What this section does NOT resolve* is a docs/code hygiene
  follow-up, not a blocker for this spec. While it is pending, the
  normative *Wire-schema dependency* text in that section is
  authoritative.

### 13.3 Why This Spec Does Not Define Verification

Three mutually-incompatible candidate mechanisms for identity-bound
delegation verification existed when this spec was first drafted,
and picking one was Slice C's job rather than this document's:

1. Retaining an archive of superseded parent public keys so historic
   `issued_by_sig` values still verify after rotation. **(Adopted by
   `SOMA-DELEGATION-SPEC.md` §Rotation Interaction as of Slice C /
   Gate 5.)**
2. Cascade re-signing children on each parent rotation (rejected as
   the default in ADR-0004 D2 on availability grounds, but still a
   candidate for specific classes; Mechanism 2 MAY be re-added later
   as a policy-level option without superseding Mechanism 1).
3. Redesigning the signature scheme to key off identity rather than
   credential (e.g. identity-based signatures, BLS aggregation, or
   threshold schemes).

Mechanism 1 was selected because the historical state it needs
already exists in this subsystem: every controller snapshot already
carries the complete rotation event chain (§10.2, §4.7), and every
event's `newCredential` contains the public key that was
authoritative at that event. The Gate 4 / Slice D historical-
credential lookup (§15) exposes that existing state to the
delegation verifier without new persistence, new cryptography, or a
new signing scheme.

This spec still scopes itself to rotation semantics. The normative
text of delegation-under-rotation verification lives in
`SOMA-DELEGATION-SPEC.md` §Rotation Interaction; the only contract
this spec owes the delegation subsystem is the historical-credential
lookup called out in §15.

## 14. v0.1 Invariants (Normative Set)

The following invariants form the v0.1 normative set. They are
numbered to align with existing `InvariantViolation` codes (§11).

1. **Threshold mandatory for Tier 0.** (Substrate-level; see
   `SOMA-CAPABILITIES-SPEC.md` for threshold semantics.)
2. **Session credentials always derived, never imported.** Secret
   material MUST originate inside the backend that holds it.
3. **Rotation events anchored before effect.** See §4.2.
4. **(Reserved — removed from v0.1.)** Invariant 4 previously claimed
   M-of-N panic freeze. See §7.4.
5. **Proof-of-possession mandatory per use.** Rotation events carry
   L2 signatures (§4.3); per-call PoP is enforced by downstream
   consumers (e.g. `SOMA-CAPABILITIES-SPEC.md`).
6. **Backends come from a signed allowlist.** `backendAllowlist` is
   enforced at every operation (`BackendNotAllowlisted`).
7. **Backends are isolated.** No backend reads another backend's
   state; no cross-backend imports.
8. **Challenge period and rate limit for destructive operations.**
   See §8.
9. **Pre-rotation commitment.** Every credential commits to the next
   credential's full manifest (§3); rotation into a non-matching
   manifest raises `PreRotationMismatch`.
10. **Post-compromise security via durable ratchet state.** Ratchet
    anchors mix into each new credential's derivation (§4.6); an
    attacker capturing a secret at time `t` cannot derive the
    successor without also capturing ratchet state at `t`.
11. **No legacy path.** No coexistence with static auth; rotation
    is the only credential-management path.
12. **Verify before revoke.** See §6.
13. **Event chain retention.** An identity's rotation event chain is
    append-only and MUST NOT be pruned or compacted for the lifetime
    of the identity; every credential the chain has ever made
    `effective` MUST remain recoverable by walking the chain. See
    §4.7.

Invariant 4 is removed, not renumbered: existing
`InvariantViolation` codes stay stable, and the gap is normative.
Invariant 13 is a structural retention constraint (§4.7) and has no
corresponding runtime `InvariantViolation` code; it is enforced at
the controller-design level and asserted by the historical-credential
lookup required by `SOMA-DELEGATION-SPEC.md` §Rotation Interaction's
Slice D code contract, landing under the §15 Gate 4 reconciliation.

## 15. Code Reconciliation Readiness (Slice D Gate)

This spec is drafted before the source comments that cite it have
been reconciled. Slice D (Gate 4 per ADR-0004) MUST land a code-only
PR that:

1. Removes the `§13c` / `§14` architecture-doc strings from
   `src/heart/credential-rotation/types.ts` and
   `src/heart/credential-rotation/controller.ts`.
2. Replaces them with references to `SOMA-ROTATION-SPEC.md` by
   section number (§3 for L1, §4 for the lifecycle, §5 for
   rollback, §7 for single-witness, §8 for floors, §9 for
   mechanism vs. default, §10 for snapshots).
3. Updates the `types.ts` header invariant list to drop invariant 4
   (or re-annotate it as reserved per §14, matching §7.4).
4. Annotates `witnessEvent` (currently at
   `src/heart/credential-rotation/controller.ts:587`, flagged as
   "MVP single-witness quorum" at line 584) as
   single-witness-by-design for v0.1, pointing at §7.
5. Lands the rollback acceptance test described in §5.4 under
   `tests/heart/credential-rotation/`.
6. Lands the commitment test vectors described in §3.3 under
   `tests/heart/credential-rotation/vectors/`.
7. Lands backend registration / policy-validation code that rejects
   any `backendId` containing a delimiter byte used by the
   commitment encoding — at minimum `|` (U+007C), `:` (U+003A),
   and U+0000 — per §3.2. The rejection MUST happen before the
   backend is admitted to the `backendAllowlist`, and MUST raise a
   clear, typed error so a malformed id can never reach the
   commitment encoder. Slice D MUST land a test that exercises this
   rejection path.
8. For `commitStagedRotation` failure handling (per §5.2), does one
   of: (a) lands a test asserting a specific recovery shape on the
   reference backend when `commitStagedRotation` throws (same
   observable pre-stage state as §5.2's pre-commit rollback,
   retriable), or (b) documents in the Slice D PR an explicit
   constraint on the set of failure modes the reference backend is
   permitted to produce from `commitStagedRotation`, alongside the
   code that enforces the constraint. v0.1 does not permit silently
   deferring commit-call failure handling.

Slice D is code-only. It MUST NOT revise this spec; any divergence
between Slice D and this spec is a spec bug that MUST be fixed by a
follow-up spec PR, not by drifting the code away from the spec.

## 16. Open Questions

1. **Hybrid-suite activation.** When does `ed25519+ml-dsa-65` graduate
   from reserved identifier to normatively supported suite? Blocked
   on a hybrid-verify test and a PQ-hardening ADR. Out of v0.1 scope.
2. **L1 log backend.** Whether `src/heart/key-rotation.ts` becomes the
   canonical L1 log backend under `credential-rotation/`, or is
   deprecated, is a future ADR concern. v0.1 keeps it internal.
3. **M-of-N witness quorum.** A future ADR must either specify it
   (and add tests that fail with a single witness against a
   threshold > 1) or re-confirm the single-witness model for a
   subsequent version. v0.1 is single-witness per §7.
4. **Break-glass ceremony.** Deferred per ADR-0004 D4. Naming a
   follow-up ADR is non-blocking and does not gate any readiness
   work.
5. **Delegation verification under rotation.** Slice C / Gate 5
   territory. See §13.
6. **Snapshot migration.** v0.1 is version 1. Future versions MUST
   define an explicit migration path; v0.1 does not pre-commit to a
   migration shape.
7. **Per-class TTL floor elevation.** Whether any per-class
   `DEFAULT_TTL_POLICY.*.floorMs` is ever raised to a protocol-wide
   absolute floor (rejected by the controller, parallel to
   `POLICY_FLOORS.challengePeriodMs` and
   `POLICY_FLOORS.maxRotationsPerHour`) is a future-ADR concern.
   v0.1 treats per-class `floorMs` as operator-configured per §9.1
   and enforces only the relative `defaultMs >= floorMs` rule within
   each class.

## 17. Links

- ADR-0004: `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- Proposal: `docs/proposals/credential-rotation.md` (merged `9d0514e`)
- Tracking issue: Soma#24 — *Define credential rotation semantics and
  trust model for Soma*
- Source: `src/heart/credential-rotation/{types.ts,controller.ts,snapshot.ts,index.ts}`
- Internal primitive: `src/heart/key-rotation.ts`
- Delegation spec with OQ6: `SOMA-DELEGATION-SPEC.md` (line 307)
- Spec index: `docs/reference/spec-index.md`
- Package surface: `packages/soma-heart/package.json` `exports` map
