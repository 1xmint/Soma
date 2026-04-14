Status: proposed

# Credential Rotation — Protocol Semantics and Trust Model

Status: proposed


**Status:** design. No implementation changes.
**Tracks:** Soma#24 (`Define credential rotation semantics and trust model for Soma`).
**First consumer:** ClawNet (see
`claw-net/docs/proposals/credential-rotation-first-consumer.md`).
**Covers:** what the normative rotation contract should be, which parts
of the current Soma code are candidates for ratification, and which
questions must be answered — or deliberately marked open — before an
ADR and spec can land.

---

## 0. Scope note — what this proposal is and is not

This is a **framing document**. It exists because Soma currently ships
code that behaves as if a rotation spec exists, references an
architecture document that does not exist in this repo, and has two
parallel rotation subsystems with no normative ruling on which is
canonical.

The proposal:

- summarises what the code does today as *evidence of intent*, not as
  normative truth;
- recommends which subsystem should be treated as the canonical
  consumer-facing substrate;
- enumerates the decisions that must be **either resolved or explicitly
  marked as blocking/open** before a rotation ADR and `SOMA-ROTATION-SPEC.md`
  can be accepted;
- calls out places where current code disagrees with comments and
  intended invariants, so an ADR does not ratify an invariant the code
  does not enforce.

It does **not** rewrite the controller, unify the two subsystems,
change any package API, or ship any claw-net code.

---

## 1. Why this proposal exists now — the strongest finding

`src/heart/credential-rotation/types.ts` declares:

> The twelve invariants (summarised, see architecture doc §13c for full text):
> 1. Threshold mandatory for Tier 0.
> 2. Session credentials always derived, never imported.
> 3. Rotation events anchored before effect.
> 4. Panic freeze requires M-of-N quorum.
> 5. Proof-of-possession mandatory per use.
> 6. Backends come from a signed allowlist in the birth certificate.
> 7. Backends are isolated.
> 8. Challenge period for destructive operations.
> 9. Pre-rotation (every event commits to next public key manifest).
> 10. Post-compromise security via durable ratchet state.
> 11. No legacy path — no coexistence with static auth.
> 12. Verify before revoke.
>
> Implementation locks (§14 L1-L3):
>   L1. Pre-rotation commits to `sha256(nextPubKey || nextAlgorithmSuite || nextBackendId)`.
>   L2. Rotation events are signed under the OLD key; new key signs first PoP.
>   L3. An event is only effective after local log write + pulse-tree anchor
>       + external witness.

**The referenced document `architecture doc §13c / §14` does not exist
anywhere in this repo.** A grep of `docs/` returns zero matches for
`§13c`, `§14`, or `twelve invariants`. The only place those phrases
appear is inside `src/heart/credential-rotation/types.ts` and
`src/heart/credential-rotation/controller.ts`. `docs/reference/spec-index.md`
lists `SOMA-CHECK-SPEC.md`, `SOMA-DELEGATION-SPEC.md`, and
`SOMA-CAPABILITIES-SPEC.md`, but no rotation spec.

This is the primary reason this proposal exists. The current controller
is shipping behaviour that claims to be normative — twelve invariants,
numbered implementation locks, a `POLICY_FLOORS` table — against a
document that a downstream implementer cannot read, review, or cite.
Soma's rotation rules should be defined in `docs/` and referenced *by*
the code, not declared *in* the code.

---

## 2. Current code as evidence of intent (non-normative)

This section records what the controller does today. It is evidence of
what the author intended the protocol to be. It is not yet a contract.
Nothing in this section is ratified by this proposal; §4 and §5 handle
ratification.

### 2.1 Two parallel rotation subsystems

There are two rotation implementations in `src/heart/`:

| Path | Shape | Size | Behaviour |
|---|---|---|---|
| `src/heart/credential-rotation/` | Pluggable backends, policy-driven, class/suite/staging aware, the "twelve invariants" framing | `controller.ts` 905 lines, `types.ts` 384 lines, `index.ts` 67 lines | Used by ClawNet `api-key-rotation.ts` via `soma-heart` ESM entry `./credential-rotation` |
| `src/heart/key-rotation.ts` | Single-file KERI-style forward-digest DID chain, closes audit limit #6 | 413 lines | Internal heart primitive; no pluggable backend, no policy, no class model |

The two do not share types. They do not cross-reference each other. No
Soma document ranks them, and neither is marked deprecated. This is
the first question the ADR has to answer.

### 2.2 Classes, suites, TTL policy, floors

`types.ts` defines three `CredentialClass` values (`A | B | C`), four
`AlgorithmSuite` values (`ed25519`, `ed25519+ml-dsa-65`, `secp256k1`,
`secp256k1+ml-dsa-65`), a `DEFAULT_TTL_POLICY` by class, and a
`POLICY_FLOORS` table for per-class minimum TTLs, rate limits, and
challenge periods. The MVP only supports `ed25519`; the three hybrid
suites are declared as reserved identifiers that "must pass a
hybrid-verify test before they are accepted into any allowlist"
(`types.ts` line 40-43).

### 2.3 Pre-rotation commitment

`controller.ts` implements L1: every credential carries a
`nextManifestCommitment` which is `sha256(nextPublicKey ||
nextAlgorithmSuite || nextBackendId)`. `types.ts` line 55-58 records
the rationale: "committing the whole manifest instead of just the
public key closes a cross-suite confusion attack where an adversary
who obtains a future private key could reuse its public key under a
different suite or backend."

### 2.4 Rotation event lifecycle

Events move through `pending → anchored → witnessed → effective →
revoked`. `controller.ts` enforces L3 as an external witness
cosignature before `anchored → effective`, but see §2.8 on what
"witness" currently means.

### 2.5 Staged rotation

`CredentialBackend` exposes `stageNextCredential` / `commitStagedRotation`
/ `abortStagedRotation`. A `StagedRotationConflict` error is defined in
`types.ts`. This is intended to model "a rotation is in progress but
has not yet taken effect."

### 2.6 Challenge period

`controller.ts` enforces `ChallengePeriodActive` for destructive
operations against the floor defined in `POLICY_FLOORS.challengePeriodMs`.
Default is 1h, floor is 15min. `POLICY_FLOORS` itself is flat (not
per-class); per-class floors today only exist in `DEFAULT_TTL_POLICY`.
This is invariant 8.

### 2.7 Rate limit

`rotate()` enforces `RateLimitExceeded` against
`maxRotationsPerHour` + `rotationBurst`. Only `rotate` is rate-limited;
`incept` and adoption paths are not. `DEFAULT_POLICY` is
`maxRotationsPerHour: 10`, floor `2`, burst `3`.

### 2.8 Witness quorum — intended vs implemented

`types.ts` line 13 states invariant 4 as "Panic freeze requires M-of-N
quorum." `controller.ts` line 584 comments `witnessEvent` as:

> "the MVP single-witness quorum; the counter still increments so
> future multi-witness policies can use it."

**The code is single-witness.** The first `witnessEvent` call moves
the event from `anchored` directly to `effective`. Subsequent witness
calls are counted but have no effect on state transitions. There is
no M-of-N verification and no panic-freeze path at all. This is a
gap the ADR must address; see §5.1.

### 2.9 Error taxonomy

The controller defines a rich error class set: `InvariantViolation`,
`BackendNotAllowlisted`, `SuiteDowngradeRejected`, `PreRotationMismatch`,
`NotYetEffective`, `RateLimitExceeded`, `ChallengePeriodActive`,
`VerifyBeforeRevokeFailed`, `CredentialExpired`, `DuplicateBackend`,
`StagedRotationConflict`. These encode the intended invariants
operationally but are not documented outside the code.

### 2.10 Delegation interaction — not specified anywhere

`SOMA-DELEGATION-SPEC.md` defines delegation keys with a `parent_id`
that is a credential `key_id` (e.g. `dlg_3c1e...`). The spec's own
"Open Questions" section, line 307, reads:

> "6. Key rotation: if parent rotates its signing key, do children
> need re-issuance?"

So the delegation spec explicitly does not define what happens when a
credential rotates. The rotation controller, in turn, never mentions
delegation. These two subsystems have no contract between them today.

---

## 3. Proposed canonical subsystem

**Recommendation (proposal-level, not settled truth):** treat
`src/heart/credential-rotation/` as the canonical consumer-facing
rotation substrate. Treat `src/heart/key-rotation.ts` as an internal,
non-consumer-facing KERI primitive that the rotation controller may
(eventually) use as its L1 log, but which should not be imported
directly by downstream packages.

Rationale:

- `credential-rotation/` already exposes the backend interface ClawNet
  needs to integrate. `key-rotation.ts` has no backend model.
- `credential-rotation/` models class, suite, staging, and challenge
  period. `key-rotation.ts` models only identity continuity.
- soma-heart's package `exports` already surfaces
  `./credential-rotation` as a public subpath; `key-rotation` is not
  in the exports map.
- The rotation architecture framing (invariants, L1-L3) lives in
  `credential-rotation/`. Whatever normative rotation doc Soma ships
  will describe that shape.

**Open for review.** The alternative — unifying both under
`key-rotation.ts` and treating `credential-rotation/` as a policy
wrapper — is defensible but would require rewriting the controller
and the backend interface. This proposal does not pick that path
because it has a higher blast radius and ClawNet's first-consumer
work already depends on the `credential-rotation/` shape. An ADR may
still override this recommendation.

---

## 4. Observed implementation, proposed normative contract, unresolved blockers

This is the ratify-vs-propose table. Each row carries one of:

- **R** — *ratify*: proposal asserts the current behaviour is the
  normative contract. ADR can adopt it with little change.
- **P** — *propose*: proposal recommends the current behaviour be
  treated as a starting point, but the ADR must choose or refine
  before the contract is normative.
- **O** — *open*: proposal marks this as a blocking question. ADR or
  spec acceptance must either answer it or explicitly carry it as a
  known gap with a remediation plan.

### 4.1 Identity continuity

| Aspect | Code evidence | Proposed status |
|---|---|---|
| Identity (`identityId`) is stable across rotations; credential (`credentialId`) is not | `controller.ts` maintains a per-identity state, credentials are rotated underneath it | **R** |
| Birth certificate binds to identity, not to credential | `key-rotation.ts` models this directly; `credential-rotation/` assumes it via `identityId` | **P** — ADR should state this as a single normative rule so both subsystems agree |
| A rotated credential retains its place in audit history under the same `identityId` | Implicit in controller | **R** |

### 4.2 Delegation interaction

| Aspect | Code evidence | Proposed status |
|---|---|---|
| Delegation keys reference a parent `key_id` that is a credential identifier | `SOMA-DELEGATION-SPEC.md` §Concepts | **R** — this is what the spec says today |
| When a parent credential rotates, what happens to children? | Undefined in both code and spec. `SOMA-DELEGATION-SPEC.md` line 307 lists this as Open Question 6 | **O** |
| Preferred direction: delegations should bind to a stable identity anchor, not to a credential that can rotate underneath them | Not in code. Not in spec. | **O — requires review and update against `SOMA-DELEGATION-SPEC.md`** |

The last row is called out because it looks like the "obvious" answer
but it is a substantive change to delegation semantics. It must not
be smuggled into a rotation ADR. It belongs in a delegation spec
revision that this rotation ADR blocks on.

### 4.3 Revocation interaction

| Aspect | Code evidence | Proposed status |
|---|---|---|
| Controller enforces verify-before-revoke | `controller.ts` (`VerifyBeforeRevokeFailed`) | **R** |
| Revocation of a rotated credential is local to the heart | Current behaviour | **P** — needs ADR ruling on relationship to `revocation-gossip.md` proposal |
| Rotation event itself carries an implicit revoke of the prior current credential | `controller.ts` `witnessEvent` sets prior event status to `revoked` on effective transition | **P** — implicit behaviour should be documented explicitly |

### 4.4 Staged rotation

| Aspect | Code evidence | Proposed status |
|---|---|---|
| Backends expose `stageNextCredential` / `commitStagedRotation` / `abortStagedRotation` | `types.ts` `CredentialBackend` interface | **P** — interface shape is fine, semantics are undocumented |
| `StagedRotationConflict` is raised when an identity already has a staged rotation in flight | `types.ts` error class | **P** — needs normative definition of "in flight" window |
| Abort paths on failure midway through a staged rotation | Not comprehensively tested; see `rotation-battle-test-and-roadmap.md` §P1.1 (transactional adoption) | **O** — rollback semantics are an acceptance blocker |

### 4.5 Rollback and recovery

| Aspect | Code evidence | Proposed status |
|---|---|---|
| A failed rotation can be rolled back cleanly without leaving the identity in a half-rotated state | Not enforced; no transaction boundary | **O** — blocks ADR acceptance |
| After a confirmed compromise, there is a defined recovery path | Not defined; §4.6 covers the "panic" half of this | **O** — blocks ADR acceptance |

### 4.6 Trust model — M-of-N panic freeze

| Aspect | Code evidence | Proposed status |
|---|---|---|
| Invariant 4 ("Panic freeze requires M-of-N quorum") is described in a code comment | `types.ts` line 13 | **O** — code does not implement M-of-N; `controller.ts` line 584 is single-witness. Must not be ratified as-is. |
| `witnessEvent` counts additional witnesses but does not gate state transitions on a threshold | `controller.ts` line 584-608 | **O** — the ADR must either implement M-of-N or drop invariant 4 from the normative contract |

**The ADR must not ratify invariant 4 as-is.** Doing so would declare
the protocol requires something the controller does not enforce. Two
acceptable outcomes: (a) specify M-of-N and add a test that fails
with a single witness against a threshold > 1, or (b) restate
invariant 4 as a future requirement not part of v0.1.

---

## 5. Mechanism vs policy — Class A/B/C

`credential-rotation/types.ts` hard-codes three credential classes
with default TTLs and floors. ClawNet's current usage treats those
classes as product-level categories (Soma-native, custody/on-chain,
third-party vaulted).

**Proposal:** Soma should define the **mechanism** (classes exist,
classes carry TTL/floor/rate/challenge policy, floors are enforceable
per-class) and a **default policy** (the current `DEFAULT_TTL_POLICY`
and `POLICY_FLOORS` tables). Consumer-specific policy should remain
configurable within the mechanism's bounds.

Rationale: hard-coding three classes as normative protocol
overconstrains consumers. A provider with different operational
realities — say, a hardware-wallet custody model with a 15-minute
floor that would be unsafe at Soma's default — should be able to
raise its own floors while still being a conforming implementation.
We propose the spec set floors as absolute minimums consumers cannot
lower.

The ADR needs to say whether the class model itself is normative
(i.e. there must be exactly three classes with these letters) or
whether the class set is itself configurable. This is an open
question, not a settled one.

---

## 6. Non-goals of this proposal

- Unifying `credential-rotation/` and `key-rotation.ts` into a single
  subsystem.
- Changing the `CredentialBackend` interface.
- Implementing M-of-N witness quorum.
- Implementing break-glass / panic freeze.
- Implementing canary credentials (tracked in
  `claw-net/internal/active/rotation-battle-test-and-roadmap.md`).
- Changing `SOMA-DELEGATION-SPEC.md`. (This proposal only flags
  delegation as a blocking open question.)
- Writing `docs/architecture/§13c` retroactively. The twelve
  invariants text should become part of a real rotation spec, not a
  reconstructed architecture document.
- Any claw-net code change. First-consumer integration stays in
  `claw-net/docs/proposals/credential-rotation-first-consumer.md`.

---

## 7. First consumer

ClawNet is the only intended consumer for v0.1. ClawNet's first
integration already exists at `src/core/api-key-rotation.ts` in
claw-net (shadow-adopted, inert in production). The ClawNet
first-consumer proposal (`claw-net/docs/proposals/credential-rotation-first-consumer.md`)
should be updated after this proposal's ADR lands to point at the
normative spec rather than at code symbols.

---

## 8. Security and reliability requirements

These are the bars the ADR and spec must satisfy before a rotation
v0.1 is considered shippable. They do not pre-commit to answers; they
pre-commit to the questions.

1. **Anchor-before-effect** must be a testable invariant (invariant 3).
2. **Pre-rotation manifest commitment** must be specified exactly,
   with the full byte layout of `sha256(publicKey || algorithmSuite
   || backendId)` and a test vector.
3. **Suite downgrade protection** must be specified (invariant
   implicit in `SuiteDowngradeRejected`).
4. **Verify-before-revoke** must be a testable invariant (invariant 12).
5. **Rate limit floor** must be a hard floor, not advisory (currently
   `POLICY_FLOORS.maxRotationsPerHour = 2`).
6. **Challenge period floor** must be a hard floor (currently 15min).
7. **Witness quorum** — either specify M-of-N with a threshold or
   drop invariant 4 from v0.1. No middle ground.
8. **Rollback semantics on mid-rotation failure** must be defined.
9. **Delegation-vs-rotation interaction** must be carried as a named
   blocking open question until `SOMA-DELEGATION-SPEC.md` is updated.

---

## 9. Delivery shape

Assuming this proposal is accepted, the follow-up sequence is:

1. **ADR:** `docs/decisions/ADR-0NNN-credential-rotation-semantics.md`.
   Resolves (or explicitly carries as open) every **O** row in §4, the
   mechanism-vs-policy question in §5, and picks a canonical subsystem.
2. **Spec:** `SOMA-ROTATION-SPEC.md` at repo root, added to
   `docs/reference/spec-index.md`. Contains the normative invariants,
   pre-rotation byte layout, event lifecycle, error taxonomy, policy
   floors, and test vectors.
3. **Delegation spec update:** `SOMA-DELEGATION-SPEC.md` revision to
   close Open Question 6, blocked on the rotation ADR.
4. **Controller alignment PR:** small code-only PR in Soma that
   reconciles code comments with the spec (e.g. drops the "twelve
   invariants" comment in favour of a `SOMA-ROTATION-SPEC` reference,
   removes the `§13c` reference, and either implements or explicitly
   marks invariant 4 as deferred).
5. **First-consumer ADR in ClawNet:** updates
   `claw-net/docs/decisions/` with the integration model for ClawNet
   specifically, pointing at the Soma spec.
6. **ClawNet first-consumer PR slices** against the ratified spec.

Steps 1 and 2 can be a single PR if the material is compact enough. A
compressed path is acceptable as long as the spec file exists as a
normative target when first-consumer code lands.

---

## 10. ADR Needed?

Yes. This proposal is the precursor to an ADR. The ADR must, at
minimum:

- name the canonical rotation subsystem (§3);
- answer or explicitly carry every **O** row in §4 as a named
  blocking question with an owner and remediation plan;
- state whether invariant 4 (M-of-N panic freeze) is part of v0.1
  or deferred (§4.6);
- state whether the Class A/B/C mechanism is normative protocol or a
  default policy within a bounded mechanism (§5);
- reference a rotation spec file by path, not an imaginary
  architecture document.

---

## 11. Open questions (the blocking set)

This section restates the **O** rows from §4 plus the mechanism/policy
question, for ease of ADR review. Each question is a candidate to be
either resolved or explicitly carried as a known gap. The proposal
does not force premature resolution.

1. Canonical subsystem: `credential-rotation/` or `key-rotation.ts`? (§3)
2. Delegation-vs-rotation interaction when a parent credential
   rotates. Blocks on `SOMA-DELEGATION-SPEC.md` revision. (§4.2)
3. Rollback semantics on mid-rotation failure. (§4.4, §4.5)
4. Recovery path after confirmed compromise. (§4.5)
5. Witness quorum model — M-of-N or single-witness for v0.1. The
   controller is single-witness today; invariant 4 claims M-of-N. (§4.6)
6. Is the Class A/B/C model normative protocol or a default policy
   within a configurable mechanism? (§5)
7. Where does the normative invariant text live — inside
   `SOMA-ROTATION-SPEC.md`, inside a new `docs/architecture/rotation.md`,
   or inside both? (§1)

---

## 12. Links

- Soma#24 — `Define credential rotation semantics and trust model for Soma`
- `src/heart/credential-rotation/{types.ts,controller.ts,index.ts}`
- `src/heart/key-rotation.ts`
- `SOMA-DELEGATION-SPEC.md` (Open Question 6, line 307)
- `docs/reference/spec-index.md`
- `docs/proposals/revocation-gossip.md` (touched by §4.3)
- `docs/proposals/session-mode.md` (touched by §4.2)
- `claw-net/docs/proposals/credential-rotation-first-consumer.md`
- `claw-net/internal/active/rotation-battle-test-and-roadmap.md`
  (P0/P1/P2 audit findings, consumer-side)
