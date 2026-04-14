# ADR-0004: Credential Rotation Semantics

Status: proposed

## Note on ADR style

This ADR intentionally departs from the short form used by ADR-0001
through ADR-0003. Those ADRs declare greenfield rules in ~20 lines each.
ADR-0004 ratifies pre-existing, security-sensitive code that was merged
before a normative spec existed (~1,770 LOC across
`src/heart/credential-rotation/` and `src/heart/key-rotation.ts`).

Per `AGENTS.md`, the fitness check and evidence ledger apply "before
treating pre-system or salvaged work as build-ready". This ADR is the
build-ready gate for rotation. The evidence ledger is therefore
included inline rather than maintained as a separate doc. Length is a
deliberate exception, not a template drift.

The ADR stays in `Status: proposed` until (a) every decision row below
has a disposition reviewers have explicitly approved, and (b) this PR
has been reviewed and approved for merge. Candidate dispositions in the
draft are not sufficient. `Status: accepted` is the *result* of that
acceptance, not its trigger — advancing the status line is the last
step of acceptance, not a shortcut to it.

## Context

Soma ships rotation code that behaves as if a normative spec exists:

- `src/heart/credential-rotation/types.ts` cites "architecture doc §13c"
  and "§14 L1-L3"; neither exists in `docs/`.
- Two parallel rotation subsystems coexist:
  `src/heart/credential-rotation/` (pluggable, class/suite/staging
  aware, 1,356 LOC) and `src/heart/key-rotation.ts` (KERI-style
  forward-digest chain, 413 LOC).
- `src/heart/credential-rotation/index.ts` already declares the second
  subsystem internal, but no decision record or spec ratifies that
  choice.
- `soma-heart` v0.3.0 exposes `./credential-rotation` as a public
  subpath while the normative contract lives only in source comments.
- ClawNet has shadow-adopted this surface via claw-net PR #30 and PR #31
  (inert `ClawNetApiKeyBackend`). No request-path behaviour depends on
  it today.

PR #28 (`docs/proposals/credential-rotation.md`, merged as `9d0514e`)
framed the gap and enumerated seven decisions that must be resolved —
or explicitly carried as open — before a rotation ADR can land. This
ADR proposes dispositions for all seven: three that propose ratifying
existing evidence (D1, D6, D7) and four that require reviewer judgment
beyond existing evidence (D2, D3, D4, D5). None are ratified until
reviewers approve them and the ADR advances to `Status: accepted`.

## Decision

All seven rows below are **proposed dispositions** authored by the ADR
drafter. Nothing in this section is ratified until reviewers approve
each row and the ADR advances to `Status: accepted`.

Three rows (D1, D6, D7) propose ratifying existing code state or the
proposal-§5 consensus. They are expected to be low-friction but still
require reviewer sign-off; they carry no dedicated reviewer-focus
block because the proposal is "accept the current evidence as-is".

Four rows (D2, D3, D4, D5) propose dispositions that require reviewer
judgment beyond the existing evidence. Each carries a reviewer-focus
block. These are the reviewer-attention set and are listed in §Reviewer
focus below in recommended discussion order.

### D1. Canonical subsystem

**Proposed disposition.** `src/heart/credential-rotation/` is the
canonical consumer-facing rotation substrate.
`src/heart/key-rotation.ts` is an internal KERI-style log primitive.
Downstream packages MUST NOT import `key-rotation.ts` directly. A
future ADR may use it as `credential-rotation/`'s L1 log backend or
deprecate it; ADR-0004 does not.

**Evidence.** `src/heart/credential-rotation/index.ts` header already
states this; `packages/soma-heart/package.json` `exports` surfaces
only `./credential-rotation`. The proposal is to ratify this
existing code state, not to change it.

### D2. Delegation-vs-rotation interaction

**Proposed disposition.** Delegations bind to a stable identity anchor,
not to the credential that issued them. When a parent credential
rotates, existing delegation keys remain valid without re-issuance,
provided the parent's `identityId` is unchanged and the new credential
has reached `effective`.

**Reviewer focus.** Is identity-binding the right semantic choice for
v0.1, or does it leak too much implicit trust across rotation events?
The alternative is cascade re-issuance on every parent rotation,
trading availability for a tighter blast radius.

**Resolution path.** This ADR records the *intended interaction*. It
does NOT close `SOMA-DELEGATION-SPEC.md` Open Question 6. That spec
update is a separate PR (Slice C) which codifies whichever answer this
ADR accepts into normative delegation-spec text. ADR acceptance alone
does not close OQ6; the delegation-spec PR does.

### D3. Rollback semantics on mid-rotation failure

**Proposed disposition.** v0.1 requires that a mid-rotation failure
leaves the identity in its pre-rotation state. Specifically: if any
step between `stageNextCredential` and `commitStagedRotation` throws,
backend state and controller state must both revert to the pre-stage
state.

**Reviewer focus.** Does v0.1 require clean rollback, or can v0.1
explicitly defer and ship with a documented half-rotation failure mode?

**Implementation note — not pre-decided.** One possible implementation
is a transaction boundary at the controller level: `rotate()` wraps the
stage → verify → commit sequence in a try/abort block that calls
`abortStagedRotation` on any throw. This is a *candidate* approach, not
a committed design. Detailed implementation belongs in the spec and
Slice D; the ADR should not lock it in.

**Acceptance criterion if this row is accepted as proposed.** The
rotation spec must state rollback as a testable invariant, and Slice D
must land a test in `tests/credential-rotation/` that forces a throw
mid-rotation and asserts clean revert.

### D4. Recovery path after confirmed compromise

**Proposed disposition.** v0.1 defines no operator-facing recovery
ceremony beyond the existing `rotate()` + `revokeCredential()`
primitives. Break-glass, panic freeze, and M-of-N-authorized recovery
are deferred to a named follow-up ADR.

**Reviewer focus.** Is deferral acceptable given that Soma is shipping
rotation to a first consumer (claw-net) before break-glass exists?

**Resolution path.** Pick (a) deferral with rationale recorded here, or
(b) name a follow-up ADR with scope and owner and carry the deferral
through that pointer.

### D5. Witness quorum model

**Proposed disposition.** v0.1 is single-witness. Invariant 4 ("panic
freeze requires M-of-N quorum"), currently declared in `types.ts`
line 13, is dropped from the v0.1 normative set. The controller's
existing single-witness behaviour (`witnessEvent` at `controller.ts`
line 584) is proposed as intended-for-v0.1 rather than a placeholder
pending M-of-N.

**Reviewer focus.** Does dropping invariant 4 from v0.1 weaken the
security model unacceptably for the first consumer?

**Implementation consequence if accepted as proposed.** Slice D removes
invariant 4 from the `types.ts` comment and explicitly annotates
`witnessEvent` as single-witness-by-design for v0.1, with a pointer to
a future ADR for M-of-N.

**Alternative.** Implement M-of-N now. This expands Slice D
significantly — threshold verification, test coverage, and a migration
path for identities already in a single-witness state.

### D6. Class A/B/C — mechanism vs. policy

**Proposed disposition.** The class-based policy model is normative
*mechanism*: exactly three classes (`A` | `B` | `C`), with per-class
TTL (`DEFAULT_TTL_POLICY`) and floor semantics. The *default policy* —
the concrete numeric values in `DEFAULT_TTL_POLICY`, `DEFAULT_POLICY`
fields, and `POLICY_FLOORS` — is a starting set, not normative values.

Consumers may raise floors and tighten policy within the mechanism;
they may not lower floors below the absolute minimums the spec will
declare. Adding or removing classes beyond `A | B | C` is not a
configurable policy choice and requires a superseding ADR.

**Evidence.** This is the recommendation from proposal §5. The
proposal carries it as a recommendation, not a settled decision; this
ADR proposes accepting it as the disposition reviewers should ratify.

### D7. Normative invariant text location

**Proposed disposition.** The normative rotation contract lives in
`SOMA-ROTATION-SPEC.md` at repo root, indexed from
`docs/reference/spec-index.md`, following the existing pattern of
`SOMA-CHECK-SPEC.md`, `SOMA-DELEGATION-SPEC.md`, and
`SOMA-CAPABILITIES-SPEC.md`. No separate `docs/architecture/rotation.md`
is created. Source comments cite the spec path; they do not redeclare
invariants.

**Evidence.** The three existing `SOMA-*-SPEC.md` files establish a
pattern; the proposal is to follow it.

## Consequences

- `credential-rotation/` is the named canonical substrate. Any future
  decision to unify or replace it requires a superseding ADR.
- ClawNet's first-consumer implementation stays paused until this ADR
  is accepted, `SOMA-ROTATION-SPEC.md` is ratified, and Slice D code
  reconciliation lands. These correspond to Gates 2, 3, and 4 below.
- Invariant 4 stops being declared-but-unimplemented once Slice D
  lands. Its exact disposition depends on D5.
- `SOMA-DELEGATION-SPEC.md` Open Question 6 is unblocked for update by
  Slice C, but remains open until that PR lands. ADR acceptance alone
  does not close it.
- `src/heart/key-rotation.ts` stays in the tree as an internal
  primitive. A future ADR may deprecate or remove it; ADR-0004 does not.
- Four rows (D2, D3, D4, D5) require reviewer judgment beyond existing
  evidence; their proposed dispositions are the reviewer-focus set.
  Any one of them may change scope or introduce additional slices if
  reviewers pick an alternative to the drafter's proposal.

## Readiness Gates

Downstream work MUST NOT be merged or ratified until the prior gate
has cleared. Drafting work below a gate requires explicit authorization
and does not imply future acceptance.

- **Gate 1 — ADR drafted.** This document exists and is open for
  review.
- **Gate 2 — ADR accepted.** Reviewers have explicitly approved the
  disposition of every decision row (D1–D7), and the PR has been
  reviewed and approved for merge. Only then does `Status:` advance
  from `proposed` to `accepted`. Candidate dispositions in the draft
  are not sufficient; the presence of proposed text does not clear
  this gate.
- **Gate 3 — `SOMA-ROTATION-SPEC.md` ratified.** Separate PR (Slice B).
  Spec includes byte layouts, test vectors, error taxonomy, snapshot
  wire format version, and policy-floor semantics. Indexed in
  `docs/reference/spec-index.md`. Not draftable without Gate 2
  authorization.
- **Gate 4 — Code reconciliation merged.** Separate PR (Slice D).
  Source comments point at `SOMA-ROTATION-SPEC.md` only; `§13c`/`§14`
  strings removed. Invariant 4 disposition applied per D5. Not
  draftable without Gate 2 authorization.
- **Gate 5 — `SOMA-DELEGATION-SPEC.md` Open Question 6 closed.**
  Separate PR (Slice C), parallelizable with Gate 4. Not draftable
  without Gate 2 authorization.
- **Gate 6 — `soma-heart` package surface stabilised.** Conditional
  (Slice E). Version bump if public API changed; no bump if only
  semantics were documented. Not draftable without Gates 3 and 4.
- **Gate 7 — claw-net implementation unlock.** Separate ADR in
  `claw-net/docs/decisions/`. Out of scope for Soma. Not draftable
  without Gate 6.

## Evidence Ledger

### Part 1 — Header

| Field | Value |
|---|---|
| current status | `partial-foundation` — ~1,770 LOC in `src/heart/credential-rotation/` + `src/heart/key-rotation.ts`; no normative spec; shadow-adopted by claw-net (PR #30, PR #31) via inert `ClawNetApiKeyBackend` |
| upstream dependencies | `soma-heart` v0.3.0 `./credential-rotation` export surface; `SOMA-DELEGATION-SPEC.md`; `docs/explanation/security-model.md` |
| downstream dependencies | `claw-net/src/core/api-key-rotation.ts`; inert `ClawNetApiKeyBackend`; any future claw-net rotation consumer |
| missing evidence | no normative `§13c`/`§14` architecture doc; no rollback-on-failure test; no M-of-N implementation or test (intentional if D5 defers); no byte-layout test vectors for `sha256(publicKey \|\| algorithmSuite \|\| backendId)`; no delegation-rotation interaction test |
| blocks current work | yes — claw-net first-consumer implementation unlock is gated on this ADR plus `SOMA-ROTATION-SPEC.md` |
| next gate | Gate 2 — ADR acceptance |
| terminal condition | every decision row has a reviewer-approved disposition; ADR merged with `Status: accepted`; `SOMA-ROTATION-SPEC.md` ratified; Slice D merged; `soma-heart` version bump landed if public API changed |

### Part 2 — Decision rows

| # | Question | Evidence today | ADR disposition | Next gate | Terminal condition |
|---|---|---|---|---|---|
| 1 | Canonical subsystem | `credential-rotation/index.ts` header declares `key-rotation.ts` internal; package `exports` surfaces only `./credential-rotation` | Proposed: ratify existing code state (D1) | Gate 2 | Spec references only `credential-rotation/` symbols |
| 2 | Delegation-vs-rotation (OQ6) | Undefined in both specs today | Proposed: delegations bind to identity (D2); reviewer judgment required | Gate 5 (Slice C) | `SOMA-DELEGATION-SPEC.md` line 307 replaced with a normative rule |
| 3 | Rollback on mid-rotation failure | Not enforced; no transaction boundary in `controller.rotate()` | Proposed: required for v0.1 (D3); reviewer judgment required | Gate 3 (spec), Gate 4 (code) | Testable invariant in spec; test in `tests/credential-rotation/` asserting clean revert on mid-rotation throw |
| 4 | Recovery after confirmed compromise | Not defined | Proposed: deferred from v0.1 to a named follow-up ADR (D4); reviewer judgment required | Gate 2 | Deferral rationale recorded or follow-up ADR named with owner |
| 5 | Witness quorum | Single-witness MVP at `controller.ts:584`; invariant 4 claims M-of-N at `types.ts:13` | Proposed: single-witness, drop invariant 4 from v0.1 (D5); reviewer judgment required | Gate 4 (Slice D) | `types.ts` invariant 4 removed or re-annotated; single-witness test in `tests/credential-rotation/` |
| 6 | Class A/B/C mechanism vs. policy | Hard-coded in `types.ts` `DEFAULT_TTL_POLICY` / `POLICY_FLOORS` | Proposed: ratify proposal §5 — mechanism normative, default policy non-normative (D6) | Gate 3 (spec) | Spec distinguishes mechanism from default policy; floors annotated as absolute minimums |
| 7 | Normative text location | Comments in `types.ts` cite `§13c`/`§14`; no `docs/` counterpart | Proposed: ratify — `SOMA-ROTATION-SPEC.md` only (D7) | Gate 4 (Slice D) | `§13c`/`§14` strings removed from source; comments cite spec path |

## Reviewer focus

For efficient review, attend to these rows first:

1. **D3 (rollback)** — the single most expensive decision. Picks v0.1
   scope and likely determines whether Slice D can be small.
2. **D5 (witness quorum)** — picks whether invariant 4 survives v0.1.
   Cheap to defer, expensive to implement.
3. **D2 (delegation)** — the proposed answer may look obvious but it
   commits delegation semantics across rotation events. Should not be
   accepted without reviewing against `SOMA-DELEGATION-SPEC.md`
   §Concepts.
4. **D4 (recovery)** — cheap to defer, but the deferral itself should
   be a conscious choice, not silent carryover.

## Links

- Proposal PR: `docs/proposals/credential-rotation.md` (merged `9d0514e`)
- Tracking issue: Soma#24 — `Define credential rotation semantics and trust model for Soma`
- `src/heart/credential-rotation/{types.ts,controller.ts,index.ts}`
- `src/heart/key-rotation.ts`
- `SOMA-DELEGATION-SPEC.md` — Open Question 6 at line 307
- `docs/reference/spec-index.md`
- `packages/soma-heart/package.json` — `exports` map
- `AGENTS.md` — fitness-check and evidence-ledger rules
- `docs/proposals/PROPOSAL-TEMPLATE.md` — Evidence Ledger template
