# ADR-0006: Lineage Fork Ceremony

Status: accepted

## Note on ADR shape

This ADR is a decision packet, not implementation. It ratifies the
decisions surfaced by `docs/proposals/lineage-fork-ceremony.md` for
how independently-deployed Soma hearts establish cryptographic
parent-child lineage. It does not ship ceremony code, CLI tools,
tests, or package surface changes. Acceptance clears the
implementation gate only.

Per `AGENTS.md`, decisions that change or clarify protocol semantics,
public package API, or security posture require a proposal and likely
an ADR before implementation. The lineage fork ceremony adds new
exported functions to `soma-heart`, introduces a new CLI entry point,
and defines a new operational protocol for establishing trust
relationships across deployment boundaries. This ADR is the gate
that review called for.

This ADR was accepted after reviewers explicitly approved every
decision row (D1-D9). The advancement of `Status:` from `proposed`
to `accepted` is the result of that review, recorded here at merge
time. Acceptance clears Gate 2 only. Gate 2 does **not** authorise
ceremony implementation, CLI tools, or package/API surfaces; it only
unblocks Gate 3 drafting under the constraints enumerated below.
Credential-rotation semantics remain unchanged: ADR-0004 and
`SOMA-ROTATION-SPEC.md` stay authoritative. Trust certificate
semantics remain unchanged: ADR-0005 stays authoritative. Lineage
certificates are distinct from trust certificates and use their own
type system (`LineageCertificate`).

## Context

Soma hearts can be created (`createSomaHeart`) and persisted
(`serializeHeart`/`loadHeartState`). The lineage subsystem
(`src/heart/lineage.ts`) already supports signed parent-child
certificates, chain verification, capability attenuation, TTL, and
budget credits. Attack test #14 (lineage grafting) validates the
cryptographic defenses. The persistence format carries `lineageChain`
and `lineageRootDid` fields.

But no ceremony protocol exists for establishing lineage across
deployment boundaries. ClawNet boots its heart via
`createSomaHeart()` with no parent. Pulse boots its heart via
`createSomaHeart()` with no parent. Both hearts are cryptographic
strangers. An observer cannot verify cross-repo trust relationships
or distinguish "your Pulse agent" from "a stranger's Pulse agent."

Pulse already forks sub-agent hearts from its own operator heart
(`forkAgentHeart` in `hosted/heart-client.ts`), but the operator
heart itself has no lineage. Pulse PR #38 merged heart persistence
and escalated lineage as the next step, noting that lineage chain
design touches Pulse, ClawNet, and `soma-heart` repos.

The lineage primitive is built and tested. The ceremony — the defined
protocol for how an operator with access to both hearts establishes
the parent-child relationship — is the missing piece.

## Decision

All nine rows below are **accepted decisions** derived from the
proposal and the resolved open questions. Reviewers explicitly
approved the disposition of every decision row (D1-D9) and the PR
was approved for merge. `Status:` advanced from `proposed` to
`accepted` at merge time, following the pattern used by ADR-0004 and
ADR-0005.

Acceptance of these rows does not implement the ceremony, does not
ship a CLI tool, and does not authorise any package/API surface
beyond what is needed for Gate 3 drafting.

### D1. Offline ceremony model

**Decision.** The fork ceremony is an offline provisioning step, not
a runtime protocol. It runs once per parent-child relationship at
deployment time by an operator with access to both hearts.

**Source.** Proposal section 3 (ceremony protocol) and section 5
(alternatives considered).

**Alternatives considered and rejected.**

- *Runtime ceremony.* ClawNet exposes a fork endpoint; Pulse calls it
  at boot. Creates a hard runtime dependency, a new network attack
  surface, and a chicken-and-egg authentication problem since the
  child has no lineage yet to prove it is authorized to request a
  fork. Rejected.
- *Shared-secret derivation.* Both hearts derive lineage from a
  shared operator seed. Loses the parent-child model entirely: no
  capability attenuation, no directed revocation, no asymmetric
  authority. Two hearts from the same seed are peers, not parent and
  child. Rejected.
- *Registry/broker ceremony.* A third service brokers the fork.
  Over-engineered for the current scale (two consumers). The registry
  itself becomes a new trust anchor that must be secured. May be
  appropriate later for N-party dynamic forking but not now. Rejected.

### D2. CLI tool as primary ceremony interface

**Decision.** The primary ceremony interface is a CLI tool
(`soma-heart fork` or similar — name non-binding). Secrets come from
environment variables, never CLI arguments (no shell history leaks).
The CLI is a thin wrapper around the ceremony library.

**Source.** Proposal section 3 (CLI sketch) and section 13 (delivery
shape).

**Security requirements (from proposal section 12).** The CLI tool
MUST NOT make network requests, MUST wipe all key material from
memory after use, MUST NOT persist secrets or intermediate state, and
MUST fail-fast on invalid blobs, wrong passwords, or mismatched
crypto providers.

### D3. Lineage is opt-in, not required

**Decision.** Lineage is opt-in. Root hearts legitimately have no
lineage. No warning is emitted on boot when lineage is absent.
Hearts function fully without lineage; lineage is required only for
cross-repo trust verification.

**Source.** Resolution of proposal open question Q1 ("Should lineage
be required for production hearts?").

**Rationale.** Root hearts are valid by definition — they are the
trust anchors. Requiring lineage or emitting warnings would create
noise for legitimate single-heart deployments and contradict the
existing design where `lineageChain` is an optional field in
`HeartState`.

### D4. No protocol-enforced max chain depth

**Decision.** The protocol does not enforce a maximum chain depth.
This is a policy-level decision for downstream consumers or verifier
policies. The ceremony tool supports multi-level chains (the
parent's chain is prepended per proposal section 3 step 4).

**Source.** Resolution of proposal open question Q2 ("Should the CLI
tool enforce a maximum chain depth?").

**Rationale.** Chain depth limits are deployment-topology concerns,
not protocol concerns. Different deployments may have legitimately
different depths (operator → service → sub-agent vs. a flat
two-level topology). Hardcoding a limit in the protocol would be
premature. Verifier policies can enforce depth limits per their own
requirements.

### D5. HistoricalKeyLookup integration for verifyLineageChain

**Decision.** `verifyLineageChain` accepts an optional
`HistoricalKeyLookup` parameter. When provided, each certificate's
`parentPublicKey` is checked against the rotation subsystem for
validity at `issuedAt`. When omitted, current self-contained
verification is preserved (signature checked against the embedded
key). This mirrors the existing pattern in `verifyBirthCertificate`.

**Source.** Proposal section 6 (key rotation interaction).

**Cross-reference.** ADR-0004 and `SOMA-ROTATION-SPEC.md` remain
authoritative for rotation semantics. This ADR proposes no
credential-rotation semantic changes. The `HistoricalKeyLookup`
integration is an additive, non-breaking change that composes
existing rotation primitives with existing lineage verification.

### D6. Ceremony library as exported package surface

**Decision.** The ceremony is delivered as exported functions in
`soma-heart` (provisionally `forkCeremony(opts)` — name
non-binding). The function orchestrates the full ceremony protocol:
decrypt parent heart, create lineage certificate, patch child heart
state, re-encrypt child heart. The CLI tool wraps the library.

**Source.** Proposal section 13 (delivery shape).

**Non-decision at this layer.** Package surface details — exact
export names, subpath exports, file locations — are
implementation-level and decided at implementation time, not by this
ADR. This follows the ADR-0005 pattern where D12 explicitly defers
package/API timing.

### D7. Audit log receipt deferred

**Decision.** A separate signed ceremony receipt (distinct from the
lineage certificate itself) is deferred. The lineage certificate is
the record of the ceremony. A separate operational receipt
(timestamp, parent DID, child DID, cert ID) is a nice-to-have for a
future iteration but is not needed for the ceremony to ship.

**Source.** Resolution of proposal open question Q3 ("Should the CLI
tool emit a signed receipt of the ceremony?").

**Rationale.** The lineage certificate already contains all the
information an audit trail needs: parent identity, child identity,
capabilities, timestamp, and the parent's signature. A separate
receipt would duplicate this information. If operational needs
require a separate artifact, it can be added without protocol
changes.

### D8. Revocation distribution deferred

**Decision.** Revocation distribution — how a child or observers
learn about a parent's revocation of a lineage cert — is
acknowledged as the same gossip/distribution problem as general
revocation. It does not block the ceremony design and is deferred to
future work.

**Source.** Resolution of proposal open question Q5 ("If the parent
revokes a child's lineage cert, how does the child or observers
learn about it?").

**Rationale.** The revocation primitive already exists
(`heart.revoke({targetKind: 'lineage'})`). The distribution problem
is orthogonal to the ceremony protocol and applies equally to all
revocation types, not just lineage. Solving it here would expand
scope beyond the ceremony without adding ceremony-specific value.

### D9. Scope boundary — Soma owns ceremony/CLI/tests, downstream owns deployment integration

**Decision.** Soma owns: the ceremony protocol, CLI tool
implementation, `HistoricalKeyLookup` integration in
`verifyLineageChain`, ceremony tests (happy path, re-ceremony,
multi-level chains, capability attenuation across ceremony boundary),
and package surface (exported ceremony functions + CLI).

Downstream repos own: deployment timing (at image build, at deploy,
at first boot), secret storage and rotation in their infrastructure,
deployment documentation for their specific topology, and CI/CD
integration.

**Source.** Proposal section 10 (scope boundary).

**Explicitly out of scope.**

- N-party dynamic forking (registry-brokered ceremonies)
- On-chain anchoring of lineage chains
- Gossip-based lineage distribution
- Lineage-based reputation scoring
- Automatic re-forking on parent key rotation

## Non-goals

- No ceremony code, CLI tool, or tests implemented by this ADR.
- No modifications to `lineage.ts`, `persistence.ts`, or any source
  files.
- No N-party dynamic forking.
- No on-chain anchoring.
- No gossip-based lineage distribution.
- No lineage-based reputation scoring.
- No automatic re-forking on parent key rotation.
- No normative spec changes (the `LineageCertificate` format is
  unchanged).
- No downstream deployment documentation.

## Security and assurance boundaries

The ceremony requires the same secrets that `loadHeartState` already
requires; no new trust assumptions are introduced. The ceremony is a
composition of existing primitives (`loadHeartState`,
`createLineageCertificate`, `serializeHeart`), not a new
cryptographic protocol.

- **CLI security.** Secrets from environment variables only. Memory
  wipe after use. No network requests. No secret persistence.
  Fail-fast validation on invalid inputs.
- **Idempotency.** Re-running the ceremony produces a new certificate
  (new nonce, new timestamp) without corrupting the child's existing
  state. The ceremony is safe to retry on failure.
- **Key rotation interaction.** Existing lineage certificates remain
  valid after parent key rotation. The signature was made by the old
  key, and `parentPublicKey` records the old key; signature
  verification succeeds against the recorded key. Verifiers use
  `HistoricalKeyLookup` for temporal key resolution to confirm the
  old key legitimately belonged to the parent at `issuedAt`.
  Compromised (not merely rotated) keys are a revocation problem,
  not a lineage problem.
- **Assurance boundary.** Lineage certificates prove provenance and
  capability attenuation — who spawned this heart, when, and with
  what permissions. They do not prove factual truth, endpoint quality,
  model correctness, or future reliability.

## Consequences

- The proposal's ceremony direction is locked as the decision packet
  for implementation. Downstream systems can cite accepted ADR rows
  without waiting for implementation, provided they do not ship
  runtime behaviour that would require ceremony code that does not
  yet exist.
- Implementation gate is cleared: ceremony library, CLI tool, tests,
  and `verifyLineageChain` enhancement can proceed under Gate 3.
- Package surface changes (new exports, new CLI entry point) are
  authorised in principle; exact names and paths are
  implementation-level decisions.
- ADR-0004 rotation semantics stay authoritative. Any
  lineage-driven rotation concern references ADR-0004 and
  `SOMA-ROTATION-SPEC.md`; this ADR does not amend them.
- ADR-0005 trust certificates are distinct from lineage
  certificates. Lineage certificates predate the trust certificate
  primitive and use their own type system (`LineageCertificate`).
  This ADR does not alter trust certificate semantics.
- Downstream integration work (deployment timing, secret management,
  CI/CD) belongs in downstream repos per D9.

## Readiness and next gates

Downstream work MUST NOT be merged or ratified until the prior gate
has cleared. Drafting work below a gate requires explicit
authorisation and does not imply future acceptance.

- **Gate 1 - ADR drafted.** Cleared by the initial draft of this
  document.
- **Gate 2 - ADR accepted.** Cleared: reviewers explicitly approved
  the disposition of every decision row (D1-D9) and the PR was
  approved for merge. `Status:` advanced from `proposed` to
  `accepted` at merge time. Subsequent gates (3 onward) are unblocked
  for drafting under the constraints recorded in this ADR.
- **Gate 3 - Ceremony implementation.** Ceremony library + CLI tool +
  `verifyLineageChain` enhancement + tests. Delivered as a separate
  PR in Soma. Draftable now that Gate 2 is cleared.
- **Gate 4 - Package surface stabilised.** Version bump or new
  exports as implementation dictates. Not draftable without Gate 3.
- **Gate 5 - Downstream integration unlock.** Separate work in
  downstream repos (Pulse, ClawNet). Out of scope for Soma. Not
  draftable without Gate 4.

## Open questions

The following questions remain spec-level or implementation-level
rather than ADR-blocking and can be resolved during Gate 3
(ceremony implementation) without re-opening any D row above:

1. Canonical ceremony output format — the exact JSON shape of the
   patched child heart blob is an implementation-level detail, not an
   ADR concern.
2. Whether the ceremony should support batch forking (multiple
   children from one parent in a single invocation) — a nice-to-have
   for operational convenience, not required for v1.

## Links

- `docs/proposals/lineage-fork-ceremony.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/decisions/ADR-0005-soma-heart-trust-certificates.md`
- `src/heart/lineage.ts`
- `src/heart/persistence.ts`
- `src/heart/key-rotation.ts`
- `src/heart/historical-key-lookup.ts`
- `tests/attacks/14-lineage-grafting.test.ts`
- `AGENTS.md`
- `SOMA-ROTATION-SPEC.md`
