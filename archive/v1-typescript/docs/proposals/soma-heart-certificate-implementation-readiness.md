# Soma Heart Certificate Implementation Readiness

Status: implemented

> Docs-only planning packet for the post-Gate-6 implementation
> slices of the Soma Heart certificate package surface. This
> document is planning only. It does not merge package, API,
> runtime, source, test, or vector code, and its acceptance does
> not authorise implementation. Every slice described below is a
> future instrument that MUST be separately proposed, reviewed,
> and authorised against the ownership, boundary, and export plan
> ratified in
> `docs/proposals/soma-heart-certificate-gate6-stabilisation.md`.
> Credential-rotation semantics remain authoritative in ADR-0004
> and `SOMA-ROTATION-SPEC.md` and are not modified by anything in
> this packet.

## Context

- **Gate 1**: cleared by the ADR-0005 draft PR.
- **Gate 2**: cleared by the ADR-0005 acceptance PR.
- **Gate 3**: cleared by the initial merge of
  `SOMA-HEART-CERTIFICATE-SPEC.md` as `Status: Draft`.
- **Gate 4**: cleared by the spec acceptance PR, plus the
  post-Gate-4 docs-only amendment that pinned canonical
  encoding and hash rules in spec sections 9.2-9.5.
- **Gate 5**: cleared by the package-surface proposal
  acceptance PR, which also confirmed vector delivery at
  `test-vectors/soma-heart-certificate/v0.1/` and resolution of
  spec section 21 items 2-7, 9, and 10.
- **Gate 6**: cleared by
  `docs/proposals/soma-heart-certificate-gate6-stabilisation.md`
  moving to `Status: accepted`. Gate 6 pinned package-surface
  ownership, naming, import path, source-file ownership,
  public/internal API boundary, vector conformance requirement,
  failure-mode wire identifiers, export plan, and `soma-sense`
  re-export posture.
- **Gate 7**: remains blocked. It is downstream to Soma and MUST
  be raised in `claw-net/docs/decisions/`. This packet does not
  unblock, authorise, or pre-approve Gate 7.

This packet is not implementation. It is a planning artifact
that proposes how a sequence of future PR slices could safely
land certificate package code *if and only if* each slice is
separately proposed, reviewed, and authorised against the
Gate 6 accepted plan.

## Goals

- Split the future certificate package work into small, safe,
  reviewable PR slices with explicit ownership, allowed files,
  forbidden files, test/check requirements, and merge gates.
- Preserve the Gate 6 accepted package shape across every
  slice, including subpath `soma-heart/certificate`, the
  public/internal partition, and the `soma-sense` observer-safe
  re-export posture.
- Preserve vector conformance against
  `test-vectors/soma-heart-certificate/v0.1/manifest.json` as
  the non-negotiable correctness contract of every slice that
  touches canonical bytes, certificate identifiers, or
  signature-input hashes.
- Keep credential-rotation semantics unchanged. Rotation
  lookup is consumed through existing surfaces only; no slice
  modifies rotation lifecycle, rollback, pre-rotation
  commitment, witness, quorum, class, policy-floor, snapshot,
  or historical-lookup semantics.
- Fail closed on ambiguous state at every slice boundary, in
  line with spec section 18.
- Keep every boundary rule from ADR-0005, the spec, and the
  Gate 6 proposal intact across all slices.

## Non-goals

- No code. This packet authorises zero source, zero tests,
  zero vectors, zero package manifests, zero export maps, zero
  CI.
- No TypeScript, no interfaces, no class sketches that could
  be mistaken for a binding contract. Any names below are
  illustrative only, per the Gate 5 and Gate 6 proposals.
- No edits to `package.json`, any `packages/*/package.json`,
  any `exports` map, `pnpm-workspace.yaml`, or build config in
  this packet.
- No edits to source files under `src/` or `packages/*/`.
- No edits to the vector corpus at
  `test-vectors/soma-heart-certificate/v0.1/`. Any
  typo/blocker found during slice drafting MUST be reported
  before any vector file is touched.
- No edits to `SOMA-HEART-CERTIFICATE-SPEC.md`, ADR-0005,
  ADR-0004, `SOMA-ROTATION-SPEC.md`, or any other spec or
  ADR.
- No ClawNet runtime, first-consumer integration, or Gate 7
  scaffolding.
- No runtime "is-this-trusted" query API.
- No reputation systems, scoring, ranking, or aggregate trust
  signals or judgments.
- No tokenomics, staking markets, proof mining, reward/burn
  mechanics, marketplace, hosted witness operations, platform
  cuts, pricing, routing, cache/orchestration, or `$CLAWNET`
  utility concerns in any slice.
- No elevation of x402 to a hard protocol dependency. x402
  stays as the first/default rail adapter only.
- No claim that Soma verifies real-world truth.
- No automatic transitive trust across chain links.
- No credential-rotation semantic changes.

## Proposed PR slices

The slices below are **non-binding at the identifier level** and
**binding at the ownership / allowed-files / forbidden-files /
merge-gate level**. Every slice's acceptance is a separate
future instrument, not a consequence of accepting this packet.

Reference: the Gate 6 accepted package is `soma-heart`, the
subpath export is `soma-heart/certificate`, and the conceptual
source directory is `packages/soma-heart/src/certificate/` as
recorded in the Gate 6 proposal. The existing `soma-heart`
build maps exports such as `./credential-rotation` from
`src/heart/credential-rotation/` to
`packages/soma-heart/dist/heart/credential-rotation/`. Slice 1
is responsible for reconciling the Gate 6 conceptual directory
with the existing build convention and pinning the exact
on-disk source path before any other slice writes a source
file. Reconciliation MUST preserve the accepted subpath
`soma-heart/certificate` and the accepted ownership under
`soma-heart`; it MUST NOT introduce a new top-level package.

### Slice 1 - Package skeleton and internal module layout only

- **Purpose.** Create the empty directory layout for the
  certificate module and reconcile the Gate 6 conceptual
  source directory with the existing `soma-heart` build
  convention. No behaviour.
- **Allowed files.**
  - The on-disk source directory for the certificate module
    (exact path pinned by this slice; must resolve to the
    `soma-heart/certificate` subpath export without modifying
    unrelated subpath exports).
  - A single `index` entry file per internal area with no
    runtime behaviour beyond a module-level barrel or
    placeholder `export {}` equivalent.
  - An internal README or module header comment describing
    which spec sections each area owns, per the Gate 6 area
    mapping table.
- **Forbidden files.**
  - `package.json`, any `packages/*/package.json`, any
    `exports` map edit beyond adding the `./certificate`
    subpath export (if Slice 1 elects to land the export entry
    in this slice at all, it MUST be the only change in this
    slice's manifest edit).
  - Any source file implementing canonicalisation,
    identifier hashing, signature input, vector loading,
    validation, or any other certificate behaviour. Those
    belong to later slices.
  - `SOMA-HEART-CERTIFICATE-SPEC.md`, ADR-0005, ADR-0004,
    `SOMA-ROTATION-SPEC.md`, any other spec or ADR.
  - `test-vectors/**`.
  - `src/heart/credential-rotation/**` and any other rotation
    source. Rotation remains consumed, not modified.
- **Tests / checks required.**
  - `pnpm install`, `pnpm lint`, `pnpm typecheck`, `pnpm build`
    all pass on the skeleton.
  - `pnpm test` passes with no new test files.
  - Build output for `soma-heart` still contains every
    pre-existing subpath export unchanged.
  - If Slice 1 adds the `./certificate` subpath export to
    `packages/soma-heart/package.json`, the exports map MUST
    continue to resolve every previously-exported subpath
    byte-for-byte, and MUST NOT widen, narrow, or reorder any
    unrelated subpath.
- **Boundary risks.**
  - Accidentally importing rotation internals from the
    skeleton. Mitigation: Slice 1 MUST NOT import anything
    from `src/heart/credential-rotation/**` or
    `soma-heart/credential-rotation`.
  - Accidentally exporting a public identifier under
    `soma-heart/certificate` before Slice 2 implements the
    first behaviour. Mitigation: Slice 1 exports only the
    barrel module or placeholder and nothing else.
  - Reconciliation drift from the Gate 6 conceptual directory
    name. Mitigation: Slice 1 records the exact on-disk path
    in the PR description and in the module header comment
    and cites the Gate 6 proposal.
- **Merge gate.**
  - Every check above green.
  - PR description explicitly confirms no behaviour, no
    vectors, no spec edits, no ADR edits, no rotation edits.
  - Reviewer sign-off that the on-disk source directory is a
    faithful reconciliation of the Gate 6 conceptual directory
    and not a new top-level package or a bypass of the
    accepted subpath.

### Slice 2 - Canonical JSON, certificate identifier, and signature input helpers

- **Purpose.** Implement spec sections 9.1-9.4 as pure helpers
  without any vector loader, validator, or verifier wiring.
- **Allowed files.**
  - Source files under the certificate source directory
    pinned by Slice 1, limited to:
    - canonicalisation helpers (spec sections 9.1-9.2);
    - certificate identifier helpers (spec section 9.3);
    - signature input helpers (spec section 9.4);
    - a small unit test file per helper under the existing
      `tests/` convention.
  - No new top-level source file outside the certificate
    source directory.
- **Forbidden files.**
  - Any vector loader, vector manifest reader, or test that
    reads from `test-vectors/**`. That belongs to Slice 3.
  - Any profile, claim, evidence, policy, signature
    verification, Soma Check binding, or rail adapter source.
  - Any rotation source. Rotation is not consumed yet.
  - `SOMA-HEART-CERTIFICATE-SPEC.md`, any ADR, any other
    spec.
  - `packages/*/package.json`, `exports` maps beyond what
    Slice 1 already landed.
  - `test-vectors/**`.
- **Tests / checks required.**
  - Unit tests MUST cover every canonicalisation rule from
    spec section 9.2: UTF-8 no BOM, code-point key ordering,
    duplicate-key rejection, escape tightenings, integer
    millisecond timestamps, string decimals outside the
    `[-(2^53-1), 2^53-1]` integer range, NaN / Infinity /
    undefined rejection, absent optional fields omitted, array
    order preserved, base64 RFC 4648 section 4 with padding,
    `signatures` omitted from the canonical input entirely.
  - Unit tests MUST cover the identifier construction
    `lowercase_hex(sha256("soma-heart-certificate:v0.1:" || canonical_bytes))`
    per spec section 9.3.
  - Unit tests MUST cover the signature input construction
    `"soma-heart-certificate:v0.1:<role>:" || canonical_bytes`
    per spec section 9.4, including role-prefix mismatch
    rejection.
  - `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`
    green.
- **Boundary risks.**
  - Divergence from the pinned canonical rules. Mitigation:
    Slice 2 MUST cite spec sections 9.1-9.4 in PR description
    and in source comments where a reader might otherwise
    reach for a default JSON stringifier.
  - Introducing a production signing primitive under
    `soma-heart/certificate` that observer-only
    `soma-sense` could later re-export. Mitigation: Slice 2
    implements signature *input* helpers only, not signature
    *production*. Key material handling belongs to Slice 6 or
    later and MUST NOT be re-exported to `soma-sense`.
  - Accidentally base64url-encoding a byte array. Mitigation:
    explicit unit test locking padding and alphabet per spec
    section 9.2.
- **Merge gate.**
  - Every canonicalisation test above green.
  - PR description explicitly confirms Slice 2 adds no vector
    loader, no validator, no verifier, no rotation consumer,
    no binding helper, and no rail adapter.

### Slice 3 - Vector loader and conformance tests

- **Purpose.** Add a vector loader for
  `test-vectors/soma-heart-certificate/v0.1/manifest.json` and
  drive the Slice 2 helpers against it as the normative
  conformance test.
- **Allowed files.**
  - A vector loader source file under the certificate source
    directory.
  - A conformance test file under the existing `tests/`
    convention that reads the manifest from the repo root
    `test-vectors/` path and asserts Slice 2 outputs match
    every vector's `canonical_json`, `canonical_utf8_hex`,
    `expected_certificate_id`, and
    `signature_inputs[].input_sha256`.
- **Forbidden files.**
  - `test-vectors/**`. Slice 3 READS vectors; it MUST NOT
    edit them. If a typo or blocker is found, Slice 3 stops
    and reports, and a separate vector-amendment PR handles
    it.
  - Any validator, verifier, policy, binding, or adapter
    source.
  - Any rotation source.
  - Any spec, ADR, or reference doc edit.
  - `package.json` / `exports` edits beyond what Slices 1 and
    2 already landed.
- **Tests / checks required.**
  - Conformance test MUST hit every entry in the manifest
    once, with no skips, no xfail, no conditional branches
    that mask a failure.
  - Mismatches MUST surface as
    `canonicalisation-divergence` per spec section 18, using
    the wire identifier from the spec verbatim.
  - Failing conformance blocks the slice. Slice 3 does not
    land until every manifest entry passes.
- **Boundary risks.**
  - Bundling vectors into the package at build time.
    Mitigation: Slice 3 reads from the repo `test-vectors/`
    path at test time only; no build-time copy into `dist/`.
    Whether to offer an integrator-facing vector-loading API
    is an open question for later slices (see the Gate 6
    proposal open question 5).
  - Hiding real divergence behind lenient equality
    comparisons. Mitigation: byte-level equality on
    `canonical_utf8_hex` and string equality on
    `expected_certificate_id` and
    `signature_inputs[].input_sha256` with no tolerance.
- **Merge gate.**
  - 100% of manifest entries pass.
  - PR description explicitly confirms Slice 3 does not
    touch the vector corpus or the spec.

### Slice 4 - Profile, claim, and evidence validators

- **Purpose.** Implement spec sections 5, 6, 7, and 8 as pure
  validators that take a decoded certificate and a profile /
  claim / evidence classification and emit accept / reject
  results with spec section 18 error identifiers.
- **Allowed files.**
  - Validator source files under the certificate source
    directory.
  - Unit tests under `tests/` covering accepted profiles
    (`birth`, `one-sided`, `heart-to-heart`,
    `freshness-receipt-bound`), deferred profiles
    (`policy-statement`, `witnessed`), accepted claim kinds,
    deferred claim kinds (`capability_statement`,
    `delegation_or_endorsement`), accepted evidence kinds,
    and deferred evidence kinds
    (`credential_presentation_reference`,
    `media_content_hash`,
    `third_party_attestation_reference`).
- **Forbidden files.**
  - Signature verification, policy evaluator, binding
    helper, rail adapter, rotation consumer.
  - `test-vectors/**`.
  - Spec, ADR, or reference doc edits.
  - `package.json` / `exports` edits.
- **Tests / checks required.**
  - Every deferred profile MUST reject.
  - Every deferred claim kind MUST reject.
  - Every deferred evidence kind MUST reject.
  - `open` profiles, claims, and evidence MUST be treated as
    non-ratified and rejected by default; any relaxation is a
    Gate 6 boundary violation and blocks the slice.
  - Slice 4 tests MUST NOT mock the Slice 2 canonicaliser or
    the Slice 3 vector loader.
- **Boundary risks.**
  - Silently defaulting an absent optional field. Mitigation:
    explicit unit tests locking "absent means absent", not
    "absent means default".
  - Treating a deferred item as accepted because the test
    harness was permissive. Mitigation: deferred coverage is
    enumerated in unit tests by name, not by list.
- **Merge gate.**
  - Every accepted/deferred case covered.
  - PR description explicitly confirms no shift from `open`
    to `accepted` for any claim, evidence, or profile.

### Slice 5 - Failure-mode error identifier mapping

- **Purpose.** Freeze the lowercase kebab-case wire
  identifiers from spec section 18 as the only error
  identifiers emitted by the certificate module for the
  mapped failure modes.
- **Allowed files.**
  - A single error-mapping source file under the certificate
    source directory.
  - Unit tests under `tests/` asserting each of the 16
    failure modes from spec section 18 maps to the exact
    lowercase kebab-case identifier in the spec.
- **Forbidden files.**
  - Any validator, verifier, policy, binding, or adapter
    source.
  - Any spec or ADR edit. The identifiers come from spec
    section 18 verbatim and MUST NOT be reinterpreted in
    this slice.
  - `test-vectors/**`.
- **Tests / checks required.**
  - Every identifier string matches the spec exactly. A
    character-level diff test against the spec is acceptable
    if implemented as a unit test rather than a build-time
    generator.
  - No additional implementation-internal error identifiers
    collide with spec section 18 identifiers.
- **Boundary risks.**
  - Inventing a vendor-specific identifier that hides a real
    failure. Mitigation: Slice 5 MUST NOT add any identifier
    outside the spec section 18 list.
- **Merge gate.**
  - Byte-level identifier match.
  - PR description explicitly cites spec section 18.

### Slice 6 - Signature verification and rotation lookup adapter

- **Purpose.** Wire Slice 2 signature input helpers into a
  signature verification surface that resolves the signing-
  time credential via an internal-only adapter over
  `soma-heart/credential-rotation`, per spec section 15 and
  ADR-0004.
- **Allowed files.**
  - Source files under the certificate source directory
    implementing signature verification and the internal-only
    rotation lookup adapter.
  - Unit and integration tests under `tests/` exercising the
    historical credential lookup path.
- **Forbidden files.**
  - `src/heart/credential-rotation/**`. The adapter consumes
    rotation surfaces; it MUST NOT re-implement, extend, or
    patch them.
  - `SOMA-ROTATION-SPEC.md`, ADR-0004.
  - `test-vectors/**`.
  - Verifier-policy evaluator source. That belongs to
    Slice 7.
- **Tests / checks required.**
  - Signature verification MUST fail closed on ambiguous
    rotation state.
  - Signature verification MUST reject certificates whose
    claimed signing time falls outside the effective window
    of the resolved credential
    (`credential-ineffective`).
  - Signature verification MUST reject certificates signed
    with a revoked credential (`credential-revoked`).
  - Rotation lookup adapter MUST be internal-only; the
    `soma-heart/certificate` public surface MUST NOT expose
    a rotation primitive.
  - Slice 6 MUST NOT call into any non-public rotation
    internal that is not already exported by
    `soma-heart/credential-rotation`. If such a call seems
    necessary, Slice 6 stops and reports; a rotation ADR
    slice is required instead.
- **Boundary risks.**
  - Absorbing a rotation gap into the certificate module
    instead of escalating it. Mitigation: hard stop + report
    on any missing rotation surface.
  - Re-exporting rotation primitives through
    `soma-heart/certificate`. Mitigation: explicit public
    export test asserting the rotation lookup adapter is not
    on the public surface.
- **Merge gate.**
  - Fail-closed coverage on ambiguous rotation state.
  - Historical lookup test passes against a rotation fixture
    equivalent to the one in the vector manifest.
  - PR description explicitly confirms no edits to
    `src/heart/credential-rotation/**`, `SOMA-ROTATION-SPEC.md`,
    or ADR-0004.

### Slice 7 - Verifier-policy evaluator boundary

- **Purpose.** Implement the verifier-policy evaluator per
  spec sections 4.2, 11, and 12, including the v0.1
  `policy_ref` shape from section 12.
- **Allowed files.**
  - Source files under the certificate source directory
    implementing the policy evaluator.
  - Unit tests under `tests/` exercising policy acceptance,
    rejection, and fail-closed paths.
- **Forbidden files.**
  - `soma-sense` re-export surfaces. The verifier-policy
    evaluator is public but full-install only per Gate 6;
    Slice 7 MUST NOT add it to `soma-sense`.
  - `test-vectors/**`.
  - Any rotation source.
  - `SOMA-HEART-CERTIFICATE-SPEC.md`, ADR-0005.
- **Tests / checks required.**
  - Absent policy field MUST NOT be treated as "accept by
    default".
  - Evaluator MUST NOT expose an "is-this-trusted" surface
    based on chain presence.
  - Evaluator MUST NOT imply automatic transitive trust
    across chain links.
  - Evaluator MUST fail closed on policy mismatch, missing
    REQUIRED evidence, deferred profile, and deferred claim
    or evidence kind.
- **Boundary risks.**
  - Introducing an implicit "accept if no policy" shortcut.
    Mitigation: explicit unit test locking "absent policy
    rejects".
  - Leaking the evaluator into `soma-sense`. Mitigation:
    explicit re-export test asserting `soma-sense` does not
    surface the evaluator.
- **Merge gate.**
  - Fail-closed coverage on every negative path.
  - PR description explicitly confirms no `soma-sense`
    re-export addition.

### Slice 8 - Soma Check evidence binding helper

- **Purpose.** Bind Soma Check freshness receipts,
  content-hash commitments, zero-charge unchanged-result
  evidence, and transcript hashes into
  `freshness-receipt-bound` certificates per spec section 13.
- **Allowed files.**
  - A binding helper source file under the certificate
    source directory.
  - Unit tests under `tests/` exercising the binding helper.
- **Forbidden files.**
  - Any Soma Check internal. Slice 8 MUST consume Soma Check
    outputs through the existing public surface only.
  - `SOMA-CHECK-SPEC.md`, any Soma Check source.
  - `test-vectors/**`.
- **Tests / checks required.**
  - Binding helper MUST preserve Soma Check's
    freshness-and-payment-avoidance posture. No reputation,
    no pricing, no routing, no provider selection, no cache
    orchestration, no semantic-truth surface may be
    introduced through this slice.
  - Binding helper MUST NOT alter the certificate canonical
    bytes computed by Slice 2 beyond adding the
    `freshness-receipt-bound` evidence per spec section 13.
- **Boundary risks.**
  - Leaking pricing or routing decisions into the binding
    helper. Mitigation: Slice 8 tests forbid any
    pricing/routing-related identifier on the public surface.
- **Merge gate.**
  - No Soma Check internal access.
  - PR description explicitly confirms Soma Check stays
    freshness-and-payment-avoidance only.

### Slice 9 - Payment rail evidence adapter interface

- **Purpose.** Define the rail-agnostic evidence adapter
  interface per spec section 14 and ship the x402 adapter as
  the first/default adapter only. x402 MUST NOT become a
  hard dependency.
- **Allowed files.**
  - An adapter interface source file under the certificate
    source directory.
  - An x402 adapter source file (may live in a separate
    module that depends on `soma-heart/certificate` and is
    NOT imported by the certificate core, per Gate 6 open
    question 3).
  - Unit tests under `tests/` exercising the adapter
    interface and the x402 adapter.
- **Forbidden files.**
  - Any import of x402 protocol types from the certificate
    core. The core stays rail-agnostic.
  - Any `package.json` dependency entry elevating x402 to a
    hard dependency of `soma-heart`.
  - `test-vectors/**`.
  - Rotation source.
- **Tests / checks required.**
  - A conforming non-x402 rail MUST be demonstrable as a
    substitute in at least one unit test, even if the test
    rail is a fixture.
  - The adapter interface MUST bind rail-specific receipt
    material as a rail-agnostic
    `payment_receipt_reference` evidence entry per spec
    section 14.
- **Boundary risks.**
  - Slipping an x402 type into the certificate core
    signature. Mitigation: a lint or type test asserting the
    core has zero x402 imports.
  - Treating x402 as the only adapter in practice.
    Mitigation: the non-x402 fixture test is mandatory.
- **Merge gate.**
  - Non-x402 fixture test green.
  - Core import-of-x402 assertion green (zero imports).
  - PR description explicitly confirms x402 is first/default
    only and not hard-depended.

### Slice 10 - `soma-sense` observer-safe re-export

- **Purpose.** Wire the observer-safe re-exports from
  `soma-heart/certificate` through `soma-sense`, limited to
  the Gate 6 accepted set (areas 1, 2, 3, 4, 5, 6, 7, and
  12).
- **Allowed files.**
  - `packages/soma-sense/` re-export source or manifest edit
    strictly scoped to the observer-safe set.
  - Unit tests under `tests/` asserting the exact public
    surface of `soma-sense` after the re-export.
- **Forbidden files.**
  - `soma-sense` re-export of signature production, evidence
    binding (Slice 8), rail adapter wiring (Slice 9 concrete
    adapter), rotation lookup (Slice 6 adapter), or
    verifier-policy evaluator (Slice 7).
  - Any source not directly required for the re-export.
  - `test-vectors/**`.
- **Tests / checks required.**
  - Public surface test MUST enumerate the exact identifiers
    exposed by `soma-sense` after Slice 10 and assert no
    others.
  - Public surface test MUST fail if any forbidden re-export
    slips in.
- **Boundary risks.**
  - An observer-only install gaining access to a signing or
    binding primitive. Mitigation: enumerated public surface
    test above.
- **Merge gate.**
  - Public surface test green.
  - PR description explicitly confirms no minting surface is
    re-exported.

### Slice 11 - `docs/reference` package docs update

- **Purpose.** Update the canonical `docs/reference/packages.md`
  and `docs/reference/spec-index.md` entries so they describe
  the shipped certificate module accurately. Docs only.
- **Allowed files.**
  - `docs/reference/packages.md`.
  - `docs/reference/spec-index.md`.
  - `docs/reference/primitives.md` only if strictly required
    by the packages/spec-index entries.
- **Forbidden files.**
  - `SOMA-HEART-CERTIFICATE-SPEC.md`, ADR-0005, ADR-0004,
    `SOMA-ROTATION-SPEC.md`.
  - Source, tests, vectors, package manifests.
- **Tests / checks required.**
  - Docs-only; no code checks beyond link/lint.
- **Boundary risks.**
  - Redefining a certificate semantic in reference docs.
    Mitigation: reference docs cite spec sections verbatim
    and MUST NOT introduce new normative language.
- **Merge gate.**
  - Link check clean.
  - PR description explicitly confirms no normative drift.

### Slice 12 - Release and readiness review

- **Purpose.** Run the Soma release / readiness review over
  the accumulated slices, verify AGENTS.md workflow rules,
  and prepare the release tag for the certificate module
  under the `soma-heart-v<version>` tagging convention.
- **Allowed files.**
  - Release notes under the existing release docs
    convention.
  - Version bump in `packages/soma-heart/package.json` only
    if the release gate actually fires. Otherwise none.
- **Forbidden files.**
  - Any source, test, vector, spec, ADR, or reference edit
    beyond the release-note file.
  - `$CLAWNET`, ClawNet runtime, or any first-consumer work.
- **Tests / checks required.**
  - `pnpm ci` (lint + format:check + typecheck + test +
    build:packages) green.
  - Manual reviewer confirmation that every prior slice's
    merge gate was actually green, not just waved through.
- **Boundary risks.**
  - Tagging a release that silently regresses the vector
    corpus conformance from Slice 3. Mitigation: the release
    review MUST re-run the conformance test as a blocking
    check.
- **Merge gate.**
  - `pnpm ci` green.
  - Vector conformance still 100%.
  - PR description explicitly confirms no downstream
    (ClawNet / Gate 7) work is riding on this release.

## Dependency ordering

- **Must precede everything else**: Slice 1 (package skeleton)
  and Slice 2 (canonical helpers). Nothing else is safe to
  land until the conceptual directory is reconciled and the
  canonical helpers exist.
- **Slice 3 depends on Slice 2**: the conformance test drives
  Slice 2 helpers against the manifest.
- **Slice 4 depends on Slice 2 and is independent of Slice 3**
  at the behaviour level but SHOULD land after Slice 3 so that
  any canonicalisation regression surfaces before validator
  work.
- **Slice 5 is independent of Slices 2-4** but SHOULD land
  after Slice 4 so the validators emit the pinned identifiers
  from the start instead of being retrofitted.
- **Slice 6 depends on Slice 2 (signature inputs) and Slice 5
  (error identifiers)**. Slice 6 MUST land after Slice 5.
- **Slice 7 depends on Slice 4 (validators) and Slice 5 (error
  identifiers)**. Slice 7 MUST land after Slices 4 and 5.
- **Slice 8 depends on Slice 2 and Slice 4** and SHOULD land
  after Slice 7 so the full verification path exists when the
  binding helper is exercised.
- **Slice 9 depends on Slice 4 and Slice 5** and MAY land in
  parallel with Slice 8 as long as the non-x402 fixture test
  is in place.
- **Slice 10 depends on every prior behavioural slice**
  (Slices 2, 3, 4, 5, 6, 7, and 12 re-exports) and MUST NOT
  land before the public surface it re-exports is stable.
- **Slice 11 depends on Slice 10** because package docs should
  describe the shipped surface, not a draft one.
- **Slice 12 depends on every prior slice** and is the release
  gate.

Slices that MAY run in parallel at PR drafting stage:

- Slice 4 and Slice 5, provided Slice 5 lands first in merge
  order.
- Slice 8 and Slice 9, provided both cite the same Slice 4 /
  Slice 5 tip.

Slices that MUST NOT run in parallel:

- Slice 1 and anything else. Slice 1 is the first instrument.
- Slice 6 and any rotation ADR slice. If a rotation ADR slice
  is active, Slice 6 waits.

## Package and export plan

The package/export plan below restates what Gate 6 accepted.
This planning PR makes no package or export edit; every change
below is a future instrument.

- **Package**: `soma-heart` (source of truth). No new
  top-level package.
- **Public subpath export**: `soma-heart/certificate`. Added
  to `packages/soma-heart/package.json` no earlier than
  Slice 1 and no later than Slice 2, as a strictly additive
  subpath entry that does not widen, narrow, or reorder any
  other subpath.
- **`soma-sense` re-export**: observer-safe set only (areas 1,
  2, 3, 4, 5, 6, 7, 12 per Gate 6). Added no earlier than
  Slice 10.
- **Build mapping**: follows the existing `soma-heart`
  convention used by `soma-heart/credential-rotation`. Slice 1
  reconciles the Gate 6 conceptual directory with the
  on-disk build layout and pins the exact source path before
  any other slice writes a source file.
- **Release tag**: `soma-heart-v<version>` via GitHub Actions
  `Publish Packages`, per AGENTS.md. Slice 12 is the release
  gate; no local `npm publish`.

## Vector conformance plan

- Future implementation MUST exactly match
  `test-vectors/soma-heart-certificate/v0.1/manifest.json`:
  `canonical_json`, `canonical_utf8_hex`,
  `expected_certificate_id`, and
  `signature_inputs[].input_sha256`. Mismatch is a
  `canonicalisation-divergence` failure per spec section 18.
- Slice 3 is the instrument that locks this conformance. No
  later slice may relax it, and no later slice may land if
  Slice 3's conformance test regresses.
- Vector files MUST remain reproducible from
  `SOMA-HEART-CERTIFICATE-SPEC.md` plus ADR-0004 and
  `SOMA-ROTATION-SPEC.md` alone. No slice is permitted to
  introduce a package-internal helper that the vectors depend
  on to reproduce.
- If a slice finds a genuine typo or divergence in the vector
  corpus, the slice stops, reports, and a separate
  vector-amendment PR is opened before the slice resumes.

## Security review checklist

Every slice MUST pass this checklist in its PR review:

- **No automatic transitive trust.** A chain does not imply
  that a verifier trusts every downstream link by default. The
  verifier-policy evaluator enforces per-link independence.
- **No claim that Soma verifies real-world truth.** Validator
  and evaluator surfaces adjudicate attribution and policy,
  not external-world facts.
- **No reputation, scoring, ranking, or aggregate trust
  judgment language.** No slice introduces a "how trusted is
  this" surface or any reputation primitive. No slice
  introduces reputation systems, scoring/ranking surfaces,
  or aggregate trust signal language in any form.
- **x402 is not a hard protocol dependency.** The certificate
  core has zero x402 imports. x402 is the first/default
  adapter only, and a non-x402 rail can substitute equivalent
  evidence.
- **No ClawNet economics.** No slice introduces pricing,
  routing, cache/orchestration, staking, reward/burn, proof
  mining, marketplace, platform cuts, or `$CLAWNET` utility.
- **Credential rotation consumed through existing surfaces
  only.** No slice modifies `src/heart/credential-rotation/**`,
  `SOMA-ROTATION-SPEC.md`, or ADR-0004. Slice 6's rotation
  lookup adapter is internal-only and is not re-exported
  through `soma-heart/certificate` or `soma-sense`.
- **Fail closed on ambiguous state.** Every slice that touches
  verification, policy, or rotation MUST fail closed on
  ambiguity. No slice ships a "best effort" accept path.
- **Observer-only installs cannot mint.** `soma-sense` is
  limited to the observer-safe read path and MUST NOT
  re-export signature production, evidence binding, rotation
  lookup, rail adapter wiring, or verifier-policy evaluation.
- **No runtime "is-this-trusted" query API.** No slice adds a
  runtime trust query surface through any area.
- **Spec-faithful error identifiers only.** No slice emits a
  vendor-specific identifier for a mapped spec section 18
  failure mode.
- **No silent defaulting of absent optional fields.** Every
  validator and canonicaliser test locks "absent means
  absent".

## Gate 7 remains blocked

Gate 7 is the ClawNet first-consumer unlock. It remains
blocked by this packet and by every slice described above.
Gate 7 MUST be planned in `claw-net/docs/decisions/`, not in
this repo. Accepting this planning packet does not unblock,
authorise, or pre-approve Gate 7 in any form, and no slice
above may introduce ClawNet runtime, first-consumer
integration, or Gate 7 scaffolding.

- Soma does not ship ClawNet integration code through any
  slice.
- Soma does not ship ClawNet runtime contracts through any
  slice.
- Soma does not ship pricing, routing, cache/orchestration,
  staking, reward/burn, proof mining, marketplace, hosted
  witness operations, platform cuts, or `$CLAWNET` utility
  through any slice.
- ClawNet MAY cite accepted Soma certificate semantics and
  build product policy around them in `claw-net`. ClawNet
  MUST NOT redefine certificate, claim, evidence, or chain
  semantics locally, and MUST NOT ship code that would
  require Soma to take on any of the concerns above.

## Acceptance criteria for this planning packet

Acceptance of this packet requires all of the following:

1. **Planning only.** This packet ships no code, no tests, no
   vectors, no manifest edits, no export edits, no spec or ADR
   edits, and no reference-doc edits. Acceptance MUST confirm
   that the diff is a single new file under `docs/proposals/`.
2. **Gate 6 plan preserved.** The slice plan above MUST
   preserve the Gate 6 accepted package shape, subpath,
   public/internal boundary, `soma-sense` re-export posture,
   vector conformance requirement, and failure-mode wire
   identifiers. Any drift blocks acceptance.
3. **Vector conformance non-negotiable.** Slice 3 is the
   conformance gate and every later slice is subordinate to
   it.
4. **Credential-rotation semantics untouched.** No slice
   modifies rotation. Rotation lookup is consumed through
   existing surfaces, and Slice 6 stops and reports on any
   missing surface.
5. **Boundary rules intact.** No slice introduces reputation
   systems, scoring/ranking surfaces, or aggregate trust
   signal language, automatic transitive trust,
   real-world-truth claims, runtime trust query APIs,
   reputation primitives, pricing, routing,
   cache/orchestration, staking, reward/burn, proof mining,
   marketplace, platform cuts, or `$CLAWNET` utility. x402
   stays first/default only.
6. **No implementation authorisation.** Acceptance of this
   packet does not authorise, trigger, or pre-approve any
   slice. Each slice remains a distinct future instrument
   that MUST be separately proposed, reviewed, and
   authorised.
7. **Gate 7 blocked and downstream.** Acceptance explicitly
   re-confirms Gate 7 remains blocked and downstream to
   `claw-net/docs/decisions/`.

## Links

- `docs/proposals/soma-heart-certificate-gate6-stabilisation.md`
- `docs/proposals/soma-heart-certificate-package-surface.md`
- `docs/proposals/soma-heart-trust-certificates.md`
- `SOMA-HEART-CERTIFICATE-SPEC.md`
- `docs/decisions/ADR-0005-soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `SOMA-ROTATION-SPEC.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
- `test-vectors/soma-heart-certificate/v0.1/manifest.json`
- `test-vectors/soma-heart-certificate/v0.1/README.md`
- `docs/reference/packages.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `AGENTS.md`
