# Soma Heart Certificate Gate 6 Stabilisation Proposal

Status: accepted

> Docs-only readiness proposal for Gate 6 of the ADR-0005 gate
> sequence. This document does not itself merge package, API,
> runtime, or test source, and its acceptance does not
> authorise implementation. It defines the stabilisation plan
> for the future `soma-heart` certificate package surface so
> that a later implementation PR, if separately authorised, can
> be proposed without re-litigating shape, ownership, or
> boundaries. Any such implementation PR is a distinct future
> instrument, not a consequence of accepting this proposal.
> Credential-rotation semantics remain authoritative in ADR-0004
> and `SOMA-ROTATION-SPEC.md` and are not modified by anything in
> this proposal.

## Acceptance note

Gate 6 is accepted by this document. Acceptance confirms the
package-surface ownership and stabilisation plan set out below:

- package: `soma-heart` (source of truth, no new top-level
  package);
- subpath export: `soma-heart/certificate`;
- conceptual source directory:
  `packages/soma-heart/src/certificate/` (conceptual ownership
  only; no file created by this acceptance);
- `soma-sense` re-export posture: observer-safe read path only,
  covering canonicalisation helpers, certificate identifier
  derivation, signature-input construction, vector-corpus
  loading and conformance helpers, profile validation,
  claim-vocabulary validation, evidence-vocabulary validation,
  and the failure-mode / error mapping (areas 1, 2, 3, 4, 5, 6,
  7, and 12);
- public / internal API boundary as listed in the
  "Public vs internal API boundary" section of this proposal,
  including the full-install-only posture for the
  verifier-policy evaluator (area 8) and the internal-only
  posture for the rotation lookup adapter (area 9) and concrete
  rail adapter wiring (area 11 concrete implementations);
- vector conformance requirement against
  `test-vectors/soma-heart-certificate/v0.1/manifest.json`; any
  future implementation PR, if separately authorised, MUST
  produce canonical bytes, certificate identifiers, and
  signature-input hashes that exactly match every entry in that
  corpus;
- failure-mode wire identifiers: the lowercase kebab-case
  identifiers defined in `SOMA-HEART-CERTIFICATE-SPEC.md`
  section 18 are the only error identifiers that may be emitted
  for the mapped failure modes.

Acceptance does not:

- implement package code;
- edit `package.json`, any `packages/*/package.json`, any
  `exports` map, or any build configuration;
- edit TypeScript or any other source file under `src/` or
  `packages/*/`;
- edit the vector corpus at
  `test-vectors/soma-heart-certificate/v0.1/`;
- edit `SOMA-HEART-CERTIFICATE-SPEC.md`, ADR-0005, ADR-0004,
  `SOMA-ROTATION-SPEC.md`, or any other spec or ADR;
- change credential-rotation semantics in any way;
- authorise Gate 7.

Acceptance makes a future implementation PR eligible to be
proposed separately against the ownership, boundary, and export
plan ratified here. No such PR is triggered or pre-approved by
accepting this proposal; any implementation PR remains a
distinct future instrument that MUST be separately proposed,
reviewed, and authorised. Gate 7 remains blocked and downstream
to `claw-net/docs/decisions/`.

## Title

Soma Heart Certificate Gate 6 Stabilisation Proposal

## Context and gate history

The ADR-0005 gate sequence is:

1. Gate 1 - ADR drafted.
2. Gate 2 - ADR accepted.
3. Gate 3 - spec drafted.
4. Gate 4 - spec accepted.
5. Gate 5 - package surface proposal accepted.
6. Gate 6 - package surface stabilised (this proposal).
7. Gate 7 - ClawNet first-consumer unlock, handled in `claw-net`.

State at this document's acceptance:

- **Gate 1**: cleared by the ADR-0005 draft PR.
- **Gate 2**: cleared by the ADR-0005 acceptance PR.
- **Gate 3**: cleared by the initial merge of
  `SOMA-HEART-CERTIFICATE-SPEC.md` as `Status: Draft`.
- **Gate 4**: cleared by the spec acceptance PR that moved
  `SOMA-HEART-CERTIFICATE-SPEC.md` to `Status: accepted`, plus
  the post-Gate-4 docs-only amendment that pinned canonical
  encoding and hash rules in spec sections 9.2-9.5 under the
  v0.1 contract without reopening Gate 4.
- **Gate 5**: cleared by `docs/proposals/soma-heart-certificate-package-surface.md`
  moving to `Status: accepted`. Gate 5 ratified:
  - the v0.1 canonical byte layout, certificate identifier hash,
    and signature input (spec sections 9.2-9.5);
  - the v0.1 vector corpus at
    `test-vectors/soma-heart-certificate/v0.1/`;
  - the functional-area boundary shape of the future
    package/API surface;
  - resolution of spec section 21 items 2-7, 9, and 10.
- **Gate 6**: cleared by this document moving to
  `Status: accepted`. Gate 6 pinned surface ownership, naming,
  import path, source-file ownership, public/internal API
  boundary, vector conformance requirement, failure-mode wire
  identifiers, export plan, and `soma-sense` re-export posture
  as listed in the Acceptance note above and the sections
  below. Gate 6 acceptance by itself does not authorise the
  implementation PR; acceptance only makes it eligible to be
  proposed against a stabilised surface shape.
- **Gate 7**: remains blocked. It is downstream to Soma and
  MUST be raised in `claw-net/docs/decisions/`, not in this
  repo. Gate 6 acceptance does not unblock Gate 7 by itself.

This proposal assumed the accepted state of Gates 1-5 and did
not re-litigate anything they already ratified. Gates 1-6 are
now cleared. If any earlier gate is later reopened, this
acceptance MUST be re-reviewed against the reopened gate.

## Goals

- Pin the package-surface ownership and import path for the
  future Soma Heart certificate module so that a later
  implementation PR, if separately authorised, can be drafted
  with zero architectural ambiguity. This proposal does not
  itself authorise implementation.
- Pin the public vs internal API boundary for the certificate
  module at the level of surface areas (without writing code).
- Pin the source-file layout inside `packages/soma-heart` for
  the certificate module at the level of directory ownership
  (without writing files).
- Pin the vector-conformance expectations that the eventual
  implementation MUST satisfy against the v0.1 corpus.
- Pin the error identifier mapping from spec section 18 failure
  modes to the lowercase kebab-case wire identifiers already
  defined in the spec.
- Pin the package export plan for `soma-heart` and, if
  applicable, `soma-sense`, without actually editing any
  package manifest, source file, or export map.
- Keep credential rotation, ClawNet product concerns, and
  payment rail choices untouched.

## Non-goals

- No implementation. This proposal authorises no source code,
  no TypeScript, no runtime behaviour, and no tests.
- No edits to `package.json`, any `packages/*/package.json`,
  any `exports` map, or any build configuration.
- No edits to TypeScript files under `src/` or `packages/*/`.
- No edits to the vector corpus at
  `test-vectors/soma-heart-certificate/v0.1/`. Typos or blockers
  found during drafting MUST be reported before any vector file
  is touched.
- No re-opening of pinned canonicalization rules. Any future
  change goes through a new spec or ADR slice under spec
  section 9.5 crypto-agility rules.
- No re-opening of the accepted package-surface functional
  areas from the Gate 5 proposal. Gate 6 ratifies ownership,
  not shape.
- No ClawNet work, no Gate 7 scaffolding, no first-consumer
  implementation.
- No tokenomics, staking markets, proof mining, reward/burn
  mechanics, `$CLAWNET` utility, marketplace, or business-model
  behaviour.
- No ClawNet pricing, provider routing, cache/orchestration,
  or hosted witness operations.
- No runtime "is-this-trusted" query API.
- No reputation systems, scoring, ranking, or aggregate trust
  signals or judgments.
- No claim that Soma verifies real-world truth.
- No automatic transitive trust across chain links.
- No elevation of x402 to a hard protocol dependency.
- No credential-rotation semantic changes. ADR-0004 and
  `SOMA-ROTATION-SPEC.md` remain authoritative. If a
  certificate-driven use case surfaces a rotation gap, it MUST
  be escalated to a rotation ADR slice rather than absorbed into
  the certificate module.

## Proposed package-surface ownership

### Recommended package and subpath

The future certificate module SHOULD live inside `soma-heart`
under a dedicated subpath export:

- **Package**: `soma-heart` (source of truth).
- **Subpath**: `soma-heart/certificate`.
- **Conceptual directory**: `packages/soma-heart/src/certificate/`.
- **Build output**: under the existing `packages/soma-heart/dist/`
  tree, consistent with how `soma-heart/credential-rotation` is
  built today.

Rationale:

- `soma-heart` is already the source-of-truth package in
  `docs/reference/packages.md`.
- `soma-heart` already uses subpath exports for protocol-adjacent
  modules (e.g. `./credential-rotation`, `./crypto-provider`,
  `./sense`). A `./certificate` subpath matches that convention
  and gives the certificate module its own import boundary
  without fragmenting the publish surface.
- The certificate module consumes rotation lookup at a boundary
  (functional area 7 in the Gate 5 proposal); co-locating it in
  `soma-heart` lets it call into
  `soma-heart/credential-rotation` without introducing a new
  package dependency or a circular graph.
- Keeping the certificate module inside `soma-heart` preserves
  the "one package, source of truth" posture from `AGENTS.md`
  and avoids inventing a new publishable package in Gate 6.

Non-recommendation alternatives, retained for review context:

- A new top-level package such as `soma-certificate`. Rejected
  at the recommendation level because it fragments the publish
  surface and forces an additional GitHub Actions release
  workflow for a protocol primitive that logically belongs to
  the heart. Reviewers MAY reopen this if Gate 6 discussion
  surfaces a concrete reason.
- Publishing the certificate module directly from the `soma-heart`
  package root (`soma-heart`). Rejected because it mixes
  certificate surface with the top-level heart exports and hides
  the "certificate as a distinct module" boundary that Gate 5
  accepted.

### `soma-sense` re-exports

`soma-sense` is a thin compatibility re-export for observer-only
installs (`docs/reference/packages.md`). The recommendation for
Gate 6 is:

- `soma-sense` SHOULD re-export only the observer-safe read
  path of the certificate module from
  `soma-heart/certificate`. Specifically: canonicalisation
  helpers, certificate identifier derivation, signature-input
  construction, vector-corpus loading helpers, profile
  validation, claim-vocabulary validation, evidence-vocabulary
  validation, and the failure-mode mapping.
- `soma-sense` MUST NOT re-export signature production, private
  key material, evidence binding (Soma Check, rail adapter), or
  verifier-policy evaluation surfaces that would give an
  observer-only install the ability to act as an issuer,
  counterparty, witness, or policy owner.
- The exact re-export list is a Gate 6 acceptance item, not a
  Gate 7 item. It MUST be pinned here so that any future
  implementation PR inherits it; it is not itself an
  authorisation to implement.

### Spec-section mapping for ownership

Every functional area from the Gate 5 proposal maps to at least
one accepted spec section. Gate 6 ownership pinning does not
change the spec; it only records which spec section governs the
correctness contract for each area.

| Area | Spec sections |
|---|---|
| Canonicalization helpers | 9.1, 9.2, 9.5 |
| Certificate identifier helpers | 9.3 |
| Signature input helpers | 9.4, 10 |
| Vector loading / conformance helpers | 19.1, 19.2 |
| Claim vocabulary validator | 7 |
| Evidence vocabulary validator | 8 |
| Profile validator | 5, 6 |
| Verifier-policy evaluator boundary | 4.2, 11, 12 |
| Rotation lookup adapter boundary | 15 (defers to ADR-0004 / `SOMA-ROTATION-SPEC.md`) |
| Soma Check evidence binding boundary | 13 |
| Rail / payment evidence adapter boundary | 14 |
| Failure-mode / error mapping | 18 |

Gate 6 acceptance MUST confirm that this mapping is the one the
implementation will be held to. Any drift requires an amendment
to this proposal or a follow-up ADR slice.

## Proposed module / surface areas

These surface areas are **non-binding** at the name level and
**binding at the boundary level** per the Gate 5 proposal. Gate 6
acceptance pins ownership and visibility, not identifier names.

### 1. Canonicalization helpers

- Owns: deterministic serialisation of a logical certificate to
  canonical bytes per spec sections 9.1-9.2.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST cover every REQUIRED field and every CONDITIONAL field
  that is present. MUST NOT silently default absent optional
  fields. MUST reject duplicate keys, NaN, Infinity, and
  undefined per spec section 9.2.

### 2. Certificate identifier helpers

- Owns: `certificate_id = lowercase_hex(sha256("soma-heart-certificate:v0.1:" || canonical_bytes))`
  per spec section 9.3.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST compute the identifier from canonical bytes produced by
  area 1 with the `signatures` field omitted from the canonical
  input entirely.

### 3. Signature input helpers

- Owns: construction of `"soma-heart-certificate:v0.1:<role>:" || canonical_bytes`
  per spec section 9.4, with role in lowercase ASCII.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes (for verification);
  MUST NOT expose any signing primitive that would let an
  observer mint certificates.

### 4. Vector loading and conformance helpers

- Owns: loading the v0.1 vector corpus at
  `test-vectors/soma-heart-certificate/v0.1/manifest.json` and
  checking that implementation output matches each vector's
  `canonical_json`, `canonical_utf8_hex`,
  `expected_certificate_id`, and `signature_inputs[].input_sha256`
  values.
- Visibility: public under `soma-heart/certificate` (used by
  downstream tests and by integrators who want to confirm
  conformance on their own machine).
- Observer-re-export in `soma-sense`: yes.
- MUST be reproducible from the spec plus ADR-0004 and
  `SOMA-ROTATION-SPEC.md` alone, not from package internals.

### 5. Claim vocabulary validator

- Owns: per-claim accept/open/defer classification per spec
  section 7.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST reject deferred claim kinds
  (`capability_statement`, `delegation_or_endorsement`).
  MUST treat `open` claims as non-ratified.

### 6. Evidence vocabulary validator

- Owns: per-evidence accept/open/defer classification per spec
  section 8.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST reject deferred evidence kinds
  (`credential_presentation_reference`, `media_content_hash`,
  `third_party_attestation_reference`).
  MUST treat `open` evidence kinds as non-ratified.

### 7. Profile validator

- Owns: profile acceptance per spec section 5 and the profile
  signature/claim/evidence requirements per spec section 6.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST reject certificates declaring a deferred profile
  (`policy-statement`, `witnessed`) and treat `open` profiles as
  non-ratified.

### 8. Verifier-policy evaluator boundary

- Owns: application of a verifier policy reference to a
  certificate or chain per spec sections 4.2, 11, and 12.
- Visibility: public under `soma-heart/certificate` for the
  evaluator; private (internal-only) for any concrete policy
  decoders that ship in the first implementation slice.
- Observer-re-export in `soma-sense`: no. The evaluator is a
  verification surface, not a minting surface, but whether it is
  offered to observer-only installs is a Gate 6 acceptance
  decision; the recommended default is "no", so that
  `soma-sense` remains observer-read-only and the verifier
  policy engine lives only in the full `soma-heart` install.
- MUST NOT treat an absent policy field as "accept by default".
  MUST NOT expose an "is-this-trusted" surface based on chain
  presence. MUST NOT imply automatic transitive trust across
  chain links.

### 9. Rotation lookup adapter boundary

- Owns: resolving the signing-time credential via historical
  lookup under `SOMA-ROTATION-SPEC.md` per spec section 15.
- Visibility: internal boundary. The certificate module consumes
  `soma-heart/credential-rotation` through this adapter and does
  not re-export rotation primitives under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: no.
- MUST use existing rotation surfaces without re-implementing or
  extending them. MUST fail closed on ambiguous rotation state.
  MUST NOT introduce a new rotation mechanism. If a
  certificate-driven use case surfaces a rotation gap, it MUST
  be escalated to a rotation ADR slice rather than absorbed into
  the certificate module.

### 10. Soma Check evidence binding boundary

- Owns: binding Soma Check freshness receipts, content-hash
  commitments, zero-charge unchanged-result evidence, and
  transcript hashes into `freshness-receipt-bound` certificates
  per spec section 13.
- Visibility: public under `soma-heart/certificate` for the
  binding helper; its inputs MAY come from an external Soma
  Check implementation and the certificate module MUST NOT
  reach into Soma Check internals.
- Observer-re-export in `soma-sense`: no. Binding is a minting
  surface.
- MUST keep Soma Check freshness-and-payment-avoidance only.
  MUST NOT introduce reputation, pricing, routing, provider
  selection, cache orchestration, or semantic-truth surface
  through Soma Check.

### 11. Rail / payment evidence adapter boundary

- Owns: accepting rail-specific receipt material and binding it
  as a rail-agnostic `payment_receipt_reference` evidence entry
  per spec section 14.
- Visibility: public under `soma-heart/certificate` for the
  adapter interface boundary; concrete adapter implementations
  (including the x402 adapter) MAY live in a separate module
  that depends on `soma-heart/certificate` but MUST NOT be
  imported by the certificate module core.
- Observer-re-export in `soma-sense`: no.
- The certificate core MUST NOT import x402 protocol types,
  MUST NOT elevate x402 to a hard protocol dependency, and MUST
  allow a conforming non-x402 rail to substitute equivalent
  evidence. x402 is the first/default adapter only.

### 12. Failure-mode / error mapping

- Owns: mapping the 16 failure modes from spec section 18 to
  the lowercase kebab-case wire identifiers defined there.
- Visibility: public under `soma-heart/certificate`.
- Observer-re-export in `soma-sense`: yes.
- MUST use the spec's wire identifiers verbatim. Implementation
  MUST NOT invent new error identifiers in Gate 6; any new
  failure-mode classification goes through a spec slice.

## Public vs internal API boundary

Gate 6 acceptance pins the boundary between public surface and
internal-only helpers. The rule for the first implementation PR
is:

- **Public under `soma-heart/certificate`**: areas 1, 2, 3, 4,
  5, 6, 7, 10 (binding helper), 11 (adapter interface only),
  12.
- **Public but restricted to full `soma-heart` install**: area
  8 (verifier-policy evaluator).
- **Internal-only (not exported)**: area 9 (rotation lookup
  adapter), area 11 concrete adapter wiring, and any serialisation
  or policy-decoder helpers that are implementation detail.
- **Not shipped by Gate 6 at all**: deferred profiles
  (`policy-statement`, `witnessed`), deferred claims
  (`capability_statement`, `delegation_or_endorsement`),
  deferred evidence kinds
  (`credential_presentation_reference`, `media_content_hash`,
  `third_party_attestation_reference`), and any receipt-primitive
  migration or `fulfillment-receipt-bound` binding (future ADR
  candidates per spec section 21 items 8 and 11).

Name-level bikeshedding is still permitted in the implementation
PR, but the public/private boundary above is binding once Gate 6
is accepted.

## No implementation in this proposal

This proposal is docs-only. It authorises:

- zero lines of TypeScript,
- zero edits to `package.json`, `pnpm-workspace.yaml`, or any
  `packages/*/package.json`,
- zero edits to `packages/*/src/**` or `src/**`,
- zero new test files,
- zero CI changes,
- zero vector corpus edits.

Any claim in this proposal that looks like a code contract is a
boundary sketch, not a binding identifier. The binding contract
is:

- spec sections 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
  18 in `SOMA-HEART-CERTIFICATE-SPEC.md`;
- the v0.1 vector corpus in
  `test-vectors/soma-heart-certificate/v0.1/`.

Any future implementation PR, if separately authorised, MUST
cite both of those and MUST NOT silently redefine either. Gate 6
acceptance does not itself authorise such a PR; it only makes
the PR eligible to be proposed against a stabilised surface
shape.

## Gate 6 acceptance criteria

Gate 6 acceptance required all of the following, in order, and
all are satisfied by this document:

1. **Package namespace chosen.** The subpath export
   `soma-heart/certificate` (or an explicitly named alternative)
   MUST be pinned as the sole public import path for the
   certificate module in Gate 6. Any alternative MUST be
   justified against the recommendation above and recorded in
   the acceptance note.
2. **Source file ownership chosen.** The conceptual directory
   `packages/soma-heart/src/certificate/` (or an explicitly
   named alternative under `packages/soma-heart/src/`) MUST be
   pinned as the sole owner of certificate source code. No
   certificate source code may live outside this directory after
   Gate 6.
3. **Public/private API boundary chosen.** The public vs internal
   partitioning above MUST be reviewed and either accepted as
   written or explicitly amended. The amendment MUST preserve
   the non-goals and boundary rules of ADR-0005 and the spec.
4. **Vector conformance requirements stated.** Gate 6 MUST
   restate that any future implementation PR, if separately
   authorised, will be required to produce canonical bytes,
   certificate identifiers, and signature-input hashes that
   exactly match every vector in
   `test-vectors/soma-heart-certificate/v0.1/manifest.json`.
   Mismatches are `canonicalisation-divergence` failures per
   spec section 18. Gate 6 acceptance does not itself authorise
   that PR.
5. **Error identifiers mapped.** Gate 6 MUST confirm that the
   spec section 18 failure-mode wire identifiers are the only
   error identifiers the implementation may emit for the
   mapped failure modes. Additional error identifiers for
   implementation-internal conditions MAY exist but MUST NOT
   collide with spec section 18 identifiers.
6. **Package export plan approved but not yet implemented.**
   Gate 6 MUST record the intended `exports` map shape for
   `soma-heart/certificate` (and, if applicable, the
   `soma-sense` re-export list) as a planning artifact in this
   proposal's acceptance note. No `package.json` edit may ship
   in the same PR that accepts Gate 6.
7. **`soma-sense` re-export list pinned.** The exact set of
   observer-safe re-exports (area 1, 2, 3, 4, 5, 6, 7, 12 by
   recommended default) MUST be pinned. Any addition to or
   removal from this list MUST be justified against the
   observer-only install posture in `AGENTS.md`.
8. **No ClawNet or Gate 7 work.** Gate 6 acceptance MUST NOT
   introduce any ClawNet runtime, first-consumer integration,
   Gate 7 scaffolding, tokenomics, pricing, routing, cache,
   staking, proof mining, reward/burn, reputation, or runtime
   trust query APIs. Any drift of that kind blocks acceptance.
9. **No credential-rotation semantic changes.** Gate 6
   acceptance MUST explicitly confirm no change to ADR-0004,
   `SOMA-ROTATION-SPEC.md`, or the rotation lookup adapter
   boundary beyond consuming existing rotation surfaces.
10. **No canonicalization or hash changes.** Gate 6 acceptance
    MUST explicitly confirm that spec sections 9.2-9.5 are
    unchanged. Any future change goes through a new spec or
    ADR slice under the crypto-agility rules in spec section 9.5.
11. **Boundary rules preserved.** The ADR-0005 boundary rules
    and the spec's accepted non-goals MUST remain intact. Any
    drift into ClawNet runtime concerns, reputation or
    aggregate trust judgment language, automatic transitive
    trust, real-world-truth claims, or hard x402 dependency
    blocks acceptance.
12. **Implementation PR is a separate future instrument.**
    Gate 6 acceptance DOES NOT, by itself, authorise or merge
    package code, package/API edits, source edits, or export
    map edits. Any future implementation PR is a distinct
    instrument from this proposal and MUST be separately
    proposed, reviewed, and authorised against the ownership,
    boundary, and export plan ratified here. No such PR is
    triggered or pre-approved by accepting this proposal.

## Gate 7 remains blocked and downstream

Gate 7 is the ClawNet first-consumer unlock. It remains blocked
after Gate 6 acceptance and by any future implementation PR
that may follow, and it MUST be planned in
`claw-net/docs/decisions/` rather than in Soma. Gate 6
acceptance does not unblock, authorise, or pre-approve Gate 7
in any form.

- Soma does not ship ClawNet integration code under Gate 6.
- Soma does not ship ClawNet runtime contracts under Gate 6.
- Soma does not ship pricing, routing, cache/orchestration,
  staking, reward/burn, proof mining, marketplace, hosted
  witness operations, or `$CLAWNET` utility under Gate 6.
- ClawNet MAY cite accepted Soma certificate semantics and
  build product policy around them in `claw-net`. ClawNet MUST
  NOT redefine certificate, claim, evidence, or chain semantics
  locally, and MUST NOT ship code that would require Soma to
  take on any of the concerns above.

Gate 7 acceptance is out of scope for Soma and was not part of
this proposal's acceptance criteria.

## Security and abuse considerations

Gate 6 MUST preserve the assurance boundaries accepted in
ADR-0005 and the spec:

- Signatures prove issuer key control under a verification
  policy, not factual truth. The signature input helpers in
  area 3 MUST NOT be used to construct a "proof of truth"
  surface.
- Hashes prove commitment to bytes, not correctness. The
  certificate identifier helpers in area 2 MUST NOT be used to
  imply that the bytes they commit to are trustworthy.
- Chains prove provenance and linkage, not universal
  trustworthiness. The verifier-policy evaluator in area 8
  MUST NOT imply automatic transitive trust across chain links.
- Soma does not verify real-world truth at any layer. The
  validator surfaces in areas 5, 6, 7, and 8 MUST remain
  attribution and policy enforcement, not truth adjudication.
- Verifiers MUST fail closed on ambiguous rotation state,
  missing REQUIRED evidence, policy mismatch, deferred profiles,
  and deferred claim or evidence kinds.
- Soma Check MUST remain freshness and payment-avoidance only.
  No reputation, pricing, routing, provider selection, cache
  orchestration, or semantic-truth surface may be introduced
  through area 10.
- x402 MUST NOT be elevated to a hard protocol dependency.
  Area 11 keeps the certificate core rail-agnostic; x402 is the
  first/default adapter only.
- Private evidence pointers MUST declare their verification
  limits; hidden evidence MUST NOT be implied to have been
  verified.
- Witness-independence is out of scope for v0.1; `witnessed`
  profiles remain deferred.
- Observer-only installs via `soma-sense` MUST NOT gain access
  to signing, evidence binding, rail adapter wiring, rotation
  lookup, or verifier-policy evaluation by Gate 6 re-export
  choices.
- The rotation lookup adapter boundary in area 9 MUST remain a
  consumer of `soma-heart/credential-rotation`, not a
  re-implementation. No certificate-driven rotation shortcut
  is permitted.

Abuse scenarios Gate 6 MUST not open:

- Minting a certificate from an observer-only install.
- Forging a signature by reusing a canonical byte layout or
  signature-input construction against a mismatched role prefix.
- Treating an absent verifier policy as "accept by default".
- Treating a deferred profile, claim, or evidence kind as
  accepted.
- Emitting a non-spec error identifier for a mapped failure
  mode, thereby hiding a real failure behind a vendor-specific
  code.
- Introducing an "is-this-trusted" runtime query surface
  through any area.
- Introducing an automatic transitive trust shortcut through
  chain evaluation.

## Open questions

1. Final `exports` map shape for `soma-heart/certificate`
   (subpath only, subpath plus nested paths, or subpath plus
   deep imports). Recommendation: subpath only, matching how
   `soma-heart/credential-rotation` is currently exported.
2. Final `soma-sense` re-export list (observer-safe areas 1,
   2, 3, 4, 5, 6, 7, 12 by recommended default; reviewers MAY
   add or remove).
3. Whether the rail-adapter concrete implementations (area 11)
   live inside `soma-heart` as an internal module, inside
   `soma-heart/certificate` as a pluggable interface with
   adapters shipped separately, or inside a new package that
   depends on `soma-heart/certificate`. Recommendation: the
   adapter interface lives in `soma-heart/certificate`;
   concrete adapters MAY ship in a separate module.
4. Whether the verifier-policy evaluator (area 8) is exported
   under `soma-heart/certificate` or under a separate subpath
   such as `soma-heart/certificate/policy`. Recommendation:
   same subpath as the rest of area 8.
5. Whether vector-loading helpers (area 4) read from the
   `test-vectors/` tree at runtime, bundle vectors at build
   time, or expect the integrator to pass vectors in. This is
   a Gate 6 readability-of-conformance decision, not a spec
   change.
6. Whether `fulfillment-receipt-bound` and `fulfillment_receipt`
   should graduate from deferred to accepted in a follow-up
   spec slice. Default: handled in a separate spec slice and a
   separate ADR after Gate 6; not a blocker for the
   implementation slice.
7. Whether a future migration of receipt references to a
   distinct Soma receipt primitive (spec section 21 item 8)
   should affect the certificate package surface. Default: no;
   it is a future ADR candidate and was not required for the
   certificate package surface to stabilise.
8. Whether `soma-heart/certificate` should expose any
   observability hook (metrics, tracing, structured error
   context) in its first implementation slice, or defer all
   observability to a later slice. Default: defer to a later
   slice; Gate 6 did not require observability to be planned.

None of these open questions blocked Gate 6 acceptance. They
remain implementation-slice questions to be resolved in the
acceptance note of any future implementation PR or in a
follow-up ADR slice, and do not reopen Gate 6.

## Links

- `SOMA-HEART-CERTIFICATE-SPEC.md`
- `docs/decisions/ADR-0005-soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/proposals/soma-heart-certificate-package-surface.md`
- `docs/proposals/soma-heart-trust-certificates.md`
- `test-vectors/soma-heart-certificate/v0.1/manifest.json`
- `test-vectors/soma-heart-certificate/v0.1/README.md`
- `SOMA-ROTATION-SPEC.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
- `docs/reference/spec-index.md`
- `docs/reference/packages.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `AGENTS.md`
