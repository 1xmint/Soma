# Soma Heart Certificate Package Surface Proposal

Status: proposed

> Docs-only readiness proposal for Gate 5 of the ADR-0005 gate
> sequence. This document does not authorise package, API, runtime,
> or test-vector code. It defines the package/API surface shape and
> the readiness checklist that must be satisfied before Gate 5
> acceptance, consistent with `SOMA-HEART-CERTIFICATE-SPEC.md`
> (accepted) and ADR-0005 (accepted). Credential-rotation semantics
> remain authoritative in ADR-0004 and `SOMA-ROTATION-SPEC.md` and
> are not modified by anything in this proposal.

## Title

Soma Heart Certificate Package Surface Proposal

## Context

- Gate 1 (ADR drafted): cleared by ADR-0005 draft PR.
- Gate 2 (ADR accepted): cleared by ADR-0005 acceptance PR.
- Gate 3 (spec drafted): cleared by the initial merge of
  `SOMA-HEART-CERTIFICATE-SPEC.md` as `Status: Draft`.
- Gate 4 (spec accepted): cleared by the acceptance PR that moved
  the spec to `Status: accepted`. Gate 4 ratified the normative
  contract and boundary rules in sections 1-18 of the spec plus
  the required test-vector coverage list in section 19.1. Gate 4
  did NOT ratify the final canonical byte layout, hash algorithm,
  or vector files.
- Post-Gate-4 amendment: the final canonical byte layout and hash
  algorithm were subsequently pinned in
  `SOMA-HEART-CERTIFICATE-SPEC.md` sections 9.2-9.5 as a docs-only
  amendment under the v0.1 contract, without reopening Gate 4.
  The pinned rules in the spec are authoritative.
- Gate 5 (package surface proposal) is now draftable. This
  document is that draft.

Gate 5 acceptance was explicitly blocked by:

1. existence of test vector files that satisfy spec section 19.1
   under the pinned canonical encoding from spec sections 9.2-9.5
   (spec section 19.2).

The canonicalization/hash blocker that previously headed this list
has been resolved by the post-Gate-4 amendment and is no longer a
Gate 5 decision point.

The vector-file blocker is resolved by the v0.1 corpus at
`test-vectors/soma-heart-certificate/v0.1/`, subject to reviewer
confirmation that the corpus satisfies spec section 19.1. Drafting
is still not acceptance: the package-surface readiness items below
must be accepted before any implementation is authorised.

## Goals

- Identify the future package and API surface shape that will
  eventually expose Soma Heart Trust Certificate primitives to
  `soma-heart` (and, transitively, `soma-sense` where observer-only
  behaviour applies).
- Define the readiness preconditions that MUST be satisfied before
  any package or API implementation is authorised.
- Decide which items must be specified, vectored, or otherwise
  resolved before code is written.
- Keep the certificate primitive payment-rail agnostic, verifier-
  policy owned, and credential-rotation-compatible per ADR-0005.
- Keep downstream product concerns (ClawNet runtime, pricing,
  routing, cache/orchestration, staking, proof mining, reward/burn,
  `$CLAWNET` utility, marketplace, hosted witness operations) out
  of Soma protocol surfaces entirely.

## Non-goals

- No implementation. This proposal authorises no code.
- No package or API file edits.
- Test vector files are docs/test-vector artifacts only; they do
  not authorise package, API, runtime, or verifier implementation.
- No TypeScript type definitions, interfaces, or class sketches
  that could be mistaken for a binding contract.
- No ClawNet work, no Gate 7 scaffolding, no first-consumer
  implementation.
- No tokenomics, staking markets, proof mining, reward/burn
  mechanics, `$CLAWNET` utility, marketplace or business-model
  behaviour.
- No ClawNet pricing, provider routing, cache/orchestration, or
  hosted witness operations.
- No runtime "is-this-trusted" query API.
- No reputation, scoring, ranking, or aggregate trust signals.
- No claim that Soma verifies real-world truth.
- No automatic transitive trust.
- No elevation of x402 to a hard protocol dependency.
- No credential-rotation semantic changes. ADR-0004 and
  `SOMA-ROTATION-SPEC.md` remain authoritative.

## Proposed package-surface areas

These are the conceptual functional areas the eventual package
surface must cover. Each area is described as a boundary, not as a
code contract. No names below are binding; all are illustrative.

1. **Certificate canonicalization helpers.** Deterministic
   serialisation of a logical certificate to canonical bytes per
   spec section 9. Coverage MUST include every REQUIRED field and
   every CONDITIONAL field that is present; absent optional fields
   MUST NOT be silently defaulted.
2. **Certificate identifier / content-addressed hash helper.**
   Computes the certificate identifier from canonical bytes,
   excluding the `signatures` field from the hashed bytes, per
   spec section 9 signature-exclusion rule. Stable across
   credential rotation.
3. **Profile validation.** Rejects certificates whose declared
   profile is not in the accepted set for v0.1 (spec section 5).
   Rejects certificates declaring a deferred profile. Treats
   `open` profiles as non-ratified.
4. **Claim vocabulary validation.** Rejects certificates carrying
   deferred claim kinds (spec section 7). Allows `accepted` claims
   under their documented verification limits. Treats `open`
   claims as non-ratified.
5. **Evidence vocabulary validation.** Rejects certificates
   carrying deferred evidence kinds (spec section 8). Allows
   `accepted` evidence kinds under their documented verification
   limits. Treats `open` evidence kinds as non-ratified.
6. **Signature verification.** Verifies each signature under the
   resolved signing-time credential per spec section 10.
7. **Credential-rotation lookup integration boundary.** Resolves
   the credential effective at signing time via historical lookup
   under `SOMA-ROTATION-SPEC.md`, using existing rotation surfaces
   without re-implementing or extending them. MUST fail closed on
   ambiguous rotation state.
8. **Verifier-policy evaluator boundary.** Accepts a verifier
   policy object (URI, hash, inline, or package-version reference -
   wire representation is a Gate 5 precondition per spec section 21
   open item 2) and applies it to a certificate or chain. MUST NOT
   treat an absent policy field as "accept by default". MUST NOT
   expose an "is-this-trusted" surface based on chain presence.
9. **Soma Check evidence binding helper.** Binds Soma Check
   freshness receipts, content-hash commitments, zero-charge
   unchanged-result evidence, and transcript hashes into
   `freshness-receipt-bound` certificates per spec section 13.
   Soma Check MUST remain freshness and payment-avoidance only.
10. **Payment rail evidence adapter boundary.** Accepts rail-
    specific receipt material and binds it as a rail-agnostic
    `payment_receipt_reference` evidence entry per spec section 14.
    x402 is the first/default adapter; the adapter is pluggable.
    The core MUST NOT import x402 protocol types, MUST NOT elevate
    x402 to a hard dependency, and MUST allow a conforming non-x402
    rail to substitute equivalent evidence.
11. **Error taxonomy mapping.** Maps the 16 failure modes in spec
    section 18 to stable wire identifiers. Wire representation is
    a Gate 5 precondition per spec section 21 open item 10.

### What the surface intentionally does not cover

- Chain laundering detection beyond per-link independent
  evaluation (spec section 11.3).
- Any claim-truth adjudication beyond attribution (spec section 4.2).
- Witness-independence (spec section 17; `witnessed` profile is
  deferred in v0.1).
- Rotation lifecycle, rollback, witness, quorum, class, policy-
  floor, snapshot, or historical-lookup semantics. Those remain
  owned by ADR-0004 and `SOMA-ROTATION-SPEC.md`.
- Any runtime trust query API.

## Canonicalization and hash decision packet

> **Status update (post-Gate-4 amendment).** The canonicalization
> and hash algorithm blocker has been resolved. Option A below
> (canonical JSON + SHA-256) has been **pinned** in
> `SOMA-HEART-CERTIFICATE-SPEC.md` sections 9.2-9.5 as a
> docs-only amendment under the v0.1 contract. The option space
> below is retained for historical context only; the pinned rules
> in the spec are authoritative, and Gate 5 review no longer
> selects between the options. The remaining Gate 5 blocker is
> test-vector-file delivery under spec section 19.2.

Spec section 9 originally stated requirements only and deferred
the final byte layout and hash algorithm as a Gate 5 precondition.
Sections 9.2-9.5 now pin the v0.1 canonical encoding
(canonical JSON with explicit key ordering, number, byte-array,
and escaping rules), the certificate identifier hash
(`lowercase_hex(sha256("soma-heart-certificate:v0.1:" || canonical_bytes))`),
the signature input (`"soma-heart-certificate:v0.1:<role>:" ||
canonical_bytes`), and the crypto-agility rules for any future
revision.

### Option space

| Option | Canonical encoding | Hash algorithm | Notes |
|---|---|---|---|
| A | Canonical JSON (sorted keys, UTF-8, stable number handling) | SHA-256 | Matches `SOMA-ROTATION-SPEC.md` section 4.4 (`sha256(canonicalJson(...))`) and `SOMA-CHECK-SPEC.md` (SHA-256 content hashes). Lowest cognitive load for implementers already familiar with rotation/check. |
| B | DAG-CBOR or deterministic CBOR | SHA-256 | More compact, less forgiving of reader bugs, requires a CBOR dependency for every conforming verifier. |
| C | Canonical protobuf or flatbuffers | SHA-256 | Higher tooling burden, strong schema discipline; not used elsewhere in Soma today. |
| D | SSZ / deterministic binary framing | SHA-256 or BLAKE3 | Used in some adjacent ecosystems; no existing Soma precedent. |
| E | Any of the above with SHA-3-256 or BLAKE3 instead of SHA-256 | - | Introduces a hash family Soma does not currently use. |

### Pinned v0.1 decision

**Option A (canonical JSON + SHA-256) is pinned for v0.1.** The
decision has been ratified in `SOMA-HEART-CERTIFICATE-SPEC.md`
sections 9.2-9.5 as a docs-only amendment under the v0.1
contract. Gate 5 review no longer decides between Options A-E;
the option table above is retained as historical context only.

The spec's pinned rules are authoritative. In summary:

- Canonical encoding (spec section 9.2): canonical JSON, UTF-8
  with no BOM, Unicode code-point key ordering, duplicate keys
  rejected, no insignificant whitespace, tightened RFC 8259
  string escaping, integer-millisecond timestamps, string
  decimals for monetary or out-of-range numbers, NaN / Infinity /
  undefined rejected, optional absent fields omitted, array order
  preserved, byte arrays as base64 RFC 4648 section 4 with
  padding, `signatures` omitted from the canonical input
  entirely.
- Certificate identifier hash (spec section 9.3):
  `certificate_id = lowercase_hex(sha256("soma-heart-certificate:v0.1:" || canonical_bytes))`.
- Signature input (spec section 9.4):
  `"soma-heart-certificate:v0.1:<role>:" || canonical_bytes`,
  with role in lowercase ASCII.
- Crypto-agility (spec section 9.5): future revisions ship as a
  separate spec or ADR slice with a new version-prefixed domain
  separator; identifier stability is preserved (no retroactive
  rehash); any migration MUST ship vectors for both encodings.

The pinning is justified by existing repo patterns:

- `SOMA-ROTATION-SPEC.md` section 4.4 defines event hashing as
  `sha256("soma-rotation-event:" || canonicalJson(preEventWithSignatures))`.
- `SOMA-CHECK-SPEC.md` specifies lowercase-hex SHA-256 content
  hashes as the v0.1 identifier shape for content addressing.
- Canonical JSON keeps tooling surface small for implementers who
  are already producing rotation events and Soma Check hashes.

Any future change to the canonical encoding or hash algorithm
MUST go through a new spec or ADR slice under the crypto-agility
rules in spec section 9.5, not through Gate 5 review of this
proposal.

### Hard requirements at any option

- Determinism.
- Total field coverage.
- Signature exclusion from hashed bytes, with signatures covering
  those identifier bytes.
- Identifier stability across credential rotation.
- Collision resistance and deterministic replay.
- No silent defaulting of absent optional fields.

## Test vector delivery plan

Spec section 19.2 requires test vector files to exist and satisfy
section 19.1 before Gate 5 may be accepted. The v0.1 vector corpus
now lives at `test-vectors/soma-heart-certificate/v0.1/`; this
section records that location and the coverage it must preserve.

### Proposed location

`test-vectors/soma-heart-certificate/v0.1/`.

### Vector structure (conceptual only)

The v0.1 corpus uses a compact manifest:
`test-vectors/soma-heart-certificate/v0.1/manifest.json`.
Each vector entry contains:

- a canonical certificate input file;
- the expected canonical byte output;
- the expected certificate identifier;
- the expected verifier outcome (accept, reject, fail-closed) plus
  the expected error code when rejection is expected;
- the verifier policy used to produce the expected outcome;
- any rotation-state fixture needed to resolve the signing-time
  credential.

### Required vector coverage (cross-reference to spec section 19.1)

- at least one conforming certificate for each accepted profile
  under spec section 5 (`birth`, `one-sided`, `heart-to-heart`,
  `freshness-receipt-bound`);
- at least one rejection vector for each deferred profile
  (`policy-statement`, `witnessed`);
- at least one rejection vector for each deferred claim kind
  (`capability_statement`, `delegation_or_endorsement`);
- at least one rejection vector for each deferred evidence kind
  (`credential presentation references`, `media/content hashes`,
  `third-party attestation references`);
- a signature-verification vector exercising historical credential
  lookup under `SOMA-ROTATION-SPEC.md`;
- a chain-link-mismatch vector;
- a chain-link-unresolvable vector;
- a credential-ineffective vector (new credential effective after
  claimed signing time);
- a credential-revoked vector;
- a freshness-window-expired vector;
- a canonicalisation-divergence vector;
- a redaction/disclosure vector exercising spec section 16;
- at least one malformed-evidence vector exercising spec section 17
  evidence laundering.

### Reproducibility constraint

Vector files MUST be reproducible from the accepted spec plus
ADR-0004 and `SOMA-ROTATION-SPEC.md` alone. They MUST NOT depend
on package internals, private helpers, or ClawNet runtime.

### Gate 5 acceptance dependency

Gate 5 acceptance is blocked until:

1. the vector file set exists at the agreed location and satisfies
   spec section 19.1 under the pinned canonical encoding from spec
   sections 9.2-9.5.

The canonicalization and hash decision is already pinned in the
spec and is no longer a Gate 5 blocker. The vector corpus has been
delivered at `test-vectors/soma-heart-certificate/v0.1/`. No
implementation may be authorised before reviewers confirm the vector
condition is met and the package-surface readiness items in this
proposal are accepted.

## Package / API shape sketch (conceptual only)

The names below are **tentative and non-binding**. They are
included only to communicate the boundary between functional
areas. No TypeScript, no interface, and no package surface is
ratified by this sketch.

- `canonicalize(certificate) -> canonical_bytes` (area 1)
- `certificate_id(canonical_bytes) -> identifier` (area 2)
- `validate_profile(certificate, policy) -> result` (area 3)
- `validate_claims(certificate, policy) -> result` (area 4)
- `validate_evidence(certificate, policy) -> result` (area 5)
- `verify_signatures(certificate, rotation_lookup) -> result`
  (area 6)
- `resolve_signing_time_credential(signer_identity, issued_at) ->
  credential` (area 7, backed by existing rotation surfaces)
- `evaluate_policy(certificate_or_chain, policy, rotation_lookup)
  -> decision` (area 8)
- `bind_soma_check_evidence(certificate, soma_check_inputs) ->
  certificate` (area 9)
- `bind_payment_receipt_reference(certificate, rail_adapter_output)
  -> certificate` (area 10)
- `error_code_for(failure_mode) -> wire_identifier` (area 11)

Every shape above is a boundary sketch only. The Gate 5 review
MUST decide:

- whether the surface lives in `soma-heart` directly or in a
  sub-namespace such as `soma-heart/certificate`;
- whether `soma-sense` re-exports observer-only primitives;
- whether any adapter surface (area 10) ships inside `soma-heart`
  at all, or lives in a separate rail-adapter package;
- whether the rotation-lookup boundary (area 7) uses existing
  `soma-heart` rotation exports or introduces a new adapter type.

## Security and assurance constraints

The proposal MUST preserve the assurance boundaries accepted in
ADR-0005 and the spec:

- Signatures prove issuer key control under a verification policy,
  not factual truth.
- Hashes prove commitment to bytes, not correctness.
- Chains prove provenance and linkage, not universal
  trustworthiness.
- Soma does not verify real-world truth at any layer.
- Trust is not automatically transitive across chain links.
- Verifiers MUST fail closed on ambiguous rotation state, missing
  REQUIRED evidence, policy mismatch, deferred profiles, and
  deferred claim or evidence kinds.
- Soma Check MUST remain freshness and payment-avoidance only.
  No reputation, pricing, routing, provider selection, cache
  orchestration, or semantic-truth surface may be introduced
  through Soma Check.
- x402 MUST NOT be elevated to a hard protocol dependency. The
  certificate core stays rail-agnostic; x402 is the first/default
  adapter only.
- Private evidence pointers MUST declare their verification
  limits; hidden evidence MUST NOT be implied to have been
  verified.
- Witness-independence is out of scope for v0.1; `witnessed`
  profiles remain deferred.

## Credential-rotation compatibility

ADR-0004 and `SOMA-ROTATION-SPEC.md` remain authoritative for:

- rotation lifecycle;
- rollback invariant;
- pre-rotation commitment;
- witness, quorum, class, policy-floor, and snapshot semantics;
- historical-lookup semantics.

This proposal uses those surfaces without modifying them. Rotation
lookup is consumed at area 7; no rotation mechanism is introduced
through certificate processing. If a certificate-driven use case
surfaces a rotation gap, it MUST be escalated to a rotation ADR
slice rather than absorbed into the certificate package surface.

## Deferred to ClawNet

The following concerns are downstream product concerns and MUST
NOT be defined as Soma protocol or package surfaces:

- runtime trust queries;
- provider routing;
- cache and orchestration behaviour;
- pricing and billing policy;
- staking markets;
- proof mining;
- reward/burn mechanics;
- `$CLAWNET` utility;
- marketplace and business-model behaviour;
- hosted witness operations;
- Gate 7 first-consumer implementation unlock.

ClawNet MAY cite accepted Soma certificate semantics and build
product policy around them in `claw-net`. ClawNet MUST NOT
redefine certificate, claim, evidence, or chain semantics
locally, and MUST NOT ship code that would require Soma to take
on any of the concerns above.

## Acceptance criteria

Gate 5 acceptance requires all of the following, in order:

1. **Canonicalization and hash algorithm already pinned.** The
   final canonical byte layout and hash algorithm are pinned in
   `SOMA-HEART-CERTIFICATE-SPEC.md` sections 9.2-9.5. Gate 5
   acceptance MUST confirm that this proposal is consistent with
   the pinned rules and does not attempt to redefine them. Any
   future change MUST go through a new spec or ADR slice under
   the crypto-agility rules in spec section 9.5.
2. **Vector files exist.** Test vector files MUST exist at
   `test-vectors/soma-heart-certificate/v0.1/` and MUST satisfy
   spec section 19.1 under the pinned canonical encoding. Vector
   files MUST be reproducible from the spec plus ADR-0004 and
   `SOMA-ROTATION-SPEC.md` alone.
3. **Package surface shape agreed.** The functional areas above
   MUST be reviewed and either accepted as the Gate 5 surface
   shape or explicitly amended. Name-level bikeshedding is
   expected at this step; the boundary-level shape is what is
   being ratified.
4. **No implementation yet unless a later PR starts it.** Gate 5
   acceptance DOES NOT, by itself, merge package code. A
   subsequent PR (or Gate 6 sequence) MUST be the instrument that
   lands code. This proposal's acceptance only unlocks that
   subsequent work.
5. **Boundary rules preserved.** The ADR-0005 boundary rules and
   the spec's accepted non-goals MUST remain intact. Any drift
   into ClawNet runtime, tokenomics, pricing, routing, cache,
   proof mining, staking, reward/burn, reputation, or runtime
   trust query APIs blocks acceptance.
6. **Credential-rotation semantics unchanged.** The acceptance
   MUST explicitly confirm no change to ADR-0004 or
   `SOMA-ROTATION-SPEC.md` semantics.

Gates 6 and 7 remain blocked until Gate 5 acceptance lands under
the criteria above.

## Open questions

1. Verifier policy wire representation (spec section 21 open
   item 2).
2. Wire representation for the spec section 18 failure modes
   (spec section 21 open item 10).
3. Whether the package surface lives in `soma-heart` directly or
   in a sub-namespace such as `soma-heart/certificate`.
4. Whether `soma-sense` re-exports observer-only primitives from
   this surface and, if so, which ones.
5. Whether the rail adapter boundary (area 10) ships inside
   `soma-heart` at all or lives in a separate adapter package.
6. Whether receipt references remain certificate fields or
   migrate to a distinct Soma receipt primitive (future ADR
   candidate, spec section 21 item 8).
7. Joint resolution of the `fulfillment-receipt-bound` profile
   and the `fulfillment_receipt` claim (future ADR candidate,
   spec section 21 item 11).

Resolved since the original draft:

- Final canonical byte layout and hash algorithm. Pinned in
  `SOMA-HEART-CERTIFICATE-SPEC.md` sections 9.2-9.5 (canonical
  JSON + SHA-256, domain separator
  `soma-heart-certificate:v0.1:`, lowercase hex digest). Any
  future migration is governed by the crypto-agility rules in
  spec section 9.5 and is out of scope for Gate 5.
- Test vector file location. The v0.1 corpus lives at
  `test-vectors/soma-heart-certificate/v0.1/`.

## Links

- `SOMA-HEART-CERTIFICATE-SPEC.md`
- `docs/decisions/ADR-0005-soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/proposals/soma-heart-trust-certificates.md`
- `SOMA-ROTATION-SPEC.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
- `docs/reference/spec-index.md`
- `docs/reference/packages.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `AGENTS.md`
