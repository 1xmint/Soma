# ADR-0005: Soma Heart Trust Certificates - v0.1 Certificate Primitive, Profiles, and Claim/Evidence Vocabulary

Status: proposed

## Note on ADR shape

This ADR is a decision packet, not implementation. It records the
dispositions this repo should take on the certificate primitive, v0.1
profiles, and the bounded claim/evidence vocabulary surfaced by
`docs/proposals/soma-heart-trust-certificates.md`. It does not ship
runtime code, package/API exports, or normative spec text. Any
normative contract lives in a follow-up spec; any package surface
waits until that spec shape is accepted. Where ADR-0004 ratified
pre-existing rotation code, ADR-0005 ratifies no code: there is no
certificate implementation in the tree, and none is authorised by
this ADR's acceptance.

Per `AGENTS.md`, decisions that change or clarify protocol semantics,
trust primitives, or security posture require proposal review and an
ADR before implementation. The source proposal is docs-only; this
ADR is the ADR gate that review called for.

## Context

Agent commerce and agent-to-agent exchange need records that are
attributable, bounded, and reusable across later verification
decisions. A verifier may need to know which Soma identity issued a
statement, which endpoint or artifact the statement concerns, which
evidence was bound to it, whether prior certificates were
intentionally referenced, and which verification policy interpreted
the chain.

Soma already owns the protocol layer for identity, delegation,
verification semantics, trust primitives, and security limits. Soma
Check already gives a narrow freshness and payment-avoidance
protocol. Credential rotation already has an accepted ADR
(`ADR-0004`) and a normative spec (`SOMA-ROTATION-SPEC.md`). The
missing piece is a Soma Heart certificate language that can bind
identity, exchange context, bounded claims, evidence references, and
prior certificates without pretending to verify real-world truth.

Without this boundary, a downstream runtime could accidentally
combine freshness, receipts, provider routing, pricing, reputation,
staking, proof mining, and business policy into one product-defined
"trust" surface. Soma should define the open certificate and chain
semantics and stop there; downstream systems decide how to query,
cache, price, route, and operationalise them.

The proposal's credential-rotation compatibility check (proposal
section 7) found no incompatibility between certificate design and
the rotation semantics accepted in ADR-0004. Certificates can
reference rotation state without redefining rotation lifecycle,
rollback, witness, quorum, class, policy-floor, snapshot, or
historical-lookup semantics. This ADR therefore proceeds on the
accepted rotation substrate as-is.

## Decision

All twelve rows below are **proposed decisions**. Acceptance happens
when reviewers explicitly approve each row and `Status:` is advanced
from `proposed` to `accepted` at merge time, following the pattern
used by ADR-0004. The proposal's ADR decision surface (section 23)
is the source artifact; this ADR packages those rows for review.

### D1. One certificate primitive with profiles

**Decision.** Soma Heart Trust Certificates are a single certificate
primitive expressed through profiles. Soma Birth Certificates,
heart-to-heart records, freshness-bound records, and later profiles
are profile variants of that primitive, not separate normative
primitives, unless a later ADR finds a concrete semantic reason to
split them.

**Rationale.** Profiles share envelope structure, issuer/credential
binding, signature semantics, and chain-reference semantics. Splitting
the primitive now would fragment verifier implementations before any
real divergence has appeared. Splitting remains available as a future
ADR move if a profile develops irreducibly different semantics.

### D2. v0.1 required certificate field set

**Decision.** A conforming v0.1 Soma Heart Trust Certificate must
expose the following fields, as drawn from proposal section 11:

- `version` / `profile` (required);
- certificate identifier / hash (required);
- issuer identity, expressed as stable Soma `identityId` (required);
- issuer credential / rotation reference, resolvable under
  `SOMA-ROTATION-SPEC.md` (required);
- subject identifier / hash (required);
- `issued_at` (required);
- expiry / freshness bounds (conditional; required where profile
  depends on freshness or revocation windows);
- claim set (required; drawn from the v0.1 accepted claim primitives);
- evidence references (conditional; required where the claim set
  depends on bound evidence);
- prior certificate references (conditional; required for
  chain-forming profiles; forbidden from implying automatic
  transitive trust);
- disclosure / privacy profile (conditional; required when any
  evidence is hidden, encrypted, selectively disclosed, or otherwise
  outside the verifier's reach);
- signature set (required; issuer signature plus any additional
  signatures the profile requires).

**Non-decision at this layer.** Canonical encoding, byte layouts,
hash algorithm, field names, and wire format are spec-level and not
decided here.

### D3. v0.1 profile disposition

**Decision.** v0.1 profile candidates (proposal section 12) are
dispositioned as follows:

| Profile | v0.1 | Notes |
|---|---|---|
| `birth` | accept | First Soma-verifiable introduction of a subject into a provenance trail. |
| `one-sided` (single-issuer trust) | accept | Issuer asserts bounded claims with no counterparty signature. |
| `heart-to-heart` (counterparty-signed) | accept | Binds the same statement to issuer and counterparty identities. |
| `freshness-receipt-bound` | accept | Carries Soma Check-style freshness or zero-charge unchanged-result evidence. |
| `fulfillment-receipt-bound` | open | Must wait for evidence on how fulfillment records should interact with Soma's assurance boundary; the spec PR may resolve this without a new ADR if it does not alter semantics. |
| `policy-statement` | defer | Attributable policy statements are useful but not required for v0.1 coverage; revisit when verifier policy distribution is scoped. |
| `witnessed` | defer | Witness semantics depend on independence assumptions that are not in scope for v0.1 (see ADR-0004 D5 assurance bound). |

**Rationale.** The four accepted profiles cover the smallest set that
lets a first consumer produce provenance records, single-signer trust
statements, counterparty-bound records, and Soma Check-bound freshness
receipts without introducing witness-independence or fulfillment
semantics that are not yet well defined.

### D4. v0.1 claim primitive disposition

**Decision.** v0.1 claim primitives (proposal section 13) are
dispositioned as follows:

| Claim primitive | v0.1 |
|---|---|
| `identity_control` | accept |
| `credential_validity` | accept |
| `endpoint_observation` | accept |
| `freshness_receipt` | accept |
| `payment_receipt_reference` | accept |
| `content_hash_commitment` | accept |
| `policy_statement` | accept |
| `fulfillment_receipt` | open |
| `capability_statement` | defer |
| `delegation_or_endorsement` | defer |

**Note on `policy_statement` as claim vs profile.** D3 defers the
`policy-statement` *profile*, while D4 accepts the `policy_statement`
*claim primitive*. These are deliberate. A claim primitive is a
building block a certificate can carry; a profile is a bundle of
required fields and signatures aimed at a specific use case. Accepting
the claim primitive lets other profiles attach attributable policy
text without committing to a standalone policy-statement profile in
v0.1.

**Rationale.** Accepted claims are the minimum needed to express
identity control, credential validity under rotation, endpoint
observation, Soma Check freshness, payment references, content
commitments, and attributable policy. `fulfillment_receipt` stays
open because it is tied to profile-level fulfillment semantics;
`capability_statement` and `delegation_or_endorsement` are deferred
because their normative meaning lives in
`SOMA-DELEGATION-SPEC.md` / `SOMA-CAPABILITIES-SPEC.md` and changing
either is out of scope here.

### D5. v0.1 evidence primitive disposition

**Decision.** v0.1 evidence primitives (proposal section 14) are
dispositioned as follows:

| Evidence primitive | v0.1 |
|---|---|
| signatures | accept |
| hash commitments | accept |
| timestamps | accept |
| request/response transcript hashes | accept |
| receipt references | accept |
| payment rail receipt references | accept |
| verifier policy references | accept |
| observation log references | open |
| private evidence pointers with disclosed verification limits | open |
| credential presentation references | defer |
| media/content hashes | defer |
| third-party attestation references | defer |

**Rationale.** Accepted evidence kinds are the minimum needed to
attach signatures, hash commitments, timestamps, transcript hashes,
and receipt or policy references to accepted claims. Observation logs
and private evidence pointers are open because both depend on
disclosure and verification-limit language that is spec-level work.
Credential presentations, media hashes, and third-party attestations
are deferred to keep v0.1 focused on evidence Soma can define without
importing external credential formats or attestation trust models.

### D6. Verifier-policy interpretation is mandatory

**Decision.** Chain and certificate interpretation is owned by
verifier policy, not by certificates themselves. Every conforming
verifier MUST:

- treat trust as non-transitive by default; no chain link implies
  automatic trust in a downstream claim;
- fail closed on policy mismatch, missing evidence, or ambiguous
  rotation state;
- reference a policy that identifies accepted issuers, accepted
  profiles, accepted claim kinds, accepted evidence kinds, freshness
  windows, and revocation/rotation rules in enough detail that an
  independent verifier running the same policy against the same
  certificates could reproduce the same decision.

**Rationale.** Without this rule, certificates risk being treated as
standalone truth. Chains prove provenance and linkage, not universal
trustworthiness (proposal sections 10 and 15). Forcing verifier policy
to carry interpretation keeps Soma's assurance boundary honest and
prevents downstream runtimes from implying Soma vouches for claim
truth.

### D7. Soma Check boundary

**Decision.** Soma Check remains freshness and payment-avoidance
only. Certificate profiles MAY carry Soma Check evidence
(`freshness_receipt`, content hashes, zero-charge unchanged-result
evidence, transcript hashes). Soma Check MUST NOT be used as:

- a reputation system;
- a pricing, routing, or provider-selection engine;
- a staking or reward surface;
- a certificate-chain verifier;
- a shared cache orchestrator;
- a proof of semantic truth.

**Rationale.** Soma Check is narrowly useful for "has this content
changed, do I need to pay or re-fetch". Widening it to anything else
would collapse the boundary the proposal is designed to preserve.

### D8. x402 adapter boundary

**Decision.** x402 is accepted as the first and default payment
adapter for v0.1 certificate profiles that carry payment evidence.
x402 is **not** a Soma protocol dependency. The certificate core
MUST stay payment-rail agnostic:

- certificate claims at the core layer use
  `payment_receipt_reference`, not x402-specific protocol semantics;
- rail adapters translate rail-specific challenges, proofs,
  settlements, refunds, and zero-charge outcomes into evidence
  references;
- a conforming non-x402 rail may be substituted if it can bind
  equivalent evidence into the certificate profile;
- Soma does not define wallet semantics or settlement finality beyond
  what the adapter's evidence can verify.

**Rationale.** x402 is a reasonable first fit for HTTP agent commerce
given its scope, but promoting it to a hard protocol dependency would
foreclose future rails and contradict the proposal's rail-agnostic
goal.

### D9. Credential-rotation compatibility

**Decision.** Certificate verification references ADR-0004 and
`SOMA-ROTATION-SPEC.md` as authoritative for rotation state. This
ADR proposes no credential-rotation semantic changes. Certificate
verification MUST:

- bind to stable Soma `identityId`, not to a specific credential key;
- resolve the credential effective at signing time via historical
  lookup rather than assuming the current credential signed old
  material;
- respect the `effective` window before treating a new credential as
  authoritative;
- respect rotation/revocation status as inputs to verification
  outcomes;
- leave rotation lifecycle, rollback, witness, quorum, class,
  policy-floor, snapshot, and historical-lookup semantics entirely to
  ADR-0004 and `SOMA-ROTATION-SPEC.md`.

**Compatibility check.** Proposal section 7 documents the check; no
incompatibility was found. This ADR re-affirms that check and does
not re-open it.

### D10. Deferred-to-ClawNet

**Decision.** The following concerns are downstream product concerns
and MUST NOT be defined as Soma protocol semantics in this ADR or in
the follow-up spec:

- runtime trust queries;
- provider routing;
- cache and orchestration behaviour;
- pricing and billing policy;
- staking markets;
- proof mining;
- reward/burn mechanics;
- `$CLAWNET` utility;
- marketplace and business model;
- hosted witness operations;
- first-consumer Gate 7 implementation.

ClawNet MAY cite accepted Soma certificate semantics and build
product policy around them. ClawNet MUST NOT redefine certificate,
claim, evidence, or chain semantics locally.

**Rationale.** ADR-0001 and ADR-0002 already require protocol truth
to live in Soma. D10 restates that rule for the specific concerns
that would otherwise drift into Soma via trust-certificate design.

### D11. Normative spec ownership

**Decision.** The normative contract for Soma Heart Trust Certificates
will live in a future top-level spec, provisionally named
`SOMA-HEART-CERTIFICATE-SPEC.md` (name non-binding), following the
existing pattern of `SOMA-CHECK-SPEC.md`, `SOMA-DELEGATION-SPEC.md`,
`SOMA-CAPABILITIES-SPEC.md`, and `SOMA-ROTATION-SPEC.md`. The spec
MUST be indexed from `docs/reference/spec-index.md`. No spec text is
drafted or implemented by this ADR.

**Rationale.** ADR-0004 D7 established the convention that normative
contracts live in top-level `SOMA-*-SPEC.md` files. This ADR follows
that convention rather than inventing a new location.

### D12. Package/API timing

**Decision.** No package or API proposal is authorised by this ADR.
Package surface work waits until the ADR is accepted and the
follow-up spec shape is agreed. ClawNet and other downstream
consumers MUST NOT ship trust-certificate surfaces based on this
ADR alone.

**Rationale.** Package surfaces encode normative behaviour. Shipping
them before the spec would repeat the pre-system pattern ADR-0004
had to clean up for rotation; the proposal's stated goal is to avoid
that for certificates.

## Non-goals

- No implementation of certificate encoding, hashing, signing, or
  verification.
- No package or API surface changes.
- No spec text or spec ratification.
- No reputation systems, tokenomics, staking markets, reward/burn
  mechanics, `$CLAWNET` utility, ClawNet pricing, routing, caching,
  proof mining, or marketplace mechanics.
- No runtime trust query API.
- No claim that Soma verifies real-world truth, endpoint quality,
  model correctness, delivery quality, or future reliability.
- No automatic transitive trust.
- No credential-rotation semantic changes.
- No elevation of x402 to a hard protocol dependency.
- No witness-independence guarantees; witnessed profiles are deferred.

## Security and assurance boundaries

Soma certificates make claims attributable and evidence
tamper-evident. They do not make claims true. This ADR treats the
certificate language as an **assurance-boundary clarification**
rather than a change to existing Soma security guarantees.

- Signatures prove issuer key control under a verification policy,
  not factual truth.
- Hashes prove commitment to bytes, not correctness, completeness,
  legality, or quality.
- Receipts prove a referenced event or artifact within the receipt's
  own trust model, not quality or truth.
- Chains prove provenance and linkage, not universal trustworthiness.
- Counterparty signatures prove participation in a signed view, not
  agreement with unstated facts.
- Witness signatures, where ever accepted, prove only that the
  witness signed a statement; they do not imply independence,
  neutrality, or omniscience. Witnessed profiles are deferred in D3
  specifically because independence is not in scope for v0.1.
- Private evidence pointers reduce what a verifier can check;
  certificates must disclose those limits rather than implying hidden
  evidence was verified.
- Credential rotation confusion must fail closed. Verifiers must
  resolve the credential effective at signing time.

The proposal's security-and-abuse section (section 19) enumerates
false signed claims, evidence laundering, chain laundering, replay,
credential rotation confusion, revocation gaps, privacy leakage,
private evidence overclaiming, sybil issuers, witness
non-independence, and endpoint equivocation. The follow-up spec
MUST carry those considerations forward as normative text or
test-vector requirements; this ADR records them as assurance-boundary
constraints only.

If reviewers conclude the clarification is large enough to warrant
direct edits to `docs/explanation/security-model.md`, that escalation
should be recorded at acceptance time. The default disposition of
this ADR is that no direct security-model edit is required.

## Consequences

- The proposal's direction is locked as the decision packet for the
  follow-up spec. Downstream systems can cite accepted ADR rows
  without waiting for spec ratification, provided they do not ship
  runtime behaviour that would require spec-level normative text.
- `docs/reference/spec-index.md` will gain a new entry once the
  follow-up spec lands; the ADR itself does not add that entry.
- A future spec can split D3's open and deferred profiles into a
  normative disposition without re-opening D1, D2, D4, or D5 unless
  the split changes the shared envelope.
- ClawNet integration work that touches runtime trust queries,
  routing, caching, pricing, staking, proof mining, reward/burn,
  token utility, marketplace, hosted witness operations, or Gate 7
  implementation remains out of scope for Soma per D10. Those items
  belong in `claw-net/docs/decisions/`, not here.
- Package surface work stays paused until the follow-up spec shape
  is agreed (D12).
- ADR-0004 rotation semantics stay authoritative. Any future
  certificate-driven rotation concern must be handled by referencing
  ADR-0004, not by amending it here.

## Readiness and next gates

Downstream work MUST NOT be merged or ratified until the prior gate
has cleared. Drafting work below a gate requires explicit
authorisation and does not imply future acceptance.

- **Gate 1 - ADR drafted.** Cleared by this document.
- **Gate 2 - ADR accepted.** Reviewers explicitly approve each of
  D1-D12 and advance `Status:` from `proposed` to `accepted` at
  merge time.
- **Gate 3 - Follow-up spec drafted.** A separate PR introduces
  `SOMA-HEART-CERTIFICATE-SPEC.md` (name non-binding) with canonical
  encoding, byte layouts, signature scheme, required/optional fields,
  profile-level requirements, test vectors, and error taxonomy.
  Indexed from `docs/reference/spec-index.md`. Not draftable until
  Gate 2 is cleared.
- **Gate 4 - Follow-up spec accepted.** Reviewers approve the spec
  and it moves to `Status: accepted`.
- **Gate 5 - Package surface proposal.** A separate proposal decides
  whether and how to expose certificate primitives in
  `soma-heart`. Not draftable until Gate 4 is cleared.
- **Gate 6 - Package surface stabilised.** Version bump or new
  package/export as the Gate 5 proposal dictates. Not draftable
  without Gate 5.
- **Gate 7 - ClawNet first-consumer implementation unlock.** Separate
  ADR in `claw-net/docs/decisions/`. Out of scope for Soma. Not
  draftable without Gate 6.

## Open questions

The following questions remain spec-level rather than ADR-blocking
and can be resolved by Gate 3 (follow-up spec) without re-opening
any D row above:

1. Canonical encoding and hash algorithm for certificate identifiers.
2. How verifier policy is identified on the wire: URI, hash, inline
   object, package version, or another mechanism.
3. Which evidence references are allowed to remain private and what
   disclosure language is mandatory when they are private.
4. Accepted timestamp sources per profile.
5. How revocation state, stale gossip, and unavailable rotation
   history affect certificate verification, consistent with
   ADR-0004 and `SOMA-ROTATION-SPEC.md`.
6. The counterparty-signature threshold that distinguishes a
   `heart-to-heart` record from a `one-sided` record.
7. Which x402 evidence fields the first adapter preserves while the
   certificate core remains rail-agnostic.
8. Whether receipt references remain fields inside certificates or
   whether Soma later defines a distinct receipt primitive. This is
   noted as spec-level but could rise to a new ADR if a distinct
   primitive is chosen.
9. How certificate profiles interact with existing delegation and
   capability specs without changing their semantics.
10. Required test vectors: certificate hash, signature verification,
    chain link verification, rotation lookup, redaction, and malformed
    evidence.

The two D3 items marked `open` (`fulfillment-receipt-bound` profile)
and the one D4 item marked `open` (`fulfillment_receipt` claim) are
tied together; the spec PR should resolve them jointly. If the
spec's resolution alters the claim's meaning beyond what D4 covers,
a follow-up ADR slice may be needed.

## Links

- `docs/proposals/soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0001-soma-is-the-protocol-home.md`
- `docs/decisions/ADR-0002-source-of-truth-boundaries.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-ROTATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `AGENTS.md`
