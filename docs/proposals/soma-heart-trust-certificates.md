Status: proposed

# Soma Heart Trust Certificates and Evidence-Bound Trust Chains

**Normativity:** design-only. Nothing in this document is normative until a
superseding ADR is accepted and, if needed, a spec is ratified. This proposal
does not ship runtime code, package/API changes, package exports, or spec
changes in its own merge.

**Primary artifact:** Soma Heart Trust Certificates. The claim and evidence
language below is deliberately scoped to certificate and chain interpretation.
It is not a broad standalone claim/evidence framework.

**First consumer:** ClawNet is expected to be the first downstream consumer of
these semantics, but ClawNet runtime, pricing, routing, staking, marketplace,
proof-mining, reward/burn, and token-utility choices are out of scope here.

**Credential-rotation posture:** `ADR-0004` and `SOMA-ROTATION-SPEC.md` are
authoritative. This proposal references rotation state for certificate
verification but proposes no credential-rotation semantic changes.

---

## 1. Context and motivation

Agent commerce and agent-to-agent exchange need records that are attributable,
bounded, and reusable across later verification decisions. A verifier may need
to know which Soma identity issued a statement, which endpoint or artifact the
statement concerns, which evidence was bound to it, whether prior certificates
were intentionally referenced, and which verification policy interpreted the
chain.

Soma already owns the protocol layer for identity, delegation, verification
semantics, trust primitives, and security limits. Soma Check already gives a
narrow freshness and payment-avoidance protocol. Credential rotation already
has an accepted ADR and a draft normative spec. The missing piece is a Soma
Heart certificate language that can bind identity, exchange context, bounded
claims, evidence references, and prior certificates without pretending to
verify real-world truth.

Without this boundary, a downstream runtime could accidentally combine
freshness, receipts, provider routing, pricing, reputation, staking, proof
mining, and business policy into one product-defined "trust" surface. Soma
should instead define the open certificate and chain semantics, while
downstream systems decide how to query, cache, price, route, and operationalize
them.

## 2. Goals and non-goals

### Goals

- Define Soma Heart Trust Certificates as the center of the proposal.
- Define Soma Birth Certificates as a certificate profile for origin/provenance
  records.
- Define heart-to-heart trust chains as linked certificate graphs interpreted
  by verifier policy, not automatic transitive trust.
- Provide a bounded claim/evidence vocabulary that is safe to standardize now
  as supporting certificate language.
- Preserve Soma Check as freshness/payment-avoidance only.
- Keep certificate semantics modular, rail-agnostic, and independent of any
  ClawNet runtime.
- Make assurance limits explicit enough that a verifier cannot mistake
  signatures, hashes, receipts, or chains for factual truth.
- Reference credential-rotation semantics without revising them.

### Non-goals

- No implementation.
- No package/API/export changes.
- No broad standalone claim/evidence framework.
- No tokenomics, staking markets, reward/burn mechanics, or `$CLAWNET` utility.
- No ClawNet pricing, provider routing, cache/orchestration, proof mining, or
  marketplace/business model.
- No Pulse work.
- No Gate 7 or ClawNet first-consumer implementation work.
- No claim that Soma verifies real-world truth, endpoint quality, model
  correctness, delivery quality, or future reliability.
- No automatic transitive trust. Chains are interpreted by verifier policy.
- No credential-rotation semantic changes.

## 3. Broad idea

A **Soma Heart Trust Certificate** is a signed, hash-addressable record from a
Soma identity that binds a bounded set of claims to evidence references and, if
applicable, prior certificate identifiers.

A **Soma Birth Certificate** is a Trust Certificate profile used when an
artifact, resource version, agent instance, endpoint observation, delegation
context, or fulfillment record first enters a Soma-verifiable provenance trail.

A **heart-to-heart trust chain** is a graph of certificates linked by hashes,
participant identities, signatures, and certificate references. The chain
preserves provenance and linkage. It does not create universal trust in later
claims and does not make trust transitive by default. Verifiers apply their own
policy to decide which issuers, evidence kinds, certificate profiles, freshness
windows, revocation state, and chain shapes they accept.

## 4. What 10/10 looks like

- One conforming Soma implementation can produce certificates that another
  conforming implementation can parse and verify once a later spec exists.
- Birth and trust certificates are profiles of a focused certificate primitive
  unless a later ADR finds a concrete semantic reason to split them.
- Claim/evidence primitives are narrow enough to support certificates without
  becoming a general-purpose truth framework.
- Soma Check stays independently useful and does not become a reputation,
  pricing, staking, or routing surface.
- x402 can be the first/default payment adapter while Soma certificates remain
  payment-rail agnostic.
- ClawNet can consume the protocol without owning it.

## 5. Fitness check

- protocol vision fit: high. This is protocol semantics, certificate language,
  trust primitives, assurance limits, and package/spec surface planning.
- real implementer/operator need: high. First consumers need citable Soma
  semantics before product runtimes harden around local definitions.
- security exposure: high. Certificates may influence payment, access,
  delegation interpretation, audit, and provider selection.
- evidence this is needed now: downstream designs would otherwise define trust
  chain, claim, and evidence semantics locally; a prior draft merged in
  proposal space already surfaced the need for a narrower Soma-owned
  vocabulary.
- keep / reshape / pause / remove: reshape in proposal space; do not implement
  until ADR/spec decisions are accepted.

## 6. Evidence ledger

| Field | Value |
|---|---|
| current status | proposed protocol design; no implementation in this slice |
| upstream dependencies | `AGENTS.md`, `SOMA-CHECK-SPEC.md`, `SOMA-DELEGATION-SPEC.md`, `SOMA-ROTATION-SPEC.md`, `ADR-0004`, Soma security model |
| downstream dependencies | ClawNet may be the first consumer, but its runtime and business choices are deferred |
| missing evidence | canonical certificate encoding, verifier policy model, privacy profile, adapter conformance rules, test vectors, concrete package surface |
| blocks current work | yes, for downstream designs that would otherwise define Soma trust-chain semantics locally |
| next gate | proposal review, then ADR if accepted direction changes protocol ownership, semantics, package surface, or security posture |
| terminal condition | accepted ADR and, if warranted, a normative Soma Heart certificate/trust-chain spec |

## 7. Credential-rotation compatibility check

Accepted rotation semantics can support Soma Birth Certificates and Soma Heart
Trust Certificates without semantic revision, provided certificate verification
references rotation state instead of redefining it.

Relevant accepted constraints:

- `ADR-0004` defines `src/heart/credential-rotation/` as the canonical
  consumer-facing rotation substrate.
- Identities persist across credential rotations via stable `identityId`
  anchors.
- `SOMA-ROTATION-SPEC.md` requires append-only event-chain retention for the
  lifetime of an identity.
- Historical credential lookup resolves the credential that was effective when
  a signature was made, rather than assuming the current credential signed old
  material.
- New credentials become authoritative only once the rotation event reaches
  `effective`; certificate verification must respect that effective window.

Certificate fields may therefore reference `identityId`, issuer credential
metadata, event-chain position, effective window, and revocation/rotation
status as inputs to verification. They must not alter rotation lifecycle,
rollback, witness, quorum, class, policy-floor, snapshot, or historical-lookup
semantics.

Gate 7 remains out of scope for this proposal. No credential-rotation
incompatibility was found that would block certificate design at proposal time.

## 8. Soma Birth Certificate definition

A **Soma Birth Certificate** is a Soma Heart Trust Certificate profile that
records the first Soma-verifiable introduction of a subject into a provenance
trail.

The subject may be:

- a generated output;
- a deterministic endpoint response;
- a resource or content version;
- an agent or heart instance;
- a delegation/capability context;
- an endpoint observation;
- a fulfillment artifact;
- another bounded artifact later ratified by spec.

A Birth Certificate should bind, at minimum:

- issuer identity;
- subject identifier or subject hash;
- creation or observation time;
- certificate profile/version;
- bounded claim set;
- evidence references;
- issuer signature;
- optional prior inputs or parent certificates;
- optional verifier-policy reference if the issuer is asserting a policy-bound
  interpretation.

A Birth Certificate proves only that the issuer signed the certificate payload
and bound the included evidence references to that subject. It does not prove
that the subject is factually true, useful, fair, complete, high quality, or
legally sufficient.

## 9. Soma Heart Trust Certificate definition

A **Soma Heart Trust Certificate** is the general certificate primitive. It is
a signed, hash-addressable envelope containing:

- certificate metadata: version, profile, identifier/hash, issued time, expiry
  or freshness bounds when applicable;
- issuer identity and credential/rotation reference sufficient for signature
  verification under accepted Soma semantics;
- subject: endpoint, resource, artifact, agent, delegation, policy, capability,
  fulfillment, receipt reference, or other later-ratified subject;
- bounded claims from the safe claim vocabulary in this proposal or later
  accepted extensions;
- evidence references from the safe evidence vocabulary in this proposal or
  later accepted extensions;
- optional participant, verifier, witness, or counterparty identities;
- optional prior certificate references;
- optional disclosure/privacy profile;
- issuer signature and any participant, witness, or counterparty signatures
  required by the profile.

Trust Certificates should be profile-driven. A profile states which fields are
required, which claims are allowed, which evidence kinds are acceptable, how
freshness and revocation are evaluated, and which verification failures are
fatal. A later spec must define canonical encoding, hashing, signatures,
required/optional fields, and test vectors.

## 10. Heart-to-heart trust chain semantics

A heart-to-heart trust chain is a graph of Soma Heart Trust Certificates where
each edge is an intentional reference from one certificate to prior evidence.
Edges may point to Birth Certificates, Trust Certificates, receipt references,
delegation records, policy statements, or fulfillment records, depending on
the profile.

A chain can establish:

- provenance links between certificates;
- issuer/counterparty participation where signatures verify;
- evidence continuity where hashes and references match;
- freshness/payment/fulfillment references where the relevant evidence verifies;
- compatibility with the verifier's accepted certificate profiles;
- whether each signing credential was valid at signing time under current Soma
  rotation and revocation semantics.

A chain cannot establish:

- that any claim is factually true;
- that trust transfers automatically from issuer A to issuer B;
- that all prior relevant evidence was disclosed;
- that a verifier must accept downstream claims because it accepted upstream
  claims;
- that a provider, model, endpoint, or fulfiller will remain reliable.

Verifier policy owns chain interpretation. A verifier policy may require
specific roots, issuer allowlists, profile allowlists, freshness windows,
counterparty signatures, witness signatures, payment rails, receipt kinds,
revocation checks, disclosure limits, or maximum chain depth. If the chain does
not satisfy policy, verification fails closed for that verifier.

## 11. v0.1 minimum certificate fields

This table is a proposal to the ADR for the smallest field set a conforming
v0.1 Soma Heart Trust Certificate should expose. Canonical encoding, byte
layouts, hash algorithms, and field names are deferred to a follow-up spec.

| Field | Purpose | Required | Notes |
|---|---|---|---|
| `version` / `profile` | Declares certificate profile and version so verifiers can match policy. | yes | Profile names drawn from the v0.1 profile candidates table. |
| certificate identifier / hash | Stable content-addressed handle for the certificate. | yes | Canonical encoding and hash algorithm are spec-level. |
| issuer identity | Stable Soma `identityId` of the issuer. | yes | Must survive credential rotation; references identity, not a specific key. |
| issuer credential / rotation reference | Pointer to the credential and rotation state effective at signing time. | yes | Must resolve under `SOMA-ROTATION-SPEC.md` semantics; does not redefine them. |
| subject identifier / hash | Identifies the bound subject (endpoint, artifact, agent, delegation, policy, receipt, etc.). | yes | May be an opaque hash for privacy profiles. |
| `issued_at` | Signer-asserted issuance time. | yes | Policy decides accepted time sources. |
| expiry / freshness bounds | Absolute expiry or freshness window. | conditional | Required where the profile depends on freshness or revocation windows. |
| claim set | Bounded claims from the v0.1 claim primitive table. | yes | Empty claim sets are not meaningful; profiles define allowed claims. |
| evidence references | Evidence drawn from the v0.1 evidence primitive table. | conditional | Required where the claim set depends on bound evidence. |
| prior certificate references | References to earlier certificates this one intentionally extends. | conditional | Required for chain-forming profiles; forbidden from implying automatic transitive trust. |
| disclosure / privacy profile | Declares what was hidden, redacted, or withheld. | conditional | Required when any evidence is private, encrypted, selectively disclosed, or outside the verifier's reach. |
| signature set | Issuer signature plus any additional signatures the profile requires. | yes | Counterparty, witness, and participant signatures are profile-specific. |

## 12. v0.1 profile candidates

This table is a proposal to the ADR for which certificate profiles should be
ratified in v0.1. The v0.1 column uses the same legend as the claim and
evidence tables (accept, defer, open).

| Profile | Purpose | Minimum signers | Required evidence kinds | v0.1 |
|---|---|---|---|---|
| `birth` | Records the first Soma-verifiable introduction of a subject into a provenance trail. | issuer | subject hash, creation or observation time | accept |
| `one-sided` (single-issuer trust) | Issuer asserts bounded claims about a subject with no counterparty signature. | issuer | claim-appropriate evidence | accept |
| `heart-to-heart` (counterparty-signed) | Binds the same statement to issuer and counterparty identities. | issuer + counterparty | transcript and/or exchange-envelope evidence | accept |
| `freshness-receipt-bound` | Carries Soma Check-style freshness or zero-charge unchanged-result evidence. | issuer | freshness receipt, content hash | accept |
| `fulfillment-receipt-bound` | References a fulfillment record for a requested action, delivery, or service. | issuer (+ counterparty when available) | fulfillment receipt, transcript or log reference | open |
| `policy-statement` | Attributable statement of issuer, verifier, endpoint, or certificate policy. | issuer | policy text/hash | defer |
| `witnessed` | Adds an independent or non-independent witness signature to any of the above. | issuer + witness | witness signature, witness policy reference | defer |

Each profile's required fields and signatures are cumulative with section 11. The ADR
must decide which profiles are ratified, which are deferred, and which remain
open pending further evidence.

## 13. Safe claim primitives

These primitives are safe now only as bounded certificate claim types. Each
claim must identify its issuer, subject, evidence references, time bounds where
relevant, and verification limits.

| Claim primitive | Meaning | Safe bound | v0.1 |
|---|---|---|---|
| `identity_control` | Issuer claims control of an identity or key at a time. | Proved only by valid signature/proof-of-possession under accepted identity and rotation semantics. | accept |
| `credential_validity` | Issuer or verifier claims a credential was valid, effective, or revoked in a stated window. | Must reference Soma rotation/revocation state; does not redefine it. | accept |
| `endpoint_observation` | Issuer claims it observed an endpoint request/response or endpoint state. | Proves an observation record was signed, not that the endpoint was honest or complete. | accept |
| `freshness_receipt` | Issuer claims a freshness check or hash comparison occurred. | Binds Soma Check-style freshness evidence; does not prove semantic freshness beyond the check policy. | accept |
| `payment_receipt_reference` | Issuer references a payment event, challenge, proof, settlement, or zero-charge result. | Rail-agnostic reference; proves only what the rail evidence can verify. | accept |
| `content_hash_commitment` | Issuer commits to bytes via a content hash. | Proves commitment to bytes, not correctness, authorship, legality, or quality. | accept |
| `policy_statement` | Issuer states a verifier, issuer, endpoint, or certificate policy. | Policy is attributable; acceptance is verifier-controlled. | accept |
| `capability_statement` | Issuer states a capability, permission, or supported operation. | Capability meaning is verifier/service policy; statement alone grants nothing. | defer |
| `fulfillment_receipt` | Issuer claims a requested action or delivery was fulfilled. | Proves a fulfillment record was signed; does not prove quality or real-world completion unless supporting evidence and policy say so. | open |
| `delegation_or_endorsement` | Issuer references a delegation, endorsement, or vouching relationship. | Must preserve Soma delegation/revocation semantics; does not create automatic transitive authority or trust. | defer |

v0.1 column legend: **accept** = proposed for ratification in the first ADR;
**defer** = recognized but not normative in v0.1; **open** = ADR must decide
inclusion. Dispositions above are proposals to the ADR, not decisions.

This list is intentionally small. Future claims require proposal/ADR/spec
review if they alter protocol semantics, security posture, package surface, or
chain interpretation.

## 14. Safe evidence primitives

Evidence primitives are references or commitments attached to claims. They are
not truth guarantees by themselves.

| Evidence primitive | Meaning | Verification limit | v0.1 |
|---|---|---|---|
| signatures | Cryptographic signatures by issuers, participants, witnesses, or counterparties. | Prove key control under verification policy, not factual truth. | accept |
| hash commitments | Content-addressed commitments to bytes or canonical structures. | Prove byte equality/commitment, not correctness. | accept |
| timestamps | Local, monotonic, witness, or policy-accepted time evidence. | Depend on clock/witness policy and freshness windows. | accept |
| request/response transcript hashes | Hashes over exchange transcripts. | Prove commitment to a transcript representation, not that undisclosed context is absent. | accept |
| receipt references | References to delivery, payment, freshness, or fulfillment receipts. | Prove only what the referenced receipt and verifier can validate. | accept |
| credential presentation references | References to credential presentations, proofs, or disclosure artifacts. | Depend on credential format and verifier policy; may disclose limited fields only. | defer |
| payment rail receipt references | Rail-specific payment evidence references. | Rail-agnostic at Soma layer; rail adapter/verifier determines what can be checked. | accept |
| verifier policy references | Identifiers or hashes for the policy used to interpret a certificate or chain. | Make policy attributable; do not force other verifiers to accept it. | accept |
| observation log references | References to logs, witness records, monitoring events, or local observations. | Log integrity and completeness depend on the log's own guarantees. | open |
| media/content hashes | Hashes of images, audio, video, documents, or other content. | Prove commitment to media bytes, not authenticity or provenance beyond other evidence. | defer |
| third-party attestation references | References to external attestations. | Inherit the attester's trust model and verifier allowlist. | defer |
| private evidence pointers with disclosed verification limits | Encrypted, access-controlled, or selectively disclosed evidence references. | Verifier must know which checks were impossible because evidence was private or withheld. | open |

v0.1 column legend matches the claim primitives table.

## 15. Assurance limits

Soma certificates make claims attributable and evidence tamper-evident. They
do not make claims true.

- Signatures prove issuer key control under a verification policy, not factual
  truth.
- Hashes prove commitment to bytes, not correctness, completeness, legality,
  or quality.
- Receipts prove a referenced event or artifact within the receipt's own trust
  model, not quality or truth.
- Chains prove provenance and linkage, not universal trustworthiness.
- Counterparty signatures prove participation in a signed view, not agreement
  with unstated facts.
- Witness signatures prove the witness signed a statement, not that the witness
  was independent, neutral, or omniscient.
- Private evidence pointers reduce what a verifier can check; certificates
  must disclose those limits rather than implying hidden evidence was verified.

## 16. Endpoint truth models

Certificates must not treat all endpoints as if they have the same truth model.
Profiles and verifier policies should distinguish at least:

- **Deterministic data.** The same input and same data version should produce
  the same output. Hash commitments and freshness receipts are comparatively
  strong here, but still do not prove source correctness.
- **Random/LLM/image/video generation.** Outputs may be stochastic or
  non-repeatable. Certificates can bind prompt/request hashes, model or policy
  identifiers, output hashes, and observation records, but cannot prove the
  output is correct or reproducible unless the generation mode supplies that
  evidence.
- **Physical fulfillment.** Delivery, shipping, robotics, real-world services,
  or human action require external evidence. Soma can reference receipts,
  attestations, media hashes, and logs; it does not verify the physical world.
- **Private/proprietary endpoints.** Some evidence cannot be disclosed. Private
  evidence pointers must state what was hidden and which verification limits
  follow.
- **One-time actions.** Actions such as sending a message, executing a trade,
  or consuming a nonce may not be replayable for verification. Certificates can
  bind receipts and transcript hashes, but policy must handle irreversibility
  and non-repeatability.

## 17. Soma Check interaction

Soma Check remains freshness/payment-avoidance only. It answers whether a
caller's known hash matches the provider's current hash or whether payment/fetch
should proceed.

Soma Check may contribute:

- `freshness_receipt` claims;
- content hash evidence;
- zero-charge unchanged-result evidence;
- request/response headers or transcript hashes needed by a later certificate
  profile.

Soma Check does not provide reputation, pricing, staking, routing, provider
selection, reputation systems, certificate-chain verification, shared cache
orchestration, or proof of semantic truth.

## 18. Payment rail boundary

x402 is the first/default payment adapter for the initial Soma Heart
certificate design because it is a practical fit for HTTP agent commerce.

x402 is not a hard Soma protocol dependency. Soma Heart certificates remain
rail-agnostic:

- certificate claims should use `payment_receipt_reference`, not x402-specific
  protocol semantics, at the core layer;
- rail adapters translate rail-specific challenges, proofs, settlements,
  refunds, or zero-charge outcomes into evidence references;
- a conforming non-x402 rail may be used if it can bind equivalent evidence
  into the certificate profile;
- Soma does not define wallet semantics or settlement finality beyond what the
  adapter evidence can verify.

## 19. Security and abuse considerations

- **False signed claims.** A malicious issuer can sign false claims. Soma makes
  those claims attributable; it does not make them true.
- **Evidence laundering.** Attackers may attach impressive but irrelevant
  evidence. Profiles must require evidence-to-claim binding, not loose bundles.
- **Chain laundering.** A later certificate may reference a legitimate earlier
  certificate to imply more than the earlier certificate supports. Verifier
  policy must evaluate each link and each claim independently.
- **Replay.** Certificates and receipts need nonce, timestamp, expiry, audience,
  or transcript binding where replay would be harmful.
- **Credential rotation confusion.** Verifiers must resolve the credential
  effective at signing time and fail closed on ambiguous rotation state.
- **Revocation gaps.** Profiles must state how revocation state is checked and
  what happens when revocation or gossip state is stale.
- **Privacy leakage.** Endpoint identifiers, payment references, participant
  identities, transcript hashes, and timing can leak sensitive business or user
  information even when payloads are hashed.
- **Private evidence overclaiming.** Certificates with private evidence pointers
  must disclose what the verifier could not inspect.
- **Sybil issuers.** Free-to-mint identities require verifier policy,
  attestations, allowlists, or other application-level controls.
- **Witness non-independence.** A witness may be operated by the same party as
  the issuer. Certificates must not imply independence unless the evidence and
  policy support it.
- **Endpoint equivocation.** Providers can show different outputs to different
  verifiers. Transcript hashes, counterparty signatures, logs, and witnesses can
  make equivocation attributable but cannot prevent it in all cases.

## 20. Deferred to ClawNet

The following are downstream ClawNet concerns and must not be defined as Soma
protocol semantics in this proposal:

- runtime trust queries;
- provider routing;
- cache and orchestration behavior;
- pricing and billing policy;
- staking markets;
- proof mining;
- reward/burn mechanics;
- `$CLAWNET` utility;
- marketplace and business model;
- hosted witness operations;
- product-specific policy defaults;
- first-consumer Gate 7 implementation.

ClawNet may later cite accepted Soma certificate semantics and build product
policy around them. It should not redefine certificate, claim, evidence, or
chain semantics locally.

## 21. Protocol surface

- spec change: likely yes after ADR acceptance; a future
  `SOMA-HEART-CERTIFICATE-SPEC.md` (name non-binding) or equivalent may be
  needed.
- package API change: none in this proposal.
- security model change: assurance-boundary clarification rather than a change
  to existing guarantees; the ADR should record whether reviewers consider
  that clarification large enough to require updating
  `docs/explanation/security-model.md` directly.
- downstream integration impact: yes; ClawNet should treat accepted Soma
  semantics as upstream constraints.

## 22. Delivery shape

1. Review this proposal.
2. Draft an ADR that resolves each row of the section 23 ADR decision surface and
   records the accepted dispositions for the v0.1 field, profile, claim, and
   evidence tables.
3. If accepted, draft a normative Soma Heart certificate/trust-chain spec
   (provisional name `SOMA-HEART-CERTIFICATE-SPEC.md`) and index it from
   `docs/reference/spec-index.md`.
4. Only after spec shape is clear, propose package/API surfaces.
5. Defer ClawNet first-consumer implementation to a downstream proposal that
   cites the accepted Soma ADR/spec.

## 23. ADR decision surface

An ADR is needed. This proposal changes or clarifies protocol semantics, trust
primitives, certificate language, assurance limits, payment-rail boundaries,
and future package/spec surface. Per `AGENTS.md`, those decisions need
proposal review and ADR/spec follow-up before implementation.

The ADR must decide each row below. The "Proposal suggests" column records the
direction this document leans, not a pre-decided outcome.

| # | Decision | Proposal suggests |
|---|---|---|
| D1 | One certificate primitive with profiles, or separate normative primitives for Birth, Trust, and Heart-to-Heart records? | One primitive with profiles unless review finds a concrete semantic reason to split. |
| D2 | What is the v0.1 required certificate field set? | The v0.1 minimum certificate fields table in section 11. |
| D3 | Which v0.1 profiles are accepted, deferred, or left open? | Accept `birth`, `one-sided`, `heart-to-heart`, `freshness-receipt-bound`; open `fulfillment-receipt-bound`; defer `policy-statement`, `witnessed`. |
| D4 | Which claim primitives are accepted for v0.1? | The accept rows in the section 13 claim primitives table. |
| D5 | Which evidence primitives are accepted for v0.1? | The accept rows in the section 14 evidence primitives table. |
| D6 | What verifier-policy properties are required for chain interpretation? | Policy must be attributable, declare accepted issuers/profiles/freshness/revocation rules, fail closed, and never imply automatic transitive trust. |
| D7 | Soma Check boundary. | Soma Check remains freshness/payment-avoidance only; certificates may bind Soma Check evidence but Soma Check does not verify chains, claims, or reputation. |
| D8 | x402 adapter boundary. | x402 is the first/default payment adapter, not a hard Soma protocol dependency; certificates stay rail-agnostic at the core layer. |
| D9 | Credential-rotation compatibility posture. | Certificate verification references `ADR-0004` and `SOMA-ROTATION-SPEC.md` state without proposing any rotation semantic changes. |
| D10 | Deferred-to-ClawNet items. | Runtime trust queries, routing, caching, pricing, staking, proof mining, reward/burn, token utility, marketplace, hosted witness operations, and first-consumer Gate 7 implementation. |
| D11 | What spec file owns normative certificate and trust-chain semantics? | A future `SOMA-HEART-CERTIFICATE-SPEC.md` (name non-binding) indexed from `docs/reference/spec-index.md`, following the existing spec pattern. |
| D12 | Is a package/API proposal warranted now? | No. Package surface work waits until spec shape is accepted. |

Security model impact is an assurance-boundary clarification: certificates and
chains do not weaken or strengthen existing Soma security guarantees, but they
make the limits of attribution, provenance, and linkage explicit. If
reviewers conclude this clarification rises to a security model change, the
ADR should record that upgrade explicitly.

## 24. Open questions

The ADR decision surface in section 23 covers primitive/profile, field-set, claim,
evidence, boundary, rotation-compatibility, and deferred-to-ClawNet decisions.
The following remain open and may be answered by the ADR or by the spec that
follows it:

1. What canonical encoding and hash algorithm should certificate IDs use?
2. How should verifier policy be identified: URI, hash, inline object, package
   version, or another mechanism?
3. Which evidence references are allowed to remain private, and what
   disclosure language is mandatory when they are private?
4. What timestamp sources are acceptable for each profile?
5. How should revocation state, stale gossip, and unavailable rotation history
   affect certificate verification, while remaining consistent with
   `ADR-0004` and `SOMA-ROTATION-SPEC.md`?
6. What counterparty signature is required before a record can be labelled
   `heart-to-heart` rather than `one-sided`?
7. Which x402 evidence fields should the first adapter preserve, while keeping
   the core certificate model rail-agnostic?
8. Should receipt references be fields inside certificates only, or should
   Soma later define a distinct receipt primitive?
9. How should certificate profiles interact with existing delegation and
   capability specs without changing their semantics?
10. What test vectors are required before implementation: certificate hash,
    signature verification, chain link verification, rotation lookup,
    redaction, and malformed evidence?

## 25. Acceptance criteria

This proposal is ADR-ready when all of the following hold:

- The proposal remains centered on Soma Heart Trust Certificates.
- Claim/evidence language is scoped as supporting protocol language, not a
  standalone framework.
- Soma Birth Certificate and Soma Heart Trust Certificate definitions are
  present.
- Heart-to-heart trust chains are interpreted by verifier policy and do not
  imply automatic transitive trust.
- A v0.1 minimum certificate fields table is present (section 11).
- A v0.1 profile candidates table with accept/defer/open marks is present
  (section 12).
- Claim and evidence primitive tables carry an explicit v0.1 disposition
  column (sections 13 and 14).
- Assurance limits are explicit for signatures, hashes, receipts, chains,
  counterparty signatures, witness signatures, and private evidence.
- Endpoint truth models are addressed.
- Soma Check remains freshness/payment-avoidance only.
- x402 is the first/default payment adapter and not a hard Soma protocol
  dependency.
- ClawNet runtime, routing, caching, pricing, staking, proof mining,
  reward/burn, token utility, marketplace, and first-consumer Gate 7
  implementation are deferred.
- No credential-rotation semantic changes are proposed; `ADR-0004` and
  `SOMA-ROTATION-SPEC.md` remain authoritative.
- The ADR decision surface (section 23) enumerates every decision the ADR must
  record.
- No code, package/API, or spec implementation changes are made by this
  proposal.

## 26. Links

- `AGENTS.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-ROTATION-SPEC.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `docs/proposals/PROPOSAL-TEMPLATE.md`
