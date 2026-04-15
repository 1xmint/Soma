# Soma Heart Certificate Protocol

**Version:** `soma-heart-certificate/0.1`
**Status:** accepted
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

> v0.1 is an **accepted normative** certificate contract following
> ADR-0005. It defines the certificate primitive, v0.1 profiles, the
> bounded claim and evidence vocabulary, trust-chain semantics,
> verifier-policy requirements, and the required test-vector
> coverage list. It does not ship runtime code, package/API exports,
> canonical encoding, or any certificate implementation. Gate 5
> (package surface proposal) and Gate 6 (package surface stabilised)
> must clear before any implementation is authorised, and Gate 5
> acceptance is itself blocked on canonical-encoding selection and
> test-vector-file delivery (see section 19.2 and section 21).
> Credential-rotation semantics remain authoritative in ADR-0004
> and `SOMA-ROTATION-SPEC.md`; this spec only references rotation
> state, it does not change it.

## Acceptance note

This spec advanced from `Status: Draft` to `Status: accepted` at
Gate 4 after reviewer approval of every normative section (1-18)
and the required test-vector coverage list (section 19.1). Gate 4
scope is deliberately limited to ratifying the normative contract
and boundary rules. Gate 4 ratifies the canonicalization
requirements in section 9, but does NOT ratify the final canonical
byte layout or hash algorithm; those selections are Gate 5
preconditions per section 21. Gate 4 does NOT ship test vector
files (section 19.2), does NOT authorise any package, API,
runtime, or ClawNet work, and does NOT alter credential-rotation
semantics. Canonical byte layout and hash algorithm selection and
test-vector-file delivery are classified as Gate 5 preconditions
per section 21, and no package or API surface is authorised until
the Gate 5 proposal has itself been accepted. Credential-rotation
semantics remain authoritative in ADR-0004 and
`SOMA-ROTATION-SPEC.md` and are not changed by this acceptance.

RFC 2119 / RFC 8174 key words (`MUST`, `MUST NOT`, `SHOULD`,
`SHOULD NOT`, `MAY`, `REQUIRED`, `OPTIONAL`) apply throughout this
document, in the sense those RFCs intend.

## 1. Motivation

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
missing piece is a Soma Heart certificate contract that binds
identity, exchange context, bounded claims, evidence references,
and prior certificates without pretending to verify real-world
truth.

Without this contract, downstream runtimes would continue to define
trust-chain, claim, and evidence semantics locally, fragmenting
verifier behaviour. ADR-0005 decided the direction; this spec makes
the direction citable, testable, and implementer-facing.

## 2. Non-Goals

This spec deliberately excludes:

- **Runtime trust query APIs.** A verifier MUST NOT expose a
  "is-this-trusted" query surface based on this spec. Trust
  interpretation is owned by verifier policy, not by certificates.
- **Reputation systems.** Certificates do not carry, compute, or
  expose reputation, scoring, ranking, or aggregate trust signals.
- **Tokenomics, staking markets, proof mining, reward/burn
  mechanics, `$CLAWNET` utility, marketplace or business model
  behaviour.** These are downstream product concerns and out of
  scope.
- **ClawNet pricing, provider routing, cache/orchestration, and
  hosted witness operations.** These are downstream runtime
  concerns and out of scope.
- **x402 as a hard protocol dependency.** x402 is accepted as the
  first/default payment adapter; the certificate core remains
  payment-rail agnostic.
- **Break-glass rotation, panic freeze, M-of-N recovery, or any
  change to credential-rotation semantics.** Rotation is owned by
  ADR-0004 and `SOMA-ROTATION-SPEC.md`.
- **Delegation and capability redefinition.** Delegation and
  capability semantics are owned by `SOMA-DELEGATION-SPEC.md` and
  `SOMA-CAPABILITIES-SPEC.md`. Profiles deferring those claim kinds
  (see section 7) must not redefine them.
- **Claims about real-world truth.** A certificate MUST NOT be
  interpreted as proof that a subject is factually true, useful,
  fair, complete, high quality, or legally sufficient.
- **Automatic transitive trust.** A chain MUST NOT imply that a
  verifier accepts a downstream claim because it accepted an
  upstream one.
- **Package/API surface.** No TypeScript interfaces, no package
  exports, no runtime behaviour are defined by this spec. Package
  surface work is gated on Gate 5/6 per ADR-0005.

## 3. Terminology

- **Soma Heart Trust Certificate (certificate).** A signed,
  content-addressable record from a Soma identity that binds a
  bounded set of claims to evidence references and, where
  applicable, prior certificate identifiers, under a named profile.
- **Profile.** A named variant of the certificate primitive that
  fixes which fields are required, which claims are allowed, which
  evidence kinds are acceptable, how freshness and revocation are
  evaluated, and which verification failures are fatal.
- **Issuer.** The Soma identity whose signature binds the
  certificate. Identified by a stable `identityId` per ADR-0004 D2.
- **Subject.** The thing the certificate is about: endpoint,
  resource version, artifact, agent or heart instance, delegation
  context, policy, capability, fulfillment record, receipt
  reference, or other later-ratified subject.
- **Claim.** A bounded statement from the section 7 vocabulary with an
  explicit verification limit.
- **Evidence reference.** A commitment or pointer drawn from the section 8
  vocabulary that a claim depends on.
- **Certificate identifier.** The content-addressed hash of the
  canonicalised certificate, used as the stable handle for
  referencing and chain linking.
- **Trust chain.** A graph of certificates linked by intentional
  prior-certificate references. Chains preserve provenance and
  linkage; they do not create transitive trust.
- **Verifier.** The party evaluating a certificate or chain under
  a stated policy.
- **Verifier policy.** The rules a verifier uses to decide which
  issuers, profiles, claims, evidence kinds, freshness windows, and
  revocation states it accepts, and which failures are fatal.
- **Signing-time credential.** The credential that was `effective`
  at the time a signature was produced, resolved under
  `SOMA-ROTATION-SPEC.md` historical-lookup semantics.

## 4. Certificate Model

### 4.1 One primitive, many profiles

There is exactly one Soma Heart Trust Certificate primitive in v0.1,
per ADR-0005 D1. Soma Birth Certificates, heart-to-heart records,
freshness-bound records, and later profiles are variants of the
primitive, not separate normative primitives. A future ADR MAY
split the primitive if a profile develops irreducibly different
semantics; v0.1 does not.

### 4.2 What a certificate proves

A certificate proves that:

- the issuer signed the certificate payload under a signing-time
  credential;
- the bound claim set is attributable to the issuer;
- the referenced evidence items were committed to as inputs to the
  bound claims;
- any prior certificates referenced by hash were intentionally
  linked by the issuer.

A certificate does NOT prove that any claim is factually true,
useful, fair, complete, high quality, or legally sufficient. It
does NOT prove that an endpoint behaves honestly, that a model is
correct, that a delivery happened, or that a provider will remain
reliable.

### 4.3 Profile-driven verification

Verification is profile-driven. A profile fixes:

- required and optional fields (within the section 6 minimum field set);
- allowed claim kinds from the section 7 vocabulary;
- allowed evidence kinds from the section 8 vocabulary;
- freshness evaluation rules;
- revocation evaluation rules;
- which failures are fatal versus soft-fail.

Verifiers MUST reject certificates whose declared profile is not in
their policy's allowlist.

## 5. v0.1 Profiles

The v0.1 profile set is fixed by ADR-0005 D3.

| Profile | Disposition | Minimum signers | Required evidence kinds (section 8) | Summary |
|---|---|---|---|---|
| `birth` | accepted | issuer | subject hash or subject identifier; timestamps | First Soma-verifiable introduction of a subject into a provenance trail. |
| `one-sided` | accepted | issuer | claim-appropriate evidence per policy | Single-issuer trust statement about a subject with no counterparty signature. |
| `heart-to-heart` | accepted | issuer + counterparty | transcript hashes and/or exchange envelope evidence | Binds the same statement to both issuer and counterparty identities. |
| `freshness-receipt-bound` | accepted | issuer | freshness receipt, content hash commitment | Carries Soma Check-style freshness or zero-charge unchanged-result evidence. |
| `fulfillment-receipt-bound` | open | issuer (+ counterparty when available) | fulfillment receipt, transcript or log reference | References a fulfillment record; joint resolution with the open `fulfillment_receipt` claim is a spec-level task. |
| `policy-statement` | deferred | n/a in v0.1 | n/a in v0.1 | Attributable policy statement profile; claim primitive accepted in section 7, profile is not ratified in v0.1. |
| `witnessed` | deferred | n/a in v0.1 | n/a in v0.1 | Witness-augmented profile; deferred because witness-independence is out of scope for v0.1 (see ADR-0004 D5 assurance bound). |

- **Accepted** profiles are normative in v0.1. A conforming verifier
  MUST support all accepted profiles that appear in its policy
  allowlist.
- **Open** profiles MAY be present in test vectors and draft wire
  shapes but MUST NOT be treated as ratified until a subsequent
  spec revision or ADR slice closes them.
- **Deferred** profiles MUST NOT be normative in v0.1. A certificate
  declaring a deferred profile MUST be rejected by a conforming
  v0.1 verifier.

Implementers MUST NOT invent additional profiles in v0.1 without a
follow-up spec revision or ADR.

## 6. Minimum Certificate Fields

The minimum v0.1 field set, per ADR-0005 D2. Canonical encoding,
byte layouts, and field names are spec-level requirements defined
in section 9; the table below states purpose and requirement level only.

| Field | Purpose | Required | Notes |
|---|---|---|---|
| `version` / `profile` | Declares the certificate wire version and profile so verifiers can match policy. | REQUIRED | Profile MUST be drawn from section 5. |
| certificate identifier / hash | Stable content-addressed handle for the certificate. | REQUIRED | Computed per section 9; used for chain linking. |
| issuer identity | Stable Soma `identityId` of the issuer. | REQUIRED | MUST be the identity anchor, not a specific key. |
| issuer credential / rotation reference | Pointer resolvable under `SOMA-ROTATION-SPEC.md` to the credential effective at signing time. | REQUIRED | See section 15. |
| subject identifier / hash | Identifies the bound subject. | REQUIRED | MAY be an opaque hash where the privacy profile requires it. |
| `issued_at` | Signer-asserted issuance time. | REQUIRED | Accepted time sources are policy-controlled; see section 11 and section 12. |
| expiry / freshness bounds | Absolute expiry or freshness window. | CONDITIONAL | REQUIRED where the profile depends on freshness or revocation windows (e.g. `freshness-receipt-bound`). |
| claim set | Bounded claims drawn from section 7. | REQUIRED | Empty claim sets are not meaningful; profiles define allowed claims. |
| evidence references | Evidence drawn from section 8. | CONDITIONAL | REQUIRED where the claim set depends on bound evidence. |
| prior certificate references | References to earlier certificates this one intentionally extends. | CONDITIONAL | REQUIRED for chain-forming profiles. MUST NOT imply automatic transitive trust (section 11). |
| disclosure / privacy profile | Declares what was hidden, redacted, or withheld. | CONDITIONAL | REQUIRED when any evidence is hidden, encrypted, selectively disclosed, or otherwise outside the verifier's reach (section 16). |
| signature set | Issuer signature plus any additional signatures the profile requires. | REQUIRED | Counterparty, witness, and participant signatures are profile-specific. |

A conforming v0.1 certificate MUST expose all REQUIRED fields and
MUST expose CONDITIONAL fields when the profile triggers them.
Implementations MUST NOT silently drop REQUIRED fields under any
privacy profile; the disclosure field records what was withheld
rather than hiding the field itself.

### 6.1 Conceptual wire shape (non-normative)

The following sketch illustrates the field grouping for reviewers.
It is **conceptual only** - it is not a package API, not a
TypeScript definition, not a wire format, and not binding on
implementations. Canonical encoding is defined in section 9.

```
SomaHeartTrustCertificate {
  version
  profile
  certificate_id              // content-addressed hash, section 9
  issuer {
    identity_id               // stable Soma identityId
    credential_rotation_ref   // resolves under SOMA-ROTATION-SPEC.md
  }
  subject {
    id_or_hash
  }
  issued_at
  expiry_or_freshness?        // CONDITIONAL per profile
  claims [                    // section 7
    { kind, bound_values, evidence_refs?, verification_limit }
  ]
  evidence [                  // section 8
    { kind, reference, verification_limit }
  ]
  prior_certificates? [       // CONDITIONAL per profile
    { certificate_id, link_reason }
  ]
  disclosure?                 // CONDITIONAL per section 16
  signatures [                // section 10
    { signer_role, identity_id, credential_rotation_ref, signature_bytes }
  ]
}
```

## 7. Claim Primitives

The v0.1 claim vocabulary is fixed by ADR-0005 D4. Each claim
instance MUST identify its issuer, subject, evidence references
where applicable, time bounds where relevant, and its verification
limit.

| Claim | Disposition | Verification limit |
|---|---|---|
| `identity_control` | accepted | Proved only by a valid signature or proof-of-possession under accepted identity and rotation semantics. |
| `credential_validity` | accepted | MUST reference Soma rotation/revocation state; does not redefine it. |
| `endpoint_observation` | accepted | Proves an observation record was signed by the issuer. Does not prove the endpoint was honest or complete. |
| `freshness_receipt` | accepted | Binds Soma Check-style freshness evidence; does not prove semantic freshness beyond the Soma Check policy. |
| `payment_receipt_reference` | accepted | Rail-agnostic reference; proves only what the rail evidence itself can verify. |
| `content_hash_commitment` | accepted | Proves commitment to bytes, not correctness, authorship, legality, or quality. |
| `policy_statement` | accepted | Policy is attributable; acceptance is verifier-controlled. Accepted as a claim primitive even though the `policy-statement` *profile* is deferred (section 5). |
| `fulfillment_receipt` | open | Proves a fulfillment record was signed; does not prove real-world completion unless supporting evidence and policy say so. Resolved jointly with the `fulfillment-receipt-bound` profile. |
| `capability_statement` | deferred | Capability semantics are owned by `SOMA-CAPABILITIES-SPEC.md`; v0.1 does not restate or extend them. |
| `delegation_or_endorsement` | deferred | Delegation semantics are owned by `SOMA-DELEGATION-SPEC.md`; v0.1 does not restate or extend them. |

A conforming verifier MUST reject certificates containing deferred
claim kinds. It MAY accept certificates containing `open` claim
kinds but MUST NOT treat them as ratified behaviour.

## 8. Evidence Primitives

The v0.1 evidence vocabulary is fixed by ADR-0005 D5. Evidence
primitives are references or commitments attached to claims. They
are not truth guarantees by themselves.

| Evidence | Disposition | Verification limit |
|---|---|---|
| signatures | accepted | Prove key control under verification policy, not factual truth. |
| hash commitments | accepted | Prove byte equality or commitment, not correctness. |
| timestamps | accepted | Depend on clock, witness, and freshness policy (section 12). |
| request/response transcript hashes | accepted | Prove commitment to a transcript representation, not that undisclosed context is absent. |
| receipt references | accepted | Prove only what the referenced receipt and verifier can validate. |
| payment rail receipt references | accepted | Rail-agnostic at the Soma layer; the rail adapter/verifier determines what is checkable. |
| verifier policy references | accepted | Make policy attributable; MUST NOT force other verifiers to accept it. |
| observation log references | open | Log integrity and completeness depend on the log's own guarantees; acceptance awaits disclosure-language resolution (section 16). |
| private evidence pointers with disclosed verification limits | open | Verifier MUST know which checks were impossible because evidence was private or withheld; acceptance awaits disclosure-language resolution (section 16). |
| credential presentation references | deferred | Depend on external credential formats; v0.1 does not import them. |
| media/content hashes | deferred | Depend on out-of-band media trust; v0.1 does not ratify them. |
| third-party attestation references | deferred | Inherit the attester's trust model; v0.1 does not import that trust. |

A conforming verifier MUST reject certificates containing deferred
evidence kinds. It MAY accept certificates containing `open`
evidence kinds but MUST NOT treat them as ratified.

## 9. Canonicalization and Identifier Requirements

The certificate identifier is a content-addressed hash of the
canonicalised certificate. v0.1 does NOT lock the final canonical
byte layout or hash algorithm; those are spec-level open items
tracked in section 21. Implementations conforming to v0.1 MUST satisfy
the following requirements regardless of which encoding is later
ratified:

- **Determinism.** Two conforming serializers MUST produce
  byte-identical canonical bytes for the same logical certificate.
- **Total field coverage.** Canonical bytes MUST cover every
  REQUIRED field and every CONDITIONAL field that is present.
  Optional fields that are absent MUST NOT be silently replaced
  with defaults during canonicalisation.
- **Signature exclusion.** The `signatures` field MUST be excluded
  from the bytes that are hashed to produce the certificate
  identifier, but signatures MUST cover those identifier bytes.
- **Hash commitment.** The hash algorithm selected before Gate 5
  package-surface acceptance MUST be collision-resistant,
  deterministic, and replayable by any conforming verifier.
  Selection of the final canonical byte layout and hash algorithm
  is a Gate 5 precondition per section 21; Gate 4 ratifies the
  requirements stated in this section, not the final byte layout
  or algorithm.
- **Identifier stability across rotation.** Rotating an issuer's
  credential MUST NOT change the certificate identifier of any
  previously issued certificate.
- **Test vectors.** The spec's accepted canonicalisation MUST be
  accompanied by normative test vectors covering at least one
  certificate per accepted profile (section 19).

An implementation MUST NOT ship canonicalisation behaviour that is
not covered by a normative test vector.

## 10. Signature and Credential Verification

Signatures bind the certificate bytes and the signer identity under
a signing-time credential resolved via rotation state.

### 10.1 Signature coverage

The issuer signature MUST cover:

- every REQUIRED field;
- every CONDITIONAL field that is present;
- the declared profile;
- the certificate identifier bytes (per section 9);
- any prior-certificate references.

Additional signatures (counterparty, witness where ever accepted,
participant) MUST cover at least the same byte range as the issuer
signature unless their profile explicitly narrows coverage and
declares the narrowing in the disclosure field (section 16).

### 10.2 Credential resolution

For each signature, a verifier MUST:

1. resolve the signer's stable `identityId`;
2. resolve the signing-time credential via historical lookup per
   `SOMA-ROTATION-SPEC.md`;
3. confirm the credential was `effective` at the signer's claimed
   `issued_at` (or at the applicable event time for additional
   signatures);
4. confirm the signature verifies under the resolved credential.

A verifier MUST NOT accept a signature under the issuer's *current*
credential if that credential became `effective` after the claimed
signing time. A verifier MUST fail closed on ambiguous rotation
state (see section 12 and section 18).

### 10.3 Revocation

A verifier MUST consult rotation/revocation state as an input to
the decision. The exact rules for "stale" or "unavailable"
revocation state are spec-level open items (section 21); v0.1 requires
only that the rules be declared by policy and applied
deterministically.

## 11. Trust Chain Semantics

A trust chain is a graph of certificates linked by intentional
prior-certificate references. Edges MAY point to Birth Certificates,
Trust Certificates, receipt references, delegation records, or
policy statements, subject to the profile.

### 11.1 What a chain proves

A chain MAY establish:

- provenance links between certificates;
- issuer and counterparty participation where signatures verify;
- evidence continuity where hashes and references match;
- freshness, payment, or fulfillment references where the relevant
  evidence verifies;
- compatibility with the verifier's accepted profiles;
- credential validity at signing time under ADR-0004 semantics.

### 11.2 What a chain does NOT prove

A chain MUST NOT be interpreted as establishing:

- factual truth of any claim;
- automatic trust transfer from issuer A to issuer B;
- disclosure completeness of prior evidence;
- any obligation on downstream verifiers to accept claims a prior
  verifier accepted;
- future reliability of a provider, model, endpoint, or fulfiller.

Implementations MUST NOT expose a runtime API that answers
"is-this-trusted" based on chain presence alone.

### 11.3 Chain evaluation

Verifiers MUST evaluate each link and each claim independently. A
link is valid only if:

- the prior certificate's identifier matches the reference;
- the prior certificate's signature verifies under its signing-time
  credential;
- the prior certificate's profile is in the verifier's policy
  allowlist;
- the verifier's policy does not mark the link as stale or revoked.

A chain fails closed for a verifier if any required link fails.

## 12. Verifier Policy Requirements

Verifier policy owns interpretation. A conforming v0.1 verifier
policy MUST:

- declare accepted issuer identities (allowlist, pattern, or
  attestation scheme);
- declare accepted profiles from section 5;
- declare accepted claim kinds from section 7;
- declare accepted evidence kinds from section 8;
- declare freshness windows;
- declare revocation and rotation rules consistent with ADR-0004;
- declare how missing, stale, or ambiguous evidence is handled;
- fail closed on policy mismatch, missing required evidence, or
  ambiguous rotation state;
- be reproducible - another verifier running the same policy against
  the same certificates MUST reach the same decision.

A verifier MUST NOT treat the absence of a policy field as "accept
by default". A verifier MUST NOT imply automatic transitive trust.

Verifier policy MAY be represented by a URI, hash, inline object,
or package version; the exact representation is an open spec item
(section 21). Whichever representation is chosen, the policy MUST be
attributable and replayable.

## 13. Soma Check Interaction

Per ADR-0005 D7 and `SOMA-CHECK-SPEC.md`, Soma Check remains
freshness and payment-avoidance only. Certificates MAY carry Soma
Check evidence; Soma Check itself MUST NOT carry certificate
semantics.

Soma Check MAY contribute:

- `freshness_receipt` claims;
- content hash commitments;
- zero-charge unchanged-result evidence;
- request/response transcript hashes needed by a profile.

Soma Check MUST NOT:

- verify certificate chains;
- evaluate claim acceptability;
- provide a reputation, pricing, routing, staking, or provider-
  selection surface;
- orchestrate shared caches;
- act as a proof of semantic truth.

## 14. Payment Rail Boundary

Per ADR-0005 D8, x402 is the first and default payment adapter for
v0.1 certificate profiles that carry payment evidence. x402 is NOT
a Soma protocol dependency. The certificate core MUST stay
rail-agnostic:

- certificate claims at the core layer MUST use
  `payment_receipt_reference`, not x402-specific protocol semantics;
- rail adapters translate rail-specific challenges, proofs,
  settlements, refunds, and zero-charge outcomes into evidence
  references;
- a conforming non-x402 rail MAY be substituted if it can bind
  equivalent evidence into the certificate profile;
- Soma does NOT define wallet semantics or settlement finality
  beyond what the adapter's evidence can verify.

Implementations MUST NOT elevate x402 to a hard dependency of this
spec.

## 15. Credential Rotation Interaction

Per ADR-0005 D9, this spec references ADR-0004 and
`SOMA-ROTATION-SPEC.md` as authoritative for rotation state. This
spec proposes no rotation semantic changes. A conforming
implementation MUST:

- bind signatures to the issuer's stable `identityId`, not to a
  specific credential key;
- resolve the credential effective at signing time via historical
  lookup rather than assuming the current credential signed old
  material;
- respect the `effective` window before treating a new credential
  as authoritative;
- respect rotation and revocation status as inputs to verification
  outcomes;
- leave rotation lifecycle, rollback, witness, quorum, class,
  policy-floor, snapshot, and historical-lookup semantics entirely
  to ADR-0004 and `SOMA-ROTATION-SPEC.md`.

A conforming implementation MUST NOT introduce rotation mechanisms
through certificate processing. If a certificate profile would
require changing rotation semantics, the profile MUST be rejected
for v0.1 and the gap MUST be escalated to a rotation ADR slice,
not resolved here.

## 16. Privacy and Disclosure

Certificates MAY bind private, encrypted, selectively-disclosed, or
withheld evidence via the disclosure/privacy profile field. When
any evidence is private or withheld:

- the disclosure field MUST declare what was withheld;
- the disclosure field MUST declare which verification checks are
  impossible as a result;
- implementations MUST NOT imply that hidden evidence was verified;
- verifier policy MUST decide whether private-evidence certificates
  are acceptable for the decision at hand.

The exact disclosure-language grammar is an open spec item (section 21).
v0.1 requires only that disclosure be attributable, declarative,
and non-misleading.

## 17. Security and Abuse Considerations

This section enumerates threats the spec MUST address. The
corresponding detection and mitigation requirements are normative;
detailed test-vector coverage is tracked in section 19.

- **False signed claims.** A malicious issuer can sign false
  claims. The spec makes those claims attributable; it does not
  make them true. Verifier policy MUST NOT treat signature validity
  as truth.
- **Evidence laundering.** Attackers may attach impressive but
  irrelevant evidence. Profiles MUST require evidence-to-claim
  binding, not loose bundles. Verifiers MUST reject evidence that
  is not referenced by at least one claim whose verification limit
  depends on it.
- **Chain laundering.** A later certificate may reference a
  legitimate earlier certificate to imply more than the earlier
  certificate supports. Verifiers MUST evaluate each link and each
  claim independently (section 11.3).
- **Replay.** Certificates and receipts MUST carry nonce,
  timestamp, expiry, audience, or transcript binding where replay
  would be harmful. The exact binding is profile-specific.
- **Credential rotation confusion.** Verifiers MUST resolve the
  credential effective at signing time and MUST fail closed on
  ambiguous rotation state (section 10.2, section 15).
- **Revocation gaps.** Profiles MUST state how revocation state is
  checked and what happens when revocation or gossip state is
  stale.
- **Privacy leakage.** Endpoint identifiers, payment references,
  participant identities, transcript hashes, and timing can leak
  sensitive business or user information even when payloads are
  hashed. Implementations MUST make hash and transcript commitment
  choices under the disclosure requirements of section 16.
- **Private evidence overclaiming.** Certificates with private
  evidence pointers MUST disclose what the verifier could not
  inspect (section 16).
- **Sybil issuers.** Free-to-mint identities require verifier
  policy, attestations, allowlists, or other application-level
  controls. The spec MUST NOT be interpreted as granting trust to
  any signature merely because it verifies.
- **Witness non-independence.** A witness may be operated by the
  same party as the issuer. The `witnessed` profile is deferred in
  v0.1 (section 5) specifically because witness-independence is out of
  scope. Conforming verifiers MUST NOT assume independence.
- **Endpoint equivocation.** Providers can show different outputs
  to different verifiers. Transcript hashes, counterparty
  signatures, and logs can make equivocation attributable but
  cannot prevent it. Verifier policy SHOULD declare how equivocation
  is handled when detected.

## 18. Error / Failure Semantics

Conforming verifiers MUST distinguish the following failure modes
and MUST fail closed on each unless policy explicitly allows a
soft-fail disposition:

- `profile-not-allowed` - profile is not in the policy allowlist.
- `profile-deferred` - profile is `deferred` under section 5 and MUST be
  rejected.
- `claim-not-allowed` - claim kind not in the policy allowlist.
- `claim-deferred` - claim kind is `deferred` under section 7.
- `evidence-not-allowed` - evidence kind not in the policy
  allowlist.
- `evidence-deferred` - evidence kind is `deferred` under section 8.
- `signature-invalid` - signature does not verify under the
  resolved signing-time credential.
- `credential-unresolvable` - rotation state cannot resolve a
  signing-time credential.
- `credential-ineffective` - the resolved credential was not
  `effective` at the claimed signing time.
- `credential-revoked` - the signing-time credential is revoked
  under ADR-0004 rules.
- `chain-link-mismatch` - a prior-certificate reference does not
  match the expected identifier.
- `chain-link-unresolvable` - a prior certificate cannot be
  retrieved or verified under policy.
- `freshness-window-expired` - the certificate's declared freshness
  bound has lapsed.
- `evidence-missing` - a REQUIRED evidence reference is absent or
  unresolvable.
- `disclosure-missing` - the disclosure field is missing where section 16
  required it.
- `canonicalisation-divergence` - reserializing the certificate
  produces different bytes from the declared identifier.

The exact wire representation of these errors (codes, names,
structure) is an open spec item (section 21).

## 19. Test Vector Requirements

This section is normative. Gate 4 acceptance ratifies the required
test-vector coverage list in section 19.1 as part of the accepted
contract. Gate 4 does NOT itself ship vector files: canonical
encoding (section 9) and hash algorithm selection are spec-level
open items tracked in section 21, and vector files cannot be
authored deterministically until those selections are pinned.
Section 19.2 classifies vector file delivery as a Gate 5
precondition.

### 19.1 Required vector coverage

A conforming vector set MUST include:

- at least one conforming certificate for each accepted profile
  under section 5;
- at least one rejection vector for each deferred profile under
  section 5;
- at least one rejection vector for each deferred claim kind
  under section 7;
- at least one rejection vector for each deferred evidence kind
  under section 8;
- a signature-verification vector exercising historical credential
  lookup under `SOMA-ROTATION-SPEC.md`;
- a chain-link-mismatch vector;
- a chain-link-unresolvable vector;
- a credential-ineffective vector (new credential effective after
  claimed signing time);
- a credential-revoked vector;
- a freshness-window-expired vector;
- a canonicalisation-divergence vector;
- a redaction/disclosure vector exercising section 16;
- at least one malformed-evidence vector exercising section 17
  evidence laundering.

### 19.2 Vector file delivery

Vector files MUST be reproducible from this spec plus ADR-0004 and
`SOMA-ROTATION-SPEC.md` alone; they MUST NOT depend on package
internals, private helpers, or ClawNet runtime. Vector files MUST
be delivered before the Gate 5 package surface proposal may be
accepted. Gate 5 acceptance is blocked until the vector set
satisfies section 19.1 under the canonical encoding selected for
section 9. Any implementation produced under Gate 5 or Gate 6 MUST
satisfy the delivered vector set.

## 20. Readiness Gates

This spec participates in the ADR-0005 gate sequence.

- **Gate 1 - ADR drafted.** Cleared by the initial draft of
  ADR-0005.
- **Gate 2 - ADR accepted.** Cleared by the ADR-0005 acceptance PR.
- **Gate 3 - Follow-up spec drafted.** Cleared by the initial
  merge of this document as `Status: Draft`.
- **Gate 4 - Follow-up spec accepted.** Cleared by the acceptance
  PR that moves this document to `Status: accepted`. Gate 4 scope
  is the normative contract and boundary rules in sections 1-18,
  plus the required test-vector coverage list in section 19.1.
  Gate 4 ratifies the canonicalization requirements in section 9,
  but does NOT ratify the final canonical byte layout or hash
  algorithm. Gate 4 does NOT ship test vector files (section 19.2),
  does NOT authorise any package, API, runtime, or ClawNet work,
  and does NOT change credential-rotation semantics.
- **Gate 5 - Package surface proposal.** Draftable now that Gate 4
  is cleared. Gate 5 acceptance is blocked until the final
  canonical byte layout and hash algorithm (section 21 open item 1)
  are pinned and the section 19.2 vector files exist and satisfy
  section 19.1. Out of scope for this PR.
- **Gate 6 - Package surface stabilised.** Not draftable without
  Gate 5 acceptance. Out of scope for this PR.
- **Gate 7 - ClawNet first-consumer implementation unlock.**
  Separate ADR in `claw-net/docs/decisions/`. Out of scope for
  Soma. Not draftable without Gate 6.

Nothing in this spec authorises any package, API, runtime, or
ClawNet integration work. Gate 4 acceptance specifically does NOT
unlock implementation; the earliest implementation-relevant
threshold is Gate 5 acceptance, which is itself blocked on the
preconditions enumerated above.

## 21. Open Questions

These items remain open after Gate 4 acceptance. Each is classified
by the earliest gate at which it must be resolved, or marked as a
future ADR candidate or post-v0.1 follow-up. None of these items
reopens ADR-0005 D1-D12, none of them changes credential-rotation
semantics, and none of them authorises implementation. "Gate 5
precondition" items MUST be resolved before the Gate 5 package
surface proposal may be accepted. "Future ADR candidate" items
MUST NOT be resolved inline in this spec if resolution would cross
an ADR boundary; a follow-up ADR slice is the correct path.
"Post-v0.1" items MAY slip to a v0.2 revision without blocking
Gate 5 unless a reviewer explicitly promotes them.

| # | Question | Classification |
|---|---|---|
| 1 | Canonical encoding and hash algorithm for certificate identifiers (section 9). | Gate 5 precondition |
| 2 | Exact wire representation for verifier policy identifiers: URI, hash, inline object, package version, or another mechanism (section 12). | Gate 5 precondition |
| 3 | Disclosure-language grammar for private evidence pointers (section 16). | Gate 5 precondition |
| 4 | Accepted timestamp sources per profile (section 6, section 12). | Gate 5 precondition |
| 5 | Stale-revocation, stale-gossip, and unavailable-rotation-history handling, consistent with ADR-0004 and `SOMA-ROTATION-SPEC.md` (section 10.3, section 12, section 18). | Gate 5 precondition |
| 6 | Counterparty-signature threshold distinguishing `heart-to-heart` from `one-sided` (section 5). | Gate 5 precondition |
| 7 | Which x402 evidence fields the first adapter preserves while the certificate core stays rail-agnostic (section 14). | Gate 5 precondition |
| 8 | Whether receipt references remain fields inside certificates or whether Soma later defines a distinct receipt primitive. | Future ADR candidate |
| 9 | How certificate profiles interact with existing delegation and capability specs without changing their semantics. | Gate 5 precondition |
| 10 | Exact wire representation for the section 18 failure modes. | Gate 5 precondition |
| 11 | Joint resolution of the `fulfillment-receipt-bound` profile and the `fulfillment_receipt` claim. If resolution alters the claim's meaning beyond ADR-0005 D4, a follow-up ADR slice MUST be opened rather than absorbed into this spec. | Future ADR candidate |
| 12 | Whether observation log references (section 8) and private evidence pointers (section 8) can be advanced from `open` to `accepted` given the section 16 disclosure-language outcome. | Post-v0.1 (v0.2) |

Item 1 (canonical encoding and hash algorithm) is a hard Gate 5
precondition because section 19.2 vector files cannot be authored
deterministically until it is resolved.

## 22. Links

- `docs/proposals/soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0005-soma-heart-trust-certificates.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/decisions/ADR-0001-soma-is-the-protocol-home.md`
- `docs/decisions/ADR-0002-source-of-truth-boundaries.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
- `SOMA-ROTATION-SPEC.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `AGENTS.md`
