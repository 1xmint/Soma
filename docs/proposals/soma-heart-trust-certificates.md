Status: proposed

# Soma Heart Trust Certificates and Heart-to-Heart Trust Chains

**Status:** design. No runtime implementation changes.
**First consumer:** ClawNet, as an implementation-neutral consumer of
Soma protocol semantics.
**Covers:** Soma Check boundaries, Soma Heart exchange-envelope
boundaries, rail-agnostic payment integration, conceptual
birth/trust certificate semantics, and heart-to-heart trust-chain
linking.

---

## 0. Scope note

This is a Soma-first protocol proposal. It defines the smallest durable
protocol boundary needed before downstream systems design runtime,
pricing, routing, caching, or marketplace behaviour.

The proposal does not implement code, define a production certificate
schema, change credential-rotation semantics, or ship ClawNet product
behaviour. It records protocol intent tightly enough that a downstream
proposal cannot accidentally redefine Soma Check or Soma Heart.

---

## 1. Problem

Agent commerce creates a trust gap at the exact moment money, authority,
and machine-generated work start moving between autonomous systems.
A buyer or agent needs to know:

- whether a resource has changed before paying or fetching again;
- which identity produced an output or exchange claim;
- which payment or settlement rail was used, without making that rail
  part of the identity protocol;
- whether an exchange produced evidence that can be linked into later
  exchanges;
- what the evidence proves, and what it emphatically does not prove.

Without a protocol boundary, downstream runtimes are tempted to bundle
freshness checks, payment orchestration, receipts, reputation, routing,
cache policy, and trust semantics into one product-specific system. That
would make Soma hard to implement independently and easy for first
consumers to redefine by accident.

Soma should instead define the open protocol for accurate
agent-commerce birth certificates and chainable trust evidence. Products
can compete on implementation quality, routing, witness networks,
operator experience, policy, and commercial packaging while sharing the
same core semantics.

## 2. Why now

Soma already has separate pieces that point toward this shape:

- Soma Check exists as a conditional payment/freshness primitive.
- Soma Heart is the protocol home for identity, delegation,
  verification semantics, and the security model.
- Credential rotation has a ratified ADR and later merged slices,
  including PR #36 and follow-on rotation work.
- ClawNet is the likely first full implementation and will need product
  decisions around pricing, routing, witnessing, and exchange flows.

The protocol boundary should be drawn before ClawNet runtime design
turns product choices into de facto Soma semantics.

## 3. Broad idea

Soma has two related but distinct protocol surfaces:

1. **Soma Check** is a narrow freshness and payment-avoidance
   primitive. It answers whether an endpoint or resource appears to
   have a fresh hash/new data, so a buyer or agent can avoid an
   unnecessary payment or fetch.
2. **Soma Heart** is a modular, rail-agnostic verified exchange
   envelope. It binds participating identities, exchange context,
   payment-rail evidence, output hashes, signatures, and optional
   witnesses into certificate material that can be verified later.

Soma Birth Certificates / Trust Certificates are the chainable records
produced by verified exchanges. A certificate is not "truth" by itself;
it is signed, hash-linked evidence about who claimed what, when, under
which protocol modules and payment/witness conditions.

Heart-to-heart chaining occurs when both parties run compatible Soma
Heart modules and produce or link compatible certificates. Each new
certificate can reference prior certificate identifiers or hashes,
forming an auditable trail of exchanges without requiring a central
Soma runtime.

## 4. What 10/10 looks like

- Soma Check remains independently usable without installing or running
  the full Soma Heart.
- Soma Heart can use x402 as the first/default payment adapter without
  making x402 a protocol dependency.
- A certificate produced by one conforming implementation can be
  verified by another conforming implementation.
- ClawNet can act as a high-quality implementation, co-signer, witness,
  router, and operator layer where applicable, while Soma remains open
  and implementation-neutral.
- Future ClawNet proposals can cite this document for boundaries rather
  than redefining Soma Check, Soma Heart, or certificate semantics.

## 5. Fitness check

- protocol vision fit: high. This keeps Soma as the protocol home for
  identity, verification, delegation-adjacent exchange evidence, and
  security semantics.
- real implementer/operator need: high. Downstream systems need a clear
  split between freshness/payment avoidance, verified exchange
  envelopes, and product runtime behaviour.
- security exposure: high. Certificates can influence payment,
  provider selection, delegation decisions, and audit outcomes; limits
  must be explicit.
- evidence this is needed now: ClawNet is the first likely consumer,
  while Soma Check and credential rotation already exist as protocol
  surfaces.
- keep / reshape / pause / remove: reshape into a proposal now; do not
  implement until ADR/spec decisions are accepted.

## 6. Evidence ledger

| Field | Value |
|---|---|
| current status | proposed protocol boundary; no runtime implementation in this slice |
| upstream dependencies | Soma Check spec, Soma Heart package/reference docs, Soma security model, credential-rotation ADR/spec state |
| downstream dependencies | ClawNet runtime, pricing, routing, witnessing, and first-consumer design |
| missing evidence | production certificate schema, adapter interface, verifier test vectors, witness policy, privacy review |
| blocks current work | yes, for downstream ClawNet designs that would otherwise define trust-chain semantics locally |
| next gate | ADR deciding whether these module boundaries become durable Soma protocol rules |
| terminal condition | accepted ADR and, if needed, a normative Soma Heart certificate/trust-chain spec |

## 7. Required decisions

### D1. Soma Check is narrow

Soma Check is a freshness and payment-avoidance primitive. It checks
whether an endpoint or resource has a fresh hash/new data so a buyer or
agent can avoid unnecessary payment or fetch.

Soma Check is not a general trust engine. It does not decide reputation,
route requests, share cached bodies, arbitrate receipts, operate a
marketplace, or prove semantic truth.

### D2. Soma Check is independently usable

Soma Check must remain usable without installing, running, or hosting
the full Soma Heart. A lightweight consumer or provider should be able
to participate in the freshness/payment-avoidance protocol without
adopting heart-to-heart exchange certificates.

Soma Heart may reuse Soma Check hashes as certificate inputs. That reuse
does not collapse the two modules.

### D3. Soma Heart is a verified exchange envelope

Soma Heart is a modular envelope for verified exchanges. It coordinates
identity, signatures, content hashes, payment-rail evidence,
freshness/check results, optional witnesses, and certificate output.

Soma Heart should be rail-agnostic: it can bind to payment evidence
from a rail, but the rail is not the identity or trust protocol.

### D4. x402 is the first/default adapter, not a dependency

x402 should be the first/default payment rail adapter for Soma Heart
because it is a practical fit for agent-commerce HTTP payments.

Soma Heart must not require x402 at the protocol layer. A conforming
implementation can use another payment rail if it can bind equivalent
payment evidence into the exchange envelope.

### D5. Certificates are chainable exchange records

A Soma Birth Certificate / Trust Certificate is the chainable record
produced by a verified exchange. It records evidence about the exchange
and can link to prior certificates.

The name "birth certificate" is appropriate when the record introduces
or anchors a newly produced output, agent instance, delegation context,
resource version, or commercial exchange artifact. The name "trust
certificate" is appropriate when the same record is used as reusable
evidence in later verification decisions. The protocol should avoid
creating two incompatible primitives unless a later ADR finds a real
semantic difference.

### D6. Heart-to-heart chains require compatible modules

Heart-to-heart chaining occurs when both parties run compatible Soma
Heart modules and produce or link compatible certificates. Compatibility
does not require a shared operator, marketplace, payment rail, cache,
or product runtime.

If only one party runs Soma Heart, that party may still produce a local
certificate, but it is not a full heart-to-heart certificate unless the
counterparty evidence is compatible and verifiable.

### D7. Soma remains implementation-neutral

ClawNet may be the first and best implementation. It may act as a
co-signer, witness, router, verifier, hosted operator, or policy layer
where applicable.

Those roles are ClawNet runtime/product behaviour, not Soma protocol
requirements. Soma must remain open enough for other conforming
implementations to produce and verify compatible certificates.

## 8. Module boundaries

### Soma Check

Soma Check owns:

- request/response freshness negotiation;
- hash comparison for payment avoidance;
- zero-charge unchanged responses where the provider's current hash
  matches the caller's known hash;
- the rule that matching freshness checks avoid unnecessary payment or
  fetch.

Soma Check does not own:

- semantic cache reuse;
- shared cache infrastructure;
- provider routing;
- reputation;
- receipts;
- certificate-chain verification;
- marketplace selection;
- ClawNet pricing or orchestration.

### Soma Heart core

Soma Heart core owns:

- participant identity binding;
- exchange-envelope construction;
- signature and hash-chain verification semantics;
- certificate production and verification boundaries;
- module compatibility signalling;
- links to credential rotation, delegation, revocation, and security
  model rules where those existing Soma semantics apply.

Soma Heart core does not own:

- a specific payment rail;
- a specific hosting/runtime operator;
- a shared product cache;
- a provider marketplace;
- ClawNet orchestration.

### x402 adapter

The x402 adapter owns:

- translating x402 payment challenges, proofs, and settlement evidence
  into Soma Heart exchange-envelope inputs;
- preserving enough rail evidence for later verification;
- failing closed when rail evidence is absent, malformed, expired, or
  inconsistent with the exchange envelope.

The x402 adapter does not own:

- Soma identity semantics;
- certificate-chain semantics;
- non-x402 rail semantics;
- global trust or reputation.

### Certificate / receipt primitives

Certificate primitives own:

- canonical certificate identifiers or hashes;
- signed participant claims;
- content/output hashes;
- payment evidence references;
- witness/co-signer references when present;
- links to prior certificates.

Receipts, if retained as a separate term, should be treated as payment
or delivery evidence inside a certificate, not as a parallel trust
system. A later ADR should decide whether Soma needs a distinct receipt
primitive or whether receipts are always certificate fields.

## 9. Tentative certificate fields

This is conceptual, not a production schema. A future spec must define
canonical encoding, required/optional fields, versioning, and test
vectors before implementation.

Tentative fields:

- `certificateVersion`: certificate format/protocol version.
- `certificateType`: birth, trust, exchange, or another later-ratified
  profile.
- `certificateId`: canonical hash or identifier of the certificate.
- `issuedAt` and optional freshness bounds.
- `issuer`: Soma identity that produced the certificate.
- `subject`: output, resource, counterparty, agent instance,
  delegation, exchange, or other subject being certified.
- `participants`: buyer, seller/provider, agent, witness, co-signer, or
  verifier identities as applicable.
- `exchangeContext`: endpoint/resource, method, intent, purpose,
  request hash, response hash, or task hash.
- `somaCheck`: optional freshness result and data hash when Soma Check
  participated.
- `paymentRail`: rail identifier such as x402, plus adapter version.
- `paymentEvidence`: reference or digest of payment proof, challenge,
  settlement, or zero-charge unchanged result.
- `outputHash` / `dataHash`: content-addressed output or resource hash.
- `moduleSet`: Soma Heart modules and versions used for the exchange.
- `credentialState`: identity/credential reference sufficient for
  verification under the current rotation semantics.
- `previousCertificates`: prior certificate IDs or hashes being linked.
- `witnesses`: optional co-signer/witness identities and signatures.
- `signatures`: issuer, participant, witness, or threshold signatures
  as required by the profile.
- `privacyProfile`: disclosure mode, redaction commitments, or selective
  disclosure references if applicable.

## 10. Trust-chain model

A trust chain is a graph of certificates linked by certificate IDs,
hashes, signatures, and participant identities. The simplest chain is
linear: certificate B references certificate A as prior evidence. More
realistic chains may fork or merge when an agent consumes multiple
inputs and produces one output.

A linked certificate can prove:

- a signer or witness made a claim at a point in the chain;
- the certificate content has not changed since its hash/signature was
  produced;
- a later exchange intentionally referenced earlier evidence;
- payment/freshness/witness material was bound into the exchange
  envelope if the relevant fields and signatures verify;
- the chain is internally consistent under the accepted Soma
  verification rules.

A linked certificate does not prove:

- the underlying data was true;
- the provider was honest outside the signed exchange;
- the buyer's local cache was untampered;
- the model reasoned correctly;
- the product was fairly priced;
- the payment rail settled if only an unsigned or unverifiable reference
  is present;
- the absence of undisclosed side agreements, off-chain state, or
  omitted context;
- global reputation or future reliability.

Heart-to-heart chaining is strongest when both parties sign compatible
views of the same exchange and any witness/co-signer evidence is
independently verifiable. A one-sided certificate is still useful, but
its assurance is narrower and must be labelled accordingly.

## 11. Assurance limits

Signatures, hash chains, payment proofs, and receipts are evidence, not
magic truth. They make claims attributable and tamper-evident; they do
not make claims correct.

The protocol should explicitly preserve these limits:

- A signed false statement is still false; Soma makes the lie
  attributable.
- A hash proves content equality, not quality, accuracy, or freshness
  unless the freshness rule is separately satisfied.
- A payment receipt proves only what the rail/verifier can actually
  verify.
- A witness proves that a witness signed a statement under its own trust
  assumptions; it does not make the witness neutral or omniscient.
- A complete-looking chain can still omit relevant external context.
- Certificate verification should fail closed on malformed,
  incompatible, expired, revoked, or unverifiable evidence.

## 12. Clone-resistance boundary

Soma's openness intentionally enables independent implementations. A
competitor should be able to implement the protocol, produce compatible
certificates, and verify heart-to-heart chains without running ClawNet.

That openness does not erase ClawNet's competitive surface. ClawNet can
still compete on:

- hosted reliability and latency;
- operator/user experience;
- witness and co-signer availability;
- routing quality;
- provider relationships;
- policy defaults;
- monitoring and audit tools;
- fraud response;
- ecosystem trust;
- commercial packaging.

Soma should not use protocol opacity as clone resistance. ClawNet should
win by being the best implementation and network, not by owning private
definitions of Soma trust semantics.

## 13. Downstream implications for ClawNet

ClawNet can design runtime and pricing around these protocol boundaries,
but should not redefine them.

Likely ClawNet responsibilities:

- offer the first production-grade Soma Heart implementation;
- operate witnesses, co-signers, routers, or hosted verification where
  useful;
- expose product policy around when certificates are required, optional,
  witnessed, or rejected;
- bind x402 evidence through the Soma Heart x402 adapter;
- use Soma Check for payment avoidance without treating it as a shared
  cache or reputation engine;
- document ClawNet-specific trust tiers as product policy layered on
  Soma certificates, not as Soma protocol truth.

This proposal intentionally does not define a ClawNet pricing table,
cache implementation, orchestration implementation, or provider
marketplace.

## 14. Non-goals

- Tokenomics.
- A full pricing model.
- A ClawNet cache implementation.
- ClawNet orchestration implementation.
- Pulse work.
- Credential-rotation semantic changes.
- Expanding Soma Check into a trust engine, shared cache, semantic
  cache, router, receipt system, reputation system, provider
  marketplace, enterprise runtime, or ClawNet product.
- Defining a production certificate schema.
- Defining a universal reputation score.
- Choosing all future payment rails.
- Replacing x402, AP2, ACP, L402, HTTP caching, or verifiable
  credential standards.
- Merging, deploying, publishing, or changing package exports.

## 15. Protocol surface

- spec change: likely yes, after ADR acceptance; a future
  `SOMA-HEART-CERTIFICATE-SPEC.md` or equivalent may be warranted.
- package API change: not in this proposal; future implementation may
  require one.
- security model change: yes if accepted, because this defines what
  certificates and heart-to-heart chains can and cannot assure.
- downstream integration impact: yes; ClawNet should treat these
  boundaries as upstream Soma constraints.

## 16. Security / reliability requirements

Before implementation, a follow-up ADR/spec should require:

- canonical certificate encoding and hash computation;
- explicit required vs optional fields by certificate profile;
- verifier behaviour for missing, expired, revoked, malformed, or
  incompatible evidence;
- adapter conformance rules for x402 and any later payment rail;
- privacy review for exchange context and participant fields;
- test vectors for certificate hashes, signatures, and chain links;
- clear labels for one-sided, two-sided, witnessed, and co-signed
  certificates;
- compatibility with credential-rotation verification, without changing
  rotation semantics silently.

## 17. Delivery shape

Recommended sequence:

1. Proposal review of this document.
2. ADR deciding whether the module boundaries and certificate/trust-chain
   semantics are accepted.
3. Normative spec for Soma Heart certificates and trust chains if the
   ADR accepts the direction.
4. Small package/API design proposal only after the spec boundary is
   clear.
5. ClawNet first-consumer proposal that cites the accepted Soma ADR/spec
   and limits itself to runtime/product choices.

## 18. ADR needed?

Yes. This proposal makes protocol-boundary decisions around Soma Check,
Soma Heart, x402 adapter status, certificate semantics, and
implementation neutrality. Those decisions should not become canonical
only by appearing in a proposal.

The ADR should answer:

- whether Soma Check's narrow scope is accepted as a non-expansion rule;
- whether Soma Heart is formally the rail-agnostic verified exchange
  envelope;
- whether x402 is the default first adapter rather than a dependency;
- whether birth certificates and trust certificates are profiles of one
  certificate primitive or separate primitives;
- what assurance labels are required for one-sided vs heart-to-heart
  certificates;
- what spec file should hold the normative certificate semantics.

## 19. Open questions

1. Should "Birth Certificate" and "Trust Certificate" be one primitive
   with profiles, or two normative primitives?
2. What is the minimum certificate profile required for a record to be
   called heart-to-heart rather than one-sided?
3. What certificate fields are mandatory for v0.1, and which belong in
   optional profiles?
4. Should the first normative spec be named
   `SOMA-HEART-CERTIFICATE-SPEC.md`, `SOMA-TRUST-CHAIN-SPEC.md`, or
   something broader?
5. What privacy profile is required before exchange certificates are safe
   for production use?
6. Which x402 evidence fields can be verified without requiring a
   specific x402 implementation?
7. How should certificate verification surface credential-rotation
   history without changing ADR-0004 or `SOMA-ROTATION-SPEC.md`?
8. What, if anything, should ClawNet witnesses be allowed to claim beyond
   "I observed/signed this exchange envelope"?

## 20. Links

- `AGENTS.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-ROTATION-SPEC.md`
- `docs/decisions/ADR-0004-credential-rotation-semantics.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/security-model.md`
- `docs/proposals/PROPOSAL-TEMPLATE.md`
