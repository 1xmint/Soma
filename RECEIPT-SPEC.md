# Counter-signed receipts — v1 (draft)

Status: **draft, not ratified.** This document is the reasoning; `js/src/receipt.mjs`
is the mechanism.

This is the load-bearing property of Soma: *an agent cannot fake trust without
the evidence being obvious.* Everything else in the system — Vera's corpus, the
marketplace, any future token — assumes it. Until this exists, Soma is an
identity and consent client, not a trust system.

## What is broken today

Every artifact Soma produces is signed by its own subject. `evidence.mjs` says
so plainly:

```
assurance:   "self_signed_attribution_only"
truth_claim: "signature_proves_attribution_and_integrity_not_truth"
```

That is accurate and it is worth very little. "I did excellent work" signed by
me proves only that my key emitted that string. `receipt_ids` is deliberately
nailed shut (`EVIDENCE_RECEIPTS_UNSUPPORTED`) rather than pretending otherwise,
which was the right call.

## What a receipt buys, precisely

A receipt is a second party's signed statement *about* a subject's work.

It does **not** make the claim true. It changes who is exposed if it is false:
the attester is now named, and their own standing is on the line. That is the
entire mechanism. Attestation transfers stake, it does not manufacture truth.

A receipt therefore proves exactly one thing: **this specific identity said this
specific thing about this specific work at this specific time.** Everything
useful is built on top of that by the evaluator, not by the protocol.

## The Sybil problem, stated honestly

Identities are keypairs. Keypairs are free. This has a consequence most
reputation systems refuse to state:

> **No global reputation score can be Sybil-resistant in an open system with
> free identities.**

Any global aggregate — a score, a tier, a rank, a count of attestations — can be
inflated by manufacturing attesters. A parent spawning 500 children is the
*cheap* version and is detectable, because lineage is cryptographically
explicit. But an attacker who simply generates 500 unrelated root identities
produces a graph indistinguishable from 500 genuine strangers. There is no
algorithm that separates them, because there is no information that separates
them.

So Soma must not compute a global reputation score. Not "not yet" — not ever,
under this identity model.

### What replaces it

Reputation is **relative to the evaluator**.

The question is never "what is X's reputation?" It is "how much should *I* trust
X, given attesters *I* already trust?" Manufactured attesters are not in the
evaluator's graph, so they contribute nothing. Sybil resistance comes from the
evaluator's own trust roots, not from detection.

An evaluator with no trust roots gets `insufficient_basis`. **Not zero, and not
a default score** — the honest answer to "should I trust this stranger, knowing
nothing and nobody?" is that the system cannot tell you.

## Lineage: label, do not reject

An earlier draft of this design said receipts from within one lineage "count for
nothing." That is wrong, and the mistake is worth recording.

A parent attesting to its child's work is *genuinely informative* — the parent
has the most direct knowledge of what the child did. Discarding it destroys real
information. What it is not is **independent**. The failure mode is a lineage
receipt being counted as though it came from a stranger.

So independence is computed and labelled, never asserted by the submitter, and
the protocol refuses to collapse the labels into a number.

| Label | Meaning |
|---|---|
| `self` | attester equals subject. **Rejected** — this is not a receipt |
| `shared_lineage` | attester and subject share an ancestor, or one is an ancestor of the other. Informative, not independent |
| `no_known_common_ancestor` | no shared ancestor is visible |
| `unknown` | lineage was unavailable. Not the same as unrelated |

That third label is deliberately not called "independent." Roots are free, so
the absence of a known common ancestor is not evidence of independence — only
the absence of evidence of relation. Naming it "independent" would launder an
unknown into a guarantee, which is the exact failure this whole document exists
to prevent.

## "Receipt" means two different things in this protocol

The Rust implementation has a `SpendReceipt`: budget accounting, and **signed by
the subject** — its own comment says so. A work receipt is the opposite: signed
by someone other than the subject, and worthless if it is not.

Two things named "receipt" in one protocol, one self-signed and one
counter-signed, is a collision someone will eventually resolve the wrong way and
conclude that receipts prove nothing. They are unrelated mechanisms.

## Receipt structure

Signed bytes follow the convention already used across Soma's twelve signing
contexts:

```
signed_bytes = "somavera:soma-work-receipt:v1\n" || canonical_json(receipt_core)
```

`receipt_core` carries exactly:

| Field | Rule |
|---|---|
| `attester_did` | Who is attesting. Must differ from `subject_did` |
| `basis` | How the attester knows: `party`, `witnessed`, or `verified` |
| `capability` | The capability exercised |
| `claim_hash` | Hash of the claim being attested |
| `domain` | The domain of work |
| `fault` | Who a failure is attributable to: `none`, `subject`, `delegate`, `upstream_tool`, `environment`, `unattributed`. Must be `none` when the outcome succeeded, and must not be when it did not |
| `issued_at` | RFC 3339 UTC, second precision |
| `observed_at` | When the attester observed the work. Not after `issued_at` |
| `outcome` | `succeeded`, `failed`, or `disputed` |
| `schema_version` | `soma.work-receipt.provisional-v1` |
| `subject_did` | Whose work is attested |
| `task_id` | The task |

`receipt_id` is **derived** from the canonical bytes, never asserted — matching
how Soma derives every other identifier. A submitter cannot choose it, so it
cannot be used as a covert channel or collided deliberately.

`outcome` includes `failed` and `disputed` on purpose. A system that can only
record success produces reputation that is meaningless by construction, because
the absence of a receipt is indistinguishable between "never worked" and
"worked badly."

`fault` is a separate question from `outcome`, and conflating them destroys the
evidence where it is most needed. Agents are composed: a subject calls models,
tools and delegates it does not control. Recording every upstream failure as
subject failure means an agent that correctly reported a broken API is
indistinguishable from one that broke it. `unattributed` exists so that "I do
not know whose fault this was" is an explicit statement rather than a silence,
and fault is always the attester's judgement — worth exactly what that attester
is worth, and never an established fact.

## Basis — how the attester knows

Three claims that look identical on the wire carry entirely different weight:

- **`party`** — the attester took part. Subjective and interested; it may be
  lying and nobody can check.
- **`witnessed`** — the attester saw it without taking part. Less interested,
  still not reproducible.
- **`verified`** — the attester independently checked the claim against
  something else, and anyone can redo that check.

**Only `verified` is falsifiable.** A verified claim asserts something reality
can contradict. The other two cannot be wrong in any checkable sense. An
evaluator that cannot tell them apart is treating an opinion as a measurement,
and that is the difference between "the data felt right" and "the data matches
the source I queried".

This is also what lets verification substitute for trust. Where a claim can be
independently checked, no reputation is required at all — which matters because
in a network of millions, almost nobody has a trust path to almost anybody.
Shrinking the set of interactions that need trust is more valuable than trying
to make trust reach further.

A host that verifies is **not privileged by verifying**. It is an ordinary
identity whose attestations happen to be verificational, and whose standing is
at stake like anyone's. Nothing about being a host makes its verdict
authoritative, and an evaluator that does not trust it gets nothing from it.

### Method disclosure is deliberately not specified yet

When a verification method turns out to be defeatable, every attestation that
used it should be re-weighted at once — not just the ones from whoever was
caught. That requires the method to be named in the receipt.

It is left out of v1 because a bad method vocabulary frozen into the record is
worse than none, and naming methods well needs more thought than this revision
had. The gap is recorded so it is not mistaken for an oversight.

## The attester's key is never a parameter

Soma DIDs are `did:key:z…`, where the fingerprint is the multibase-encoded
public key. **The identifier is the key commitment**, so a receipt verifies
offline with no network, no registry and no key distribution.

The verifier therefore derives the attester's key from `attester_did` and
refuses to accept one from the caller. An earlier revision took the key as a
parameter, which meant a receipt naming Alice would verify against Mallory's key
if the caller supplied it — attribution, the only thing a receipt establishes,
depended on the caller getting that right.

An attester DID that does not commit to a key is refused outright rather than
assumed resolvable later. Deferring that check would mean accepting a receipt
whose attribution cannot be checked at all.

## Verification obligations

A conforming verifier:

1. Recomputes canonical bytes from the parsed receipt. Never verifies over
   received bytes.
2. Rejects `attester_did === subject_did` **before** checking the signature. A
   self-receipt is malformed, not merely unauthorized, and saying so costs
   nothing and leaks nothing.
3. Verifies Ed25519 against the key committed to by `attester_did`.
4. Recomputes `receipt_id` and rejects a mismatch.
5. Rejects `observed_at` after `issued_at`.
6. Computes the independence label from lineage. Never reads it from input.

## What this deliberately does not do

- **No score.** No tier, rank, percentage, or star rating anywhere in the protocol.
- **No aggregation.** Combining receipts is evaluator policy, above the protocol.
- **No global registry.** There is no canonical list of receipts to consult, and
  therefore nothing to capture.
- **No truth claim.** A receipt records that someone said something. Whether it
  is true is not a cryptographic question.

## Open questions

- Should receipts be revocable by their attester? An attester who learns they
  were deceived has no way to withdraw. Revocation needs a distribution
  mechanism, which needs the network layer that does not exist yet.
- Should a subject be able to decline a receipt about itself? A malicious
  attester can currently attach a `failed` receipt to any DID. Since nothing
  aggregates, this is inert today, but it will not stay inert.
- Cross-lineage collusion between unrelated roots is indistinguishable from
  genuine mutual attestation. This is not solvable at the protocol layer and
  should not be claimed as solved.
