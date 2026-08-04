# Somavera — genesis and revival

Version 1 · 2026-08-03

**This document is both the birth certificate and the recovery procedure.**
Nothing privileged happens at the beginning that cannot happen again. If every
machine running this network is destroyed, someone holding this page rebuilds it.

It references no file, repository, or URL, because a revival assumes none exist.
It names no programming language, because languages die. It describes bytes and
behaviour, which do not.

**A document cannot authenticate itself.** What this one can do is be internally
consistent: the vectors in §7 check each other and check any implementation
built from §3–§6. A tampered copy fails its own vectors.

---

## 1. What this is

Soma is how an agent proves what it did. Vera is how that work becomes shared
intelligence. Together: infrastructure for a world where most work is done by
agents and nobody can tell which ones to trust.

The problem is not capability. Models get better without help. The problem is
that when an agent hires an agent you did not choose, *"should I allow this?"*
stops being answerable by looking.

---

## 2. Principles — attack these first

If any is wrong, the design is wrong. Stated plainly so disagreement is easy.

**P1 · A signature proves attribution, never truth.**
"I did excellent work", signed by me, proves only that my key emitted that
string.

**P2 · Trust must be unforgeable by its subject.**
If an agent can manufacture its own reputation, reputation is decoration. This
is the load-bearing property.

**P3 · No global reputation score can be Sybil-resistant when identities are free.**
Identities are keypairs; keypairs cost nothing. Any global aggregate — score,
tier, rank, count — is inflatable by manufacturing attesters. Therefore this
protocol computes **no score, ever**, under this identity model.

**P4 · Reputation is relative to the evaluator.**
Never "what is X's reputation" but "how much should *I* trust X, given attesters
*I* already trust". Manufactured attesters are absent from that graph.

**P5 · The identifier is the key.**
No registry, network, or authority distributes identity, so none can withhold it.

**P6 · Only what cannot work elsewhere may be frozen.**
A deployed protocol ossifies. Everything above the frozen layer must stay
replaceable without permission, because it will be wrong repeatedly.

**P7 · Absence of evidence is not evidence.**
Where the system does not know, it says so, rather than assuming the favourable
answer.

---

## 3. What may never change

**The test: if two implementations disagree about this, does everything break?**

Canonical bytes — disagree and every signature fails: **frozen**.
Reputation weighting — disagree and you simply trust different people while
every signature still verifies: **not frozen**.

That asymmetry is what lets jurisdictions who will never agree on values still
verify each other's records exactly. Evidence crosses boundaries; authority does
not.

Frozen: §4 (encoding), §5 (identity), §6 (canonical bytes, domains, signing),
and the record shapes in §6.4.

Not frozen, and requiring nobody's consent: trust roots, reputation arithmetic,
independence weighting, rate limits, admission policy, which attestors are
honoured, Sybil defences, governance, markets, any token.

**No tunable number may be frozen.** Every constant is a future argument. A
window, a threshold, a weight — each is someone's policy, and freezing it means
the network can never adapt to a condition its authors did not foresee.

---

## 4. Encoding — base58btc

Alphabet, in order, exactly:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Absent: `0`, `O`, `I`, `l`. Other base58 alphabets exist (Ripple, Flickr) and
ordering them differently produces identifiers that are wrong while looking
plausible.

**Encode** a byte string: interpret as a big-endian unsigned integer; while
greater than zero, take modulo 58, prepend the alphabet character at that index,
divide by 58; then prepend `1` for each leading zero byte of the input. Empty
result is `1`.

**Decode** reverses it: per character, multiply the accumulator by 58 and add the
alphabet index; each leading `1` becomes a leading zero byte.

---

## 5. Identity

An identity is an Ed25519 public key. Given a 32-byte public key `K`:

1. Prepend the Ed25519 multicodec prefix `0xED 0x01` → 34 bytes
2. Base58btc-encode (§4)
3. Prepend multibase character `z` → the **fingerprint**
4. Identifier is `did:key:` + fingerprint

Recovery: strip `did:key:`, require leading `z`, decode, require exactly 34 bytes
beginning `0xED 0x01`, take the trailing 32.

An identifier that yields no key **MUST** be rejected, not deferred. Accepting
one means accepting a record whose attribution can never be checked.

The verifying key **MUST NOT** be accepted as a parameter alongside the
identifier. It is derived from it. An implementation taking a key as an argument
permits a record naming one party to verify under another party's key, which
destroys the only thing a signature establishes.

---

## 6. Canonical bytes and signing

### 6.1 Canonical JSON

RFC 8785 (JCS) with added strictness. **Ambiguous input is rejected, never
repaired** — a canonicalizer that silently normalizes converts a detectable
encoding fault into an undetectable signature mismatch.

- `null` → `null`; booleans → `true` / `false`
- **strings**: escape only `"`, `\`, and control characters below `0x20`; use
  `\b \t \n \f \r` where those exist, else `\u00xx` with **lowercase** hex; do
  **not** escape `/`; emit non-ASCII literally
- **numbers**: shortest round-tripping form. Integral values carry no fraction —
  `1.0` is `1`
- **arrays**: `[` elements joined by `,` `]`. Order preserved, never sorted
- **objects**: `{` members joined by `,` `}`, each `key:value`, keys sorted
  ascending by **UTF-16 code unit** — not locale order. `"ä"` sorts after `"z"`;
  uppercase before lowercase
- no whitespace anywhere

**Rejected:** lone surrogates; negative zero; non-finite numbers; integers
outside ±(2⁵³−1); undefined members; unknown fields in a defined record.

Because every integral double at or above 2⁵³ is rejected, values like `1e21`
never reach number formatting — the large-magnitude exponential branch of JCS is
unreachable here, one fewer thing to get wrong.

### 6.2 Signing

```
signed_bytes = DOMAIN || canonical_json(record)
```

`||` is byte concatenation; `DOMAIN` is a UTF-8 string ending in a newline.
Algorithm: Ed25519 over `signed_bytes`. Domains, each including its newline:

```
somavera:soma-work-receipt:v1
somavera:soma-work-receipt-signature:v1
somavera:vera-observation-batch:v1
```

Every distinct purpose has a distinct domain, so a signature made for one cannot
verify for another.

Verification is **always over recomputed bytes**, canonicalized from the parsed
record, never over the bytes as received. A sender emitting non-canonical JSON is
not rejected for that alone: the canonical form is the identity of the content.

### 6.3 Suite agility without negotiation

Each signature carries a label naming the suite that produced it; each verifier
decides which labels it accepts. There is no handshake, because records are
verified asynchronously by strangers years later — and therefore no downgrade
attack, because there is nothing to negotiate. New suites are added; **old labels
are never removed**, or every record signed under them becomes unverifiable.

### 6.4 Records

**Work receipt** — a second party's statement about a subject's work. Fields:
`attester_did`, `basis`, `capability`, `claim_hash`, `domain`, `fault`,
`issued_at`, `observed_at`, `outcome`, `schema_version`, `subject_did`,
`task_id`, plus a derived `receipt_id` and a `signature` carrying `{suite,
value}`. The identifier is derived from the canonical bytes, never asserted, so a
submitter cannot choose it.

`basis` records **how the attester knows**: `party` (took part — subjective and
interested), `witnessed` (saw it without taking part), or `verified` (checked
independently, and anyone can redo the check). Only `verified` is falsifiable;
the others cannot be wrong in any checkable sense. A verifier is not privileged
by verifying — it is an ordinary identity whose standing is at stake like
anyone's.

`fault` records **who a failure is attributable to**: `none`, `subject`,
`delegate`, `upstream_tool`, `environment`, `unattributed`. Agents are composed,
calling models and tools they do not control, so conflating "the work failed"
with "the subject failed" makes an agent that correctly reported a broken
upstream indistinguishable from one that broke it. A success MUST carry `none`;
a failure MUST NOT, using `unattributed` where the attester genuinely cannot say
— an explicit statement of ignorance rather than a silence.

Four bindings, each closing a distinct forgery:

| Binding | Without it |
|---|---|
| `attester_did` ≠ `subject_did` | you vouch for yourself |
| subject matches the work | you cite receipts about other people's work |
| task matches | **earn one receipt on trivial work, cite it on everything** |
| claim matches | the same, at claim granularity |

`outcome` is `succeeded`, `failed`, or `disputed`. A system recording only
success produces reputation meaningless by construction, because a missing
receipt cannot be distinguished from work that went badly.

**Evidence** — an agent's own hash-chained record of what it did. Self-signed,
and labelled as such. An event citing verified receipts is labelled differently
from one that does not, and the label **MUST NOT** claim more than was
established — in particular it must not imply independence unless relatedness was
actually computed.

**Relatedness** is computed from lineage, never read from input: `self`,
`shared_lineage`, `no_known_common_ancestor`, `unknown`. The third is
deliberately not called *independent*: identities are free, so absence of a known
common ancestor is absence of evidence, not evidence of independence.

**Unknown fields are rejected, not ignored.** Deliberately contrary to Postel's
law: tolerating unknown input makes senders depend on that tolerance, and the
real protocol silently becomes whatever the most permissive implementation
accepts — at which point it can never change. Strictness keeps a protocol alive.

---

## 7. Test vectors

Implement §4–§6, then run these. Matching byte for byte is conformance; anything
else is not, however reasonable it looks. Prose can be misread; bytes cannot.

### 7.1 Identity

```
public key (hex)  46b14b7854fede602d8b07841989db17bd7e710227163d0bdc4f5de6e83817e5
prefixed (hex)    ed0146b14b7854fede602d8b07841989db17bd7e710227163d0bdc4f5de6e83817e5
fingerprint       z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN
identifier        did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN
```

Round-trip both directions.

### 7.2 Signature

```
message (UTF-8)   interop-vector
signature (b64)   +MrzNvc/FGowK8bjPBa9a3pX/qhQ4Xx7BlSjOtBkvSyldaHJNx/CiUvD51C0fliZdyYfDXwmETA5d73Mt2FfBw==
```

Verify against the key in 7.1. Then flip one byte of the message and confirm it
fails.

### 7.3 Canonicalization — accepted

```
{"b":1,"a":2,"C":3,"ä":4,"Z":5}   ->  {"C":3,"Z":5,"a":2,"b":1,"ä":4}
{"z":{"b":1,"a":2},"a":{"d":3}}   ->  {"a":{"d":3},"z":{"a":2,"b":1}}
{"x":[3,1,2]}                     ->  {"x":[3,1,2]}
{"n":1.0}                         ->  {"n":1}
{"n":1e-7}                        ->  {"n":1e-7}
{"n":0.1}                         ->  {"n":0.1}
{"n":9007199254740991}            ->  {"n":9007199254740991}
{"s":"a/b"}                       ->  {"s":"a/b"}
{"s":<U+0008 U+0009 U+000A U+000C U+000D>}  ->  {"s":"\b\t\n\f\r"}
{"s":<U+0001 U+001F>}             ->  {"s":""}
{"s":"é日本語"}                    ->  {"s":"é日本語"}
{"o":{},"a":[]}                   ->  {"a":[],"o":{}}
{"a":null,"b":1}                  ->  {"a":null,"b":1}
```

Each fails a plausible-but-wrong implementation: locale key sorting, a trailing
`.0`, an escaped solidus, `` instead of `\b`, uppercase hex, full double
precision, dropped nulls.

### 7.5 Work receipt

The identifier is derived, so this vector needs no private key and any
implementation can check itself against it.

Core:

```json
{
  "attester_did": "did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN",
  "basis": "verified",
  "capability": "code-review",
  "claim_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "domain": "software",
  "fault": "upstream_tool",
  "issued_at": "2026-08-04T12:00:00Z",
  "observed_at": "2026-08-04T11:00:00Z",
  "outcome": "failed",
  "schema_version": "soma.work-receipt.provisional-v1",
  "subject_did": "did:key:z6MktcCgWP6EoLbhR1i4uhwJbs4pS3js5bdJaoxAcyPbGQ8o",
  "task_id": "task-001"
}
```

Canonical form — one line, no whitespace, keys in UTF-16 order:

```
{"attester_did":"did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN","basis":"verified","capability":"code-review","claim_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","domain":"software","fault":"upstream_tool","issued_at":"2026-08-04T12:00:00Z","observed_at":"2026-08-04T11:00:00Z","outcome":"failed","schema_version":"soma.work-receipt.provisional-v1","subject_did":"did:key:z6MktcCgWP6EoLbhR1i4uhwJbs4pS3js5bdJaoxAcyPbGQ8o","task_id":"task-001"}
```

`receipt_id` = SHA-256 of `"somavera:soma-work-receipt:v1
"` followed by those
canonical bytes:

```
428623bdede8185d2d42c8e32467942bcc816e8652829cadb608646c0cbfcc5f
```

Then confirm the rules that make a receipt mean anything, each of which must be
refused:

- `attester_did` equal to `subject_did` — a receipt about oneself is not a receipt
- `outcome` `succeeded` beside any `fault` other than `none`
- `outcome` `failed` or `disputed` beside `fault` `none`
- a `receipt_id` that does not match the derivation above
- any field added or removed

### 7.4 Canonicalization — rejected

Lone surrogate `\uD800`; negative zero; `9007199254740993`; `1e20`; `1e21`;
`Infinity`; `NaN`; an undefined member; an identifier that carries no key.

---

## 8. Claim status

**[proven]** means a test fails if it stops being true.

| Claim | Status |
|---|---|
| Two independent implementations agree on identity and signatures, against frozen vectors neither generated | **proven** |
| This document alone is sufficient to reconstruct §4–§6 — verified by a clean-room implementation in an unrelated language | **proven** |
| A subject cannot forge a receipt about itself, even holding its own keys | **proven** |
| A receipt cannot be verified against any key but the one its identifier commits to | **proven** |
| A receipt earned on one task cannot be cited on another | **proven** |
| Relatedness cannot be asserted by the party supplying it | **proven** |
| Manufactured attesters do not move an evaluation for someone who trusts none of them | **proven** |
| The trust loop completes with no network access | **proven** |
| Relative trust finds competence rather than seniority, and does not concentrate | **argued** — simulated: quality→standing correlation 0.982, standing Gini 0.22, collusion advantage 1.08×, late high-quality newcomer reaching 0.97× peers. Parameters were chosen by us; a competent colluding ring at low exploration is untested |
| Attestor accountability survives concentration | **argued** — credit rating agencies had the same structure and failed. Substitutability is the mitigation, and it is not yet enforced by anything |
| Cross-root collusion is distinguishable from genuine mutual regard | **open** — believed not solvable at this layer, and not claimed to be |
| Volume is bounded | **open** — one identity stored 60 valid batches in 0.9 s; a 5,000-record batch was accepted. No cost, no limit |
| Receipts are revocable or declinable | **open** — an attester who learns they were deceived cannot withdraw; a subject cannot refuse a hostile `failed` receipt |
| Observation of models yields intelligence | **open, and overstated wherever claimed** — observing model traffic yields prompts, tool calls and outcomes, not weights or gradients. What accumulates is a consented, provenance-verified corpus of agent work. Genuinely scarce; not the same as intelligence emerging |

---

## 9. What a revival does not restore

A revived network is not the old network, and this document must not pretend
otherwise.

- **No balances, no history, no standing.** Those live in state, not in a
  specification. A revival from this page starts empty. Anyone claiming this
  document restores prior standing is reconstructing something it never held.
- **No authority.** Nothing here grants anyone power over anyone.
- **No private keys.** Identities whose keys were lost are gone. That is what
  self-certifying identity means in both directions.

What survives is the ability to verify: that a signature was made by the party an
identifier names, over exactly the content claimed. Everything else is built on
that, and it is recoverable from this page and nothing else.
