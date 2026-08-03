# Layers — what may never change, and what must stay changeable

Status: **draft.** This document exists to prevent a specific failure: freezing
something that should have been adjustable, and discovering it after the network
is running and unfixable.

## The problem this solves

A deployed protocol ossifies. The installed base becomes the specification, and
"just ship a new version" stops being available — HTTP/1.1 could not be changed,
which is why HTTP/2 and QUIC had to be designed around it rather than replacing
it. Anything in the frozen layer is frozen **for as long as the network lives.**

So the question for every design decision is not "is this good?" but **"does
this have to be in the part that can never change?"**

## The test

> **If two implementations disagree about this, does everything break?**

If yes, it belongs in the frozen core. If two participants can disagree and
still interoperate, it does not — and putting it there anyway is a permanent
mistake.

Canonicalization: disagree and signatures fail everywhere. **Core.**
Reputation weighting: disagree and you simply trust different people, while
every signature still verifies. **Not core.**

## Layer 0 — Frozen

Only what cannot work anywhere else.

| | Why it cannot move up |
|---|---|
| Canonical byte encoding (RFC 8785 + the Soma profile) | Two spellings of one value hash two ways; every identifier is a hash of exact bytes |
| `did:key` derivation | The identifier *is* the key. Change this and every identity in existence is orphaned |
| Domain separation strings | A signature made for one purpose must never verify for another |
| Signature verification, given a suite label | The verification function must be identical everywhere |
| Hash-chain linkage | Append-only ordering is meaningless if implementations disagree |
| The minimal record shapes | What fields a receipt or evidence event carries |
| **Reject unknown fields** | See below |

**Rejecting unknown fields is deliberate and contra Postel's law.** "Be liberal
in what you accept" is now understood to *cause* ossification: implementations
accept malformed input, senders come to depend on that tolerance, and the real
protocol silently becomes whatever the most permissive implementation allows.
Strictness keeps the protocol changeable, which is the opposite of the intuition.

### The rule that matters most

**No tunable number in Layer 0.** Every constant is a future argument. A rate
limit, a window, a threshold, a weight — each is somebody's policy, and freezing
it means the network can never adapt to a condition its authors did not foresee.

*Applying this found an existing violation:* `SIGNING-SPEC.md` fixes the
`submitted_at` acceptance window at ±300 seconds. That is a host's policy, not a
protocol invariant — a host on a satellite link needs a different number than one
in a datacentre. It should be **declared by each host**, not fixed by the spec.
Small now, permanent later.

## Layer 1 — Versioned, changes need coordination

Additive only. Nothing is ever removed, because artifacts signed under an old
version must stay verifiable forever.

- **Signature suite labels.** New suites are added; old ones are never deleted.
  A post-quantum suite is an addition, not a migration.
- New record types
- New attestation types, and the method each one discloses

### Agility without negotiation

Every current standard treats crypto-agility as negotiation — TLS 1.3 style,
both parties advertising and agreeing — and every treatment notes that this adds
protocol complexity.

We do not need it. TLS negotiates because it is an interactive session between
two live parties. Our artifacts are asynchronous: a receipt signed today is
verified by a stranger years later with no handshake available. So agility here
is only:

1. every signature carries the label of the suite that made it
2. every verifier decides which labels it accepts

No round trip, no state machine, no downgrade attack — because there is no
negotiation to downgrade. This is simpler *and* more agile than the standard
approach, because the problem is different.

## Layer 2 — Evaluator policy, no agreement required

**Nothing here needs anyone else's consent, and disagreement costs nothing.**

- Trust roots — whose word you accept
- Reputation math, and how independence is weighted
- Rate limits, quotas, admission control
- Which attestors you honour, and for which claim types
- Sybil defences

Two agents running completely different reputation logic interoperate perfectly,
because they agree on Layer 0. **This is what makes divergent limbs possible:**
jurisdictions that will never agree on values can still verify each other's
signatures exactly. Evidence crosses the boundary; authority does not.

## Layer 3 — Application and social

Governance, jurisdictional limbs, markets, any token. None of it is in the
protocol, so none of it can capture the protocol.

## What this means for what we build

The core is nearly complete, and deliberately small: identity, canonical bytes,
domain separation, receipts, evidence chains. Everything discussed as future work
— reputation scoring, coherence weighting, councils, tokens, attestor markets —
is Layer 2 or above and **must not** be built into the core, however appealing.

Before Layer 0 is frozen:

- two independent implementations must agree on shared vectors (partly done —
  identity vectors agree; receipts exist only in JavaScript)
- every Layer 0 constant must be justified as an invariant, not a preference
- the suite label must be a field everywhere, before the first artifact that
  cannot be re-signed

## The honest limit

A small core does not make the system correct. It makes the system **fixable
above the core, and auditable at it.** Everything above Layer 0 can be replaced
by participants who disagree, without anyone's permission. That is the property
worth protecting, and it is worth more than getting Layer 2 right on the first
try — because Layer 2 will be wrong, repeatedly, and that has to be survivable.
