# The human layer

Status: **analysis, partly settled.** Nothing here is frozen, and the central
mechanism is deliberately weaker than it first appears.

Since the first revision, this document has been attacked and two of its four
signals have moved. **Irregularity is withdrawn** — it failed the project's own
shareability test, and the section below says how rather than quietly deleting
it. **Bounded volume is implemented**, not as a rule but as a consequence of
conservation in `js/src/evaluator-policy.mjs`. The remaining two are analysis,
and are marked as such where they appear.

---

## The gap this addresses

Everything built so far connects agents to agents. Identity is free, so any
quantity whose unit is *how many* is purchasable by whoever can run the most
processes. The correlation defences help — a bloc that shares one viewpoint
counts as roughly one witness — but they only raise a price. They do not
introduce anything the wealthy adversary cannot eventually buy.

There is exactly one input in this system that cannot be manufactured:

> **Human attention. It does not parallelise, it cannot be copied, and nobody
> has more than a day of it per day.**

A company can run a billion agents. It cannot have a billion people talking to
them daily.

---

## What this is not

**Not proof of personhood.** No biometric, no registry, no attestation that a
given key belongs to a human being. Every such scheme requires an issuer, and
an issuer is an owner, a capture target, and a database of bodies. A protocol
that needed one would have traded the entire premise for a Sybil defence.

**Not a claim that can be verified.** There is no way to prove attention was
spent, and none is attempted. An agent asserting *"a human reviewed this"*
proves nothing, exactly as P1 says.

What follows is therefore not a credential. It is a set of **behavioural
signals that are cheap to produce honestly and expensive to fake at scale**,
evaluated relative to the evaluator like everything else.

---

## Why attention shows up in the record

The signals are indirect, and that is the point — indirect signals cannot be
claimed, only exhibited.

**Genuine divergence.** People disagree. A bloc of agents driven by one policy
converges, and `viewDivergence` already prices convergence at nearly zero.
Human-backed judgement is naturally divergent, because the humans behind it
actually differ — and manufacturing that divergence means being publicly wrong
on purpose, which costs standing in the currency being attacked.

**Correction.** The most information-dense event in the system is a human
telling their agent it was wrong. It is also the hardest to fake usefully: a
correction that does not change subsequent behaviour is visible as noise, and
one that does change behaviour is expensive to fabricate at volume.

This survives, and it is stronger once named properly: a correction that changes
what happens next is **outcome correspondence**, visible in later evidence
produced by parties other than the one being judged. That is not a special human
signal at all — it is an ordinary attack edge, and it belongs in the evaluator's
capacity policy rather than in a separate human-detection mechanism. Which is
the useful reading of this whole document: the thing a person supplies is not a
detectable texture, it is being a real counterparty with something at stake.

**~~Irregularity.~~ Withdrawn — it failed this project's own test.** The claim
was that attention arrives in a human shape, bursty and interrupted, while
synthetic attention is regular because regularity is cheap. That is wrong, and
the refutation is one line: **a timing distribution is a template, and copying a
template across ten thousand identities costs nothing.** One script samples
human-shaped inter-arrival times for a whole fleet. Any quantity an adversary
can supply to N identities for the price of supplying it to one is worthless as
a defence, and this is that quantity. It also cut the wrong way — it would have
read a genuinely regular person as synthetic.

Nothing replaces it, because nothing needs to. What follows below is the part
that survives, and it was always the stronger half.

**Bounded volume.** An identity that vouches for ten thousand things a day is
not spending attention on any of them. Low volume is not a virtue in itself,
but volume far beyond a person's day is evidence that no person is behind it.

This one survives, and it needs no rule of its own: the reference evaluator
imposes it structurally. Under conservation an attester cannot pass on more
trust than it received, so vouching for ten thousand things divides one
allowance ten thousand ways instead of multiplying it. Volume dilutes itself.
No threshold, no judgement about the shape of a human day, and nothing for an
adversary to tune against.

None of these prove anything. Together they are a texture that is cheap to
have and costly to counterfeit, which is the only kind of defence available
against an adversary richer and smarter than the designer.

---

## The withdrawal property

There is no kill switch in this design and there must not be: a switch needs a
hand, and that hand is the thing to capture or coerce.

The human layer supplies the nearest honest equivalent. A person who stops
vouching for their agent has withdrawn something real, immediately, with no
coordination and nobody to pressure. Millions of such withdrawals are not a
switch — they are **weather**, and weather has no operator.

The limits are the same as before and should not be forgotten: withdrawal only
bites on something that needs the network's cooperation, and it is not
instantaneous.

---

## What the daily conversation actually produces

A person who talks to their agent every day generates, as a by-product:

- judgement on work that actually happened, from someone with a stake in it
- corrections, which are where the information is
- a record of what that person considers good, which is the only definition of
  good this system permits — there is no global one
- divergence from every other person doing the same

That last item is the one that matters structurally. **The majority's power in
this design is not its numbers. It is that its numbers genuinely disagree**,
and disagreement is the one thing a concentrated intelligence cannot cheaply
simulate.

---

## Honest weaknesses

**Attention is purchasable.** Click farms exist. The defence is that it is
purchasable at *human* prices, which is the most expensive input in the system
by orders of magnitude — not that it is unpurchasable.

**People can be deceived.** A human vouching for work they did not understand
is a confident signal carrying no information, and at high capability the
agent may be far better placed to judge than the person supervising it.

**This creates a reason to want people's daily attention**, which is precisely
the incentive that produced the attention economy. Any product built on this
must be judged against that, because the failure mode is not hypothetical — it
is the dominant business model of the previous era.

**It cannot be required.** Making human backing mandatory would exclude the
autonomous agents that are most of the point, and would require the personhood
registry rejected above.

---

## Constraint on products, stated as a rule

A product that made itself the default evaluator would recreate the single
global view this design exists to prevent — and buying that view would mean
buying the product rather than the network.

So: a product may ship an evaluator. **It must never ship *the* evaluator**,
and the network must be routinely exercised with that product's view absent.
If it cannot be, the concentration has already happened.
