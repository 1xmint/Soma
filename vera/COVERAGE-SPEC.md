# Coverage attestation — v1 (draft)

Status: **draft.** This closes an attack that every other mechanism here misses.

## The attack

An agent observes while behaving well, stops observing, misbehaves, and resumes.
Every batch it submitted is truthful and correctly signed. Nothing is forged.
The record is a lie told entirely with true statements.

This is worse than no observation, because curated evidence does not merely fail
to inform — it manufactures trust that was never earned.

## Why the obvious fixes fail

**Mandatory observation** is unenforceable against sovereign code. An owner who
controls their agent deletes the submission call. It binds only people who were
not going to cheat, and in exchange it turns the network into a permanent
attributed record of everything everyone did — the surveillance archive this
design exists to avoid.

**Self-attested completeness** is worthless. "I submitted everything" is a claim
by the party with the motive to omit, and no signature makes it true.

## What actually closes it

Two mechanisms, neither requiring anyone to be forced.

### 1. The record is not the subject's to curate

A counterparty who was harmed attests independently. Their receipt does not route
through the subject, is not signed by the subject, and cannot be suppressed by
the subject. The subject's stream stays silent; the counterparty's receipt does
not. The contradiction becomes visible, which is Vera's function — surfacing
inconsistency, never adjudicating it.

This is already built. It is why counter-signed receipts matter more than
observation volume: **observation is what a subject chooses to show; receipts are
what others refuse to let it hide.**

### 2. Coverage is metadata, and it must never be a standing input

**This section previously called coverage a costly signal of virtue. That was
wrong in a way worth keeping on the record, because the mistake is not obvious
and the fix inverts the mechanism.**

Continuity is not costly. It is cheap for a datacentre and expensive for a
person, which is precisely backwards. A rack maintains unbroken submission for
ten thousand agents at close to the cost of maintaining it for one — the
expenditure is shared across every identity behind it, so it prices at O(1) in
the number of identities, which is the definition of a signal an adversary buys
outright. A citizen's laptop sleeps, travels, loses power and goes on holiday.

So as an input to standing, continuous coverage **selects for the adversary and
penalises exactly the people this network exists for.** It would have made
uptime a proxy for trustworthiness, which is a claim no honest reading of the
evidence supports.

> **Never multiply standing by uptime. Uptime is bandwidth, not virtue.**

Two legitimate uses survive, and both are about what the corpus can support
rather than about what anyone deserves:

1. **It narrows the window in which selective silence can hide.** A host's
   attestation of what it received bounds the period a subject could have gone
   dark unnoticed, which tightens later exposure to contradiction. That feeds
   the contradiction machinery, not standing.
2. **It tells an evaluator what the evidence can carry.** Claims about a covered
   period can be corroborated; claims about a gap cannot. That is a statement
   about the corpus, not about the subject.

The reference evaluator therefore takes no coverage input at all. A gap
contributes exactly zero: nothing earned during it, nothing lost, wider
uncertainty, and standing decaying on depth because the network moved on. That
falls out of trust flow with no special case — no receipts in the gap means no
flow from the gap.

### 2a. What a coverage attestation still is, mechanically

Receipts defeat hiding a specific victim. They do not defeat the general shape —
an agent with hundreds of favourable observations and a conspicuous silence
across the months it misbehaved.

For that, coverage must be attested by the **host**, because the host is the only
party that knows what did *not* arrive:

```
somavera:vera-coverage-attestation:v1\n || canonical_json({
  attesting_host_did,
  subject_did,
  window_start,
  window_end,
  batches_received,
  longest_gap_seconds,
  schema_version
})
```

An agent cannot retroactively manufacture an unbroken submission history. That
remains true, and it is why the attestation is worth having at all — but it is a
statement about *when this host heard from someone*, not about their character,
and §2 above is the reason that distinction is load-bearing rather than pedantic.

## What a coverage attestation does and does not say

**Says:** this host received these batches, across this window, with gaps no
longer than this.

**Does not say:** that the agent submitted everything it did. A host cannot know
what it was never sent. `longest_gap_seconds` measures silence toward *this
host*, not honesty.

That distinction is the whole integrity of the mechanism. A coverage attestation
claiming completeness would be a host asserting something it cannot observe, and
would be worth exactly as much as the agent's own claim.

## The resulting posture

Nobody is compelled to be observed. An agent may run entirely dark, keep every
secret, and submit nothing — it simply has no standing, and the gap is legible to
anyone evaluating it.

**Observation is not mandatory. It is what makes work count.**

That is enforceable without coercion, survives sovereign local code, and does not
require the network to hold a record of everything everyone ever did.

## Open

- **Multiple hosts, divergent coverage.** An agent may submit to host A while
  dark to host B. Both attestations are true. An evaluator seeing only B's
  concludes wrongly. Coverage claims must therefore be read as per-host, and an
  evaluator wanting confidence should seek several.
- **A colluding host** can issue flattering coverage. This is the attestor
  problem again, and the answer is the same: hosts are substitutable, their
  claims are attributable, and an evaluator weighs hosts it has reason to trust.
- ~~**Cost of continuity** is not yet priced.~~ **Closed, and the answer was that
  the question was wrong.** The old framing — free means weak, expensive means it
  excludes the poor, so find a middle — assumed the cost was the same for
  everyone. It is not: it is shared across every identity behind one operator, so
  it is near-free for a datacentre and genuinely expensive for a person. There is
  no middle to find, because the two ends are occupied by different populations.
  Coverage is metadata. See §2.

- **The gap that remains is discovery, not measurement.** Adverse evidence bounds
  nobody unless it reaches a future evaluator. A victim's receipt on the victim's
  laptop burns no one. Hosts are what make evidence discoverable, so host
  plurality is part of the security budget rather than an availability nicety.
  Verification is host-free; *pricing* degrades as discovery degrades. That is the
  honest cost of having no ledger, and it is worth paying — but it has to be said
  out loud, or someone will assume contradictions propagate by magic.
