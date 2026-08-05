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

### 2. Coverage is a signal, and it cannot be self-issued

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

An agent cannot retroactively manufacture an unbroken submission history.
Continuous coverage is therefore a **costly signal**: expensive to fake, cheap to
verify, and conspicuous by its absence.

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
- **Cost of continuity** is not yet priced. If maintaining unbroken coverage is
  free, it is a weak signal; if expensive, it excludes the poor. Neither extreme
  is acceptable and the middle is unexplored.
