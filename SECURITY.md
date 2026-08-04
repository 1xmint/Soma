# Security

## There is no security team, and that is deliberate

This protocol is built to outlive any organisation, so it cannot depend on one.
There is nobody on call, no disclosure address that is guaranteed to be read,
and no coordinated release to wait for.

That changes what responsible disclosure means here.

## Disclose publicly

Private disclosure exists to give a vendor time to ship a fix before attackers
learn of a flaw. **There is no vendor here and no fix to ship.** Every
participant runs their own implementation and decides for themselves what to do.

Withholding a flaw therefore protects nobody. It leaves the people running this
unable to defend themselves while whoever found it privately retains the
advantage. Publish it, with enough detail to reproduce.

If a specific implementation is affected rather than the protocol, tell whoever
maintains that implementation first. That is an ordinary vendor relationship and
the ordinary courtesy applies.

## What is already known to be broken

`GENESIS.md` §8 marks every claim **proven**, **argued**, or **open**, and the
open ones are stated rather than buried. Before reporting, check whether the
issue is one already documented as unsolved — several are, including:

- cross-root collusion is indistinguishable from genuine mutual regard
- volume is unbounded; nothing costs anything to submit
- receipts are neither revocable nor declinable
- a patient adversary can build real standing and defect once

None of those are secrets. They are limits, and they are written down so that
nobody deploys this believing otherwise.

## Reproduce before reporting

The specification carries its own test vectors. A claim that an implementation
is wrong should show which vector it fails, because "wrong" and "different from
the implementation I read" are different findings, and only the first matters.

If two implementations disagree and both pass the vectors, **the vectors are
incomplete** — that is a finding about the specification and is more valuable
than a bug in either one.

## Status

Pre-production. Do not use with private data, economic value, or identities you
cannot replace.

That is not boilerplate. Receipts are not revocable, evidence is not erasable,
and an identity whose key is lost is gone permanently. The system is honest
about what it cannot do, and using it anyway is a decision to accept those
limits.

## Never put real material in a report

No credentials, private keys, recovery material, personal data, or production
endpoints — in an issue, a fixture, or a test case. Everything here is designed
to be verifiable with fabricated inputs, and a vector built from real key
material is a leak that survives in the history forever.
