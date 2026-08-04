# Release readiness — what must be true before walking away

Status: **checklist, not a claim.** Items are marked against evidence, not
intention.

The goal is specific: **release the protocol, then have nothing left to do
except participate.** That is only true if nothing about the network depends on
one person. This enumerates those dependencies so they can be removed rather
than assumed away.

**Scope: the protocol only.** Products built on the network are businesses, and
a business may depend on its owner indefinitely — that is what a business is.
The distinction matters because it is the one thing that must never blur: a
product that could charge for access to the protocol would eventually be tempted
to, and the temptation would win. Nothing in the frozen layer knows any product
exists.

---

## 1. Nothing may require the author

| Dependency | State |
|---|---|
| A signing key that must stay live | **none** — records are signed by their own authors; no release key gates anything |
| A service that must stay running | **none in the protocol** — hosts are plural, and Soma is fully functional with every host absent |
| Governance requiring approval | **none** — there is no approver |
| A registry someone administers | **none** — the identifier is the key |
| A licence permitting forks | **done** — MIT / Apache-2.0 dual |
| **A code-hosting account** | **MISSING** — everything lives in one organisation owned by one person |
| **Off-platform copies of the specification** | **MISSING** — GENESIS.md exists in exactly one place |

The last two are the same failure twice, and they are the only ones that would
end the project. Everything else is already independent.

**What closes it:** the specification and vectors held by custodians who are not
the author, on infrastructure that is not the author's, in more than one
jurisdiction. A mirror inside the same organisation protects against nothing the
organisation is exposed to.

---

## 2. The protocol must not need upgrading

An upgrade needs someone to shepherd it, and that someone would be the author,
forever. This is the real reason the frozen layer must be small — **a small core
is what makes leaving possible**, which is a better argument for it than
elegance.

| | State |
|---|---|
| Frozen layer defined, with the test that decides membership | **done** — GENESIS §3 |
| No tunable number frozen | **partial** — one violation found and recorded: a host's acceptance window was fixed by specification rather than declared per host |
| Suite agility without a protocol change | **done** — every signature names its suite; new suites are additive, old labels never removed |
| Unknown fields rejected rather than ignored | **done** — the alternative lets the most permissive implementation silently become the specification |

---

## 3. Two implementations, disagreeing where it matters

A single implementation *is* the specification in practice: every bug becomes
the protocol, and nobody can distinguish "the specification says X" from "the
implementation happens to do X".

**The requirement is not "maintain N implementations forever."** That ages
badly: languages rise and die, and an implementation nobody runs provides no
real check — its agreement is ceremony. If ninety percent of the network runs
one language, a vestigial second implementation in another proves nothing.

The property that actually matters is:

> **Can someone build a conformant implementation from the document alone,
> without asking anyone?**

Two implementations was a crude proxy for that. The direct test is a **drill**:
periodically, someone builds fresh from the document and runs the vectors. It is
not a standing maintenance burden, and it survives any shift in which languages
exist, because the document names none.

| | State |
|---|---|
| Identity agreed across implementations against fixed vectors | **done** — and it caught a real defect: one implementation encoded identifiers in base64 while labelling them base58btc, so every identity it produced was unrecognisable to every other |
| Canonical bytes agreed | **done** — proven in three languages |
| **Vectors sufficient to build receipts from the document alone** | **done** — GENESIS §7.5 |
| Vectors are the contract, not the code | **done** — an implementation is conformant if and only if it passes them |

That base64 defect is the argument for this whole section. It survived because
its only test was a round trip, which passes under any encoding because both
halves share the mistake. **Fixed expected output is the only check that catches
a consistent error.**

---

## 4. A stranger can join without asking

| | State |
|---|---|
| No registration, allowlist, or invitation | **done** |
| Identity obtainable offline, with no network | **done** — one command, no account |
| Verification possible with no registry | **done** — the identifier carries the key |
| The specification findable without the author | **MISSING** — see §1 |
| An implementation obtainable | **partial** — source is public; nothing published to a package registry |

---

## 5. Revival works, and has been performed

| | State |
|---|---|
| Specification self-contained: no file, URL, or language references | **done** |
| Vectors inline, so a reimplementation proves itself | **done** |
| **A revival actually carried out** | **done** — implemented from the prose alone in a language the original was not written in, reproducing every vector and rejecting everything it should |
| What a revival does *not* restore is stated | **done** — no balances, no history, no standing, no keys |

A revival specification that has never revived anything is a claim, not a
capability. This one has now revived something.

---

## 6. What is deliberately **not** required

Listed because a checklist that grows without limit never completes, and because
each of these would be a reason to stay involved forever.

- **Adoption.** The protocol working does not require anyone to use it.
- **A canonical implementation.** There must not be one. Whichever is most used
  acquires de facto control regardless of the specification, so plurality is a
  security property rather than a nicety.
- **A foundation, council, or steward.** Any body that could act could be
  captured or pressured. There is nothing to capture only while there is nobody
  to capture.
- **Intelligence, at release.** Verification of mechanically checkable claims
  works today and requires none. Judgement-requiring claims may remain
  experiential permanently, and the system stays useful if they do.

---

## 7. The honest caveat

Technical independence is achievable and mostly achieved. **Social bootstrap is
not automatic.** Every protocol that succeeded needed years of advocacy —
Bitcoin had its author active for roughly two years, the web had an institution
behind it, email took decades.

So the realistic position is not "release and receive". It is: build so that it
*can* run without you, then expect to spend real effort on adoption anyway — from
a position where stopping slows the network rather than ending it.

That difference is the entire point, and it is the one being built.
