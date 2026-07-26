# SOMAVERA PHOENIX ORIGIN CARD

Status: **draft 0.1 — not ratified**
Purpose: the shortest honest rule set for deciding what a surviving Somavera release can revive.

## Verify the claimed Origin first

A document cannot authenticate itself. Matching a hash printed inside the same recovered bundle proves internal integrity, not that the bundle is the original ratified release.

To claim original-release authenticity, a recoverer needs at least one independent trust fact obtained outside the recovered bytes—for example a previously trusted release hash or public key, a valid threshold-signature chain rooted in a separately preserved trust anchor, or independently witnessed archive/transparency records. If no such fact survives, disclose that limitation and treat the document as a candidate constitution, not authenticated historical authority.

## Choose exactly one recovery mode

| What survives | Honest result |
|---|---|
| Origin bytes, authenticated or explicitly disclosed as unauthenticated, but no complete authenticated state/replay package | **Origin-only Phoenix:** adopt the rules as a new constitution; create a new network lineage, null asset lineage, zero supply, and no inherited balances, reputation, credentials, consent, evidence, governance power, or issuance history |
| Authenticated Origin release plus a uniquely finalized checkpoint package with complete reproducible public state bytes/chunks, its ordered replay material, the committed old-network-death evidence, and the checkpoint-pre-state authorization quorums | **Candidate exact continuity:** follow `RECOVERY.md`; independently reproduce the state and validate every pre-state threshold before any successor transaction |
| Competing valid histories | Stop automatic succession, publish both, assign distinct identifiers, and disclose the fork |
| Original network still finalizing | Restore services; do not create a successor |

A checkpoint root, signature, manifest, or balance list without the complete state material needed to reproduce it is evidence of a commitment, not recoverable continuity. Exact continuity also needs old-context replay protection and a valid, precommitted succession transition authorized by the recovery and chamber keys active in the reproduced checkpoint pre-state. New keys may prove possession but may not authorize themselves.

There is no absolute cryptographic death oracle. The committed death predicate only establishes that specified evidence was absent for a specified observation window under stated clock, path, observer, and quorum assumptions. A partition, censored view, later valid proof, or conflicting valid history can defeat exclusivity; the result must then remain halted or be disclosed as a fork.

## Never invent what did not survive

No recovery process may invent or infer private keys, private data, identity mappings, consent, reputation, evidence, balances, supply counters, external currency or stablecoin reserves, bridge claims, liquidity, debts, contracts, market prices, model weights, or social legitimacy. External economic claims remain governed by their own custodians, issuers, contracts, and legal systems; Somavera recovery cannot recreate them.

## Fail closed and publish evidence

Verify all files offline, build independent implementations, reproduce public state from the surviving bytes, run the adversarial conformance suite, and publish inputs, hashes, transcripts, deviations, and authority limits. Any undocumented founder knowledge, private service, missing state chunk, unverifiable signature, ambiguous history, or supply mismatch blocks an exact-continuity claim.

Normative detail: `ORIGIN-SPEC.md`, `RECOVERY.md`, `ID-DERIVATION.md`, `ASSURANCE-CASE.md`, and the signed release manifest. This card does not override them.
