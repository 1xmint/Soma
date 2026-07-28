# SOMAVERA AND PHOENIX ASSURANCE CASE

Document ID: `somavera/assurance/0.1-draft`
Status: **required release doctrine; not yet satisfied**

## 1. Meaning of "bulletproof"

No software, cryptographic system, AI model, organization, or recovery process is literally bulletproof. Somavera uses a stricter and testable standard:

> Every security, privacy, continuity, and economic claim names its assumptions, adversaries, failure behavior, automated tests, independent evidence, and recovery path. Unknown or failed critical assumptions stop release.

Public releases should say **fail-closed**, **independently verifiable**, **reproducibly recoverable**, or **tested against named threats**. They must not use absolute claims such as unhackable, poison-proof, fully private, guaranteed, immortal, or bulletproof.

## 2. Assurance properties

### Soma

- Observer off means zero observer/training egress.
- A grant cannot authorize a broader class, destination, purpose, duration, or field set than the controller approved.
- Network acts are attributable to a versioned key and cannot be replayed at another endpoint, host, time, or execution context.
- Local secrets do not enter release artifacts, logs, prompts, evidence, or exports.
- Sensitive local bodies remain encrypted at rest under user-controlled keys; non-public contributions/queries remain encrypted through intermediaries to the exact host ingest boundary; and complete signed answers remain encrypted back to the exact query-bound Soma return key.
- Evidence tampering, deletion, insertion, reordering, and truncation are detectable.
- Ordinary host succession cannot change the pin without a controller signature over the exact successor subject; crash or race recovery yields exactly the prior or successor inert pin, never connection, consent, disclosure, or send authority.
- A portable host-trust capsule v2 commits complete current pin, host-succession, and dual-signed controller-rotation bytes; verifies the whole controller chain from an independently supplied initial-key fingerprint; authenticates historical host records at their signing-key intervals; remains explicitly non-restoring and not an external anchor; and detects rollback or fork only when compared with separately preserved trusted evidence. Legacy v1 remains verification-only and cannot represent controller rotation.
- Ordinary Soma controller rotation preserves one stable controller identity through an exact old/new dual-signed chain, one atomic commit, historical public verification, and post-commit old-private-key destruction; it expressly does not claim compromise recovery or independent rollback resistance.
- Loss, rotation, revocation, export, and exit have documented behavior without a universal backdoor.

### Vera Host

- Invalid identity, consent, signature, schema, audience, nonce, expiry, size, network, rules, or provenance fails before state mutation.
- A peer cannot choose the content ID of unverified content or overwrite a valid event by arriving first.
- Replication carries updates, revocations, tombstones, and cursor progress and converges under the specified fault model.
- Raw private material never becomes public-derived intelligence without a valid authorized projection.
- Wrong-recipient, signing/encryption-key-reused, mutated, downgraded, expired, revoked-key, nonce/content-key-reused, or outer/inner-mismatched application ciphertext fails before authoritative storage or display; host-confidential plaintext never enters peer replication.
- Model output never silently becomes protocol truth; provenance, evaluation status, uncertainty, and disputes remain visible.
- Missing security configuration prevents public startup.

### Ledger and VERA

- Supply, balances, bonds, escrows, fees, burns, issuance, and consumed receipts replay from genesis.
- No ordinary observation, task, outcome, social action, or self-report can trigger minting.
- No wealth or stake changes identity assurance, reputation, factual confidence, consent, or learning priority.
- A substrate migration cannot create two spendable claims to the same lineage.
- A fresh Phoenix lineage cannot impersonate lost historical continuity.

## 3. Phoenix survival promise

The Phoenix Origin has two honest modes:

| Surviving evidence | Permitted result |
|---|---|
| Origin bytes only, authenticated or explicitly disclosed as unauthenticated | A new compatible Phoenix network and, after all gates, a new asset lineage; no historical authority or state is implied |
| Authenticated Origin plus a uniquely finalized checkpoint, complete state/replay material, committed death evidence, and checkpoint-pre-state authorization quorums | Candidate exact-state continuation under the precommitted succession procedure |
| Original network still finalizing | Restart services; do not create a successor |
| Conflicting valid histories | Explicit fork and public evidence; no automatic exclusive claim |
| No valid state or quorum | Fresh genesis; no invented balances, reputation, consent, identity, or history |

The Origin can preserve rules and public protocol artifacts. It cannot recover lost private keys, undisclosed memories, deleted private data, missing model weights, external stablecoin reserves, social legitimacy, or history for which no authenticated checkpoint survives.

Integrity and authenticity are different claims. Recomputing a manifest hash proves that recovered bytes match that manifest. It does not prove that the manifest is the original ratified release when the manifest and its claimed trust keys came from the same recovered bundle. Original-release authenticity requires an independent, previously trusted fact outside the candidate bytes. Without it, a clean-room team may test the software or adopt the text as a new constitution, but must not claim recovered historical authority.

Exact continuity also requires availability: the complete canonical public state bytes/chunks and ordered transition log needed to reproduce the checkpoint. A signed root without those bytes is a valid commitment to unavailable state, not a recoverable network.

## 4. Required Phoenix capsule

A ratified release capsule must contain or content-address:

- the printable OriginSpec, constitutional rights, threat model, governance, economics, and recovery procedure;
- every normative schema, canonicalization rule, signature domain, ID projection, state transition, and test vector;
- source for at least one minimal implementation and an independent verifier;
- exact compiler, runtime, dependency, and build-environment locks;
- offline dependency/source bundles where lawful redistribution permits;
- reproducible build instructions, expected source/binary/bytecode hashes, SBOM, and provenance;
- network and token genesis formats, checkpoint formats, succession certificates, and supply-audit tools;
- for every recovery checkpoint, the complete deterministic public state bytes/chunks, their ordered hash/size/encoding manifest, and the replay log from genesis or an authenticated replay base;
- checkpoint-era recovery-key and chamber-seat manifests with their exact thresholds, terms, purposes, and revocations;
- the genesis-bound old-network-death policy plus signed observation, conflict-search, availability, and hold-down evidence;
- clean-room bootstrap, backup, restore, fork, migration, and key-ceremony instructions;
- public keys and threshold release signatures, never private keys or recovery shares;
- licenses for code, documents, data, and model artifacts;
- known limitations, unresolved risks, and superseded release identifiers.

The capsule is mirrored across independent organizations, legal jurisdictions, media types, and offline storage. Every copy is verifiable without contacting HeyVera or trusting DNS.

## 5. Clean-room recovery tests

Origin-only revival and exact continuity use separate pristine environments, evidence sets, and reports. Passing one never implies passing the other.

### 5.1 Origin-only Phoenix

Before ratification, a team that did not build the release must:

1. receive the proposed capsule, ordinary documented hardware, and any independently preserved release trust fact as a separately inventoried input;
2. distinguish internal integrity from release authenticity, verify what can be verified offline, and label the result unauthenticated if no external trust fact exists;
3. build the verifier and reference software in the pinned environment;
4. reproduce expected binaries and conformance results;
5. create a fresh Phoenix network with the correct new lineage identifiers;
6. prove zero imported balance, supply, consent, reputation, evidence, credential, governance, or external economic state;
7. reject a corrupted file, forged signature, downgraded algorithm, copied old identifier, and false continuity certificate; and
8. publish the entire transcript, artifacts, hashes, failures, and deviations.

### 5.2 Exact-continuity succession

A different team on pristine media must:

1. receive the authenticated release, checkpoint/finality proof, complete state chunks, replay log, old-network-death evidence, and checkpoint-era recovery/chamber manifests—never private recovery shares;
2. independently fetch and hash every required chunk, replay with two implementations, and reproduce the checkpoint public/app root and all protected counters before proposing a change;
3. validate the death predicate and conflict search exactly as committed by the old genesis/recovery state;
4. validate certificate signatures against only the recovery keys and chamber seats active in the reproduced pre-state, at every exact threshold;
5. collect separate proof of possession from proposed new keys while proving that none authorized its own elevation;
6. execute only the committed `RecoverySuccession` transition, reproduce the post-transition root, and reject any unrelated state change;
7. reject missing state bytes, unavailable chunks, threshold-minus-one authority, a fresh-key self-authorization, stale/fresh-finality conflict, ambiguous history, replay, supply mismatch, and fake continuity; and
8. if the old authorization quorum is unavailable, stop at published read-only reproduction and test a separate new-lineage Phoenix instead.

If any undocumented founder knowledge, live service, private repository, package registry, DNS name, cloud account, or secret is required, the Phoenix claim fails.

## 6. Adversarial release matrix

Each release must cover at least:

- consent off, revoked, expired, narrowed, wrong destination, wrong purpose, and third-party-data cases;
- signature mutation, cross-endpoint replay, stale nonce, key rotation, revoked key, downgrade, and malformed canonical data;
- Sybil identity, fake credential, self-dealing, reciprocal jobs, forged outcomes, verifier collusion, and receipt replay;
- malicious peer, first-writer poisoning, equivocation, rollback, pagination loss, tombstone loss, partition, and clock manipulation;
- secret canaries, copied local ciphertext, wrong-recipient envelopes, nonce/key reuse, downgrade, proxy/queue plaintext exposure, prompt injection, training-data poisoning, model exfiltration, hostile artifacts, and malicious model output;
- SSRF, redirect token leak, oversized body, decompression bomb, concurrency exhaustion, disk exhaustion, paid-inference exhaustion, and database corruption;
- backup loss, operator disappearance, validator capture, key compromise, chain halt, substrate loss, and conflicting recovery attempts;
- VERA price collapse/rise, liquidity exit, stablecoin/bridge/paymaster failure, validator exit, bribery, wash trading, and treasury abuse.

Passing happy-path tests is not release evidence.

## 7. Independent evidence gates

No public pilot ships with an unresolved critical or high-risk finding in identity, consent, privacy, remote execution, replication, state integrity, secrets, or recovery.

No valuable token activates until:

- two independent implementations agree on every conformance vector and state root;
- independent security, privacy, economic, and legal reviews examine the exact release;
- three separately reported origin-only Phoenix clean-room rebuilds and three separately reported exact-continuity substrate-death succession drills pass; evidence permitted in one mode must not leak into the other;
- protocol use and payments exist without speculation;
- independent operators satisfy the published concentration gates;
- every deployment and governance key is disclosed with hard authority limits and rotation/sunset rules;
- a final public challenge period closes without an unresolved release blocker.

## 8. Evidence over confidence

Founder conviction, model consensus, an audit badge, a long document, test coverage percentage, cryptographic terminology, a VPS demo, and a market price are not proof of safety. Release confidence comes from reproducible artifacts, adversarial results, independent operation, clean-room recovery, narrow claims, and the willingness to stop when evidence is insufficient.
