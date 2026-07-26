# SOMAVERA THREAT MODEL

Status: draft 0.1
Rule: provenance proves who asserted bytes and whether they changed. It does not prove the assertion is true, useful, lawful, or safe.

## 1. Protected assets

- user control of Soma identities, agents, delegations, and exports;
- signing, encryption, recovery, validator, and treasury keys;
- consent choices and private work;
- integrity and provenance of evidence, reputation inputs, datasets, models, releases, and checkpoints;
- ledger safety, liveness, balances, supply, and asset lineage;
- availability of public intelligence and recovery artifacts;
- the right to exit, verify, implement, and fork.

## 2. Adversaries

Assume the existence of:

- malicious or compromised agents;
- Sybil fleets and colluding counterparties;
- malicious observers, hosts, validators, indexers, relays, model providers, and governance delegates;
- wealthy token holders attempting to buy epistemic authority;
- founder, foundation, donor, corporate, or state capture;
- network partitions, rollback, censorship, equivocation, long-range attacks, and dead substrates;
- prompt injection, data poisoning, backdoors, benchmark gaming, model extraction, and unsafe model releases;
- dependency compromise, malicious updates, build-system attacks, stolen domains, and mirror tampering;
- insiders with filesystem, database, memory, backup, or logging access;
- traffic analysis and correlation even when content is encrypted;
- accidental operator error and permanent key loss.

Quantum cryptanalysis is a migration concern, not a reason to claim present-day protection. The protocol uses explicit algorithm suites and upgrade ceremonies.

## 3. Trust assumptions

V1 does not assume any host can keep plaintext secret from its own privileged operator while processing it. Encryption at rest protects media and some operational failures, not process memory.

V1 safety requires:

- at least one honest implementation used for independent verification;
- consensus fault assumptions stated by the selected consensus profile;
- release and recovery thresholds not controlled by one organization;
- users protecting their own signing and recovery material;
- external mirrors or anchors surviving operator loss;
- explicit rights to every accepted training contribution.

If these assumptions are unmet, interfaces must report degraded security rather than silently soften checks.

## 4. Primary threats and required controls

| Threat | Failure | Required controls |
|---|---|---|
| consent bypass | private work leaves Soma | off-by-default observer, signed grant, egress firewall, fail-closed class/purpose/destination checks |
| key exfiltration | attacker controls an agent or validator | OS/hardware keystore, path containment, no bearer-to-arbitrary-URL tools, rotation and revocation |
| Soma controller rotation split or false recovery | crash/race creates two active controller keys, old history disappears, or a stolen old key is misrepresented as recovery authority | stable controller DID, exact sequence/predecessor, old/new role-separated signatures, no-gap validity windows, one atomic identity commit, deterministic finalization/quarantine, old public retention and post-commit private-key destruction, explicit non-recovery authority; suspected compromise remains blocked for precommitted recovery |
| host rotation takeover or split local pin | stolen current key installs attacker keys, confirmation is rebound, or a crash/race leaves ambiguous authority | prior descriptor precommitment, exact predecessor/sequence, dual role-separated signatures, immutable-field checks, short proof window, controller-signed exact-subject confirmation, one atomic current-pin commit point, authenticated prepared transition, deterministic recovery, append-only history, idempotency/conflict tests; ordinary recovery blocked after total compromise |
| local host-trust rollback or capsule substitution | a compromised device presents an older pin/history set or a self-chosen controller | complete signed portable pin/host-history bytes plus the v2 dual-signed controller chain, out-of-band expected initial-controller fingerprint, strict chain reconstruction and historical key-window verification, separately preserved prior capsule/hash, controller-and-host prefix-only comparison, explicit non-anchor/non-restore claims; same-device export alone provides no rollback assurance |
| replay or field substitution | valid signature authorizes another action | domain-separated full envelope, audience, network, action, nonce, expiry, payload commitment |
| self-issued reputation | Sybil fabricates trust | independent receipts, contextual formulas, issuer weighting, disputes, decay, collusion analysis |
| receipt replay | repeated payment or issuance | globally unique receipt ID, consumed-state bit, actor/counterparty binding, finality |
| mesh poisoning | hostile host imports invented knowledge | verify signatures, lineage, license, rules, content IDs, evaluations, quarantine, tombstones |
| hidden plaintext | “encrypted” data becomes public lesson/log | local at-rest encryption, per-host recipient envelopes, dataflow review, taint tests, separate stores, minimization, release grant |
| validator capture | balances or rules are rewritten | diverse set, concentration gates, BFT finality, light-client verification, public checkpoints |
| governance capture | wealth buys rights or truth | three chambers, constitutional bounds, disclosure, exit and fork |
| supply exploit | arbitrary mint or double spend | deterministic issuance ceiling, replay protection, invariant replay, no hidden admin mint |
| recovery takeover | guardians seize continuity | pause-only authority, authenticated checkpoint, two replays, challenge, succession certificate |
| rollback/equivocation | history is replaced | chained checkpoints, external mirrors/anchors, fork evidence, no unilateral choice |
| build compromise | released binary differs from source | pinned toolchain, reproducible builds, SBOM, multiple builders, signed manifest |
| model poisoning | Vera gets less reliable or unsafe | provenance, quarantine, held-out evaluation, adversarial testing, staged release and rollback |
| correlatability | one identity graph reveals a person’s life | pairwise/domain identities, selective disclosure, separate logs, minimal public commitments |
| denial of service | bodies or hosts become unavailable | quotas, bounded bodies, timeouts, backpressure, replication, offline export, tokenless recovery path |

## 5. Forbidden shortcuts

The following are not accepted controls:

- a signature as proof that work happened;
- a zero exit code as proof of quality;
- stake as proof of truth;
- encryption at rest, TLS, or recipient encryption as proof the authorized operator cannot read data during ordinary processing;
- several agreeing Sybils as independent verification;
- a zero-knowledge proof as proof that the input or claim is factually true;
- a hidden benchmark as permanent poisoning protection;
- a multisig as authority to rewrite history;
- a terms-of-service checkbox as universal training consent;
- a prose OriginSpec as a substitute for authenticated state.

## 6. Mandatory release tests

Before a valuable mainnet:

- cross-language canonicalization and signature vectors;
- signature mutation, replay, wrong-network, wrong-audience, nonce, and expiry tests;
- consent-off egress and all-action membrane tests;
- path traversal, SSRF, redirect, DNS rebinding, log leakage, and secret-scanning tests;
- malicious receipt, Sybil ring, collusion, contradiction, and dispute simulations;
- arbitrary peer, invalid signature, rule mismatch, stale update, tombstone, and partition mesh tests;
- mint ceiling, fee split, slash, migration, supply replay, and double-spend invariants;
- validator Byzantine, censorship, halt, long-range, state-sync, and light-client tests;
- recovery from clean media, conflicting checkpoints, lost guardians, and dead substrate;
- reproducible builds from two organizations;
- poisoning, privacy leakage, memorization, benchmark gaming, and intelligence-quality evaluations;
- load and chaos tests with at least the gate counts claimed by the release.

Security review is continuous. “Audit passed” is not a permanent property.

## 7. Current prototype disposition

The July 2026 soma and vera-host prototypes are demonstrations only. They must not process real secrets, private work, valuable balances, or adversarial public traffic until their findings in the private audit are fixed and the conformance gates above pass.
