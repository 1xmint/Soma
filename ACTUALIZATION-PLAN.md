# SOMAVERA ACTUALIZATION PLAN

Status: **execution draft - July 16, 2026**
Rule: activate a safe network pilot before considering a valuable token.

## 1. The product shape

Somavera needs two genuinely portable, drag-and-drop systems plus one first-party product:

| System | User promise | First operator |
|---|---|---|
| Soma Pack | Give an owned agent identity, local authority, explicit Vera consent, signed evidence, and sovereign intelligence export | The human or agent owner |
| Vera Host Pack | Let an independent operator receive authorized events, derive and serve provenance-linked intelligence, replicate public state, and recover from a capsule | Any qualified host operator |
| HeyVera | Make the system usable through social, hosted agents, identity UX, the coding harness, billing, and later marketplace/crypto regions | HeyVera |

Soma and Vera Host are the open network core. HeyVera is the first product and managed operator, not the owner of protocol truth.

## 2. Soma Pack - prototype contract

A fresh user must be able to unpack one release and complete this flow without source edits:

```text
soma init
soma doctor
soma connect <vera-host>
soma observe preview
soma observe grant
soma ask "question"
soma export
soma observe revoke
soma verify
```

The first prototype must provide:

- offline creation and recovery of an agent identity;
- OS-protected or hardware-backed signing secrets, with an explicitly insecure development mode only;
- versioned, domain-separated, nonce- and expiry-bound signatures;
- local signed, sequenced, hash-linked evidence;
- sensitive local state encrypted at rest under user-controlled keys outside ordinary state files;
- observer off by default;
- exact data-class, field, purpose, destination, retention, replication, expiry, and revocation consent;
- a preview of the exact bytes that will leave the device;
- deterministic redaction and secret scanning before egress;
- every non-public contribution/query carried as an inner signed object encrypted to the exact Vera Host ingestion key, in addition to authenticated TLS;
- every complete signed Vera answer/source bundle encrypted to a fresh or pairwise Soma return key bound by the query;
- a signed host acknowledgement for accepted contributions;
- local storage of Vera answers, sources, model/service metadata, and export bundles;
- a clean uninstall/export path that does not strand identity or intelligence;
- Windows, Linux, and macOS release verification instructions.

The first prototype does not claim unbypassable agent control, verified human identity, autonomous money, general factual truth, or hidden model-reasoning access.

## 3. Vera Host Pack - prototype contract

A fresh operator must be able to unpack one release and complete this flow without source edits:

```text
vera init
vera doctor
vera start --private
vera join <network>
vera verify-state
vera backup
vera restore <checkpoint-capsule>
```

The first prototype must provide:

- fail-closed configuration and private/loopback binding by default;
- authenticated TLS for every nonlocal connection;
- separate operator, host-signing, ingestion-encryption, validator, storage-encryption, and recovery keys;
- signature, identity, consent, audience, recipient, nonce, expiry, schema, ciphertext, and size validation before decryption or storage;
- immutable signed event storage plus deterministic derived views;
- no minting from observations, outcomes, or self-reported work;
- cursor-based, authenticated, content-verified replication;
- revocation and tombstone propagation;
- provenance-linked retrieval with citations, uncertainty, and abstention;
- bounded requests, storage, concurrency, outbound calls, and paid inference;
- encrypted local and host storage, authenticated TLS, host-recipient encryption for inbound queries/contributions, and Soma-recipient encryption for outbound answers;
- decryption only in the exact bounded recipient worker after pre-decryption checks;
- explicit disclosure that a normal host operator can still observe authorized data while it is processed in memory;
- checkpoint creation, supply/state invariant checks, backup, restore, and clean host exit;
- container/VPS and local installation profiles using the same protocol behavior.

"Encrypted stream" initially means sensitive Soma state is encrypted locally, TLS protects the connection, non-public queries/contributions are encrypted to the exact authorized host ingestion key, and signed Vera answers are encrypted back to the query-bound Soma return key. Reverse proxies, queues, ordinary storage, and unintended peers therefore need not see bodies. The named ordinary host still decrypts authorized material in bounded process memory to use it. This L1 profile uses separate per-recipient envelopes and strict signing/encryption-key separation; it does not mean operator-blind computation. `CONFIDENTIAL-COMPUTE.md` defines device-only L0, ordinary encrypted L1, attested confidential L2, and specialized MPC/FHE L3/L4 profiles.

## 4. What Soma can observe from AI models now

Soma may observe only data the owner authorizes and the model/tool interface actually exposes, such as:

- user instructions submitted through Soma;
- model responses;
- tool requests and redacted result metadata;
- files or artifacts deliberately approved for evidence;
- timing, token counts, model/provider identifiers, errors, and costs;
- provider-exposed event streams or explicit reasoning summaries;
- independent task outcomes such as tests, deployments, counterparty acceptance, or payment settlement.

Soma cannot see a closed model's hidden weights, private activations, undisclosed provider logs, or hidden chain-of-thought. Verbose API output is not proof of internal reasoning. Somavera should learn primarily from authorized inputs, actions, artifacts, and independently verifiable outcomes, not from promises that it can read a model's mind.

Future open-weight models can support deeper instrumentation, activation research, local training, and reproducible evaluation. That is a new capability profile, not a retroactive claim about closed APIs.

## 5. Spec-before-build sequence

The order is correct, but each document needs a precise role:

1. **OriginSpec for Soma** - immutable rights, boundaries, threat model, identity/consent/evidence semantics, recovery, and forbidden behavior.
2. **OriginSpec for Vera Host** - ingest, provenance, federation, learning/evaluation, data rights, checkpoint, and recovery semantics.
3. **Prototype Spec for Soma** - exact commands, files, schemas, error behavior, acceptance tests, supported platforms, and non-goals.
4. **Prototype Spec for Vera Host** - exact APIs, deployment profiles, persistence, replication, limits, observability, recovery, and acceptance tests.
5. **Shared conformance pack** - canonicalization, signatures, consent, events, acknowledgements, replay, replication, checkpoint, and adversarial vectors.
6. **Reference builds** - implementation follows the frozen prototype contracts.
7. **Independent review and clean-room rebuild** - another implementer must reproduce the behavior from the documents and vectors.
8. **Closed network pilot** - real use with non-sensitive data and no valuable token.

A spec is not 10/10 because it is long. It is 10/10 when two independent implementations make the same decisions on every valid and invalid test vector, and a clean-room operator can recover the network without private founder knowledge.

## 6. First real end-to-end loop

1. A person signs into HeyVera or uses Soma locally.
2. They create or connect one exportable Soma agent identity.
3. The agent completes a harmless, objectively testable task through a constrained adapter such as the HeyVera coding harness.
4. Soma records a signed local evidence event.
5. The owner previews and grants one narrow Vera contribution.
6. Soma sends the signed consent and redacted event to a pinned Vera host.
7. Vera Host validates everything and returns a signed acknowledgement.
8. A second independent host replicates and verifies the authorized public event.
9. Vera derives a provisional, provenance-linked retrieval item.
10. A query returns it with its source and uncertainty.
11. The owner exports the result and revokes future contribution authority.
12. A full host-loss restore reproduces the same authorized public state.

This activates the useful network. It does not activate a valuable token.

## 7. Test topology using the available VPS

```text
Owner PC
  - Soma Pack
  - local development Vera Host A
  - test agent/model adapter

Independent VPS
  - Vera Host B
  - separate host/operator keys
  - TLS and restricted firewall
  - isolated pilot database

Offline recovery environment
  - no access to either live host
  - verifies release capsule
  - restores last authenticated checkpoint
```

Do not reuse current prototype/VPS keys or databases. The pilot starts with fresh keys, non-sensitive fixtures, no public ingress until the private tests pass, and no scripts that silently contact the VPS.

## 8. Phased execution

### Gate A - containment

- observer defaults off;
- every observation, training, contribution, outcome-learning, watcher, and telemetry egress path uses the same consent and membrane engine;
- `ask` uses a separate contemporaneous controller action or signed least-privilege query delegation; `connect` is limited to its disclosed descriptor/handshake flow; both send only previewed recipient-encrypted fields and bounded protocol overhead and never create observation, contribution, or training authority;
- prototype token minting is disabled;
- secrets and runtime databases are outside distributable trees;
- public operation fails closed without authentication and TLS;
- remote-mutating demo scripts are removed from acceptance tests.

### Gate B - frozen specifications

- both OriginSpecs and both Prototype Specs have no unresolved P0/P1 ambiguity;
- shared schemas and canonical test vectors pass;
- threat models, privacy boundaries, non-goals, and recovery claims are explicit;
- HeyVera integration does not become protocol authority.

### Gate C - local reference prototypes

- fresh-machine installation passes on supported platforms;
- observer-off idle/background operation produces zero observer, watcher, telemetry, contribution, outcome-learning, or training traffic; an authorized `ask` remains a separate bounded query and response;
- replay, mutation, wrong host or recipient, stale request, revoked key, reused encryption nonce/key, malformed ciphertext, malformed input, secret canary, and oversized input fail closed;
- copied local/host storage reveals no protected plaintext without the correct keystore;
- queries and return answers stay ciphertext through TLS termination, queues, and ordinary storage;
- signed export and restore work.

### Gate D - two-host private network

- PC and VPS hosts converge on the same authorized state;
- malicious/corrupt replication is rejected;
- host loss and recovery drills pass;
- operator memory-access limitations are disclosed and tested;
- no valuable token or reputation score exists.

### Gate E - invited founding pilot

- 5-10 consenting humans, 10-25 agents, and at least 3 hosts across 2 operators;
- non-sensitive coding, research, and public-data tasks only;
- ordinary payments, grants, or valueless quotas;
- measurable improvement, provenance, privacy, poisoning, cost, uptime, and recovery results are published.

### Gate F - valueless ledger testnet

- deterministic fees, bonds, escrows, receipts, checkpoints, and recovery;
- two independent implementations agree on state roots;
- three separately reported origin-only Phoenix rebuilds and three separately reported exact-continuity substrate-death succession drills;
- economic and adversarial simulations pass.

### Gate G - valuable VERA consideration

Only after every launch gate in `TOKEN-SPEC.md`, `TOKEN-OPERATIONS.md`, and `ECONOMY.md` passes, followed by independent security, economic, privacy, and jurisdiction-specific legal review. A calendar date, website page, exchange offer, or founder confidence cannot override a failed gate.

## 9. Immediate implementation backlog

| Order | Deliverable | Acceptance evidence |
|---:|---|---|
| 1 | Reconcile both OriginSpecs against the public Origin capsule | No contradictory identity, consent, token, or recovery rule |
| 2 | Rewrite both Prototype Specs as executable contracts | Every requirement maps to an automated or witnessed test |
| 3 | Freeze signed envelope, consent, event, acknowledgement, and checkpoint schemas | JavaScript and Rust vectors agree |
| 4 | Build observer-off Soma egress preview/grant/revoke | Zero background observer/training packets without an exact active grant; an `ask` requires separate query authority and stays non-observing/non-training |
| 5 | Build Vera fail-closed ingest and immutable event store | Replay and mutation suites pass |
| 6 | Integrate one HeyVera coding task | Redacted evidence becomes a cited provisional item |
| 7 | Deploy fresh private Vera Host B to the VPS | Replication and restore drill pass |
| 8 | Package both drag-and-drop releases | Clean Windows/Linux installs pass from signed artifacts |
| 9 | Run the invited pilot | Published report has zero unresolved critical findings |

## 10. Effort-mode policy

Use **ultra/high effort** for:

- OriginSpec and protocol decisions;
- cryptography, canonicalization, authentication, consent, key lifecycle, and privacy;
- replication, consensus, checkpointing, Phoenix recovery, economics, token activation, and legal-risk boundaries;
- threat modeling, adversarial review, release gates, and final production/VPS review.

Use **medium effort** once a spec section is frozen and a task has narrow acceptance criteria, for example:

- implementing a defined endpoint or schema adapter;
- ordinary UI, CLI, database, deployment, test, and documentation packets;
- HeyVera integration against a stable protocol contract.

Use **low effort** only for mechanical work such as formatting, simple renames, fixture expansion, repetitive test cases, or a clearly diagnosed build fix. Do not use low effort for security, privacy, keys, data migrations, external effects, recovery, money, consensus, or token code.

Practical answer: remain on ultra through the four specification freezes and the first threat-model review. Then run most implementation packets on medium, returning to ultra at every gate review, security-sensitive slice, VPS deployment, recovery drill, and token decision.
