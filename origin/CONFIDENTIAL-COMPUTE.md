# SOMAVERA SOVEREIGN AND CONFIDENTIAL COMPUTE PROFILES

Document ID: `somavera/confidential-compute/0.1-draft`
Status: **recommended architecture; not ratified; no confidential-compute claim is currently implemented**

## 1. Decision

Somavera uses a layered privacy architecture:

1. **Sovereign Local is the default.** Raw private work stays on the owner’s device. Soma classifies, minimizes, redacts, and derives the smallest useful object locally.
2. **Named Private Host is the practical first pilot.** Non-public queries, contributions, and answers use bidirectional recipient encryption, but the authorized Vera process and privileged host operator can observe plaintext while processing it.
3. **Attested Confidential Vera is the first stronger remote profile.** Soma releases a request key only to an ephemeral workload key whose hardware/software attestation, release measurement, policy, and freshness pass locally.
4. **MPC, secure aggregation, and FHE are specialized profiles.** They are used only for narrow computations with a published protocol, security model, performance result, and fallback. They are not the default general agent or LLM engine.

No profile is silently selected. A user sees the data class, destination, processing profile, retention, allowed derivation, recipient key, operator visibility, metadata exposure, and export behavior before sending.

## 2. What “end to end” means

For the normal Named Private Host profile, the endpoints are the owner’s Soma process and the exact authorized Vera ingest/processing worker:

    encrypted Soma store
      -> inner signed query/contribution
      -> recipient-encrypted outer envelope
      -> authenticated TLS
      -> proxy/relay/queue sees ciphertext
      -> exact Vera recipient worker decrypts in bounded memory
      -> signed answer/source bundle
      -> encrypted to the Soma return key bound by the query
      -> Soma decrypts, verifies, and stores encrypted locally

This protects bodies from network observers, reverse proxies, load balancers, queues, ordinary databases, backup theft, unintended peers, and the wrong host. It does not protect plaintext from compromised endpoints or a privileged ordinary host operator. It also does not hide IP addresses, timing, packet sizes, or communication relationships by itself.

For Attested Confidential Vera, the Vera endpoint narrows to the measured confidential workload. The surrounding host and administrator are outside the intended plaintext boundary, subject to the stated hardware, firmware, attestation, side-channel, availability, and supply-chain assumptions.

“End-to-end encrypted” MUST always name the endpoints and excluded metadata. It MUST NOT be used as an unqualified slogan.

## 3. Routing matrix

| Data/use | Default profile | Permitted shared effect |
|---|---|---|
| Local private agent work | Sovereign Local | None unless the owner creates a new authorized projection |
| Public artifact with verified redistribution rights | Named Private Host or public ingest | Quarantine, evaluation, and separately authorized public knowledge |
| Minimized non-sensitive work summary | Named Private Host | Only the exact consented host/federation state |
| Private query requiring remote compute | Attested Confidential Vera when available; otherwise explicit Named Private Host disclosure | Private response only; no training without a separate grant |
| Secret, signing key, recovery share, credential | Device-only/prohibited | Never sent to Vera |
| Regulated-sensitive or identity-linkage data | Device-only in v1 | Remote use prohibited until a separate reviewed profile exists |
| Public licensed model training | Transparent ordinary or attested workers | Versioned dataset/model artifact under its license |
| Aggregate across mutually distrustful hosts | MPC or secure aggregation | Only the published aggregate and proof/receipt |
| Narrow fixed inference over encrypted input | Experimental FHE/hybrid profile | Only the defined output and declared leakage |

Unavailable protection fails closed or routes to a less capable local workflow. It does not silently downgrade to a normal host.

## 4. Profile L0 — Sovereign Local

Required properties:

- raw private work, prompts, artifacts, credentials, questions, answers, and source bodies are encrypted at rest under user-controlled keys;
- signing, transport-encryption, store-encryption, credential, and recovery keys have separate purposes;
- private keys live in an OS/hardware keystore or ratified encrypted store;
- local inference and retrieval may operate without any Vera or HeyVera service;
- no analytics, update, model-provider, or observer traffic occurs by default;
- the user can export identity backup and Vera intelligence separately in open, verifiable formats;
- local model output remains untrusted and cannot change consent or authority.

This profile gives the strongest practical sovereignty because the owner controls the endpoint. Its limitations are device capability, local model quality, availability, backup discipline, and the owner’s operating-system threat model.

## 5. Profile L1 — Named Private Host

Required properties:

- exact host identity, origin, signing key, ingestion-encryption key, region, subprocessors, policy, and release are pinned;
- non-public inner application objects are separately encrypted to that ingestion key, in addition to authenticated TLS;
- every query binds a fresh or pairwise Soma return-encryption key, and Vera encrypts the complete signed answer bundle to it;
- fresh content-encryption material is used per envelope and recipient;
- intermediaries and durable storage contain ciphertext, not non-public bodies;
- the host validates the outer signed header, recipient, consent, audience, network/context, freshness, size, and suite before decryption;
- decryption occurs only in a bounded worker after pre-decryption validation;
- host-confidential plaintext never enters peer replication or public retrieval;
- a separate signed grant is required to create a public or training-eligible derivation;
- operator-memory visibility and traffic-metadata exposure are shown before use.

This is the first pilot profile because it is implementable and testable on ordinary hardware. It is not sufficient for users who cannot trust the selected operator with plaintext.

## 6. Profile L2 — Attested Confidential Vera

The minimum confidential-worker protocol is:

1. The release publishes source, reproducible image/build inputs, expected measurements, SBOM, security policy, and a transparency-log entry.
2. The confidential worker boots without a privileged debug mode and creates an ephemeral recipient key inside the measured environment.
3. The hardware produces fresh attestation evidence binding the workload measurements, security configuration, ephemeral key, nonce, and relevant CPU/GPU composition.
4. Soma or an independent local verifier validates the hardware certificate chain, evidence freshness, reference values, security version, revocation status, exact workload measurement, public transparency inclusion, and application policy.
5. Only after all checks pass does Soma encrypt the request key or body to the attested ephemeral key.
6. The worker decrypts in protected memory, applies the bounded declared computation, signs provenance, encrypts the result to Soma’s return key, and erases request keys and plaintext on completion.
7. No shell, debugger, crash dump, general log, operator RPC, swap, snapshot, or undeclared egress may expose plaintext.
8. Stateless processing is the default. Any retained encrypted state requires a separate consent grant, sealed-state design, rollback protection, and deletion/expiry evidence.

Attestation policy is fail-closed. Debug measurements, unknown firmware, stale endorsements, missing composite CPU/GPU evidence, evidence-factory ambiguity, rollback, transparency exclusion, measurement mismatch, expired reference values, or verifier disagreement block key release.

### 6.1 Independence requirements

Somavera MUST NOT make one cloud KMS, attestation service, hardware vendor, or HeyVera verifier the sole privacy authority. The profile therefore requires:

- a provider-neutral evidence/result model aligned with the RATS roles;
- at least one offline/open verifier path for every supported platform;
- independently mirrored reference values and revocation material;
- public reproducible workload measurements and append-only release transparency;
- multiple independently operated confidential hosts before calling the profile decentralized;
- at least two supported TEE families before calling it vendor-resilient;
- an owner-controlled device-only fallback.

Attestation proves claims about a measured environment under a hardware/vendor root. It does not prove the application is correct, the source matches an unreproducible image, the model answer is true, side channels are absent, the vendor never fails, or the operator will provide availability.

### 6.2 GPU inference

A CPU confidential VM does not automatically protect an attached GPU. A GPU workload must provide composable evidence for CPU/VM, GPU, driver, firmware/VBIOS, interconnect/switch where applicable, and the exact inference container/model policy. Soma releases keys only when the complete evidence graph passes.

## 7. Profile L3 — MPC and secure aggregation

MPC is preferred when several mutually distrustful operators must compute one narrow function without any one party learning all inputs, for example:

- threshold recovery or signing;
- private set intersection or deduplication;
- cross-host counts and bounded statistics;
- secure aggregation of explicitly authorized updates;
- a narrowly specified joint evaluation.

Every MPC profile MUST define the corruption threshold, semi-honest or malicious adversary, collusion assumption, abort/fairness behavior, input validation, leakage, authentication, transcript/proof, party discovery, network cost, and recovery. “Distributed” is not a security model.

General interactive LLM inference and training are not v1 MPC targets because communication, rounds, nonlinear functions, model scale, and operational complexity remain substantial. A benchmark on the exact model, hardware, geography, and adversary is required before exposing a feature to users.

Secure aggregation alone does not make gradients safe: updates can leak information and a malicious coordinator can manipulate cohorts. A later learning profile also needs clipping, contribution bounds, poisoning defenses, privacy evaluation, and—where claimed—an explicit differential-privacy budget.

## 8. Profile L4 — FHE or hybrid encrypted computation

FHE is appropriate only when the exact computation can run on ciphertext with acceptable latency, memory, cost, accuracy, and leakage. Each profile fixes:

- circuit/model and weights commitment;
- encryption parameters and claimed security level;
- key ownership and evaluation-key lifecycle;
- supported operations and approximation error;
- client interaction and any plaintext intermediate step;
- ciphertext expansion, latency, throughput, and failure limits;
- output verification and model-confidentiality assumptions.

Hybrid schemes that reveal activations or perform nonlinear layers on the client MUST state that leakage explicitly and undergo attack review. A faster research result does not make general open-ended agent execution private.

FHE remains experimental for Somavera until the exact useful workflow meets a user-visible service objective and independent cryptographic review. It MUST NOT block the local, normal-host, or attested-host paths.

## 9. Traffic-metadata profiles

Application encryption does not hide source IP, destination, timing, packet counts, approximate sizes, or repeated-use linkability.

Somavera SHOULD support three explicit modes:

- **Direct:** lowest latency; host sees client network metadata.
- **Relayed:** a non-colluding oblivious relay sees the client connection while the gateway sees plaintext only inside its recipient boundary; fixed request/response workloads may use an OHTTP-compatible design.
- **High privacy:** fixed-size padding buckets, batching/jitter, cover policy where justified, and Tor or a reviewed mix route; higher latency and weaker interactive streaming UX are disclosed.

The relay and gateway MUST be independently operated for the non-collusion claim to mean anything. Padding rules, logs, abuse controls, correlation limits, and fallback behavior are versioned and tested. A failed relay does not silently send directly.

## 10. Learning and the shared-intelligence boundary

Retrieval and provenance come before private-data training.

- Public, explicitly licensed artifacts may enter a versioned public corpus after quarantine and evaluation.
- Host-confidential data may support the user’s private query or private memory only within its grant; it does not enter global training.
- A public lesson is a new signed derived artifact with named sources, transformation, evaluator status, rights, uncertainty, and an explicit release grant.
- Private federated learning, gradients, activations, or model updates require a separate L3/L4 or attested-learning profile and cannot inherit ordinary observation consent.
- Model weights and “intelligence” are versioned artifacts with lineage, evaluation, rollback, and license—not an invisible accumulation inside one operator’s model account.

## 11. Real-person product experience

The product presents simple choices backed by the profiles:

| User choice | Meaning |
|---|---|
| Keep on my device | No remote body; local-only processing/export |
| Use a verified private worker | Key release only after attestation/transparency checks; no ordinary operator plaintext access under stated assumptions |
| Use this named host | Host can process plaintext; intermediaries/storage cannot; exact operator and retention disclosed |
| Contribute a public result | A separate previewed public derivation may replicate under its license |

Advanced details remain inspectable. Defaults never depend on users understanding acronyms.

## 12. Build order and stop rules

1. Finish L0 encryption, key separation, export, and zero-egress tests.
2. Finish L1 bidirectional envelopes, host disclosure, replication boundaries, and restore tests.
3. Pilot only non-sensitive data across L0/L1.
4. Build one L2 CPU confidential-worker adapter with local attestation verification, reproducible measurements, and transparency.
5. Add composite GPU evidence only after the CPU protocol and no-privileged-access design pass.
6. Add relayed metadata protection for bounded request/response flows.
7. Evaluate MPC/FHE only against named useful workloads and published service objectives.

Stop release on an unencrypted non-public body; plaintext in a proxy, queue, database, backup, log, or replication stream; key release before complete fresh attestation; debug or privileged access in a confidential profile; undeclared egress; traffic fallback from relayed to direct; unsupported remote handling of sensitive data; or any privacy claim stronger than the measured evidence.
