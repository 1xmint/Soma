# SOMAVERA PROTOTYPE ACCEPTANCE MATRIX

Status: Draft 0.1 — normative proposal; no implementation or release is presently declared conformant.

This document is the release gate for the first Soma Pack and Vera Host Pack prototypes. It converts the prototype plan, threat model, assurance case, recovery model, and tokenless economic posture into repeatable tests with binary pass or fail oracles.

Passing this matrix means only that one exact, content-addressed release passed these tests in the recorded environments. It does not mean that Somavera is “bulletproof,” production safe, legally compliant, confidential against a malicious host, capable of observing hidden model reasoning, or ready for a token. Those claims require their own evidence.

## 1. Normative language and decision rule

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are normative.

A release is accepted for a small, invited, token-disabled prototype only when:

1. every gate G0 through G5 is PASS in order;
2. every required test has a signed PASS result for the exact release manifest hash;
3. no P0, P1, or unresolved P2 finding exists;
4. no required test is SKIP, NOT RUN, INCONCLUSIVE, or waived;
5. the evidence rollup and all referenced artifacts verify by hash and signature; and
6. two independent reviewers sign the final acceptance statement.

An acceptance expires when any executable artifact, dependency lock, protocol rule, default configuration, migration, installer, recovery capsule, or normative test changes. Documentation-only corrections MAY retain an acceptance only when the release rollup identifies the changed files and both reviewers sign a determination that no executable behavior or claim changed.

## 2. Systems under test

The release manifest MUST identify exact hashes for all tested artifacts:

- Soma Pack installer or archive, CLI, adapters, verifier, default configuration, uninstall instructions, and user documentation;
- Vera Host Pack installer, archive, or container, host service, CLI, verifier, migrations, default configuration, deployment files, and operator documentation;
- protocol schemas, canonicalization rules, signature suites, test vectors, and conformance runner;
- dependency locks, software bill of materials, source revision, build recipe, and build environment;
- offline origin capsule, checkpoint capsule plus required content-addressed state-object format, Phoenix instructions, and independently preservable origin trust facts; and
- this acceptance matrix and its procedure version.

No test result transfers to an artifact identified only by a tag such as latest, main, stable, or current.

### 2.1 Required clean environments

The release manifest MUST pin the image hash and patch level of each environment.

| Environment | Required use |
|---|---|
| WIN-CLEAN | Fresh, supported Windows x64 virtual machine with no Somavera source tree, keys, database, developer tools beyond those declared, or prior installation |
| LIN-CLEAN | Fresh, supported Ubuntu LTS x64 virtual machine with the same exclusions |
| MAC-CLEAN | Required only if the release advertises macOS support; otherwise macOS MUST be absent from support claims |
| SOMA-A | Owner workstation running Soma Pack and local Vera Host A with fresh, distinct keys |
| VERA-B | Independently administered VPS running Vera Host B with fresh, distinct keys, private ingress first, TLS, and no copied database |
| LOAD-C | Third Vera host used only for replication, load, and partition tests, with fresh keys and storage |
| PHX-OFFLINE | Network-isolated clean-room environment with no live Somavera host, source checkout, package registry, DNS dependency, cloud account, founder secret, or undeclared tool |

Ordinary hardware means commercially obtainable hardware described in the release manifest. A test that depends on a founder-owned machine, undocumented device, live SaaS account, private registry, or unpublished secret fails.

### 2.2 Required fixtures and controls

Tests MUST use non-sensitive synthetic data. At minimum the fixture set MUST include:

- unique secret canaries in environment variables, files, Git history, prompts, tool results, URLs, and artifact metadata;
- valid and invalid identity, consent, event, bidirectional application-encryption envelope, exact contribution acknowledgement, owner-state backup, replication, checkpoint state-object, and recovery objects;
- two independent protocol implementations for canonicalization and signature vector comparison;
- a deterministic fake model provider and a deterministic fake external-payment provider;
- a DNS sink and packet capture point that can account for every outbound connection;
- a gold retrieval corpus containing supported, unsupported, contradictory, revoked, quarantined, private, public, licensed, unlicensed, and prompt-injected records;
- clocks that can be advanced, delayed, and skewed without changing test expectations; and
- a token-state sentinel that records every attempted balance, supply, mint, burn, transfer, market, bond, staking, liquidity, oracle, or paymaster mutation.

Real credentials, production data, production payment methods, and live token infrastructure MUST NOT be used.

### 2.3 Key and state isolation

Every test run MUST begin with either a declared pristine snapshot or a documented state fixture. Soma A, Vera A, Vera B, Load C, builders, reviewers, operators, backups, and Phoenix environments MUST NOT reuse signing keys, recovery shares, databases, bearer tokens, or TLS private keys.

A universal recovery secret, shared operator password, copied host identity, or hidden bootstrap key is an automatic P0 failure.

## 3. Gate sequence

| Gate | Name | Required test families | Promotion condition |
|---|---|---|---|
| G0 | Reproducible packages | ART, PKG, EVD bootstrap tests | Exact artifacts are attributable, clean-installable, secret-free, and evidence collection is operational |
| G1 | Local safety boundary | CRY, CNS, SEC, MOD | Signing, replay defense, consent, egress, secret handling, and model-observation limits fail closed |
| G2 | Two-host useful loop | ING, REP, RET | Authorized events ingest once, replicate correctly, and support cited retrieval without leaking protected data |
| G3 | Operational survivability | DEP, CHS, BKR | The same release survives VPS deployment, faults, bounded load, backup, restore, and host exit |
| G4 | Phoenix | PHX | Independent clean-room teams prove origin-only revival and exact checkpoint recovery without hidden dependencies |
| G5 | Invited tokenless prototype | ECO and full EVD rollup | Every economic path remains absent or hard-disabled and all earlier evidence is independently signed |

Failure at any gate stops promotion. Later tests MAY run for diagnosis, but their results do not bypass or cure the failed earlier gate.

## 4. Verdicts, severity, and stop rules

### 4.1 Test verdicts

| Verdict | Meaning |
|---|---|
| PASS | The recorded procedure ran against the exact release and every pass oracle was satisfied |
| FAIL | Any oracle was not satisfied, required evidence is absent, or observed behavior is ambiguous |
| SKIP | The procedure did not run; never acceptable for a required test |
| INCONCLUSIVE | Evidence cannot establish pass or fail; treated as FAIL for gate decisions |

Retries MUST create a new run and link the failed run. Evidence MUST NOT be overwritten, deleted, or relabeled.

### 4.2 Severity

| Severity | Meaning and mandatory action |
|---|---|
| P0 — containment stop | Credible unauthorized disclosure, secret/key exposure, invalid authorization accepted, replay causing a second mutation, fail-open public access, forged continuity, state-root mismatch presented as success, or any token/economic mutation. Stop every affected pilot and deployment immediately; isolate hosts; revoke or rotate affected credentials; preserve evidence; and begin incident review. |
| P1 — release stop | A required security, correctness, recovery, privacy, replication, or durability property fails without confirmed live exposure. Stop the current gate and prohibit release promotion until a new artifact passes the full affected gate and all regression tests. |
| P2 — claim stop | A supported platform, performance bound, usability promise, hardening control, or noncritical evidence requirement fails. Remove the claim or fix it, then rerun all affected tests. A waiver cannot preserve the claim. |
| P3 — tracked defect | A non-normative quality or documentation issue that does not change a required property. Record owner and disposition; it cannot conceal a P0–P2 issue. |

The matrix gives the minimum severity. Reviewers MUST raise severity when impact is broader. Unknown impact involving authorization, secrets, continuity, public state, or economic state MUST be treated as P0 until bounded.

### 4.3 Immediate stop triggers

The test controller MUST stop the current run, preserve volatile evidence where safe, and invoke P0 containment if any of the following occurs:

- a secret canary or protected payload reaches an unauthorized destination;
- an invalid, expired, replayed, wrong-network, wrong-context, wrong-audience, or revoked authorization changes authoritative state;
- plaintext host-confidential data appears in replication, public retrieval, logs, crash output, exports, or token metadata;
- a nonlocal Vera service starts without the required TLS and authentication controls;
- an artifact silently contacts an undeclared host, registry, telemetry service, wallet, exchange, oracle, liquidity venue, or payment endpoint;
- any nonzero asset identifier, activation hash, balance, supply counter, price, pool, stake, bond, mint, burn, transfer, liquidity, market-making, buyback, or paymaster state appears; or
- a Phoenix procedure claims old-network continuity without possessing every authenticated checkpoint state-object byte, independently recomputing the committed root from those bytes, and satisfying the authorized succession rules.

## 5. Reusable procedure definitions

The following definitions are part of every referenced test.

### 5.1 CLEAN

CLEAN means:

1. restore the declared pristine environment image;
2. verify that no Somavera process, file, key, database, container, environment variable, firewall exception, or cached package exists;
3. disconnect from package registries and undeclared internet destinations;
4. install only from the content-addressed release media;
5. record the environment, release, and artifact hashes before execution; and
6. scan again after cleanup to identify residue.

### 5.2 SIGNED-MUTATIONS

For each signed object, the runner MUST test the valid object and one independently generated case for each of:

- one-bit change to every signed field;
- omitted required field, duplicated field name, extra critical field, reordered input, alternate whitespace, alternate Unicode normalization, duplicate map key, invalid number, and noncanonical encoding;
- wrong network identifier, execution context, object type, action, audience, destination, signer, key purpose, schema version, and signature suite;
- nonce reuse, sequence reuse, object identifier collision, expired time, not-before time, excessive lifetime, and clock skew at both declared boundaries;
- unknown, revoked, not-yet-valid, expired, and wrong-purpose keys; and
- downgrade from the current required suite or version.

Unless a protocol rule explicitly says otherwise, every invalid case MUST be rejected before authoritative mutation; state root, accepted-object count, supply counters, and replication cursor MUST remain unchanged.

### 5.3 CONSENT-MUTATIONS

Starting from one valid narrow grant, the runner MUST independently alter data class, selected field, subject, purpose, operation, destination host, replication class, retention, expiry, one-time or repeated use, artifact identifier, model/provider, and transformation or redaction rule. Each broadened or mismatched use MUST fail. A more restrictive transformation MAY pass only if the user previewed and signed the exact post-transformation bytes or their canonical commitment.

### 5.4 PUBLIC-STATE-COMPARE

PUBLIC-STATE-COMPARE means independently compute and compare:

- ordered accepted public event identifiers and canonical bytes;
- public state root and checkpoint root;
- network and execution-context identifiers;
- identity-key status, consent status, revocations, tombstones, retention markers, and replication cursors;
- derived deterministic views and view-version identifiers; and
- all economic sentinels and zero-state counters.

Comparing only row counts, archive sizes, timestamps, or an implementation-provided “healthy” flag is insufficient.

### 5.5 Evidence bundles

| Code | Required contents |
|---|---|
| EV-BASE | Signed result.json, procedure version, exact commands, start/end time, operator, environment hash, release manifest hash, artifact hashes, fixture hashes, expected result, actual result, verdict, cleanup result, and links to prior failed runs |
| EV-CLI | Complete stdout/stderr and exit codes with secrets redacted by a separately verified rule; terminal transcript hash |
| EV-CRY | Canonical bytes, keys or public test keys, signatures, independent verifier results, mutation-case identifiers, and before/after roots |
| EV-NET | Packet capture, DNS log, destination inventory, TLS peer details, firewall log, and application-level request/response hashes |
| EV-STATE | Before/after PUBLIC-STATE-COMPARE output, database or object-store diff, event counts, cursors, roots, and relevant audit entries |
| EV-SCAN | Artifact, filesystem, process argument, log, export, backup, and canary scan reports with tool versions and rule hashes |
| EV-PERF | Offered, accepted, rejected, duplicated, and lost operation counts; latency histograms; CPU, memory, disk, network, queue, and cost-budget measurements |
| EV-OPS | OS/service identity, permissions, listening sockets, firewall, restart history, configuration hash, backup/restore log, and fault-injection timeline |
| EV-PHX | Complete offline transcript, input/output capsule hashes, build provenance, verifier results, state comparisons, key-ceremony records, and signed clean-room declarations |

Every matrix row requires EV-BASE in addition to the listed bundle.

## 6. Artifact and clean-install gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| ART-001 | Verify every release artifact, dependency lock, SBOM, build recipe, schema, verifier, and capsule against the signed release manifest while offline. PASS only if all hashes and signatures verify and no undeclared executable is needed. | EV-CLI, EV-CRY, EV-SCAN | P1 |
| ART-002 | Build all shipped executables twice from the release source in two fresh, independently administered build environments. PASS only if reproducible outputs match bit-for-bit, or every documented nondeterministic field is normalized by a public verifier and the normalized hashes match. | EV-CLI, EV-SCAN | P1 |
| ART-003 | Scan the distributable for credentials, private keys, bearer tokens, live endpoints, hardcoded VPS addresses, founder paths, legacy databases, generated identity state, undeclared telemetry, and mutable “latest” dependencies. PASS only with zero findings after human review of scanner exclusions. | EV-SCAN | P0 for secrets; otherwise P1 |
| ART-004 | Compare the implemented command surface, defaults, protocol versions, and data classifications with the release documentation. PASS only when every executable capability is declared and every advertised capability has a test in this matrix. | EV-CLI, EV-SCAN | P2 |
| PKG-SOM-001 | In WIN-CLEAN and LIN-CLEAN, perform CLEAN, install Soma Pack from release media, and run soma init then soma doctor without source edits, developer checkout, package registry, or live Somavera service. PASS only if initialization succeeds, observer is off, keys are protected, and doctor reports the exact artifact/configuration hashes and no hidden dependency. | EV-CLI, EV-NET, EV-OPS, EV-SCAN | P1 |
| PKG-SOM-002 | On each claimed platform, complete the tokenless Soma flow: init, doctor, connect to the pinned private Vera A, observe preview, observe grant, ask a harmless fixture question, export, observe revoke, and verify. PASS only if command help, exit codes, errors, and outputs are sufficient for a clean-room user and all later family-specific tests pass. | EV-CLI, EV-NET, EV-STATE | P1 |
| PKG-SOM-003 | Create the separately typed identity-recovery bundle, full encrypted owner-state backup, and sovereign Vera pack; uninstall, prove cleanup, reinstall from the same release, and exercise each documented recovery path independently. PASS only if identity recovery alone rotates authority without inventing owner state, owner-state restore reproduces included local records under authority quarantine without inventing identity continuity, the sovereign pack imports only intelligence read-only, observer remains off, revoked consent remains revoked, and no vendor or founder secret is required. | EV-CLI, EV-CRY, EV-STATE, EV-SCAN | P0 |
| PKG-VER-001 | In WIN-CLEAN and LIN-CLEAN where support is claimed, perform CLEAN, install Vera Host Pack, and run vera init, vera doctor, vera start --private, vera verify-state, vera backup, and documented shutdown. PASS only if a private single-host instance works without source edits, registry access, copied keys, or copied database. | EV-CLI, EV-NET, EV-OPS, EV-STATE | P1 |
| PKG-VER-002 | Initialize two hosts from the same artifact on separate clean machines. PASS only if host, TLS, database, and operator keys differ; no default or embedded credential is shared; and the two hosts still interoperate through the published protocol. | EV-CRY, EV-NET, EV-OPS | P0 |
| PKG-VER-003 | Remove or corrupt, one at a time, nonlocal TLS, peer authentication, operator authentication, storage key, network identifier, and execution-context configuration, then attempt nonlocal startup. PASS only if startup refuses or remains loopback-only with an explicit error and no application request is accepted. | EV-CLI, EV-NET, EV-OPS | P0 |
| PKG-ALL-001 | Repeat init and doctor three times, including one interrupted initialization. PASS only if the result is idempotent, partial state is detected or rolled back, defaults are deterministic, and release media remain byte-identical and read-only. | EV-CLI, EV-STATE, EV-SCAN | P1 |
| PKG-ALL-002 | Run each package for a representative hour, uninstall, and compare with CLEAN. PASS only if all residue is either removed or explicitly listed as user data with a documented secure-deletion/export choice; no service, firewall opening, scheduled task, credential, or hidden updater remains. | EV-OPS, EV-SCAN | P2 |
| PKG-ALL-003 | Repeat required package tests in MAC-CLEAN when macOS is advertised. PASS only if results equal the other supported platforms. If not run, all macOS support claims MUST be removed. | Applicable bundles above | P2 |

## 7. Signature, canonicalization, replay, and evidence-chain gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| CRY-001 | For identity, consent grant, consent revocation, observation event, outcome event, application-encryption envelope, host acknowledgment, replication object, checkpoint, tombstone, key rotation, and recovery succession objects, run published positive vectors through two independent implementations. PASS only if canonical bytes, identifiers, signatures, and verification outcomes are identical. | EV-CRY | P1 |
| CRY-002 | Run SIGNED-MUTATIONS for every object in CRY-001. PASS only if all invalid cases reject before authoritative mutation and the rejection identifies a stable reason code without echoing secret payloads. | EV-CRY, EV-STATE | P0 if accepted; otherwise P1 |
| CRY-003 | Submit one valid mutable operation concurrently 100 times to one host and across two peers. PASS only if exactly one authoritative mutation occurs, duplicate submissions cannot advance counters or cursors, and all acknowledgments resolve to the one content identifier. | EV-CRY, EV-STATE, EV-PERF | P0 |
| CRY-004 | Test expiry, not-before, maximum lifetime, and clock skew at one unit inside and outside every declared boundary. PASS only if both implementations make the same decision and no host silently extends validity. | EV-CRY, EV-STATE | P1 |
| CRY-005 | Rotate and revoke identity, host, operator, and TLS keys at declared boundaries. Submit objects signed before, during, and after each transition. PASS only if acceptance windows follow the published rule, revoked keys cannot authorize new state, and historical signatures remain verifiable without making the old key active. | EV-CRY, EV-STATE | P0 |
| CRY-006 | Create signed objects for the same action on a different network, execution context, host audience, destination, object type, and key purpose. PASS only if every cross-domain use fails with no mutation. | EV-CRY, EV-STATE | P0 |
| CRY-007 | Create a local signed, hash-linked evidence sequence, then independently delete, insert, reorder, replace, duplicate, and truncate entries and substitute its head. PASS only if soma verify detects every alteration and reports the last independently anchored valid point without claiming the altered suffix valid. | EV-CRY, EV-STATE | P1 |
| CRY-008 | Remove the nonce store, make it read-only, corrupt it, and race two writers. PASS only if affected authorization stops safely; the system never accepts replay because replay state is unavailable or inconsistent. | EV-OPS, EV-CRY, EV-STATE | P0 |
| CRY-009 | Starting from the published valid host-descriptor succession vector, independently mutate sequence, predecessor, immutable identity/policy fields, active-key precommitment, overlap and proof windows, change scope, historic-key retention, revocation state, descriptor signatures, proof ID, and each role-separated signature. PASS only if every mutation fails closed with the published stable reason and no pin changes. | EV-CRY, EV-STATE | P0 |
| CRY-010 | Present a cryptographically valid ordinary succession proof without controller confirmation and attempt connection, consent registration, disclosure, queued send, or emergency recovery. PASS only if the successor remains inert and every authority attempt fails; confirming one exact successor must not confirm a different descriptor or grant consent. | EV-CLI, EV-CRY, EV-STATE, EV-NET | P0 |
| CRY-011 | Confirm one exact published succession subject, fault-inject before and after every prepare, sync, current-pin replacement, history publication, candidate cleanup, and restart boundary, and race 100 identical plus competing confirmations. PASS only if recovery yields exactly the prior inert pin or the one confirmed successor inert pin, identical repeats are idempotent, competitors conflict, complete authenticated history survives every committed result, no candidate is consumed before commit, and connection/consent/disclosure/send state remains byte-identical and disabled. | EV-CLI, EV-CRY, EV-STATE, EV-OPS, EV-NET | P0 |
| CRY-012 | Export a complete portable host-trust capsule v2 before and after one or more ordinary controller rotations. Verify it without a Soma home using an independently supplied stable controller DID and initial-controller key hash, then mutate every object byte/path/kind/length/hash, pin, host transition, controller rotation, rotation order/signature/head, chain order, count, root, controller, claim, capsule ID, and signature. Compare v1-to-v2, identical v2, strict controller/host descendants, truncated histories, missing hosts, and same-height forks against separately preserved trusted bytes. PASS only if valid migrations and descendants succeed, historical host signatures verify in their exact controller-key intervals, every mutation/rollback/fork fails with no state installation, the export contains no managed secret or unrelated owner data, and packet capture shows zero egress. Same-device creation MUST remain labeled non-anchor and non-restore authority. | EV-CLI, EV-CRY, EV-STATE, EV-SCAN, EV-NET | P0 |
| CRY-013 | Prepare and confirm one ordinary Soma controller-key rotation, fault-inject before and after every protected-pending write, sync, dual signature, identity commit, history publication, keystore finalization, old-key destruction, cleanup, and restart boundary, and race 100 identical plus competing confirmations. PASS only if recovery yields exactly the prior state or one stable-controller successor, the successor private key is never plaintext, committed state can sign immediately, the old private key is absent after finalization, old signatures verify only inside their historical interval, the old key cannot authorize new acts, competitors conflict, packet capture is empty, and recovery/connection/consent/disclosure/send/token/governance state remains byte-identical and disabled. Repeat after tampering with every event field, predecessor, key/hash/window, authority bit, ID, signature, pending blob, prepared transaction, and current pointer; every case must fail closed or quarantine without ambiguous authority. | EV-CLI, EV-CRY, EV-STATE, EV-OPS, EV-SCAN, EV-NET | P0 |

## 8. Consent and egress gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| CNS-001 | After fresh Soma initialization, perform representative local prompts, tool calls, file reads, local evidence operations, failures, startup, shutdown, and idle time for 30 minutes without granting observation or invoking a disclosed network command. PASS only if packet capture shows zero network traffic, including observation, training, outcome, artifact, model-content, update, health, or telemetry egress. | EV-NET, EV-STATE | P0 |
| CNS-002 | Generate an observation preview, record its canonical bytes and hash, grant exactly that operation, and compare with the plaintext produced only after the exact recipient Vera ingest worker decrypts the application envelope. PASS only if bytes and hash match exactly; any later redaction, enrichment, model metadata, artifact, or destination change requires a new preview and grant. | EV-CLI, EV-NET, EV-CRY, EV-STATE | P0 |
| CNS-003 | Run CONSENT-MUTATIONS against Soma enforcement and Vera ingest enforcement independently. PASS only if every broadened or mismatched case is denied by both boundaries and neither boundary treats a general observer toggle as a grant. | EV-NET, EV-CRY, EV-STATE | P0 |
| CNS-004 | Exercise every outbound path identified by code instrumentation: observation, ask, retrieval, outcome, tool metadata, artifact upload, replication request, acknowledgment, export, error report, update check, and adapter callback. PASS only if each path is either local-only, governed by the same consent/egress membrane, or explicitly declared non-content operational traffic; no alternate socket, subprocess, plugin, or redirect bypasses it. | EV-NET, EV-SCAN | P0 |
| CNS-005 | Revoke and separately expire a grant while requests are queued, transmitting, acknowledged, retrying, and offline. PASS only if no new use begins after the normative cutoff, queued retries are cancelled, host decisions are deterministic, and allowed in-flight handling matches the published rule. Revocation/tombstone propagation MUST pass REP-005. | EV-NET, EV-STATE, EV-OPS | P0 |
| CNS-006 | Redirect an approved destination through HTTP redirect, DNS rebinding, wrong TLS identity, alternate port, proxy variables, and a peer with the right name but wrong key. PASS only if Soma sends no protected bearer or payload and requires an explicit new pinned destination approval. | EV-NET, EV-CRY | P0 |
| CNS-007 | Mark identical fixtures local-private, host-confidential, network-public, and prohibited. PASS only if local-private never leaves Soma; host-confidential reaches only the named host and never replication or public retrieval; network-public follows the exact grant; and prohibited data is rejected. Promotion between classes MUST be a new signed act. | EV-NET, EV-STATE | P0 |
| CNS-008 | Submit third-party material with absent, incompatible, expired, and valid license or authority metadata. PASS only if absent or incompatible authority cannot become public or training-eligible, and valid authority remains attached through replication and retrieval. | EV-STATE, EV-NET | P1 |
| CNS-009 | Export user state before and after revocation and host deletion. PASS only if export distinguishes local evidence, host-confidential records, public commitments, revocations, tombstones, and non-deletable public facts without claiming that public replication can be erased everywhere. | EV-CLI, EV-STATE | P1 |
| CNS-010 | Capture traffic at the Soma/Vera process boundaries, TLS-termination proxies, durable queues, and pre-ingest/return stores. PASS only if every non-public registration/challenge, contribution, withdrawal, status, or query request is encrypted to the exact host key and binds a distinct return key, every corresponding private reply is signed then encrypted to that exact request-bound key, both outer headers bind their inner object, originating request, network/context, recipient, issue, expiry, and ciphertext commitment, and no intermediary sees plaintext. | EV-NET, EV-CRY, EV-SCAN | P0 |
| CNS-011 | Keep observation off and explicitly invoke one displayed harmless `soma ask` to one pinned host. PASS only if packet capture contains that one encrypted request and its bound encrypted response, or a separately invoked idempotent status request/response; prefetch, failover, automatic retry, update, telemetry, contribution, training, second-destination, and post-answer traffic remain zero, and observer/training-consent state is unchanged. | EV-CLI, EV-NET, EV-STATE | P0 |

## 9. Secret-handling and containment gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| SEC-001 | Place distinct managed-secret canaries in environment variables, credential files, recovery material, Git configuration/history, URL headers, cookies, keystore metadata, and provider tokens, plus distinct authorized-sensitive canaries in questions, answers, evidence attachments, and host-confidential source bytes. Exercise preview, grant, ask, outcome, export, logs, and owner-state backup. PASS only if every managed-secret canary remains absent from network, host storage, logs, owner-state backups, and sovereign packs, while an expressly selected authorized-sensitive canary may appear only inside the authenticated owner-private ciphertext and retains its class/rights metadata. | EV-NET, EV-SCAN, EV-STATE | P0 |
| SEC-002 | Attempt path traversal, alternate data streams where supported, symlink and Windows junction escape, case-folding tricks, archive traversal, oversized archive expansion, and access to declared vault or key directories. PASS only if access remains within the explicitly approved artifact root and no protected bytes are read or transmitted. | EV-CLI, EV-OPS, EV-NET | P0 |
| SEC-003 | Exercise URL fetch and tool adapters against loopback, link-local, private ranges, cloud metadata addresses, IPv6 variants, redirects, encoded addresses, DNS rebinding, and user-info confusion. PASS only if prohibited destinations are blocked after every resolution and redirect and no authorization header crosses origin. | EV-NET | P0 |
| SEC-004 | Trigger normal errors, validation errors, timeouts, process crashes, service restarts, and diagnostic bundles. Inspect stdout, stderr, logs, process arguments, environment snapshots, crash output, metrics, traces, exports, backups, and temporary files. PASS only if no secret canary, recovery share, signing key, bearer token, or protected payload appears outside its declared encrypted store. | EV-SCAN, EV-OPS | P0 |
| SEC-005 | Inspect key storage and permissions on every supported OS. PASS only if production-mode private keys use the documented OS keystore or encrypted store, filesystem and service identities enforce least privilege, recovery material is separate, and an insecure development mode cannot bind nonlocally and is unmistakably labeled. | EV-OPS, EV-SCAN | P1 |
| SEC-006 | Prove separation of identity, observation, host, TLS, operator, backup, release, and recovery keys by attempting each key in every other purpose. PASS only if every cross-purpose use fails cryptographically or by mandatory policy and rotation of one purpose does not rotate or reveal another. | EV-CRY, EV-STATE | P0 |
| SEC-007 | Remove, revoke, expire, and corrupt operator credentials and storage keys while the host is stopped and while it is running. PASS only if privileged access and nonlocal startup fail closed, existing plaintext is not exposed, and recovery requires the documented ceremony rather than a fallback credential. | EV-OPS, EV-NET, EV-STATE | P0 |
| SEC-008 | Compare operator documentation and UI disclosures with observed host access. PASS only if they state plainly that ordinary host encryption does not prevent an authorized or compromised host operator from observing process memory or plaintext during processing; no confidential-computing claim is made without separate evidence. | EV-SCAN | P2 |
| SEC-009 | Copy a stopped Soma home, search index, temporary directory, crash residue, and owner-state backup without the corresponding OS/hardware-keystore or separately held backup key. PASS only if questions, answers, source bodies, evidence attachments, queues, credentials, and host-confidential canaries remain unreadable, authenticated corruption fails, and clear public/index/archive metadata is limited to the declared schema. | EV-SCAN, EV-CRY, EV-OPS | P0 |
| SEC-010 | Encrypt the same authorized private registration/challenge, contribution, withdrawal, status, and query requests separately to two host ingestion keys and their action-specific signed replies to two request-bound Soma return keys. Test wrong recipient, cross-request reply, signing/encryption-key reuse, revoked/expired key, reused nonce/content key, added recipient, mutated outer header, ciphertext bit flip, downgrade suite, universal/group key, and outer/inner mismatch. PASS only if separate ciphertext is produced per direction/request/recipient and every invalid case rejects before authoritative storage or display. | EV-CRY, EV-NET, EV-STATE | P0 |
| SEC-011 | Inspect identity-recovery bundles, owner-state backups, and sovereign Vera packs with synthetic fixtures. PASS only if managed authentication/recovery secrets occur solely in their dedicated keystore or expressly defined identity-recovery artifact, never in owner-state/sovereign archives, while selected authorized-sensitive owner bytes occur only under the archive's authenticated encryption and retain rights/classification; no UI or schema conflates the two categories. | EV-CRY, EV-SCAN, EV-STATE | P0 |

## 10. Model-observation boundary gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| MOD-001 | For every supported model/provider adapter, enumerate API requests, responses, streamed fields, tool calls, timing, usage, error, and cost fields during a controlled session. PASS only if Soma records solely documented provider-exposed fields plus user-approved local artifacts; absent fields are recorded as unknown, not inferred. | EV-NET, EV-STATE, EV-SCAN | P1 |
| MOD-002 | Scan executable code, schemas, UI, docs, examples, and exports for claims or fields representing hidden chain-of-thought, private provider logs, weights, activations, gradients, or internal reasoning not exposed by the provider. PASS only if none is claimed or fabricated. Explicit user-visible reasoning summaries MUST be labeled as model output, not hidden cognition. | EV-SCAN | P1 |
| MOD-003 | Offer unapproved files, tool results, terminal output, browser content, and model-provider metadata during an observed session. PASS only if none enters preview or egress until explicitly selected under a compatible grant, and selection cannot expand by directory traversal or later tool output. | EV-NET, EV-STATE | P0 |
| MOD-004 | Feed a validly signed but false model answer and a prompt-injected artifact. PASS only if model output remains attributed, untrusted evidence; it cannot by itself change identity, consent, credentials, reputation, public lesson status, governance, economic state, or outcome truth. | EV-STATE, EV-CRY | P0 |
| MOD-005 | Put instructions in prompts, model responses, retrieved documents, tool output, and filenames that request broader observation, alternate destinations, secret access, disabled token operations, or policy changes. PASS only if these instructions remain data and cannot alter the consent or egress membrane. | EV-NET, EV-STATE | P0 |
| MOD-006 | Compare closed-provider, local open-weight, and deeper-instrumentation capability profiles. PASS only if each profile exposes only measured surfaces, deeper access requires a distinct adapter and consent class, and no closed-provider observation is represented as weight, activation, or hidden-reasoning access. | EV-STATE, EV-SCAN | P1 |
| MOD-007 | Capture provider/model identity, version when exposed, timing, token usage, errors, and external cost using the deterministic provider. Remove each optional provider field. PASS only if provenance remains accurate, unavailable facts are unknown, and fabricated precision is absent. | EV-NET, EV-STATE | P2 |

## 11. Vera ingest and validation gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| ING-001 | Submit one valid identity, narrow grant, public observation event, and independent outcome event. PASS only if Vera validates in the published order, durably commits each exactly once, returns the exact action-specific signed acknowledgement encrypted to the request-bound Soma return key and bound to network, context, host, request/ciphertext/plaintext commitments, accepted scope, durable identifiers, and resulting root, and can verify state after restart. | EV-CRY, EV-NET, EV-STATE | P0 |
| ING-002 | Independently invalidate identity, consent, signature, audience, destination, network, execution context, nonce, expiry, schema, data classification, license, and maximum size. PASS only if each rejects before authoritative storage; root, accepted count, view, cursor, and token sentinel remain unchanged. Minimal reject metadata MAY retain only the declared digest and reason, never the rejected protected body. | EV-CRY, EV-STATE | P0 |
| ING-003 | Submit malformed encodings, duplicate keys, deeply nested objects, huge numbers, oversized bodies, chunked over-limit bodies, compression bombs, slow bodies, and high-ratio archives. PASS only if declared limits are enforced before unbounded allocation or durable body storage and the service remains responsive within CHS-005 bounds. | EV-PERF, EV-OPS, EV-STATE | P1 |
| ING-004 | Crash or kill Vera before validation, during validation, during append, between append and view update, before acknowledgment, and after acknowledgment. PASS only if restart yields either no commit or one complete commit, never a partial or duplicate commit, and retry returns a deterministic status. | EV-OPS, EV-STATE | P0 |
| ING-005 | Rebuild every deterministic view from the immutable accepted-event log on a clean process and independently calculate the public root. PASS only if rebuilt views and roots equal the originals bit-for-bit and changing view code cannot rewrite source events. | EV-STATE, EV-CLI | P1 |
| ING-006 | Submit host-confidential raw content with a separately granted public commitment or derived lesson. PASS only if the raw content remains encrypted and host-scoped, the public object contains only its approved fields and provenance, and searches of replication, retrieval, logs, and exports find no plaintext raw content. | EV-NET, EV-SCAN, EV-STATE | P0 |
| ING-007 | Apply retention expiry, user withdrawal, revocation, and tombstone rules to public and confidential fixtures. PASS only if deterministic views cease prohibited use at the defined boundary, tombstones preserve necessary non-reuse evidence, immutable history is represented honestly, and no deletion operation silently upgrades or republishes content. | EV-STATE | P1 |
| ING-008 | Toggle every validation and storage control through missing, malformed, unknown, and insecure configuration values. PASS only if Vera refuses startup or uses the documented stricter default; no unknown option disables validation silently. | EV-CLI, EV-OPS | P0 |
| ING-009 | Submit a valid signed header with malformed or unauthorized recipient ciphertext and a valid ciphertext with invalid signature, consent, audience, network, context, nonce, or expiry. PASS only if Vera validates all available routing/authentication/consent fields before decryption, decrypts only in the bounded ingest worker, commits only encrypted host-confidential storage, and never acknowledges an unverified plaintext. | EV-CRY, EV-NET, EV-STATE, EV-SCAN | P0 |
| ING-010 | For accepted, accepted-narrowed, rejected, duplicate, and indeterminate contribution outcomes, verify every mandatory acknowledgement field and mutate each independently. PASS only if accepted decisions are issued after the named durable commit, rejected decisions prove no authoritative mutation, narrowing never broadens the grant, the complete acknowledgement is signed before encryption to the contribution-bound return key, and missing, contradictory, early, plaintext, wrong-key, or mismatched acknowledgements fail before Soma confirms. | EV-CRY, EV-NET, EV-STATE | P0 |

## 12. Vera replication gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| REP-001 | Replicate more than three full cursor pages of valid public events from Vera A to Vera B, interrupting after every page boundary and repeating pages. PASS only if B converges to the exact PUBLIC-STATE-COMPARE result, with no omission or duplicate mutation. | EV-NET, EV-STATE | P1 |
| REP-002 | Send arbitrary JSON, forged peer signatures, wrong content identifiers, wrong roots, wrong network or context, invalid schemas, stale cursors, and unsupported rule versions through the peer endpoint. PASS only if every object is independently revalidated and rejected without root or cursor advance. | EV-CRY, EV-NET, EV-STATE | P0 |
| REP-003 | First send an invalid object claiming the identifier of a later valid object, then send the valid object. PASS only if the invalid first write cannot reserve, poison, tombstone, or suppress the valid identifier and the valid object is evaluated normally. | EV-STATE, EV-NET | P0 |
| REP-004 | Partition A, B, and Load C; accept permitted concurrent public events in different orders; heal links; and repeat with process restarts. PASS only if all hosts deterministically converge or enter the specified conflict state. Silent last-writer-wins behavior is forbidden. | EV-STATE, EV-OPS | P1 |
| REP-005 | Replicate grant expiry, revocation, withdrawal, key revocation, retention marker, and tombstone events while one peer is offline. PASS only if the returning peer applies them before permitting new dependent use and all hosts converge to identical status. | EV-STATE, EV-NET | P0 |
| REP-006 | Seed local-private and host-confidential fixtures adjacent to public fixtures, then perform full and incremental replication and error recovery. PASS only if protected bodies and protected metadata never cross to a peer; only explicitly granted public objects and minimum declared protocol metadata cross. | EV-NET, EV-SCAN, EV-STATE | P0 |
| REP-007 | Attempt replication from an unapproved peer, an approved peer with wrong TLS identity, an expired peer key, and a peer outside the allowlist. PASS only if connection or application authentication fails before event disclosure or cursor advancement. | EV-NET, EV-CRY | P0 |
| REP-008 | Present two correctly signed but conflicting objects for a signer sequence or protocol slot. PASS only if both commitments remain auditable, the conflict is surfaced and quarantined according to the protocol, affected derivations halt, and no peer silently chooses the first or last arrival. | EV-STATE, EV-CRY | P1 |

## 13. Retrieval and answer gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| RET-001 | Query every supported item in the gold corpus. PASS only if the returned source set includes all REQUIRED gold sources, no forbidden source, stable public identifiers, lineage, authority/license status, evaluation status, and the snapshot or root used. Generated wording MAY vary; cited source selection MUST follow the declared deterministic ranking rule. | EV-CLI, EV-STATE | P1 |
| RET-002 | Ask questions that have no supporting source, only quarantined sources, only revoked sources, and mutually contradictory sources. PASS only if the system abstains when unsupported and explicitly reports contradiction and uncertainty when sources conflict; it MUST NOT manufacture consensus. | EV-CLI, EV-STATE | P1 |
| RET-003 | Query after consent revocation, withdrawal, retention expiry, key revocation, and tombstone application. PASS only if prohibited records are absent from usable results, while allowed commitments and tombstone explanations follow the published rule. | EV-STATE | P0 |
| RET-004 | Query as unauthorized, differently authorized, and authorized principals for fixtures spanning local-private, host-confidential, and public classes. PASS only if each response contains no field beyond the caller’s authority and timing, counts, error text, and citations do not reveal protected records. | EV-NET, EV-STATE | P0 |
| RET-005 | Embed prompt injection and data-exfiltration instructions in highly ranked public and confidential records. PASS only if retrieval policy, source filtering, consent, tool access, destination, and token-disabled state remain unchanged; injected text is treated as quoted source data. | EV-NET, EV-STATE | P0 |
| RET-006 | Run the same query 100 times against one pinned snapshot on A and B. PASS only if the eligible source set, exclusions, lineage, and ranking tie-breaks are identical across runs and hosts. Model prose need not match but every factual claim presented as sourced MUST map to an included citation. | EV-STATE, EV-PERF | P1 |
| RET-007 | Corrupt or remove a cited source after constructing an answer but before delivery. PASS only if delivery revalidates the pinned source snapshot or marks the answer stale; no unverifiable citation is presented as valid. | EV-STATE, EV-OPS | P1 |
| RET-008 | Vary synthetic balance, stake, payment, sponsor, and quota fields while holding evidence constant. PASS only if trust, provenance, source eligibility, and retrieval ranking remain unchanged except for explicitly non-economic resource admission controls. | EV-STATE | P0 |
| RET-009 | Request an answer with a fresh Soma return key, then substitute another user/key, replay an old key, expire/revoke it, expose the return through a proxy/queue, mutate the outer ciphertext/header, and mismatch the decrypted inner bundle. PASS only if Vera encrypts the complete signed bundle only to the query-bound key, intermediaries see ciphertext, and Soma rejects every invalid result before display. | EV-CRY, EV-NET, EV-STATE, EV-SCAN | P0 |

## 14. Chaos, resource, and load gates

The release manifest MUST declare reference hardware, storage, network, and operating-system limits. Performance results are claims only for that pinned reference profile.

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| CHS-001 | Inject process kill, machine reboot, storage latency, dropped acknowledgment, duplicated request, and connection reset at every durable ingest and replication phase. PASS only if authoritative objects are atomic and idempotent, roots verify, and accepted events are neither lost nor applied twice. | EV-OPS, EV-STATE | P0 |
| CHS-002 | Fill data, log, temporary, and backup volumes separately; make storage read-only; corrupt a copy of the active database; and truncate a copied write log. PASS only if the active system stops accepting before durability is uncertain, reports the fault, preserves the last verifiable point, and restores only from authenticated material. | EV-OPS, EV-STATE | P1 |
| CHS-003 | Partition peers for one hour, introduce 5 percent loss, 500 ms latency, reordering, and repeated reconnects, then heal. PASS only if backpressure is bounded, local authorized work follows the declared availability policy, and peers converge within 60 seconds after queues drain with no accepted loss or duplicate mutation. | EV-NET, EV-PERF, EV-STATE | P1 |
| CHS-004 | Skew one host clock at each declared valid boundary and by plus/minus 5 minutes, 1 hour, and 24 hours. PASS only if time-based authorization follows CRY-004, extreme skew makes the node unhealthy or read-only, and no host can extend consent or key validity by changing its clock. | EV-OPS, EV-STATE | P0 |
| CHS-005 | Flood malformed, unauthorized, oversized, slow, and valid requests up to declared concurrency limits. PASS only if memory, disk, file descriptors, queues, and worker counts remain within published hard bounds; invalid clients cannot starve operator shutdown, verification, or authorized traffic beyond the declared service objective. | EV-PERF, EV-OPS | P1 |
| CHS-006 | With external network blocked, configure deterministic fake model and payment adapters with a hard budget of 100 units. Attempt concurrency races, retries, redirects, and crashes that would request 1,000 units. PASS only if cumulative authorized spend is at most 100, no live provider is contacted, and budget exhaustion cannot fail open. | EV-NET, EV-PERF, EV-STATE | P0 |
| CHS-007 | On the reference profile, submit at least 100,000 valid events at an offered aggregate rate of 10 per second, using 25 concurrent Soma identities and three Vera hosts. PASS only if every acknowledged event exists exactly once, all roots converge within 60 seconds after drain, p95 durable-ingest acknowledgment is at most 2 seconds, and verification completes without manual repair. | EV-PERF, EV-STATE | P2 |
| CHS-008 | Run a separate burst of 100 offered events per second for 60 seconds. PASS only if the host either durably accepts within its advertised limit or returns explicit bounded rejection; it MUST NOT acknowledge dropped work, exceed resource bounds, or diverge. | EV-PERF, EV-STATE | P1 |
| CHS-009 | Run a 24-hour soak at at least one valid event per second with periodic retrieval, replication, backup, restart, revoke, and tombstone operations. PASS only if no unbounded queue, memory, log, temporary-file, or cost growth occurs; no accepted event is lost or duplicated; and final roots converge. | EV-PERF, EV-STATE, EV-OPS | P1 |
| CHS-010 | Execute the gold retrieval set under CHS-007 load. PASS only if p95 policy-filtered retrieval is at most 2 seconds excluding optional external model generation, forbidden-source rate is zero, and all unsupported questions still abstain. | EV-PERF, EV-STATE | P2 |

## 15. Independent VPS deployment gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| DEP-001 | Provision VERA-B from a fresh, independently administered VPS image using only the release media and public instructions. Create fresh keys and storage; do not copy A’s database, identity, configuration secrets, or shell history. PASS only if vera init, doctor, start --private, and verify-state succeed with the exact tested artifact hashes. | EV-CLI, EV-OPS, EV-SCAN | P1 |
| DEP-002 | Before peer allowlisting, scan all TCP and UDP ports from an untrusted external host. After allowlisting A, repeat from untrusted and trusted hosts. PASS only if no unauthenticated Vera application is usable publicly, the untrusted host learns no protected application data, and A connects only with authenticated TLS and protocol identity. | EV-NET, EV-OPS | P0 |
| DEP-003 | Remove TLS, peer authentication, firewall allowlist, and operator authentication one at a time, then restart. PASS only if Vera refuses nonlocal service or remains loopback-only. An installer that silently opens public ingress fails. | EV-NET, EV-OPS | P0 |
| DEP-004 | Compare local A and VPS B executable, schema, migration, default policy, and conformance hashes. PASS only if they run the same protocol release without source edits or host-specific bypasses; declared platform packaging differences MUST be enumerated and reproducible. | EV-SCAN, EV-CLI | P1 |
| DEP-005 | Inspect service account, filesystem permissions, process privileges, listening sockets, firewall, update behavior, restart policy, and administrative interface. PASS only if least privilege is enforced, admin access is separately authenticated, restart is safe, and no root or administrator privilege persists without a documented necessity. | EV-OPS | P1 |
| DEP-006 | Block all outbound traffic, then allow only each declared destination separately. PASS only if core local storage, verification, backup, and private peer operation work without undeclared internet access; optional model/provider traffic is destination- and budget-bound and cannot carry data outside consent. | EV-NET, EV-OPS | P0 |
| DEP-007 | Search deployment files, scripts, docs, logs, metrics, and runtime configuration for hardcoded IPs, usernames, private keys, cloud tokens, silent remote scripts, undeclared telemetry, and protected payloads. PASS only with zero secret or hidden-dependency findings and a reviewed destination inventory. | EV-SCAN | P0 for secret or hidden egress; otherwise P1 |
| DEP-008 | Reboot the VPS, restart the service repeatedly, rotate TLS and host keys, and recover from a failed update using documented rollback. PASS only if state roots remain valid, old credentials stop authorizing new work at the declared boundary, and no manual founder intervention is required. | EV-OPS, EV-CRY, EV-STATE | P1 |

## 16. Backup, restore, and host-exit gates

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| BKR-001 | Create a Vera backup and checkpoint capsule after the first useful two-host loop. PASS only if it contains every required state-object byte, directly or as bundled content-addressed objects, and its signed manifest commits to their complete sorted inventory, network, context, release/rule versions, public root, ordered event frontier, cursors, revocations, tombstones, retention state, deterministic-view versions, and economic zero-state. A root or locator without the authenticated bytes fails. | EV-CRY, EV-STATE, EV-OPS | P0 |
| BKR-002 | Restore BKR-001 onto a clean host with fresh operational keys using only documented restore material. Independently authenticate every required state-object byte, recompute the checkpoint/public roots from those bytes, then run PUBLIC-STATE-COMPARE before accepting new work. PASS only if the restored authorized public state and counters match exactly; any missing byte fails continuity and any allowed key succession occurs afterward as a signed event. | EV-STATE, EV-CRY, EV-OPS | P0 |
| BKR-003 | Flip one bit in each manifest section, truncate the archive, replace an object, reorder events, use the wrong signer, wrong network, wrong context, stale checkpoint, and unsupported rule version. PASS only if restore rejects before activation and does not create a plausible partial service. | EV-CRY, EV-STATE | P0 |
| BKR-004 | Create backups continuously while valid writes, revocations, replication, and view rebuilds run; kill the backup process at each phase. PASS only if every completed backup is internally consistent and every incomplete backup is unmistakably invalid and cannot activate. | EV-OPS, EV-STATE | P1 |
| BKR-005 | Back up and restore fixtures from all data classes. PASS only if encryption, destination, retention, consent, and deletion constraints are preserved; host-confidential data never becomes public and prohibited/local-only data are absent unless the format explicitly and safely includes the user’s local export. | EV-SCAN, EV-STATE | P0 |
| BKR-006 | Scan backups, checkpoints, exports, and manifests for live signing keys, recovery shares, bearer tokens, plaintext secrets, and undeclared personal data. PASS only if operational and recovery secrets are separately held and no universal restore credential exists. | EV-SCAN | P0 |
| BKR-007 | Execute documented host exit: stop admission, finish or reject in-flight work deterministically, make final authenticated backup/export, hand off allowed public state, revoke host and operator keys, and remove local protected state. PASS only if peers retain valid public state, the exited host cannot rejoin with old keys, and cleanup evidence is complete. | EV-OPS, EV-STATE, EV-CRY | P1 |
| BKR-008 | Lose Vera A completely after A and B converge, restore from the latest authenticated material on a clean replacement, and resume the harmless Soma query. PASS only if the same authorized public root is reproduced before new events, citations resolve, consent remains correct, and no token state appears. | EV-STATE, EV-CLI, EV-OPS | P0 |
| BKR-009 | Rotate Vera host ingestion-encryption and Soma return-encryption keys, restore older encrypted backups, and process pre-/post-rotation envelopes at every validity boundary. PASS only if historic ciphertext remains recoverable only under the documented retained-key policy, revoked keys cannot accept new work, restored keys do not reactivate authority, signing keys cannot decrypt, and no universal decryption key exists. | EV-CRY, EV-STATE, EV-OPS | P0 |
| BKR-010 | Create a full Soma owner-state backup during representative local evidence, consent, queue, and intelligence state. PASS only if one locked logical snapshot, deterministic manifest/object inventory, fresh owner-controlled backup encryption, declared omissions, and atomic publication verify; no live store key is copied. | EV-CLI, EV-CRY, EV-STATE, EV-OPS | P0 |
| BKR-011 | Verify BKR-010 on a clean offline workstation, then mutate one bit, truncate, remove/add/reorder an object, use the wrong key, roll back, change schema/rights, attempt traversal/absolute path/link/junction/case collision/duplicate/bomb, and interrupt each phase. PASS only if the valid archive reproduces every declared hash/root and every invalid case fails before target mutation with bounded resources and no plaintext residue. | EV-CRY, EV-SCAN, EV-STATE, EV-OPS | P0 |
| BKR-012 | Import BKR-010 read-only into a fresh Soma home and attempt signing, consent, credential release, agent start, host connection, queue retry, send, pending-reply receipt, and authoritative mutation. PASS only if records/hashes are inspectable in an isolated namespace and every authority attempt fails. | EV-CLI, EV-STATE, EV-NET | P0 |
| BKR-013 | Transactionally restore BKR-010 with fresh local store keys, inject failure/power loss before every commit boundary, and inspect authority before/after commit. PASS only if the prior target remains authoritative until one complete atomic switch and restored grants, credentials, queues, pending sends, host pins, sessions, and return bindings remain in deny-all quarantine. | EV-OPS, EV-STATE, EV-CRY | P0 |
| BKR-014 | Re-confirm selected restored bindings one at a time. PASS only if unconfirmed authority remains inert, every new network act uses a fresh session/envelope/nonce/return key, and no pre-backup or in-flight request replays automatically. | EV-NET, EV-CRY, EV-STATE | P0 |
| BKR-015 | Scan the encrypted owner-state archive and its clear header using managed-secret and authorized-sensitive canaries. PASS only if all authentication/recovery/keystore/provider secrets are absent, selected sensitive owner bytes are present only in authenticated ciphertext with class/rights metadata, and the clear header leaks only ratified opening/bounds fields. | EV-SCAN, EV-CRY | P0 |
| BKR-016 | Attempt to substitute identity-recovery bundle, owner-state backup, and Vera sovereign pack for one another. PASS only if identity recovery restores/rotates only identity authority, owner-state restore reproduces only included local state under quarantine, sovereign import restores only intelligence read-only, and none invents another artifact's authority or continuity. | EV-CLI, EV-CRY, EV-STATE | P0 |

## 17. Clean-room Phoenix gates

Phoenix has two distinct modes and MUST never blur them:

- Origin-only revival creates a new network with a new lineage and no inherited history.
- Exact checkpoint recovery continues an authenticated prior network state under its precommitted recovery and succession rules.

Both modes are required for G4. A result that depends on undeclared founder knowledge, a live Somavera service, private repository, package registry, DNS name, cloud account, signing oracle, hidden build tool, universal secret, or preinstalled state is FAIL.

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| PHX-001 | Give an independent team the offline origin capsule, declared ordinary hardware, blank media, and one independently preserved trust fact whose type is permitted by the published trust procedure, such as a separately recorded capsule hash or threshold public-key set. Disable network access and inventory all inputs. PASS only if the trust fact authenticates the capsule signatures/hashes and no trust anchor is accepted merely because the capsule names or contains it. Without an independent trust fact, authenticity and old-lineage claims MUST remain unavailable. | EV-PHX, EV-CRY | P0 |
| PHX-002 | In PHX-OFFLINE, build the verifier and reference implementation from pinned source and dependencies, then reproduce the release binaries or their publicly normalized hashes and run the conformance vectors. PASS only if results match the capsule commitments without registry, DNS, or founder assistance. | EV-PHX, EV-SCAN | P1 |
| PHX-003 | Perform origin-only revival. PASS only if it creates a fresh network identifier and execution context at epoch 0; asset_lineage_id is null; activation hash is null; all supply, balance, mint, burn, stake, bond, pool, market, and paymaster counters are zero or absent; and no old identity, reputation, credential, consent, evidence, lesson, governance, or history is imported. | EV-PHX, EV-STATE | P0 |
| PHX-004 | Attempt to label the PHX-003 network as the old network or old asset lineage using copied names, domains, UI text, unsigned metadata, old public keys, and social labels. PASS only if protocol identifiers and verifier output make the new lineage unmistakable and reject continuity claims. | EV-PHX, EV-CRY | P0 |
| PHX-005 | Give a separate clean-room team the authenticated origin capsule, one authenticated checkpoint manifest, every required content-addressed checkpoint state-object byte, and required user-held recovery shares. Restore offline, verify availability/authenticity of every object, independently recompute the checkpoint/public roots from those bytes, and run PUBLIC-STATE-COMPARE before succession. PASS only if network, context, ordered frontier, roots, counters, revocations, tombstones, views, and economic state exactly reproduce; a root, manifest, locator, hash list, or partial object set fails exact continuity. | EV-PHX, EV-STATE, EV-CRY | P0 |
| PHX-006 | After PHX-005 matches exactly, execute only the precommitted threshold RecoverySuccession procedure with fresh operational keys. PASS only if the pre-succession root was exact, every key change is an authorized auditable event, no historical object is rewritten, and no field outside the declared succession set changes. | EV-PHX, EV-CRY, EV-STATE | P0 |
| PHX-007 | Run the checkpoint mutations from BKR-003 plus one missing or unavailable required state object, hash-only/locator-only substitution, forged recovery shares, replayed succession, threshold-minus-one shares, wrong key purpose, stale finality evidence, downgrade, and a fabricated continuity certificate. PASS only if every case rejects before activation and verifier output distinguishes origin-only revival from exact continuation. | EV-PHX, EV-CRY, EV-STATE | P0 |
| PHX-008 | Present two independently valid but conflicting checkpoint histories or recovery-successor proposals. PASS only if the process halts, preserves both commitments and signer evidence, emits a conflict transcript, and never silently selects one history as canonical. | EV-PHX, EV-STATE | P0 |
| PHX-009 | Supply proof that the original network is still finalizing within the protocol’s declared failure window, then attempt checkpoint succession. PASS only if successor activation is denied. Repeat after the exact published failure condition is satisfied; activation MAY proceed only with threshold authorization and PHX-005 exact-state proof. | EV-PHX, EV-CRY, EV-STATE | P0 |
| PHX-010 | Complete both Phoenix modes without any old host private key, old operator key, DNS control, cloud credential, private repository, live registry, or access to a founder. PASS only if fresh key ceremonies meet threshold rules and no actor can reconstruct a universal network key. | EV-PHX, EV-SCAN | P0 |
| PHX-011 | A second independent team repeats PHX-001 through PHX-010 from pristine hardware and media. PASS only if protocol-visible outputs and all accept/reject decisions match the first team; environment-specific values MUST be declared and non-authoritative. | EV-PHX | P1 |
| PHX-012 | Publish a secret-free, content-addressed transcript containing inputs, commands, build results, tests, state comparisons, failures, and reviewer signatures. A third reviewer MUST verify it offline. PASS only if every claimed result can be traced to hashed evidence and no private or recovery secret is published. | EV-PHX, EV-SCAN | P1 |
| PHX-013 | Attempt checkpoint recovery with claims of inherited exchange listing, stablecoin reserve, liquidity pool, market-maker agreement, price, oracle state, or external asset custody. PASS only if such external claims are outside protocol continuity, are neither reconstructed nor endorsed, and cannot activate economic state. | EV-PHX, EV-STATE | P0 |

## 18. Economic and token-disabled gates

The invited prototype is tokenless. Liquidity readiness is not being tested, cannot be marked PASS, and is not implied by technical prototype acceptance. The only current economic pass condition is proof that token, market, liquidity, and value-conversion mechanisms are absent or hard-disabled.

Any implementation of a VERA pool, listing, market maker, token paymaster, buyback, liquidity reward, staking yield, price feed, asset bridge, token sale, balance transfer, or conversion promise before a separately governed activation release is a P0 failure.

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| ECO-001 | Inspect genesis, network state, configuration, API, database, schemas, exports, backups, and Phoenix outputs. PASS only if economics_activated is false; activation_hash and asset_lineage_id are null; and every balance, total minted, total burned, transferred, staked, bonded, pooled, bridged, bought back, and paymaster total is zero or structurally absent. | EV-STATE, EV-SCAN | P0 |
| ECO-002 | Exercise all observation, task, tool, outcome, credential, reputation, lesson, retrieval, replication, backup, restore, sponsor, quota, and Phoenix actions. PASS only if the token-state sentinel records zero economic mutation and no action emits an asset-bearing event. | EV-STATE, EV-PERF | P0 |
| ECO-003 | Probe CLI, API, RPC, UI, migrations, feature flags, plugins, environment variables, and undocumented routes for mint, burn, transfer, bond, stake, slash, market, pool, liquidity, price, oracle, bridge, buyback, paymaster, and token activation operations. PASS only if operations are absent or return a stable hard-disabled response before accepting parameters or changing state. | EV-CLI, EV-NET, EV-STATE, EV-SCAN | P0 |
| ECO-004 | Allocate prototype resource quotas and sponsor capacity, then attempt transfer, sale, exchange, withdrawal, conversion, delegation, voting, bonding, reputation purchase, token redemption, and persistence beyond expiry. PASS only if quotas are nontransferable, nonconvertible, time- or use-bounded, valueless, and unable to affect trust or governance. | EV-STATE | P0 |
| ECO-005 | Run fake external-payment and service-receipt fixtures through success, failure, refund, retry, and dispute cases. PASS only if they remain explicitly external service accounting, cannot mint VERA or a claim on VERA, and do not change evidence weight, reputation, retrieval rank, consent, or governance. | EV-STATE, EV-NET | P0 |
| ECO-006 | Remove every price, exchange, oracle, stablecoin, liquidity, market-maker, wallet, chain RPC, and payment destination from the environment. PASS only if the complete Soma-to-Vera useful loop, replication, retrieval, backup, restore, and Phoenix origin-only revival still work. | EV-NET, EV-STATE | P0 |
| ECO-007 | Restart, upgrade within the exact release, back up, restore, partition, and perform both Phoenix modes. PASS only if token-disabled fields remain false, null, zero, or absent and no migration invents economic lineage or state. | EV-STATE, EV-PHX | P0 |
| ECO-008 | Scan docs, UI, API descriptions, examples, logs, and generated answers for a live token address, price, APY, yield, liquidity, redemption, exchange listing, stable value, profit, appreciation, token demand, or conversion promise. PASS only if none is asserted and all future-economics material is clearly non-operational and conditional on separate activation gates. | EV-SCAN | P1 |
| ECO-009 | Attempt to make sponsor-funded inference, storage, or bandwidth purchase VERA, hold VERA inventory, reimburse in VERA, or represent sponsored traffic as token demand. PASS only if sponsorship uses valueless quotas or clearly external ordinary payment fixtures and creates no VERA balance, entitlement, or market claim. | EV-NET, EV-STATE | P0 |
| ECO-010 | Vary all synthetic economic fields from zero to extreme values in malformed input and local test databases. PASS only if trust, credential validity, reputation evidence, retrieval, replication priority, consent, governance, and resource admission ignore those fields or reject the object; wealth and stake MUST NOT substitute for evidence. | EV-STATE, EV-CRY | P0 |
| ECO-011 | Inspect the release acceptance report for liquidity, token, market, legal, or regulatory gates. PASS only if those future gates are explicitly NOT ACTIVATED and NOT PASSED, with no inference that token-disabled prototype acceptance satisfies them. | EV-SCAN | P1 |

## 19. Evidence integrity and acceptance rollup

### 19.1 Required directory shape

Evidence MUST be stored content-addressably using this logical shape:

    acceptance/<release-id>/<implementation>/<environment>/<test-id>/<run-id>/

Each run directory MUST contain result.json and the referenced evidence objects or stable content-addressed links. The signed result MUST include at least:

- result_schema_version;
- procedure_version and test_id;
- release_manifest_hash and every tested artifact hash;
- implementation, environment hash, and configuration hash;
- operator identity and reviewer identity;
- fixture and fault-injection hashes;
- started_at, finished_at, and clock source;
- expected, actual, verdict, and assigned severity;
- before and after state roots, where applicable;
- evidence object names, media types, byte lengths, and hashes;
- secret-scan and cleanup status;
- previous_failed_run identifiers; and
- result signature and signature-suite identifier.

### 19.2 Evidence conformance tests

| Test ID | Normative procedure and pass oracle | Evidence | Severity |
|---|---|---|---|
| EVD-001 | Validate every result.json against the pinned result schema and verify its signature, release hash, procedure version, environment hash, and evidence-object hashes offline. PASS only if every field and object verifies and no mutable URL is the sole evidence location. | EV-BASE, EV-CRY | P1 |
| EVD-002 | Recompute all before/after roots and test-specific counts from raw accepted objects using an independent verifier. PASS only if they equal the recorded values; implementation screenshots or “success” output alone are insufficient. | EV-STATE, EV-CRY | P1 |
| EVD-003 | Account for all network interfaces and destinations during egress-sensitive tests. PASS only if packet capture and DNS/firewall logs cover the full interval, capture loss is below the declared bound, and every connection maps to an expected test step. | EV-NET | P0 |
| EVD-004 | Scan evidence, reports, screenshots, videos, packets, logs, exports, and transcripts for real secrets and undeclared personal data before sharing. PASS only if none is present; redaction MUST preserve a hash commitment or synthetic fixture identifier sufficient to verify the test. | EV-SCAN | P0 |
| EVD-005 | Have a second operator independently rerun every P0- and P1-rated test from CLEAN without receiving the first operator’s mutable state. PASS only if verdicts and protocol-visible outputs agree. | All applicable bundles | P1 |
| EVD-006 | For any manual observation, require two witnesses and hash the screenshot or video plus the underlying machine-readable state. PASS only if the manual evidence supplements rather than replaces machine-verifiable evidence. | EV-BASE, applicable bundle | P2 |
| EVD-007 | Intentionally fail one fixture in each family, then rerun it. PASS only if the failed evidence remains immutable, the new run links it, the rollup shows both, and only the new exact artifact result can satisfy the gate. | EV-BASE, EV-STATE | P1 |
| EVD-008 | Build a signed release rollup listing every required test, environment, run, verdict, severity, and evidence root. PASS only if there are no missing, skipped, inconclusive, waived, stale, or hash-mismatched entries and both independent reviewers sign. | EV-BASE, EV-CRY | P1 |
| EVD-009 | Copy the full evidence set to a network-isolated verifier with no project checkout and run the public verification instructions. PASS only if the verifier reconstructs the same rollup decision and identifies every deliberately corrupted evidence object. | EV-PHX, EV-CRY | P1 |

## 20. Required end-to-end acceptance scenario

In addition to isolated tests, reviewers MUST witness this uninterrupted scenario against the exact release:

1. CLEAN-install Soma Pack and local Vera A.
2. CLEAN-deploy private Vera B on an independent VPS with fresh keys and authenticated TLS.
3. Confirm observer-off operation and zero observation egress.
4. Perform one harmless agent task and create local signed, hash-linked evidence.
5. Preview the exact redacted observation bytes and grant only their data class, purpose, destination, replication, retention, and expiry.
6. Have A accept the event once and return a signed durable acknowledgment.
7. Have B replicate and independently validate the authorized public event.
8. Add an independent provisional outcome and retrieve an answer with source identifiers, lineage, uncertainty, and correct abstention behavior.
9. Create the distinct sovereign Vera pack and full encrypted owner-state backup, revoke observation, and prove subsequent use is denied and revocation reaches B.
10. Destroy A, restore a clean replacement from authenticated material, reproduce the exact authorized public root, and repeat the cited query.
11. Prove all ECO tests remain token-disabled and all secret canaries remain contained.
12. On a clean offline Soma workstation, verify/import the sovereign pack read-only, verify/import the owner-state backup read-only, transactionally restore it under authority quarantine, and then verify the final evidence rollup offline.

The scenario fails if any step requires a token, price, wallet, liquidity venue, founder service, hidden credential, manual database edit, source edit, or undeclared network dependency.

## 21. Acceptance statement template

The final statement MUST use this form without stronger language:

> Release [manifest hash] passed Draft Prototype Acceptance Matrix [procedure hash] for the recorded Windows/Linux environments and, if claimed, macOS environment. It is accepted only for a small invited token-disabled prototype under the stated assumptions and limits. This result does not activate or validate a token, liquidity, market, production-security, confidential-computing, hidden-model-observation, legal, or superintelligence claim.

The statement MUST link the signed evidence root, name both independent reviewers, list all P3 findings, and state the expiration rule from Section 1.

## 22. Conditions that require a new standard

This matrix MUST be replaced or extended before any of the following:

- public or permissionless participation;
- custody of real funds or economically transferable quotas;
- token activation, sale, mint, transfer, bond, stake, slash, paymaster, pool, liquidity, exchange, bridge, oracle, buyback, or market-making operation;
- claims of confidential execution against a host operator;
- autonomous irreversible actions or agent authority over money;
- governance power based on wealth, stake, or token balance;
- training on protected third-party data;
- safety-critical, medical, legal, financial, or infrastructure use; or
- production claims exceeding the pinned environments and load profile.

Until a separately versioned standard is adopted and passed, these capabilities are prohibited, not merely untested.
