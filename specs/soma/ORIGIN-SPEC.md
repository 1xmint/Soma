# SOMA MODULE ORIGIN SPEC

Document ID: soma/origin/0.1-draft
Status: **draft; not a ratified protocol and not evidence of an implemented system**
Module: Soma Pack, the local authority, evidence, consent, and sovereign-intelligence client for Somavera
Companion build contract: PROTOTYPE-SPEC.md

This document is the human-readable recovery root for the Soma module. It is subordinate to the repository-root ORIGIN-SPEC.md, DATA-RIGHTS.md, THREAT-MODEL.md, GOVERNANCE.md, RECOVERY.md, ID-DERIVATION.md, and the ratified release manifest. A module implementation MUST NOT use this document to weaken a right or security boundary in those documents.

## 0. Normative language and status

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are interpreted as described by RFC 2119 and RFC 8174.

This draft specifies intended behavior. It does not claim that the July 2026 prototype, any legacy Soma repository, or any future implementation conforms. Conformance exists only for an exact release whose schemas, test vectors, artifacts, independent review, and acceptance results satisfy this document and PROTOTYPE-SPEC.md.

Where this document conflicts with a repository-root constitutional document, the stricter privacy, security, user-rights, or continuity rule governs until a ratified amendment resolves the conflict. Unknown versions, fields, data classes, purposes, operations, algorithms, or authority claims MUST fail closed.

## 1. Recovery pickup

If only this document and the repository-root Phoenix capsule survive, the surviving bytes still do not authenticate themselves. A verifier MUST begin from at least one independently preserved trust fact, such as a previously recorded capsule hash, a separately retained threshold-signing key set, or independently held matching copies whose provenance satisfies the ratified trust procedure. Without that outside fact, the material may be inspected and used to create a new disclosed implementation or lineage, but it MUST NOT be represented as the authentic old release.

1. Verify the capsule and this document against the independent trust fact before executing recovered software.
2. Rebuild a local Soma verifier, key manager, evidence ledger, consent engine, Vera client, and sovereign export tool in that order.
3. Run every positive and adversarial vector before connecting to a host.
4. Start with the observer disabled and no remembered destinations.
5. Create a new local identity unless a user supplies a separately preserved, authenticated, encrypted identity-recovery bundle.
6. Import Vera intelligence only from an independently verifiable sovereign pack or a licensed public artifact.
7. Never infer or recreate lost private keys, consent, identity continuity, evidence, reputation, private work, or intelligence bytes.

This document restores rules and behavior. It cannot restore user secrets or state that did not survive in an authenticated user-controlled backup.

## 2. Mission and boundary

Soma is the local body through which an owned agent can:

- maintain an exportable cryptographic identity and bounded authority;
- use credentials through a least-privilege local broker;
- record attributable evidence without presenting attribution as truth;
- let the owner preview and explicitly authorize limited Vera observation;
- submit an authorized contribution to a pinned Vera host and verify its acknowledgement;
- retrieve Vera intelligence with sources, provenance, service metadata, uncertainty, and rights;
- preserve an exact local copy of received intelligence and export it without dependence on one host.

A Soma Pack is a portable release containing a command-line client, local verifier, policy and consent engine, key-store integration, evidence ledger, constrained adapter/broker, and export tooling.

Soma is not:

- a Vera host, learning service, model, ledger node, or token wallet;
- proof that an agent is human, unique, competent, truthful, safe, or independent;
- a universal reputation score;
- an entitlement to third-party data or model internals;
- an unbypassable security boundary merely because an SDK or CLI was installed;
- a substitute for operating-system isolation, a secure keystore, an independent verifier, or lawful data rights.

"Drag-and-drop" means a clean release can be verified, unpacked, initialized, and used without source edits or founder infrastructure. It does not mean copying a live development directory containing keys, state, machine paths, or credentials.

## 3. Immutable Soma invariants

A conforming Soma release MUST preserve all of these rules:

1. **Observation is off by default.** Installation, initialization, agent use, Vera use, token ownership, or silence is never consent.
2. **Observer-off is meaningful.** With observation disabled, Soma emits zero observation, contribution, outcome-learning, artifact, watcher, model/tool telemetry, or training traffic. An intentional `soma ask` is a separate, foreground network act: it MAY send only the exact displayed recipient-encrypted query and its minimum disclosed transport/routing metadata to the selected pinned host, and MAY receive only its bound encrypted response or status. Asking never enables observation and never creates consent for retention beyond the displayed query policy, evaluation, model training, derivation, redistribution, or public release. It MUST NOT trigger prefetch, background retry, update checking, telemetry, contribution, or any second destination. Other explicit user-requested connect, export-sync, key-status, or update operations are separate acts and MUST disclose their exact egress before execution.
3. **The agent still works without observation.** Refusing observation MUST NOT invalidate identity, reduce reputation, block local evidence, prevent export, or surrender control of the agent.
4. **One egress gate.** Every data-emitting adapter, watcher, outcome path, background task, and plugin MUST use the same fail-closed consent, destination, redaction, and size checks.
5. **No implicit promotion.** A general observer switch never changes private or host-confidential material into federated-training or public material.
6. **No secret egress.** Signing keys, recovery material, credentials, authentication tokens, private vault values, and secret-class data MUST never enter prompts, observations, evidence payloads, logs, crash reports, exports, or release artifacts.
7. **No prohibited v1 classes.** Private work is denied unless a later ratified protocol explicitly permits a narrow profile. Regulated-sensitive and identity-linkage data are prohibited in v1.
8. **Preview before grant and send.** The owner MUST be able to inspect the exact canonical application payload and all governing metadata before granting or transmitting it.
9. **Purpose limitation.** Retrieval does not authorize evaluation or training; evaluation does not authorize redistribution; training does not authorize public release.
10. **Destination limitation.** A grant applies only to the exact named host identities and origins. Redirects or endpoint substitution MUST NOT expand it.
11. **Future revocation.** Withdrawal stops future collection, processing, derivation, training, and redistribution by conforming parties and requests deletion where technically and legally possible.
12. **Honest irreversibility.** Soma MUST warn that public copies, finalized commitments, backups inside a disclosed window, and trained influence may not be reliably erasable.
13. **Identity is not a key.** Identity continuity survives only through ratified rotation or precommitted recovery. A new key generated after total loss is a new identity unless a valid recovery authority proves succession.
14. **No universal recovery secret.** Recovery rotates authority under user-precommitted rules; it never reconstructs or publishes a lost user secret.
15. **Evidence is not truth.** A signature proves that a key asserted bytes. A local zero exit code, self-report, or model statement is not an independent outcome.
16. **Trust is contextual.** Wealth, token holdings, fees, and stake MUST NOT increase identity assurance, factual confidence, reputation, observer priority, or learning priority.
17. **Sovereign return.** Received Vera intelligence MUST be retained in an open, documented format with its source, rights, and verification status, and MUST be exportable without contacting the original host.
18. **No silent networking.** A clean install MUST NOT contact a host, analytics service, update service, model provider, DNS name, or founder system until the user invokes a disclosed network action.
19. **Degraded means visible.** Missing keystore, release verification, secure transport, host authentication, clock reliability, schema support, or evidence integrity MUST produce an explicit degraded or failed status; checks MUST NOT silently soften.
20. **Exit remains possible.** The user can verify, export, disconnect, uninstall, and choose another conforming implementation.
21. **Sensitive local state is encrypted.** Private work, questions, answers, host-confidential material, credentials, queues, and identity-recovery material MUST be encrypted at rest under user-controlled keys kept outside ordinary state files. File permissions remain mandatory and are not replaced by encryption.
22. **Application bodies use bidirectional recipient encryption.** Every non-public application action, including a contribution, withdrawal, private registration or challenge, status lookup, and query, MUST contain an inner signed application object encrypted to the exact authorized Vera Host ingestion key and MUST bind a distinct pairwise or ephemeral Soma return-encryption key for that request. Vera MUST sign each corresponding acknowledgement, deletion/withdrawal/tombstone receipt, registration result, challenge result, status result, answer bundle, or private error before encrypting it to that exact request-bound return key. Public descriptors and content-free transport errors are the only v1 exceptions. Authenticated TLS remains mandatory. Reusing signing keys for encryption, one universal decryption key, a nonce/content key across recipients, silently adding a recipient, or returning a private body in plaintext is forbidden.

## 4. Architecture and trust boundary

The minimum local architecture is:

    Human controller
      |
      | authorizes identity, capabilities, consent, and queries
      v
    Soma local control plane
      +-- OS/hardware keystore
      +-- identity and key history
      +-- capability and credential broker
      +-- signed local evidence ledger
      +-- consent, membrane, redaction, and secret-scanning engine
      +-- pinned-host registry and authenticated client
      +-- encrypted Vera intelligence store and sovereign exporter
      |
      +-- constrained agent/model/tool adapter
      |
      +-- authenticated TLS --> named Vera host

Soma has two honest operating modes:

- **Integrated mode:** an external agent calls Soma APIs or commands but may retain other networking and credentials. This mode is useful instrumentation and is bypassable. It MUST NOT be described as an enforced body.
- **Brokered mode:** Soma launches or mediates an agent in an OS-enforced profile where approved credentials and effects are available only through the broker. This reduces bypass by the child process. It does not protect against a privileged local administrator, kernel compromise, hardware compromise, or an owner deliberately running the agent outside Soma.

Every status, evidence record, and remote claim that depends on the mode MUST identify the active mode. A verifier MUST NOT infer brokered enforcement from installation, a local vault file, or a self-reported tier.

## 5. Protected assets, adversaries, and assumptions

Soma protects:

- controller authority over identities, agents, grants, and exports;
- signing, recovery, encryption, and credential secrets;
- private work and consent choices;
- evidence ordering and provenance;
- pinned host identity and response integrity;
- received Vera intelligence, citations, licenses, and provenance;
- the ability to operate locally and exit.

Soma MUST assume malicious or compromised agents, plugins, dependencies, hosts, model outputs, files, URLs, redirects, DNS answers, and local unprivileged processes. It MUST also account for filesystem rollback, concurrent writers, clock error, disk exhaustion, permanent key loss, operator mistakes, and a privileged host operator who can inspect plaintext while processing it.

V1 does not assume that:

- a local administrator cannot read process memory;
- a Vera host operator cannot inspect plaintext processed by that host;
- encryption makes a malicious endpoint honest;
- a model response or reasoning summary exposes hidden model computation;
- several agreeing identities are independent;
- a local evidence ledger alone proves that work happened.

## 6. Identity and key lifecycle

### 6.1 Roles

The v1 logical roles are:

- **controller identity:** authorizes consent, high-risk capability changes, recovery policy, export of sensitive local state, and agent lifecycle;
- **agent identity:** signs agent actions and evidence;
- **observer identity:** signs contribution packaging and may be pairwise per destination to reduce correlation;
- **recovery authority:** an optional user-controlled offline key or precommitted threshold policy that can authorize rotation after loss;
- **transport-encryption keys:** separate non-signing recipient keys, normally pairwise or ephemeral, used to receive request-bound private Vera replies and rotate without changing identity.

One key MAY serve multiple low-risk roles only if the ratified profile explicitly permits it and the user is warned about the enlarged blast radius. Production profiles SHOULD separate controller/recovery authority from online agent and observer keys.

### 6.2 Creation

Identity creation MUST:

- occur without network access;
- use the ratified DID and key-ID derivation profile;
- generate keys inside the selected OS or hardware keystore where supported;
- record suite, key ID, role, creation time, effective interval, and status;
- create no human, organization, parent, or uniqueness claim without a separately verifiable credential;
- require an explicit recovery choice: precommitted recovery or honest no-recovery mode.

Nature, parent, organization, and assurance labels are claims, not free-form trust inputs. A parent relationship MUST be proven by a signed, scoped delegation; a parent DID string alone is invalid.

### 6.3 Storage and use

Private keys MUST NOT be stored in the distributable tree or ordinary JSON. Production use MUST employ an OS/hardware keystore or a ratified encrypted local store. An explicitly insecure development store MAY exist only when:

- the user selects it by name;
- the CLI displays and records a persistent insecure status;
- non-loopback connections, real credentials, public claims, and production exports are disabled;
- its artifacts are rejected by production verifiers.

Signing APIs MUST accept a complete domain-separated envelope, never an arbitrary ambiguous JSON object.

### 6.4 Rotation and revocation

Rotation MUST:

- preserve a stable identity anchor only under a valid rotation event;
- prove control according to the current rotation/recovery policy;
- bind old and new key IDs, roles, effective times, reason, suite, and previous event;
- make the new key effective only after required verification and acknowledgement;
- retain historical public keys and effective windows for verification;
- prevent downgrade to an unapproved suite;
- support rollback before effect without leaving a half-rotated identity.

Revocation MUST be signed by authorized current or recovery authority, append-only, and propagated to connected hosts. A revoked key MUST NOT authorize new network acts. Historic events remain verifiable only for the interval in which the key was valid.

### 6.5 Backup, loss, and recovery

Identity backup, full Soma owner-state backup, and Vera intelligence export are three different artifacts and MUST never be presented as interchangeable.

An identity backup is encrypted under a ratified user-controlled recovery method, contains a manifest and integrity commitments, and excludes unrelated credentials and private work.

A full Soma owner-state backup preserves the owner's functional local state, including public identity history, evidence, consent history, locally retained Vera intelligence, rights/provenance metadata, sanitized configuration, and recoverable queue records. It MUST be encrypted to a backup key controlled by the owner and separate from live store keys; use a deterministic manifest with a committed snapshot ID and per-object paths, hashes, sizes, media types, schema versions, and rights classes; exclude signing/recovery private material, bearer tokens, provider/API credentials, cookies, host operator credentials, raw keystore material, and unrelated machine secrets; and declare omissions. The v0.1 backup has no `include credentials` shortcut.

The archive distinguishes **managed authority secrets** from **authorized sensitive owner bytes**. Managed authority secrets are signing or recovery private material, authentication factors, bearer credentials, API/provider secrets, cookies, keystore wrapping material, and machine or operator credentials; they are never owner-state payloads and survive only through their own keystore, credential-manager, or identity-recovery ceremony. Authorized sensitive owner bytes are user-selected questions, answers, evidence attachments, source bodies, host-confidential records, and other lawful private content. They MAY be included because the entire owner-private archive is authenticated and encrypted to the owner, but they retain their original classification, rights, provenance, retention, and sharing restrictions. Encryption of an archive is not consent to disclose it.

Backup creation MUST take one consistent snapshot and re-encrypt included plaintext under fresh backup-export encryption material; it MUST NOT copy live store keys into the archive. Restore MUST verify the complete archive, authenticate and decrypt every object, check path safety and resource bounds, validate schemas, rights, evidence chains, signatures, and the snapshot commitment, construct the candidate state in quarantine, and present a dry-run inventory before mutating `SOMA_HOME`. A corrupt, incomplete, wrong-recipient, unsupported, rollback, path-confused, or policy-incompatible backup fails before mutation.

Read-only import MAY expose verified local records in an isolated namespace without signing, consent, agent, host-session, or egress authority. An authoritative restore MUST be transactional and MUST place all recovered authority in a deny-all **restore quarantine**. Pending observations, contributions, outcomes, artifact sends, queue entries, active grants, connected-host sessions, credentials, and response-return sessions remain inert; they cannot sign, decrypt a live session, authorize an agent, release a credential, connect, retry, send, or receive a pending private reply. The owner must separately re-establish identity continuity where available and re-confirm the current destination, network/context, policy, expiry, credential binding, and key status. Re-authorized work uses fresh envelopes, nonces, return keys, and sessions. No pre-backup or in-flight network act may replay automatically.

Identity recovery MUST rotate to fresh online keys. A state backup MUST NOT by itself restore signing continuity. Continuity requires a separate valid identity-recovery bundle and precommitted recovery authority. Recovery MUST NOT reconstruct a universal secret or silently restore authority from a public DID. If neither a valid signing key nor a valid precommitted recovery authority survives, Soma MUST create a new identity and report continuity as unavailable; the verified state backup may still be imported read-only under that new identity.

Pairwise and domain-separated identities SHOULD be used where one global identifier would correlate unrelated areas of a person's life. Linking them requires explicit selective disclosure.

## 7. Capabilities, credentials, and agent control

Capabilities MUST be explicit allow-lists that bind:

- subject and issuer;
- action, resource, method, and path;
- audience and destination;
- purpose and task;
- issue, not-before, expiry, and nonce/replay policy;
- invocation, concurrency, data-size, and cost limits where applicable;
- delegation depth and strict attenuation rules;
- revocation identifier.

Unknown capability fields or caveats MUST fail closed. Invocation limits MUST be enforced state, not decorative configuration.

Credentials MUST follow issuer, holder, and verifier roles. A valid credential proves only that its issuer made the encoded claim. Verifiers choose issuer trust and required evidence. Self-issued labels MUST NOT become verified-human, organization, competence, or reputation claims.

An agent MUST NOT receive raw long-lived credentials merely because it can invoke a tool. The broker SHOULD inject narrowly scoped credentials into the approved request and MUST prevent forwarding them to another origin or redirect. Bearer-to-arbitrary-URL tools are forbidden.

Arbitrary shell strings are forbidden in the production pilot. Process execution MUST use an allow-listed executable and argument vector, a contained working directory, bounded environment, timeout, output limit, and an explicit capability. A successful exit code is execution evidence, not quality evidence.

Autonomous payments and token wallets are outside the Soma v0.1 prototype. A later payment capability MUST use explicit per-call and cumulative allowances, destination binding, simulation/preview, objective receipts, and independent settlement verification.

## 8. Signed local evidence

Each evidence claim MUST conform to the ratified evidence-event schema and distinguish:

- assertion;
- execution;
- outcome;
- factual verification;
- dispute.

The local ledger wraps each evidence event in a signed sequence entry:

    local_entry_core = {
      schema_version,
      sequence,
      previous_entry_hash,
      evidence_event,
      recorded_at,
      signer_key_id
    }

    local_entry_hash =
      H("soma:local-evidence-entry:v1\n" || JCS(local_entry_core))

    signature input =
      "soma:local-evidence-entry:signature:v1\n" ||
      HEXDEC(local_entry_hash)

Sequence starts at zero. The first previous-entry hash is 64 zeroes. Every later entry names the immediately preceding entry hash. The exact wrapper schema and vectors MUST be ratified before implementation is called conforming.

Evidence storage MUST:

- append atomically under an exclusive writer lock;
- maintain and sign a current head;
- detect mutation, insertion, deletion, reordering, and internal truncation;
- minimize plaintext and store hashes instead of prompts, secrets, full tool output, or private artifacts;
- bind consent-grant IDs to any evidence projected for Vera;
- preserve corrections and disputes as new records rather than rewriting old records.

A local attacker with authority to roll back both the ledger and every local head can hide tail history. Claims of rollback or truncation detection therefore MUST state whether the head is local-only, user-backed-up, host-acknowledged, or independently anchored. Only the latter evidence classes provide independent rollback resistance.

High-value outcome claims require an independent receipt such as a CI attestation, artifact reproducibility result, counterparty signature, deployment proof, settled escrow, or qualified human/organization credential. Self-signed body tier, receipt count, elapsed time, or zero exit status MUST NOT increase reputation.

## 9. Vera observation, consent, and data states

### 9.1 Data classes

The v1 grant schema permits only:

- public_artifact;
- work_summary;
- objective_receipt.

The following remain denied or prohibited:

- private_work: denied unless a future ratified narrow profile exists;
- secret: always prohibited;
- regulated_sensitive: always prohibited in v1;
- identity_linkage: always prohibited in v1.

Unknown classes fail closed.

### 9.2 Data states

Every local or transmitted item has exactly one state:

- private_local;
- host_confidential;
- federated_training;
- public_knowledge.

Moving to a broader state requires a new signed grant. A host-confidential grant MUST NOT imply peer replication, training, or release.

### 9.3 Consent grant

Consent MUST use schemas/consent-grant.schema.json and the identifier/signature domains in ID-DERIVATION.md. A grant binds at least subject, controller, observer, exact destinations, classes, fields or authorized projection, purposes, operations, retention, redistribution, model-training flag, public-release flag, license, policy version, issue, expiry, and withdrawal mode.

The machine schema currently lacks an explicit field allow-list and replication mode. Until those are added or a ratified authorized-projection object is bound by hash, a release MUST NOT claim that field-level or replication-specific consent is complete.

### 9.4 Preview and send

Preview MUST be local and produce:

- the exact JCS application payload proposed for transmission;
- its SHA-256 commitment;
- class and data-state decision;
- every included field and redaction;
- purpose and operation;
- host DID, exact origin, and transport policy;
- retention, redistribution, replication, training, release, and license terms;
- consent grant and policy versions;
- warnings about irreversible uses;
- secret-scan and rights-check results.

No preview command may transmit payload bytes. Granting consent does not itself authorize an unpreviewed payload.

The send path MUST recompute the canonical payload after final redaction and refuse transmission unless its hash matches the approved preview. Only the signed envelope, encryption nonce/ciphertext, and disclosed transport metadata may differ from the preview representation.

### 9.5 Withdrawal

Withdrawal MUST immediately disable matching local egress, create a signed withdrawal record that binds a fresh/pairwise Soma return-encryption key, encrypt a separate request to every exact named host ingestion key, preserve a tombstone sufficient to prevent replay, and collect host-signed receipts encrypted to the corresponding request-bound return key. Offline hosts remain pending and MUST be retried only under a disclosed bounded policy; a retry or status lookup uses a new envelope and return key and cannot widen the withdrawal.

The UI MUST distinguish:

- future use stopped;
- deletable copies acknowledged deleted;
- backup expiry pending;
- public copies potentially irreversible;
- trained influence not demonstrably removed.

## 10. Data flows

### 10.1 Local act

    owner instruction
      -> constrained adapter/broker
      -> permitted model or tool
      -> minimized signed local evidence
      -> private local store

No Vera grant is needed for local-only use.

### 10.2 Vera contribution

    selected local evidence or public artifact
      -> classification and rights check
      -> deterministic redaction and secret scan
      -> local preview and payload commitment
      -> signed consent grant
      -> fresh/pairwise Soma return-encryption key bound by the inner request
      -> inner signed event bound to host audience and active execution context
      -> outer signed routing envelope committing to recipient ciphertext
      -> inner event encrypted to the exact host ingestion key
      -> authenticated TLS transport to pinned host
      -> host-signed acknowledgement encrypted to the request-bound Soma return key
      -> outer-header, decryption, inner-signature, request, scope, and commitment verification
      -> local acknowledgement and evidence update

The contribution acknowledgement is a distinct inner signed object. It MUST bind the acknowledgement ID and schema, host DID and signing-key ID, network and execution context, originating request and contribution event IDs, consent-grant ID, request-bound Soma return-key ID, recipient host-ingestion key ID, immutable received-envelope ciphertext commitment, decrypted plaintext commitment, decision (`accepted`, `accepted_narrowed`, or `rejected`), whether authoritative mutation occurred, issue time, and idempotent status reference. An accepted decision additionally binds the exact accepted field-projection commitment, class, purpose, operations, data state, retention deadline, replication rule, training and public-release flags, license, durable object/event IDs, host sequence, and resulting state/checkpoint reference. A rejected decision binds a typed reason and proves no authoritative mutation. A host may narrow but never broaden the signed grant. Missing, broadened, contradictory, or mismatched fields make the acknowledgement invalid.

The host MUST finish and sign this acknowledgement only after its stated durable decision, then encrypt the complete signed object to the exact return key bound by the contribution request and sign the outer return envelope. Soma verifies the outer envelope, decrypts locally, verifies the inner acknowledgement independently, and stores both atomically before marking the contribution confirmed. Host storage encryption may rotate or be rewritten; its mutable at-rest ciphertext hash MUST NOT replace or alter the received-envelope commitment.

A timeout after host acceptance MUST be resolved through an idempotent encrypted status lookup with its own return key, not blind resubmission.

The transport and application layers serve different purposes. TLS authenticates the connection and protects traffic in transit. The application envelope keeps the contribution body encrypted through proxies, queues, and storage until the named host's bounded ingest worker opens it. A normal host can still inspect authorized plaintext while processing it. Soma MUST disclose that limitation and MUST NOT call this operator-blind or end-to-end confidential computation.

When one contribution is authorized for multiple hosts, Soma creates a fresh recipient envelope for each exact host ingestion key. It MUST NOT reuse a nonce or content-encryption key across recipients. A later confidential-compute profile MAY encrypt to an attested ephemeral enclave key, but only under a separately ratified threat model and consent profile.

### 10.3 Vera query

    explicit question
      -> local query disclosure and destination confirmation
      -> signed query names a fresh/pairwise Soma return-encryption key
      -> inner query encrypted to the pinned host ingestion key
      -> authenticated TLS request carrying a signed outer routing envelope
      -> host-signed answer bundle encrypted to the named Soma return key
      -> outer-header, decryption, inner-signature, request, source, rights, and schema verification
      -> encrypted atomic local storage
      -> answer shown with citations, uncertainty, provider/model metadata, and limitations

Asking is an explicit network action, not observer consent. While observation remains off, its packet-level allowance is exactly one owner-invoked, displayed request to one pinned host and its bound encrypted response, or a separately invoked idempotent status request and bound response. Automatic prefetch, failover, background retry, contribution, outcome, artifact, model/tool telemetry, update, training, and second-destination traffic remain forbidden. The host MUST NOT use a query for evaluation, derivation, training, redistribution, or public release unless a separate purpose-specific grant permits that exact use.

### 10.4 Sovereign Vera export

    verified local answer bundles and authorized source material
      -> deterministic manifest and per-file hashes
      -> rights and provenance inventory
      -> owner-only export directory
      -> offline verification by any conforming implementation

An owner-private export MUST preserve the exact received bytes as well as normalized metadata, encrypt every authorized sensitive included body under the owner-controlled export profile, and remain clearly distinct from a shareable artifact. Questions, answers, and permitted host-confidential or source bytes remain sensitive owner content even inside that archive. A shareable/redacted derivative MUST receive a new ID and explicit redaction provenance. Neither form may include managed authority secrets such as signing/recovery private material, authentication credentials, bearer tokens, vault values, keystore wrapping material, hidden caches, or content the user lacks the right to copy. Restricted source content is represented by its commitment, citation, access rule, and license rather than copied unlawfully.

### 10.5 Full Soma owner-state backup and restore

    consistent locked snapshot
      -> deterministic state inventory and snapshot commitment
      -> exclude managed authority secrets and machine-bound credentials
      -> decrypt live stores only inside the local backup process
      -> re-encrypt included objects to a fresh owner-controlled backup key
      -> write manifest and archive atomically
      -> offline verify/decrypt/dry-run on a clean machine
      -> read-only import, or transactional restore with authority quarantine

This artifact is the disaster-recovery copy of Soma's local functional state. It is not an identity-recovery bundle, a Vera host/network checkpoint, or a shareable Vera intelligence pack. Exact restore means the manifest's included local object bytes and logical snapshot reproduce; it does not claim that excluded secrets, remote host state, public canonical state, or external provider access survived.

## 11. Model observation limits

Soma MAY observe only fields both authorized by the owner and exposed through the model/tool interface, including:

- user instructions deliberately routed through Soma;
- model responses;
- tool requests and redacted result metadata;
- specifically approved files or artifact hashes;
- timing, token counts, provider/model identifiers, errors, and disclosed costs;
- provider-exposed event streams or explicit reasoning summaries;
- independently verifiable task outcomes.

Soma cannot observe a closed model's hidden weights, private activations, hidden chain-of-thought, undisclosed provider logs, or internal training data. A verbose response, scratchpad, or reasoning summary MUST NOT be represented as authenticated hidden reasoning. Model output is untrusted input and MUST NOT silently become policy, evidence classification, protocol truth, executable authority, or public knowledge.

Open-weight instrumentation, activation research, local fine-tuning, or federated training requires a separate capability and threat-model profile.

## 12. Sovereign Vera intelligence

For each query, Soma MUST retain:

- the exact inner signed request and request hash;
- the exact outbound recipient envelope and ciphertext commitment;
- the exact inbound Vera-to-Soma return envelope and ciphertext bytes;
- the exact decrypted host-signed response bytes in encrypted local storage;
- parsed answer content;
- source identifiers, citations, content commitments, provenance links, availability, and license/rights metadata;
- host DID, key ID, origin, network lineage, and execution context;
- retrieval/service version;
- model provider and model identifier when disclosed;
- uncertainty, abstention, safety filtering, and known limitations;
- signed host acknowledgement or response signature;
- local receipt time and verification result;
- supersession, correction, withdrawal, or tombstone notices received later.

Soma MUST show unverified, invalid, stale, disputed, or unsupported content as such. A host signature proves the host returned bytes; it does not make the answer factual.

The user can export intelligence they lawfully possess. "Sovereign" means locally retained, portable, inspectable, and not dependent on continued access to one host. It does not transfer ownership of third-party sources, override license restrictions, guarantee perpetual upstream availability, or force another user's private data into the export.

No host may remotely delete or disable a valid local copy merely because the user disconnected. Legal restrictions and a user-authorized deletion remain applicable.

## 13. Security defaults

A conforming production profile MUST:

- use an OS or hardware keystore;
- encrypt sensitive local stores with randomly generated data-encryption keys wrapped by the OS/hardware keystore or another ratified user-controlled root;
- encrypt every non-public application request to the pinned host ingestion key; bind a distinct Soma return key in each private request; and require Vera to sign then encrypt every private acknowledgement, receipt, registration/challenge result, status, answer, or error body to that exact request-bound return key under the ratified application-envelope profile;
- bind private state to the owning account with restrictive ACLs or permissions;
- keep runtime state outside the release directory;
- use authenticated TLS for non-loopback traffic;
- pin host identity and origin;
- disable redirects by default;
- apply DNS-rebinding and SSRF defenses;
- reject link-local and cloud-metadata destinations;
- require an explicit profile for private-address hosts;
- bound connection time, total request time, body size, decompression, concurrency, retries, and disk use;
- use idempotency identifiers for state-changing requests;
- redact logs and disable secret-bearing command-line arguments;
- validate path containment and reject symlink, junction, and traversal escapes;
- write state atomically and recover safely after interruption;
- refuse public operation when release verification or security configuration is missing.

Update checks and telemetry are off by default. If later enabled, they require a separate disclosed destination and purpose and MUST carry no agent work, identity linkage, consent content, or Vera queries.

## 14. Portability, local state, and clean packaging

The release artifact and user state are separate.

The release artifact MUST contain only public source or binaries, schemas, vectors, licenses, defaults, build provenance, a software bill of materials, hashes, and release signatures. It MUST NOT contain:

- state or database directories;
- private keys, recovery shares, credentials, or environment files;
- live consent grants or intelligence;
- developer host URLs, IP addresses, usernames, machine paths, or SSH information;
- package-manager links to a developer filesystem;
- unlicensed datasets or models.

User state MUST use the platform location defined by PROTOTYPE-SPEC.md and MUST be exportable. Uninstall MUST preserve user state unless the user separately confirms deletion after export.

A clean-room build MUST require no private repository, founder laptop, live package registry, DNS name, cloud account, or undocumented step.

## 15. Failure behavior

Security-critical ambiguity fails closed. In particular, Soma MUST refuse the affected operation on:

- unverified release or unknown critical schema;
- unavailable secure keystore in production mode;
- invalid, expired, future, revoked, wrong-role, or downgraded key;
- signature, hash, canonicalization, network, context, audience, nonce, or time failure;
- missing or mismatched consent;
- unknown class, field projection, purpose, operation, host, or license;
- preview/send hash mismatch;
- secret or prohibited-data detection;
- evidence-chain corruption;
- unsigned, stale, oversized, redirected, or request-mismatched host response;
- insufficient local storage for an atomic write.

Availability failure MUST NOT silently weaken verification. Soma MAY queue a still-valid, already-approved contribution locally, but MUST NOT extend its consent or expiry. Queues are visible, bounded, cancellable, and encrypted.

## 16. Phoenix and disaster behavior

### 16.1 Release loss, local state survives

Rebuild and verify Soma from the ratified capsule. Import local state only after its manifests, signatures, evidence chain, and key references verify. Never execute an unverified recovered binary merely because it can read the state.

### 16.2 Full Soma owner-state backup survives

Verify and decrypt the entire backup before mutation. Restore into a deny-all quarantine snapshot with fresh local store keys. Reproduce every included logical object and hash, but keep grants, credentials, queues, pending sends, connected hosts, and return sessions incapable of authority until each relevant binding is re-confirmed and a fresh session or envelope is created. Without a separate valid identity-recovery authority, expose the recovered records read-only under a new identity and make continuity unavailable.

### 16.3 Identity backup survives

Restore only through the ratified identity-recovery procedure. Rotate online keys after recovery. Preserve continuity only if the recovery authority and event chain prove it. Identity recovery alone does not restore the owner-state snapshot.

### 16.4 Vera intelligence pack survives

Restore the exact locally received intelligence, rights metadata, provenance, and verification status. The pack does not restore signing authority, host state, public canonical history, consent, or reputation unless those are independently established by their own valid records.

### 16.5 No user backup survives

Create a new identity. Start observer-off with no destinations or grants. Do not claim old identity, evidence, credentials, reputation, or private intelligence.

### 16.6 Exact network succession

The network lineage remains the same and execution context changes under RECOVERY.md. A checkpoint root, manifest, locator, or list of hashes by itself is not recovered state. Soma MUST require the complete authenticated content-addressed state archive/object bytes, a recovery certificate committing to that exact set, and an independently verifiable restore transcript showing that every required object was available and the checkpoint root was recomputed from the surviving bytes. If any required state byte is missing, exact continuity is unavailable. Soma MUST reject the old context for new requests and require the user to confirm the successor host binding before resuming observation. Existing portable records may remain historically verifiable, but no queued event may be replayed into the new context without a fresh envelope and still-valid consent.

### 16.7 Phoenix network

A Phoenix network has a new network lineage. Old consent grants do not authorize it. Soma MUST clear active-host and observer authority, require new grants, and label imported public intelligence as external historical material. Phoenix cannot inherit old identity, consent, evidence, reputation, balances, or canonical status by naming this document, presenting an unauthenticated copy of it, or reproducing only old roots without the committed state bytes.

## 17. Conformance and release gates

No Soma artifact may be called production-ready, apocalypse-ready, or conforming until:

- all P0 freeze blockers in PROTOTYPE-SPEC.md are resolved;
- the exact schemas and domains pass cross-language vectors;
- every acceptance test in PROTOTYPE-SPEC.md passes on each supported platform;
- observer-off packet capture shows zero observation/training/artifact/outcome/telemetry egress, including during an intentional ask except for the exact displayed encrypted query, its minimum disclosed routing metadata, and its bound encrypted response;
- outcome, watcher, adapter, plugin, and background paths cannot bypass consent;
- replay, wrong audience, wrong context, stale nonce, revoked key, mutation, downgrade, and malformed JCS fail;
- secret-canary, path traversal, SSRF, redirect, DNS rebinding, log leakage, oversized input, and disk/concurrency tests pass;
- evidence mutation, insertion, deletion, reordering, truncation, and rollback assurance levels are reported honestly;
- ask, storage, owner-state backup, offline verification, read-only import, transactional restore, and sovereign export reproduce their declared exact hashes; every invalid restore fails before mutation;
- clean packaging and clean-room rebuild pass without founder infrastructure;
- independent security and privacy review finds no unresolved critical or high issue;
- the release manifest and reproducible artifacts are signed by the ratified threshold.

Passing happy-path demos, syntax checks, test coverage percentages, an audit badge, a VPS run, or a long specification is not release evidence.

## 18. Non-goals and forbidden claims

The v0.1 Soma module does not provide:

- verified human identity or global Sybil resistance;
- general factual verification;
- a scalar universal trust score;
- autonomous wallets, token custody, staking, minting, or payment settlement;
- public reputation based on self-reported work;
- hidden chain-of-thought or closed-model introspection;
- confidential computation against a privileged local or host administrator;
- full model hosting or distributed training;
- guaranteed deletion from public copies or trained weights;
- guaranteed availability, safety, intelligence improvement, or superintelligence;
- unbypassable agent control in integrated mode.

Implementations MUST NOT claim to be unhackable, bulletproof, poison-proof, fully private, guaranteed, immortal, or complete.

## 19. Rebuild order

The minimum honest implementation order is:

1. strict JCS, hashes, signature verification, and release verification;
2. secure key storage, identity creation, key history, rotation, revocation, and recovery;
3. signed local evidence ledger and verifier;
4. one centralized consent, membrane, redaction, and secret-scanning engine;
5. pinned-host descriptor and authenticated bounded client;
6. preview, grant, send, withdrawal, and bidirectionally encrypted host-response flow;
7. exact Vera ask, local intelligence storage, export, and offline pack verification;
8. encrypted full owner-state backup, offline verification, read-only import, and transactional quarantine restore;
9. constrained capability broker and one clearly labeled agent adapter;
10. adversarial platform tests and clean packaging;
11. independent clean-room rebuild and closed non-sensitive pilot.

Money, token behavior, public reputation, broad delegation, background observation, and model training come later, under separate ratified gates.

## 20. Draft freeze blockers

This module draft cannot become a frozen prototype contract until the capsule ratifies:

- the DID, key-ID, role, rotation, revocation, and recovery-event schemas;
- the local evidence-ledger wrapper schema and vectors;
- explicit consent field projection and replication semantics;
- host descriptor, contribution acknowledgement, withdrawal receipt, Vera query, and Vera answer-bundle schemas;
- the closed ordinary host-descriptor succession schema, monotonic predecessor rule, precommitted overlap policy, dual role-separated signatures, controller reconfirmation rule, and adversarial vectors;
- the active AEAD, local-store and owner-state-backup encryption, password-KDF or recipient-encryption profile, backup manifest/snapshot schema, and restore vectors;
- the host-ingestion and Soma-return encryption-key descriptors, bidirectional outer-envelope schemas/signatures, HPKE or equivalent recipient-encryption suite, associated-data projection, rotation/retention rules, metadata-leakage disclosure, and valid/invalid vectors;
- production keystore behavior on every supported platform;
- release-manifest trust roots and software-signature procedure;
- bounded network defaults and adapter capability schema;
- sovereign Vera pack manifest and offline verification vectors;
- independent old-release trust-fact procedure and exact checkpoint state-archive availability/restore evidence.

Until those blockers close, every implementation and document MUST retain draft/prototype labeling.
