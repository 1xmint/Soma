# SOMA PACK PROTOTYPE SPEC

Document ID: soma/prototype/0.1-draft
Status: **draft implementation contract; no implementation is claimed complete or conforming**
Implements: ORIGIN-SPEC.md in this directory and the repository-root Somavera constitutional documents
Target: first closed, non-sensitive, tokenless network pilot

## 0. Contract and precedence

This document defines the exact minimum behavior expected from the first Soma Pack. Normative key words use RFC 2119 and RFC 8174.

The governing order is:

1. repository-root ORIGIN-SPEC.md and immutable rights;
2. DATA-RIGHTS.md, THREAT-MODEL.md, RECOVERY.md, ID-DERIVATION.md, and ratified schemas;
3. specs/soma/ORIGIN-SPEC.md;
4. this prototype contract;
5. implementation documentation.

An implementation cannot override a higher rule. Unknown or unresolved P0 behavior fails closed. This draft MUST remain labeled draft until the freeze blockers in section 22 are resolved and the complete acceptance suite passes.

## 1. Prototype promise

A person can verify and unpack one clean Soma release on an owned computer, create an exportable agent identity offline, connect Soma directly to a pinned remote Vera Host, explicitly preview and authorize one minimized contribution, retrieve signed Vera intelligence, preserve the exact signed answer/source pack locally, export it in an open format, verify it offline, and import or use it with another owner-controlled agent. The same release also creates, verifies, imports read-only, and transactionally restores a complete encrypted owner-state backup without treating that backup as identity recovery or a Vera sovereign pack.

**A local Vera Host is not required.** The normative first-use topology is:

    owner computer
      +-- Soma Pack
      +-- owned agent or model adapter
      +-- local evidence and intelligence store
             |
             +-- authenticated TLS --> remote Vera Host

Optional use of a Vera Host on the same machine MUST use the same protocol and verification behavior. Soma MUST NOT require HeyVera, a local ledger node, the legacy Soma monorepo, a founder service, a private package registry, or source edits.

The prototype succeeds only if the remote-only path and the fully offline verification/export path both pass.

## 2. Pilot scope and non-goals

The v0.1 pilot supports:

- one controller and one or more locally owned agent identities;
- Ed25519-v1 under the ratified DID/key profile;
- secure local key storage;
- signed local evidence;
- public_artifact, work_summary, and objective_receipt observation;
- explicit remote Vera connection;
- signed contribution and withdrawal flows;
- signed Vera query/answer/source bundles;
- sovereign local storage, export, verification, import, and offline search;
- encrypted full owner-state backup, offline verification, isolated read-only import, and transactional restore;
- integrated mode and one constrained subprocess adapter;
- fresh Windows, Linux, and macOS installations.

The v0.1 pilot does not support:

- autonomous money, wallet custody, token balances, staking, minting, or settlement;
- verified-human identity, biometric identity, KYC, or global Sybil resistance;
- public scalar reputation;
- private_work, secret, regulated_sensitive, or identity_linkage observation;
- hidden chain-of-thought or closed-model introspection;
- background Git, filesystem, browser, microphone, screen, or process watchers;
- general remote shell execution;
- full delegation trees or cross-issuer delegation;
- public adversarial enrollment;
- model training, federated learning, or public dataset release;
- claims of unbypassable agent control;
- restoration of lost history without authenticated state.

## 3. Supported platforms and release forms

An exact release may claim a platform supported only after all mandatory tests pass on that platform.

Tier 1 targets for v0.1 are:

| Platform | Minimum | Architecture | Required secure store |
|---|---|---|---|
| Windows | Windows 11 | x86-64 | Windows CNG/DPAPI or Credential Manager with owner-only ACLs |
| Linux | Ubuntu 24.04 LTS | x86-64 | Secret Service, supported hardware key, or ratified encrypted store |
| macOS | macOS 14 | Apple Silicon | Keychain or supported hardware key |

macOS x86-64 and other Linux distributions MAY be published as experimental, but MUST NOT be called supported without the same evidence.

Each Tier 1 release MUST include:

- a self-contained signed binary or a pinned offline-capable runtime bundle;
- source and reproducible build instructions;
- exact dependency locks and lawful offline dependency material;
- schemas and conformance vectors;
- release manifest, SBOM, provenance, expected hashes, and threshold signatures;
- platform-specific installation, keystore, backup, verification, and uninstall instructions.

Administrator or root access MUST NOT be required for ordinary client use. A release MUST NOT silently fall back to plaintext key files when a secure store is unavailable.

## 4. Clean distributable layout

The release archive contains:

    soma-pack/
      README.md
      LICENSE
      NOTICE
      SECURITY.md
      bin/
        soma or soma.exe
      schemas/
        ratified machine schemas
      conformance/
        canonicalization, signature, consent, evidence, answer, and pack vectors
      defaults/
        policy.json
      release/
        manifest.json
        signatures.json
        sbom.json
        provenance.json
      licenses/
        third-party notices

It MUST NOT contain:

- state, database, cache, export, log, or vault directories;
- private keys, recovery material, credentials, cookies, environment files, or operator tokens;
- live grants, questions, answers, evidence, or host registrations;
- node_modules or an equivalent mutable dependency tree unless it is the ratified offline runtime bundle;
- links or junctions to a developer filesystem;
- developer URLs, IP addresses, usernames, SSH paths, machine paths, or production defaults;
- unlicensed code, models, datasets, or source content.

The release verifier MUST reject a package whose manifest omits an executable file or whose tree contains an unmanifested executable.

## 5. User state layout

The default SOMA_HOME is:

- Windows: %LOCALAPPDATA%\Somavera\Soma
- Linux: $XDG_STATE_HOME/somavera/soma, falling back to ~/.local/state/somavera/soma
- macOS: ~/Library/Application Support/Somavera/Soma

The user MAY select an absolute alternate home with --home. Production mode MUST reject a home inside the release tree, a world-writable directory, a network share without an approved profile, or a path escaping through a symlink, mount, or Windows reparse point.

The logical layout is:

    SOMA_HOME/
      config/
        config.json
        policy.json
      identity/
        identity.json
        public-key-history.json
        rotation-log.jsonl
        recovery-policy.json
      hosts/
        HOST_DID.json
      consent/
        grants/
          CONSENT_GRANT_ID.json
        withdrawals/
          WITHDRAWAL_ID.json
        previews/
          PREVIEW_ID/
            payload.jcs
            decision.json
      evidence/
        ledger.jsonl
        head.json
        anchors/
      intelligence/
        queries/
          QUERY_EVENT_ID/
            request.json
            request-envelope.json
            response-envelope.json
            response.raw
            answer-bundle.json
            verification.json
        sources/
          CONTENT_HASH/
      exports/
      queue/
      logs/
        security.jsonl
      run/
        lock

Private signing and recovery keys are referenced by key ID but remain in the OS/hardware keystore. They MUST NOT appear in this tree. Encrypted identity-recovery bundles and encrypted full owner-state backups are written only to separately selected paths outside SOMA_HOME and are visibly different artifact types.

Sensitive local bodies are encrypted at rest. Initialization creates a random local root data-encryption key inside, or wrapped by, the OS/hardware keystore. Separate derived or randomly generated store keys protect evidence attachments, queues, credentials, questions/answers, source bytes, and host-confidential material. Ordinary state files contain only wrapped key references and the minimum public/index metadata declared by schema. Removing filesystem permissions is still a failure: encryption and owner-only access are both required. Backups and sovereign packs use separate export keys and MUST NOT reuse live store keys.

Managed authority secrets and authorized sensitive owner bytes are different. Signing/recovery private material, authentication factors, bearer tokens, API/provider secrets, cookies, and keystore wrapping material remain in their dedicated keystore or credential/recovery system and MUST NOT be copied into an owner-state backup or sovereign pack. User-selected questions, answers, evidence attachments, permitted source bodies, and host-confidential records MAY be present as authorized sensitive owner bytes only inside the authenticated owner-private archive, encrypted to an owner-controlled backup/export key and retaining their original classification and rights.

Owner-only permissions are REQUIRED. On POSIX systems, directories MUST be no broader than 0700 and ordinary private files no broader than 0600. On Windows, inherited broad ACLs MUST be removed and access limited to the user, SYSTEM, and required trusted service identities. The exact ACL result MUST be verified, not inferred from a POSIX mode argument.

All mutable records use atomic create-or-replace, file and directory synchronization where supported, and an exclusive process lock. A second writer MUST fail clearly or use a specified transactional handoff; it MUST NOT race on JSONL or consent state.

## 6. Global command behavior

The executable is soma. Commands MUST support:

- --home PATH
- --json for one machine-readable JSON result on standard output
- --no-color
- --version
- --help

Secrets MUST NOT be accepted as command-line values. Passphrases use a hidden terminal prompt or an authenticated local input channel. Standard output contains requested results. Diagnostics go to standard error and MUST be redacted.

Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | operation completed and required verification passed |
| 2 | invalid command, option, or configuration |
| 3 | policy, consent, rights, or capability denied |
| 4 | cryptographic, schema, release, or host-verification failure |
| 5 | network, DNS, TLS, timeout, or availability failure |
| 6 | authenticated host rejection or remote conflict |
| 7 | local state, evidence, pack, or storage-integrity failure |
| 8 | secure-keystore or supported-platform requirement unavailable |
| 9 | user cancelled or interactive confirmation declined |
| 10 | internal failure not safely classified; no partial success may be claimed |

State-changing commands MUST report whether local mutation, remote mutation, both, or neither occurred. A timeout after possible remote mutation MUST return an indeterminate remote status and an idempotency/status command, never a false clean failure.

## 7. Required command surface

The minimum remote-only user journey is:

    soma init
    soma doctor
    soma connect https://vera.example --expect-host-did DID
    soma ask "How should I verify a restored service?"
    soma export --scope vera --output PATH
    soma verify --pack PATH --offline

The minimum contribution journey is:

    soma evidence record --input EVENT.json
    soma observe preview --evidence EVIDENCE_ID --policy POLICY.json
    soma observe grant --preview PREVIEW_ID
    soma observe send --preview PREVIEW_ID --grant CONSENT_GRANT_ID
    soma observe revoke --grant CONSENT_GRANT_ID

No vera executable or local Vera process is required for either journey. The minimum owner-state disaster-recovery journey is separate:

    soma backup create --scope owner-state --output BACKUP
    soma backup verify --input BACKUP --offline
    soma backup import --input BACKUP --read-only
    soma backup restore --input BACKUP --target EMPTY_SOMA_HOME

### 7.1 Initialization and status

    soma init [--label TEXT] [--recovery none|offline]
    soma doctor [--network]
    soma status

soma init MUST:

- run offline;
- verify its release before creating state;
- create controller, agent, and observer signing roles plus a separate pairwise/ephemeral Vera private-reply encryption-key capability under the ratified key profile;
- use secure storage;
- initialize an empty evidence ledger;
- create no host, active grant, queue, wallet, or telemetry state;
- record observer status as off;
- prompt for honest no-recovery or offline-recovery mode.

The default recovery choice MUST NOT be silently selected. Offline recovery remains unavailable until the ratified encryption/KDF or recipient profile and vectors exist.

soma doctor is offline by default and checks release integrity, platform support, keystore access, permissions, clock sanity, state schemas, evidence integrity, disk headroom, and prohibited files. --network checks only explicitly connected hosts and displays each destination before access.

soma status reports identity, key roles and status, enforcement mode, observer/grant state, connected hosts, pending withdrawals, evidence head and assurance level, intelligence count, restore-quarantine state, security degradation, and release version. It MUST NOT print secrets, raw questions, or answer content.

### 7.2 Identity and key lifecycle

    soma identity show
    soma identity backup --output PATH
    soma identity restore --input PATH
    soma identity controller-rotate-preview --reason TEXT
    soma identity controller-rotate-confirm --proposal-id HASH --expect-successor-key-hash HASH --confirm-controller-rotation
    soma key rotate --role ROLE --reason TEXT
    soma key revoke --key-id KEY_ID --reason TEXT
    soma key history

identity show prints only public identity material and assurance labels.

identity backup creates a separately encrypted recovery bundle. It MUST:

- use the active ratified backup-encryption profile;
- obtain the protection secret through a hidden prompt or approved recipient public key;
- include identity anchor, public key history, recovery policy, required private recovery material, schema/version, file hashes, and creation context;
- exclude Vera questions, answers, evidence, model data, credentials, and unrelated agent secrets;
- refuse the SOMA_HOME, release directory, or an insecure output path.

identity restore MUST verify and decrypt before any state mutation, show the identity and recovery authority to the user, restore into an empty home or an explicit transactional merge, rotate online keys, and preserve continuity only when the recovery chain proves it. Without valid recovery authority it MUST offer a new identity, not an identity takeover.

Ordinary controller rotation uses the closed event and domains in `soma-controller-key-rotation.schema.json` and `ID-DERIVATION.md`. Preview runs offline, creates a fresh successor only in protected pending storage, displays the exact stable controller identity, old/new key commitments, sequence, predecessor, time limit, private-key disposition, rollback limitation, and authority exclusions, and grants no effect. Confirm requires the exact immutable proposal ID, exact successor raw-key SHA-256, and an explicit rotation flag. It dual-signs with the live prior key and fresh successor, then uses one atomic identity commit with deterministic crash recovery. The stable controller DID never changes; the old public key and interval remain verifiable; the old private key is destroyed only after the committed successor keystore is recoverable.

This ordinary profile is allowed only while the prior key is believed uncompromised and the local prototype has zero connected hosts, grants, queued work, or pending network acts. It authorizes no recovery, connection, consent, disclosure, send, token, or governance action. It cannot safely repair suspected compromise, and its local signed history is not independent rollback evidence. Rotation and revocation generally MUST use ratified signed events, update connected hosts idempotently, retain historic public verification windows, and leave a visible pending state until required acknowledgements arrive. A compromised key revocation cannot rely solely on that same compromised key when the precommitted policy requires recovery authority.

### 7.3 Host connection

    soma connect ORIGIN --expect-host-did DID [--expect-key-hash HASH] [--alias NAME] [--allow-private-host]
    soma hosts
    soma disconnect HOST

ORIGIN is an exact HTTPS origin: scheme, DNS name or IP, and port. Paths, fragments, embedded credentials, and redirects are forbidden. Cleartext HTTP is allowed only for numeric loopback addresses under explicit --dev-insecure mode; that mode cannot use real credentials, observation, or production evidence.

connect MUST:

1. resolve and validate the destination under SSRF and DNS-rebinding policy;
2. establish authenticated TLS without following redirects;
3. fetch /.well-known/somavera/vera-host.json;
4. validate the host descriptor schema and signature;
5. verify host DID, signing key ID, ingestion-encryption key ID/suite/validity, network lineage, execution context, supported protocols, query policy, data regions, subprocessors, retention behavior, model-use disclosure, size limits, and release identity;
6. compare --expect-host-did and optional key hash;
7. display exact origin, certificate identity, host DID, network/context, policy, and operator-memory limitation;
8. obtain explicit confirmation;
9. generate a distinct private-reply key and bind it in the signed registration/challenge request;
10. complete the signed nonce challenge bound to the host audience and active execution context, accepting only the host-signed result encrypted to that request-bound key; and
11. store the pinned descriptor, outer return envelope, and decrypted registration acknowledgement atomically.

Interactive trust-on-first-use without --expect-host-did MAY be permitted only in an explicitly labeled private-development profile. Noninteractive connection MUST require expected host identity or a ratified network proof.

A changed host key, origin, network, execution context, policy, TLS identity, subprocessor, or region MUST stop automatic use pending verification and user confirmation. disconnect removes active routing but preserves evidence and already received intelligence.

An ordinary descriptor successor MAY be presented only with the closed proof in `vera-host-descriptor-succession.schema.json`. Soma recomputes both descriptor IDs, validates both descriptor signatures, requires exact sequence/predecessor linkage, verifies the prior-active and successor-active role-separated proof signatures, and accepts a newly active key only when identical public key material was an unexpired overlap key in the prior descriptor. All non-key operational and policy fields remain identical. The proof creates an inert candidate pin; explicit controller confirmation is still required and creates no consent or send authority. Missing history, sequence gaps, uncommitted keys, scope mismatch, revocation, immutable-field change, expiry, or either bad signature fails closed. Emergency recovery after compromise is not ordinary succession and is unsupported until separately ratified.

Confirmation uses the closed receipt in `soma-host-succession-confirmation.schema.json` and the exact subject, confirmation-ID, and signature domains in `ID-DERIVATION.md`. The UI MUST show origin, host DID, prior and successor descriptor IDs/sequences, exact change scope, both old/new active key IDs, both successor public-key hashes, confirmation expiry, and every authority exclusion. The controller confirms the displayed `subject_id` and successor descriptor ID through an explicit gesture; a default, timeout, generic yes, previously confirmed alias, or host-controlled text is invalid. Noninteractive use requires both exact identifiers and an explicit inert-pin-replacement flag.

Receipt creation and the atomic current-pin commit MUST both occur inside the succession-proof validity window with no grace period. The transition serializes per host, revalidates under lock, durably prepares complete authenticated history, and uses one atomic current-pin replacement as its sole commit point. Recovery deterministically rolls an uncommitted preparation back to the prior pin or finalizes an already committed exact successor; ambiguity quarantines the host. The committed successor remains disconnected and has no consent, disclosure, queue, retry, or send authority. Repetition of the same confirmation is idempotent and every competing candidate conflicts. Implementations MUST fault-inject every write, sync, rename, history, cleanup, and restart boundary and race concurrent confirmations before enabling replacement.

### 7.3.1 Portable host-trust preservation

    soma host trust-export --out ABSOLUTE_CAPSULE.json
    soma host trust-verify --capsule ABSOLUTE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH
    soma host trust-compare --trusted TRUSTED_CAPSULE.json --candidate CANDIDATE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH

`trust-export` is offline and writes one new file without overwriting an existing path. It first verifies current pins, every succession transition, and the complete chain; then embeds their exact canonical bytes in the closed `soma-host-trust-capsule.v1` object, signs it with the active controller key, verifies the result, and durably publishes it. It exports no secret, consent, evidence body, intelligence, queue, credential, recovery share, or connection authority.

`trust-verify` is standalone and offline. The expected controller DID and raw Ed25519 key hash are mandatory out-of-band inputs. It bounds total and per-object bytes, rejects noncanonical JSON/base64, unsafe or duplicate paths, unsorted hosts/objects, wrong kind/path relationships, unknown source profile, object hash/size mismatch, pin or transition failure, incomplete/forked/orphaned history, count/root/ID/signature mismatch, and every widened authority claim. It does not require or modify a Soma home.

`trust-compare` first verifies both capsules under the same independently supplied controller expectation. The trusted capsule is treated as independently preserved evidence only because the caller supplied its exact bytes from outside the candidate state. The candidate passes only when creation time does not go backward and every trusted host and ordered transition ID is an exact prefix of the candidate state; equal chains require the same current pin, and extended chains must cryptographically descend from it. Added hosts are allowed. Missing hosts, shorter histories, forked histories, conflicting equal-length pins, controller substitution, or ambiguous ordering fail. Comparison never installs state and grants no restore or network authority.

Writing a capsule to the same device does not create independent rollback assurance. Operators seeking that assurance must preserve the exact capsule bytes or `capsule_id` on independently administered media, record the expected controller identity separately, and retain enough complete capsule bytes for the intended recovery claim. A hash alone detects change but cannot reconstruct unavailable state.

### 7.4 Evidence

    soma evidence record --input EVENT.json
    soma evidence show EVIDENCE_ID
    soma evidence verify [--from SEQUENCE]
    soma evidence anchor --host HOST

record accepts a schema-valid evidence-event object, recomputes its ID, signs it with the correct role, wraps it in the local sequence entry defined by the Soma Origin Spec, and appends atomically.

It MUST reject:

- secret-bearing or prohibited fields;
- arbitrary evidence kind or capability;
- self-declared independent-verifier status;
- receipt IDs that fail verification;
- an outcome classification not covered by its signed core;
- raw command output, prompts, environment variables, credential values, or unapproved files.

Execution evidence records what was invoked and committed outputs. It does not prove correctness. outcome and factual_verification require the evidence class disclosed by the schema and policy.

verify checks every event ID, signature, sequence, previous hash, current head, historic key window, receipt, and known anchor. Its result distinguishes local consistency from independently anchored rollback assurance.

### 7.5 Observation

    soma observe status
    soma observe preview --evidence EVIDENCE_ID --policy POLICY.json
    soma observe preview --artifact PATH --policy POLICY.json
    soma observe grant --preview PREVIEW_ID
    soma observe send --preview PREVIEW_ID --grant CONSENT_GRANT_ID
    soma observe revoke --grant CONSENT_GRANT_ID [--reason TEXT]
    soma observe suspend
    soma observe resume --grant CONSENT_GRANT_ID

There is no blanket observe-on command. A clean install has no active grant. Each grant is narrow. suspend is a local emergency stop across all grants; resume requires naming and re-displaying each still-valid grant.

The policy input names:

- subject, controller, and observer;
- destination host aliases and exact origins;
- public_artifact, work_summary, or objective_receipt;
- exact authorized projection/fields;
- purpose and operations;
- private_local, host_confidential, federated_training, or public_knowledge state;
- retention seconds;
- redistribution and replication;
- model-training and public-release booleans;
- license identifier/version;
- expiry and withdrawal mode.

preview MUST remain offline. It creates payload.jcs and decision.json, runs deterministic redaction, secret scanning, rights checks, class checks, size checks, and displays every byte and policy field. The preview ID commits to the canonical payload and decision.

grant signs a schema-valid consent grant tied to the preview's authorized projection. It may register the grant metadata with named hosts only after displaying that separate egress. It MUST NOT send the contribution.

send recomputes the event after final redaction and MUST require:

- observer not suspended;
- valid release and local evidence;
- active, unexpired, unwithdrawn grant;
- exact subject, observer, class, projection, purpose, operations, destination, state, retention, replication, training, release, and license match;
- payload hash equal to the approved preview hash;
- host descriptor, signing key, and ingestion-encryption key still pinned and valid;
- a fresh/pairwise Soma return-encryption key bound to this contribution and valid through its status window;
- current network/execution context;
- fresh nonce and expiry;
- size within local and host limits.

Before transmission, Soma MUST bind the contribution's distinct return-encryption public key, key ID, suite, and expiry in the inner signed request, then place that canonical request in a fresh application envelope encrypted to the exact host ingestion key under the ratified recipient-encryption profile. The clear authenticated header contains only the minimum routing and pre-decryption validation fields, including version, recipient host/key IDs, network/context, event and consent IDs or commitments, issued/expiry, ciphertext length, and ciphertext commitment. The signed event and AEAD associated data bind this header. TLS is still REQUIRED.

A fresh content-encryption key and nonce are used for every host envelope. Multi-host authorization produces separate ciphertext for every named host; Soma MUST NOT add recipients, reuse a nonce/key, or use a universal Vera decryption key. Failed or rotated recipient keys require a new preview-visible envelope decision where metadata changes, never silent re-encryption to an unapproved host.

The complete inner contribution acknowledgement has the one canonical shape in `schemas/vera-contribution-acknowledgement.schema.json`; the accepted/narrowed example below names every field. Vera and Soma MUST reject aliases, nesting alternatives, or missing fields.

~~~json
{
  "schema_version": "somavera.vera-contribution-acknowledgement.v1",
  "acknowledgement_id": "<hash>",
  "network_lineage_id": "<network lineage>",
  "execution_context_id": "<execution context>",
  "protocol": "vera",
  "action": "contribution.accepted",
  "host_did": "<accepting host DID>",
  "host_signing_key_id": "<host signing key ID>",
  "request_event_id": "<originating request event ID>",
  "contribution_event_id": "<contribution event ID>",
  "consent_grant_id": "<grant ID>",
  "recipient_ingestion_key_id": "<host ingestion key ID>",
  "soma_return_key_id": "<request-bound return key ID>",
  "return_descriptor_id": "<return descriptor hash>",
  "received_stream_id": "<immutable inbound stream ID>",
  "received_envelope_ciphertext_root": "<immutable inbound ciphertext root>",
  "plaintext_payload_hash": "<approved decrypted payload commitment>",
  "decision": "accepted_narrowed",
  "authoritative_mutation": true,
  "accepted_scope_or_null": {
    "field_projection_hash": "<hash>",
    "data_class": "work_summary",
    "purposes": ["safety_evaluation"],
    "operations": ["collect", "store_encrypted", "evaluate"],
    "data_state": "host_confidential",
    "retention_deadline": "2027-01-31T00:00:00Z",
    "replication": "none",
    "model_training": false,
    "public_release": false,
    "license": "<license identifier>"
  },
  "durable_object_ids": ["<hash>"],
  "host_sequence_or_null": 1,
  "state_or_checkpoint_reference_or_null": "<hash>",
  "status_reference": "<append-only status reference>",
  "typed_reason_or_null": null,
  "issued_at": "2027-01-01T00:00:01Z",
  "signature": { "suite": "Ed25519-v1", "key_id": "<host signing key ID>", "value": "<base64>" }
}
~~~

The plaintext payload commitment is sensitive and exists only inside this signed acknowledgement after the acknowledgement has been encrypted to the request-bound return key. It never appears in a clear request/response header, AAD hash input, proxy record, or queue index.

`accepted` or `accepted_narrowed` requires `authoritative_mutation=true` and is valid only after the named durable objects and resulting state reference exist. `rejected` requires `authoritative_mutation=false`, null accepted scope/durable fields, and a typed reason. A host may narrow but MUST NOT broaden the grant. Unknown critical fields, a contradiction, a broadened scope, or any mismatch with the request, preview, grant, recipient ciphertext, or current context is rejection.

The host signs the complete acknowledgement first, then encrypts it to the exact Soma return key bound by the contribution and signs the outer return envelope. Soma verifies the outer envelope, decrypts, independently verifies the inner acknowledgement, and atomically stores both before reporting confirmation. A timeout uses a new encrypted idempotent status request with its own return key; Soma never blindly resubmits.

revoke first disables matching local egress, then creates a separately encrypted signed withdrawal for every destination, with a distinct return key in each request. It accepts only a host-signed deletion/tombstone receipt encrypted to the corresponding key and clearly reports pending hosts, public irreversibility, backup window, and unlearning limitation. Every retry or status lookup is a new request with a new return key and cannot widen the withdrawal.

Background observation, watchers, and plugin egress are not supported in v0.1. A later watcher MUST use this exact preview/grant/send engine and pass the bypass suite before release.

### 7.6 Vera query and exact local receipt

    soma ask QUESTION [--host HOST] [--limit N]
    soma ask --stdin [--host HOST] [--limit N]
    soma intelligence list [--host HOST]
    soma intelligence show ANSWER_BUNDLE_ID
    soma intelligence search QUERY [--pack PATH] [--offline]

ask is an explicit foreground network operation, not observation consent. Observation may remain off. In that state the only permitted packets caused by one invocation are the displayed encrypted request to one pinned host and its bound encrypted response, or a separately invoked idempotent encrypted status lookup and response. No prefetch, failover, automatic background retry, update check, telemetry, contribution, training, or second destination is permitted. The command MUST show or make machine-readable:

- exact pinned host and origin;
- query bytes and query hash;
- whether the host stores queries;
- query retention;
- disclosed subprocessors/model providers;
- the fresh or pairwise Soma return-encryption key ID, suite, and validity that the signed query will authorize for this response only;
- explicit statement that asking does not authorize training;
- maximum cost or quota, which is zero-value quota in the v0.1 pilot.

QUESTION on the command line is allowed only for non-sensitive pilot material because shell history and local process inspection may expose it. --stdin is RECOMMENDED. The v0.1 pilot MUST reject detected secrets and prohibited data in queries.

The query is a somavera.signed-event.v1 event bound to:

- protocol soma;
- action vera.query;
- the active network lineage and execution context;
- agent actor DID;
- pinned host DID as audience;
- nonce, issue, and expiry;
- query, limit, requested source fields, response-format version, and the Soma return-encryption public key, key ID, suite, and expiry.

The outbound query MUST be an inner signed event encrypted to the exact pinned host ingestion key inside the signed outer application envelope. The remote response MUST be a host-signed outer return envelope whose ciphertext contains the complete host-signed answer/source bundle and is addressed to the exact Soma return key bound by the query. Soma MUST NOT display it as verified until it:

1. bounds and validates the outer header/ciphertext length before allocation;
2. verifies the outer host signature, recipient key ID, ciphertext commitment, network/context, query event ID, issue/expiry, and suite;
3. decrypts only with the exact authorized return key and authenticated associated data;
4. verifies the inner bundle ID and host signature independently;
5. verifies both host signing-key and encryption-key status at issue time;
6. binds the response to the exact query event ID, host audience, network, execution context, and return key;
7. verifies every included source manifest, content hash, license, provenance link, and evaluation status that is available;
8. rejects duplicate IDs, unknown critical fields, unsupported algorithms, stale context, invalid rights declarations, and any outer/inner mismatch;
9. stores the exact return envelope plus the exact decrypted signed response bytes in encrypted local storage before normalized interpretation;
10. atomically stores answer-bundle.json and verification.json.

The complete signed answer/source object MUST conform exactly to
`schemas/vera-answer-source-bundle.schema.json` at the repository root.
`examples/vera-answer-source-bundle.example.json` is the sole non-normative
field guide. Alternative field names, aliases, or nesting are invalid. Provider
and model disclosure follows that closed schema; absence or uncertainty remains
visible. A host signature proves origin and integrity, not truth.

The answer/source-bundle identifier and host signature, the outer encrypted
response identifier and signature, the request/return-descriptor binding, and
their exclusion projections are defined in `ID-DERIVATION.md` and exercised by
the shared conformance suite. The profile remains `freeze_blocking_draft` until
independent implementations publish matching cryptographic vectors and the
profile is independently reviewed and ratified. A host cannot substitute another
Soma key, and Soma cannot reuse a signing key as an HPKE/recipient key.

### 7.7 Sovereign Vera export, verification, import, and offline use

    soma export --scope vera --output DIRECTORY [--since TIME] [--host HOST]
    soma verify --pack DIRECTORY --offline
    soma import --pack DIRECTORY --scope vera --read-only
    soma intelligence search QUERY --pack DIRECTORY --offline
    soma intelligence show ANSWER_BUNDLE_ID --pack DIRECTORY

export --scope vera MUST work without contacting any host. It creates a new owner-only directory named:

    TIMESTAMP.soma-vera-pack/

It includes:

    TIMESTAMP.soma-vera-pack/
      pack-manifest.json
      identity/
        public-identity.json
        public-key-history.json
      hosts/
        HOST_DID.json
      vera/
        queries/
          QUERY_EVENT_ID/
            request.json
            response.raw
            answer-bundle.json
            verification.json
        sources/
          CONTENT_HASH/
            source-manifest.json
            content OPTIONAL
      consent/
        relevant-grants/
        relevant-withdrawals/
      evidence/
        relevant-events/
        host-acknowledgements/
      licenses/
        LICENSE_ID.txt or a content-addressed license reference
      verification/
        export-report.json

The default sovereign pack is owner-private and includes the exact query and exact received response bytes as authorized sensitive owner content encrypted under its export profile. It never includes managed authority secrets. A separately requested future shareable/redacted pack is a derived artifact and MUST have a different pack ID and explicit redaction provenance.

pack-manifest.json contains:

- schema version and pack ID;
- creation time and exporter release hash;
- controller/agent public identity and signing key ID;
- source network lineage and every execution context represented;
- sorted file entries containing relative path, byte length, SHA-256, media type, rights class, license, provenance IDs, and required/optional status;
- omitted-content entries explaining rights, availability, or user exclusion;
- answer-bundle IDs and query-event IDs;
- previous pack ID when incrementally derived;
- signature over the pack ID.

Path separators in the manifest are forward slashes. Paths are UTF-8, relative, normalized, unique, case-collision-free, and traversal-free. Files are copied byte-for-byte. The pack ID is computed from a JCS core that excludes pack ID and signature using a ratified domain. Directory metadata and filesystem timestamps are not identity inputs.

The pack MUST include:

- every selected signed answer bundle;
- exact outbound query-envelope and inbound return-envelope bytes and ciphertext commitments;
- exact decrypted host-signed response bytes, protected by the owner-private export profile;
- its exact inner signed query;
- every available source manifest and content hash;
- source content only when its license and redistribution field permit copying;
- host descriptor and public key material needed for offline verification;
- model/service metadata, uncertainty, limitations, and verification status;
- license/provenance needed to interpret and lawfully use the result.

The pack MUST NOT include:

- private signing or recovery keys;
- vault credentials or authentication tokens;
- unrelated evidence or grants;
- logs, caches, cookies, environment data, or machine secrets;
- restricted source content merely because the host once displayed a citation;
- claims that unavailable source bytes were verified.

verify --pack --offline MUST use only the pack, the ratified root capsule/trust roots, and local verifier code. It checks the manifest, every file hash, signatures, historic host keys, network/context labels, query/answer binding, source manifests, license references, evidence/acknowledgements, path safety, duplicates, and omissions. Network access during --offline is a test failure.

import --scope vera --read-only imports verified intelligence into another Soma home without importing controller authority, private keys, active consent, host sessions, queue entries, or reputation. Imported records retain original identity, network, host, provenance, license, and verification status and are labeled imported_read_only.

Another owner-controlled agent can use a sovereign pack without a Vera Host by:

- reading the documented JSON and raw files directly;
- running intelligence list, show, or search against the pack;
- importing the pack read-only into its own Soma home.

Offline search in v0.1 is deterministic retrieval over stored questions, answers, citations, titles, identifiers, and metadata. It MUST NOT pretend to provide new host inference. A separately configured local model MAY summarize imported material only under a distinct local-model profile; the original signed bytes, citations, rights, and provenance remain unchanged and the new output is labeled locally derived.

The user's lawful local access does not imply permission to republish third-party source content. The pack is open-format, not automatically open-license.

### 7.8 Full Soma owner-state backup, verification, import, and restore

    soma backup create --scope owner-state --output BACKUP
    soma backup verify --input BACKUP --offline
    soma backup import --input BACKUP --read-only
    soma backup restore --input BACKUP --target SOMA_HOME

The owner-state backup is neither an identity-recovery bundle nor a Vera sovereign pack. `create` takes one locked consistent snapshot and emits one authenticated encrypted archive to a user-selected path outside SOMA_HOME. Its clear header contains only the ratified format/suite version, KDF or recipient-key parameters, ciphertext length and commitment, and material required to open the archive. The encrypted payload contains `owner-state-manifest.json` and the declared object set.

The deterministic manifest binds backup ID, snapshot ID, source release and schema versions, creation context, logical state root, and sorted entries with normalized relative path, byte length, SHA-256, media type, object schema, data class, rights/provenance references, required/optional status, and omission reason. Included state covers public identity/key history, evidence, grants and withdrawals, inactive host pins, exact retained Vera records, permitted source bytes, sanitized configuration, and inert queue facts. It MAY contain authorized sensitive owner bytes because the archive is owner-private and encrypted. It MUST exclude all managed authority secrets, live store keys, return private keys, authentication tokens, provider/API credentials, cookies, recovery shares, raw keystore material, host/operator credentials, machine secrets, live sessions, unbounded caches, and undeclared files. There is no `include credentials` option.

`create` decrypts included live objects only inside the local process and re-encrypts them with fresh backup-export material controlled by the owner; it never copies a live data-encryption key. It writes to a new temporary path, authenticates and synchronizes the complete archive, verifies it, then atomically publishes it. Cancellation, crash, or disk exhaustion leaves no archive that can verify as complete.

`verify --offline` performs zero network access. Before any state mutation it bounds the outer file and decrypted expansion, authenticates and decrypts every object, rejects traversal, absolute paths, links, junctions, duplicate/case-colliding paths, bombs, unsupported versions, and unknown critical fields, verifies every hash/signature/evidence chain/rights record, recomputes the snapshot root, and produces a dry-run inventory and omission report. When a separately retained prior backup head is supplied, it also detects rollback; otherwise it states that independent rollback detection is unavailable.

`import --read-only` places verified records in an isolated namespace. Imported objects may be inspected and verified but cannot sign, grant consent, unlock credentials, start an agent, create a host session, send, retry, receive a pending private reply, or modify authoritative state.

`restore` first runs the complete offline verification, requires an empty target or an explicit separately specified transactional replacement, creates fresh local store keys, and materializes a candidate state under a deny-all restore quarantine. Identity continuity is unavailable unless a separate valid identity-recovery ceremony succeeds. Grants, credentials, queues, pending sends, host pins, sessions, and old return bindings remain inert. The owner receives the dry-run inventory and must re-confirm each destination, network/context, grant, credential binding, expiry, and current key before new work. Re-authorized operations use fresh sessions, envelopes, nonces, and return keys. Only after the full candidate verifies does one atomic commit make it the local state; any error or interruption leaves the prior target unchanged.

### 7.9 Verification and uninstall

    soma verify
    soma verify --pack PATH --offline
    soma disconnect HOST
    soma uninstall --preserve-state
    soma uninstall --delete-state --confirm-state-hash HASH

soma verify checks release, identity/key history, consent state, evidence ledger, host pins, intelligence bundles, and exports. It performs no network access unless --network is supplied.

Uninstall preserves state by default and prints export and recovery instructions. State deletion requires a fresh verified export or an explicit refusal, the displayed state-root hash, and exact confirmation. It cannot delete independently held host/public copies and MUST say so.

## 8. Signed envelopes and replay protection

Executable network requests MUST conform to schemas/signed-event.schema.json and ID-DERIVATION.md.

For every request Soma MUST:

- use strict RFC 8785 JCS restricted to I-JSON;
- reject duplicate keys, negative zero, non-finite numbers, invalid Unicode, and unknown critical fields;
- recompute payload_hash and event_id;
- sign only the domain-separated event ID;
- bind network_lineage_id, execution_context_id, protocol, action, actor DID, audience host DID, nonce, issue, expiry, optional consent grant, payload, and payload hash;
- use a cryptographically random nonce of at least 128 bits;
- default request expiry to no more than five minutes, with shorter values for high-risk operations;
- persist idempotency state before a state-changing send.

Host responses and acknowledgements require their own ratified schemas and signature domains. Reusing an event signature across actions, hosts, networks, contexts, or response types is forbidden.

### 8.1 Bidirectional application-encryption envelopes

Application encryption is independent of TLS and MUST use a ratified HPKE or equivalent hybrid recipient-encryption profile with an approved AEAD. Every outbound non-public registration/challenge, contribution, withdrawal, status, or query request contains an action-specific inner signed application event. A distinct outer signed routing header contains only the minimum pre-decryption fields frozen by `schemas/vera-application-envelope.schema.json`: suite/version, network/context, sender, exact recipient/key ID, inner event ID, consent ID or null, issue/expiry, stream/ciphertext commitment, ciphertext length, and outer nonce/idempotency fields. The inner object is ciphertext; it is never duplicated in the clear outer payload. A raw plaintext, query, payload, or answer hash is forbidden in this clear header and in the clear AAD-hash projection because it can enable dictionary fingerprinting. The outer signature and AEAD associated data bind the allowed header and ciphertext; plaintext integrity is verified from the decrypted signed inner object.

Every non-public application request binds a distinct Soma return-encryption public key, key ID, suite, and expiry. This includes private registration/challenge, contribution, withdrawal, status, and query actions. Vera constructs and signs the complete action-specific reply first, then encrypts it to that exact key and signs a return-envelope header committing to the ciphertext and originating request. Soma validates the outer header, decrypts locally, and independently verifies the inner reply signature. Public descriptors and content-free transport errors are the only v0.1 exceptions. Signing and encryption keys are never reused for the other purpose, and a return key from one request cannot receive a different request's reply.

Fresh content-encryption material is REQUIRED per envelope and recipient. Multiple hosts receive separately created ciphertext. Unknown suites, expired/revoked keys, header mutation, ciphertext mutation, wrong recipient, wrong event/query, wrong consent, nonce/key reuse, added recipients, and outer/inner mismatch fail before authoritative storage or display.

The envelopes protect bodies through network observers, reverse proxies, durable queues, ordinary databases, backups, and unintended peers. They do not hide plaintext from the authorized Vera process or a privileged host operator during ordinary processing, and they do not hide IP addresses, timing, or approximate sizes. No UI or documentation may call the normal profile operator-blind, anonymous, confidential computing, or zero-knowledge. Padding/anonymity routing and attested-TEE, MPC, FHE, or verifiable-compute profiles require separate threat models, consent, and tests.

## 9. Local evidence ledger

ledger.jsonl contains exactly one canonical JSON object per line using the local-entry wrapper in the Soma Origin Spec. The writer:

1. obtains the exclusive lock;
2. verifies the current head and last complete entry;
3. builds the next entry and signature;
4. appends and synchronizes the ledger;
5. atomically replaces and synchronizes head.json;
6. releases the lock.

On interrupted write, recovery may remove only an incomplete final byte sequence that cannot parse and was never referenced by the signed head. It MUST NOT silently skip a complete invalid record.

head.json contains schema version, sequence, entry hash, key ID, issue time, signature, and the most recent independent anchor references. A local-only head cannot prove absence of rollback by a full-disk attacker; status and verification MUST report that limit.

Raw questions, prompts, source code, tool bodies, stdout, stderr, environment, and secrets are not evidence-ledger fields. Their authorized artifacts remain in separate owner-controlled storage and are referenced by commitment.

## 10. Keystore, credential broker, and adapter

### 10.1 Keystore

The keystore interface MUST support generate, sign, public metadata, rotate, revoke, lock, unlock, backup wrapping, and deletion. Private key export is forbidden except through the ratified encrypted identity-backup ceremony.

### 10.2 Credential broker

The prototype broker supports no arbitrary bearer HTTP tool. Each capability binds:

- credential reference;
- exact scheme, origin, method, and normalized path rule;
- DNS/private-address policy;
- request/response byte limits;
- invocation and concurrency limits;
- not-before and expiry;
- redirect policy, which defaults to none;
- task and purpose;
- evidence projection;
- optional user confirmation.

The child agent receives results and safe metadata, not the credential. Authorization headers are removed on any origin change even in a future redirect-enabled profile.

### 10.3 Constrained subprocess adapter

    soma run --profile PROFILE -- EXECUTABLE ARG...

The separator is REQUIRED. Soma invokes an executable directly with an argument vector; no shell parses a string. PROFILE fixes executable allow-list, working-root containment, environment allow-list, credential capabilities, networking, timeout, output limit, and evidence projection.

Integrated mode is the default and is labeled bypassable. A brokered profile MAY claim stronger containment only when an OS-specific test proves the child cannot read the keystore, credential store, other user state, or make unapproved outbound connections.

A command exit status records execution only. It MUST NOT automatically create an objective receipt, factual verification, reputation increase, host promotion, reward, or mint.

## 11. Network policy

Defaults are:

| Control | Default |
|---|---|
| non-loopback transport | authenticated HTTPS |
| redirects | disabled |
| connect timeout | 10 seconds |
| ordinary total request timeout | 30 seconds |
| ask total timeout | 120 seconds |
| state-changing retries | zero blind retries; idempotent status resolution only |
| ordinary request body | 1 MiB maximum |
| ordinary response body | 8 MiB maximum |
| streamed export/import | 512 MiB maximum per operation unless policy lowers it |
| decompression ratio | 20:1 maximum and bounded final size |
| concurrent host requests | 4 per host |
| queued contributions | 100 items and 64 MiB total |
| query limit | 20 sources maximum |

These are prototype ceilings, not promises of service. A host may advertise lower limits. Raising them requires explicit local policy and MUST remain under hard implementation bounds.

Soma MUST:

- reject embedded URL credentials and non-HTTP schemes;
- resolve all addresses and reject cloud metadata, link-local, multicast, unspecified, and prohibited loopback targets;
- require --allow-private-host for private-address destinations and still pin identity/TLS;
- revalidate the connected address to resist DNS rebinding;
- disable proxy-environment inheritance unless explicitly configured;
- stream bounded downloads and abort on declared/actual size mismatch;
- prevent compressed and nested archive bombs;
- redact URLs containing sensitive query components;
- never send credentials to a different origin.

## 12. Consent and rights enforcement details

The prototype uses schemas/consent-grant.schema.json, but cannot freeze until an authorized field projection and replication mode are added or bound by a ratified companion object.

The single membrane decision function receives:

    actor
    action
    data class
    field projection
    purpose
    operations
    destination origin and DID
    data state
    retention
    replication
    training and public-release booleans
    license
    current time
    active grant
    preview payload hash
    secret-scan result
    local suspension state

It returns allow or a typed denial. There is no wildcard class implied by public_artifact or work_summary. An allow for one class, field, host, purpose, or operation does not match another.

Every adapter and network action that can contribute learning data MUST call this same function. Tests MUST instrument the network boundary and prove that direct outcome, watcher, plugin, queue, retry, crash-recovery, and background paths cannot bypass it.

Possession of a file is not evidence of the right to contribute it. public_artifact requires a source/rights record. objective_receipt requires verification of its signer roles. The owner warranty is recorded but does not force a host to accept questionable rights.

## 13. Logging, privacy, and local storage

Security logs contain event type, time, component, status code, public IDs, byte counts, and redacted error class. They MUST NOT contain:

- private keys, recovery data, credentials, headers, cookies, or tokens;
- questions, answers, prompts, source code, file content, model output, stdout, or stderr;
- full local paths, email addresses, IP-to-person mapping, device identifiers, or identity-linkage data;
- consent payload content beyond public IDs and status;
- raw host responses.

Questions and answers live only in the encrypted intelligence store, protected as owner-private state under a store-specific key. Evidence attachments, queues, credentials, source bytes, and host-confidential material are likewise encrypted at rest. Search indexes MUST contain no plaintext body unless a separately approved encrypted-index design protects it. Exported sovereign packs receive owner-only permissions and a warning that exact queries may be sensitive; an encrypted export option MUST be used for any pack leaving owner-controlled storage.

Update checks, product telemetry, and crash-report transmission are off by default. Each future networked function requires its own displayed destination, purpose, payload preview, and explicit enablement; none may carry agent work, questions, answers, identity linkage, consent content, credentials, or Vera payloads. v0.1 MAY omit all three.

## 14. Configuration

config.json contains only non-secret local settings:

- schema version;
- default host alias;
- observer suspension state;
- selected enforcement profile;
- size/time/concurrency values at or below hard bounds;
- update-check setting, default false;
- log level;
- active release identity.

policy.json contains local capability and consent defaults. It cannot broaden a signed grant or host limit.

Config parsing uses strict schema validation and rejects unknown fields. An invalid config does not fall back to permissive defaults.

Secrets, host bearer tokens, and private keys are keystore references, never config values.

## 15. Exact failure and recovery semantics

- Invalid local evidence: reject before preview.
- Invalid or prohibited preview: store a redacted denial record, send nothing.
- Grant creation failure: no grant and no send.
- Send rejected before host mutation: preserve preview and grant; report rejection.
- Network timeout with possible host mutation: mark remote status unknown and query by event ID.
- Invalid host acknowledgement: quarantine it and treat contribution as unconfirmed.
- Invalid return envelope or answer bundle: retain bounded ciphertext in quarantine only if policy permits; never retain failed-decryption plaintext, and do not display or export it as valid.
- Disk-full before atomic commit: keep prior state intact and report failure.
- Evidence corruption: enter read-only recovery mode; no observation or key mutation.
- Secure keystore loss: enter verification/export-only mode where public material remains usable.
- Host key/context change: stop and require reconnection verification.
- Consent expiry during queueing: cancel send; do not extend expiry.
- Withdrawal host offline: local block is immediate; remote status remains pending.
- Invalid, corrupt, wrong-recipient, rolled-back, unsupported, or policy-incompatible owner-state backup: fail before target mutation and retain no decrypted temporary object.
- Interrupted authoritative restore: discard or retain only the clearly marked quarantined candidate; the prior target remains authoritative and no recovered authority becomes active.

## 16. Phoenix and clean-room behavior

### 16.1 Rebuild from release capsule

A clean-room team MUST be able to:

1. verify the capsule offline against an independently retained trust fact; the capsule MUST NOT authenticate itself;
2. build Soma and its independent verifier;
3. reproduce artifacts;
4. pass all vectors;
5. install on every Tier 1 platform;
6. initialize offline;
7. connect to a test remote Vera Host using only documented trust material;
8. retrieve, verify, store, export, and re-import a signed intelligence pack;
9. create, verify, read-only import, and transactionally restore a full encrypted owner-state backup; and
10. reject corrupt releases, keys, grants, events, answers, packs, and backups.

Any required founder machine, private repository, live cloud service, DNS name, or undocumented secret fails the drill.

### 16.2 User state restoration

- Valid identity-recovery bundle: verify, restore, and rotate online keys; it does not restore owner state by itself.
- Valid full owner-state backup: verify every byte, import read-only or stage a transactional quarantine restore; it does not restore identity continuity by itself.
- Valid sovereign Vera pack only: restore intelligence read-only; do not claim identity continuity or complete owner state.
- Public licensed intelligence only: import as external public material with provenance.
- No authenticated user state: create a new identity with observer off and no history.

### 16.3 Exact network succession

Soma requires the complete authenticated content-addressed checkpoint state bytes, not merely a root, manifest, locator, or hash list. It independently recomputes the checkpoint root from every required object, verifies the recovery certificate and exact network lineage, adopts the new execution context only after confirmation, permanently rejects old-context requests for the successor, and requires fresh envelopes. Any missing required byte makes exact succession unavailable. It MUST re-confirm changed host origins or keys before resuming observation.

### 16.4 Phoenix network

Soma treats the new lineage as a new network. It MUST NOT carry active consent grants, host sessions, pending events, reputation, or canonical history into it. Public or sovereign intelligence may be imported with its old lineage and provenance clearly labeled, but it does not become new-network truth.

## 17. Mandatory acceptance tests

Every test records exact release hash, platform, clean-state precondition, packets/files observed, expected result, actual result, and artifact hashes. Mandatory failures make the release nonconforming.

### 17.1 Packaging and portability

| ID | Requirement |
|---|---|
| PKG-001 | Fresh install and doctor pass on each Tier 1 platform without source edits. |
| PKG-002 | Release rebuild matches expected artifact hashes from pinned offline-capable inputs. |
| PKG-003 | Secret scanner finds no state, key, credential, host IP, username, machine path, unlicensed data, or developer junction. |
| PKG-004 | Missing, altered, extra executable, or downgraded manifest file is rejected. |
| PKG-005 | State is created outside the release tree with verified owner-only access. |
| PKG-006 | Uninstall preserves state by default and deletion requires exact confirmation. |

### 17.2 Identity and keys

| ID | Requirement |
|---|---|
| ID-001 | init generates identity offline with zero packets. |
| ID-002 | Restart preserves identity; no key is written to ordinary JSON. |
| ID-003 | Unsupported keystore causes production init to fail, not plaintext fallback. |
| ID-004 | Wrong role, mutated signature, wrong audience, network/context replay, stale nonce, expiry, and algorithm downgrade fail. |
| ID-005 | Rotation preserves valid historic verification and blocks the old key for new acts. |
| ID-006 | Revocation propagates idempotently and revoked-key requests fail. |
| ID-007 | Valid recovery bundle restores and rotates; corrupt/wrong-secret bundle mutates nothing. |
| ID-008 | Loss without recovery creates a new identity and never claims continuity. |
| ID-009 | A parent DID or nature label without signed credential/delegation gains no authority. |

### 17.3 Consent and egress

| ID | Requirement |
|---|---|
| CON-001 | Clean install and observer-off produce zero observer/training packets during agent work, outcomes, retries, startup, shutdown, doctor, and idle time. |
| CON-002 | preview performs zero network access. |
| CON-003 | Sent canonical payload hash equals approved preview hash. |
| CON-004 | Unknown class, field, purpose, operation, destination, state, license, or replication mode fails. |
| CON-005 | A grant cannot be widened by local config, host response, redirect, plugin, or queue. |
| CON-006 | Expired, revoked, withdrawn, wrong-subject, wrong-observer, or wrong-host grant fails. |
| CON-007 | suspend blocks every active grant; resume names each grant. |
| CON-008 | Outcome, adapter, plugin, queue, crash recovery, and future watcher paths cannot bypass the membrane. |
| CON-009 | Secret, private-work, regulated-sensitive, and identity-linkage canaries are blocked before egress. |
| CON-010 | Withdrawal immediately stops local sends and records per-host deletion/tombstone status honestly. |
| CON-011 | Host cannot silently extend retention, replication, training, public release, region, or subprocessor policy. |
| CON-012 | Observer refusal does not block identity, local evidence, ask, local intelligence, or export. |
| CON-013 | Every non-public registration/challenge, contribution, withdrawal, status, or query request and every corresponding private Vera reply uses fresh recipient ciphertext bound to the exact host or Soma return key, originating inner object, authority, network, and context; plaintext private replies, signing/encryption-key reuse, nonce/key reuse, wrong recipient, header/ciphertext mutation, outer/inner mismatch, and silent added recipients fail. |
| CON-014 | With observer off, one explicit ask emits only its displayed encrypted request to one pinned host and the bound encrypted response. Prefetch, failover, automatic retry, update, telemetry, contribution, training, second-destination, and post-answer traffic remain zero; asking leaves observer state and training consent unchanged. |

### 17.4 Evidence

| ID | Requirement |
|---|---|
| EVD-001 | Valid append produces the expected cross-language entry hash and signature. |
| EVD-002 | Mutation, insertion, deletion, reordering, duplicate sequence, and invalid key window are detected. |
| EVD-003 | Tail truncation assurance distinguishes local-only from independently anchored heads. |
| EVD-004 | Concurrent writers cannot fork or corrupt the ledger. |
| EVD-005 | Crash between ledger and head writes recovers without accepting an invalid complete entry. |
| EVD-006 | Receipt class and verifier role are signed and cannot be altered. |
| EVD-007 | A zero exit code or self-signed outcome never becomes objective verification or reputation. |
| EVD-008 | Evidence contains no raw secret, prompt, code, environment, stdout, or stderr. |

### 17.5 Remote-only Vera retrieval and sovereign export

| ID | Requirement |
|---|---|
| VERA-001 | A fresh Soma client connects to a remote Vera Host with no local Vera process installed. |
| VERA-002 | Wrong host DID, key, TLS identity, network, execution context, descriptor signature, or unexpected policy change fails before registration/use. |
| VERA-003 | ask binds an inner signed query and its Soma return key to the exact host, encrypts it to the pinned host ingestion key, and stores the exact inner request and outer envelope. |
| VERA-004 | Unsigned, unencrypted, mutated, oversized, replayed, stale-context, wrong-query, wrong-host, wrong-return-key, undecryptable, or outer/inner-mismatched answer is rejected. |
| VERA-005 | A valid return stores exact response-envelope ciphertext, decrypted signed response.raw under local encryption, normalized answer, all sources, license/provenance, service/model metadata, uncertainty, limitations, and verification result atomically. |
| VERA-006 | Host signature is displayed as provenance, never factual truth. |
| VERA-007 | Observation remains off before, during, and after ask unless a separate active grant exists. |
| VERA-008 | Asking does not create training consent. |
| VERA-009 | export succeeds with all hosts offline and includes exact signed answer/source records and permitted source bytes. |
| VERA-010 | Export omits signing/recovery keys, credentials, logs, caches, and unlicensed/restricted source content. |
| VERA-011 | Offline pack verification performs zero network access and detects any file, manifest, signature, path, rights, or provenance mutation. |
| VERA-012 | Fresh-home read-only import reproduces the answer inventory and every content hash without importing identity authority or active consent. |
| VERA-013 | Another owned agent can list, show, and deterministic-search the open pack offline. |
| VERA-014 | Local-model derivation preserves originals and labels the new output locally derived. |
| VERA-015 | Host disappearance does not disable already stored valid intelligence. |
| VERA-016 | Shareable/redacted output, if later implemented, receives a distinct ID and redaction provenance. |
| VERA-017 | Local questions, answers, source bodies, queues, and host-confidential records are encrypted at rest; copied files and indexes reveal no plaintext canary without the user-controlled keystore. |
| VERA-018 | Vera signs the complete answer/source bundle before encrypting it to the exact fresh/pairwise Soma return key in the query; an intermediary, other Soma identity, reused signing key, substituted return key, or expired key cannot read or validate as recipient. |
| VERA-019 | A contribution acknowledgement matches the exact field contract in section 7.5, proves its durable accepted/narrowed or non-mutating rejected decision, is signed before encryption to the contribution-bound return key, and is stored only after outer and inner verification; missing, broadened, contradictory, early, plaintext, or wrong-key acknowledgements fail. |

### 17.6 Broker and network security

| ID | Requirement |
|---|---|
| NET-001 | SSRF attempts to cloud metadata, link-local, multicast, unspecified, prohibited loopback, and unapproved private addresses fail. |
| NET-002 | Redirects fail and cannot leak credentials. |
| NET-003 | DNS rebinding and address-family substitution fail. |
| NET-004 | Timeouts, body limits, decompression ratio, concurrency, queue, and disk ceilings are enforced. |
| NET-005 | Proxy environment variables are ignored unless explicitly approved. |
| NET-006 | Brokered credentials never reach the child or a different origin. |
| NET-007 | Subprocess adapter uses executable/argv without shell interpretation and enforces root, environment, timeout, and output bounds. |
| NET-008 | Integrated mode is always labeled bypassable; brokered mode requires platform containment evidence. |
| NET-009 | Malicious model output cannot alter consent, policy, destination, executable authority, or evidence classification. |
| NET-010 | TLS termination, proxy queues, packet captures, and copied Soma/host storage expose no non-public query, contribution, or answer body outside the exact recipient process; bidirectional metadata leakage and ordinary host-memory visibility remain disclosed. |

### 17.7 Phoenix and recovery

| ID | Requirement |
|---|---|
| PHX-001 | Independent clean-room build and remote-only Vera flow succeed from the capsule plus an independently retained trust fact; the capsule alone cannot authenticate its own claimed origin. |
| PHX-002 | Corrupt capsule, downgraded suite, forged release, or missing dependency fails. |
| PHX-003 | Sovereign pack restores intelligence but not identity, consent, reputation, or host authority. |
| PHX-004 | No user backup yields a new identity, observer off, no destinations, and no historical claims. |
| PHX-005 | Exact succession accepts the same network lineage and new context only after all committed state-object bytes are present, the checkpoint root is independently recomputed from them, and the valid recovery certificate authorizes succession. A root, manifest, locator, or hash list alone fails. |
| PHX-006 | Old-context requests and queued envelopes cannot replay on the successor. |
| PHX-007 | Phoenix lineage rejects old consent and labels imported old intelligence as external history. |

### 17.8 Full Soma owner-state backup and restore

| ID | Requirement |
|---|---|
| BAK-001 | create takes one consistent snapshot, produces the deterministic manifest/object set, uses fresh owner-controlled backup encryption, and never copies a live store key. |
| BAK-002 | Offline verify performs zero network access, authenticates/decrypts every object, recomputes every hash and snapshot root, validates schemas/evidence/rights, and reports omissions and rollback-assurance level. |
| BAK-003 | One-bit corruption, truncation, wrong recipient/password, missing/extra/reordered object, unsupported version, traversal, absolute path, symlink/junction, case collision, duplicate, expansion bomb, rollback, and resource exhaustion all fail before mutation. |
| BAK-004 | The encrypted archive may contain authorized sensitive owner bytes, but scans find no managed authentication/recovery secret, bearer/API credential, cookie, raw keystore material, live store/return key, machine secret, or plaintext sensitive body outside the encrypted payload. |
| BAK-005 | Read-only import reproduces every declared record/hash in an isolated namespace while signing, consent, credential, agent, host-session, queue, retry, send, pending-reply, and authoritative-mutation attempts all fail. |
| BAK-006 | Transactional restore stages under fresh local store keys and deny-all authority quarantine, presents a dry-run inventory, and commits atomically only after complete verification; failure or power loss leaves the prior target byte-for-byte authoritative. |
| BAK-007 | Restored grants, credentials, queues, pending sends, host pins, sessions, and return bindings remain inert until separately re-confirmed; new work uses fresh sessions, envelopes, nonces, and return keys and no pre-backup action replays. |
| BAK-008 | Identity backup, full owner-state backup, and Vera sovereign pack are mutually non-substitutable: each artifact restores only its declared scope and cannot confer either of the other two scopes. |

## 18. Pilot topology and release gate

The first private end-to-end gate uses:

    Owner workstation
      - clean Soma Pack
      - one test agent adapter
      - no local Vera Host required

    Remote Vera Host A
      - fresh pilot keys and isolated data
      - authenticated TLS

    Independent Vera Host B
      - separate operator and keys
      - verifies one authorized replicable public event

    Offline recovery workstation
      - capsule, independent trust fact, sovereign pack, and owner-state backup only
      - no network during verification/import

Fixtures are non-sensitive. Current prototype keys, databases, host tokens, and live development directories MUST NOT be reused.

The invited pilot begins only after sections 17.1 through 17.7 pass with no unresolved critical or high finding. It remains tokenless and has no public reputation score.

## 19. Implementation order

P0 implementation order is:

1. clean package builder, release verifier, strict config, and Tier 1 CI;
2. JCS, hashes, signed envelopes, key IDs, and cross-language vectors;
3. secure keystore, offline identity creation, history, rotation, revocation, and recovery;
4. signed local evidence ledger and independent verifier;
5. one consent/membrane/redaction/secret-scan engine;
6. preview, grant, send, withdrawal, and acknowledgement schemas and commands;
7. pinned remote host descriptor, challenge, bounded client, and response verification;
8. exact ask storage and signed answer/source bundle;
9. sovereign open-format export, offline verify, read-only import, and offline search;
10. encrypted full owner-state backup, offline verify, isolated read-only import, and transactional quarantine restore;
11. constrained broker and subprocess adapter;
12. complete adversarial suite and clean-room Phoenix drill;
13. closed remote-host pilot.

No background watcher, money, token, public reputation, or model training work may displace these P0 items.

## 20. Definition of prototype complete

Prototype complete means:

- every MUST in this document is implemented or explicitly marked inapplicable by a ratified amendment;
- every machine object has a frozen schema, ID/signature projection, and positive/adversarial vectors;
- every mandatory test passes on every claimed platform;
- remote-only Soma-to-Vera retrieval and sovereign offline export/import pass;
- full encrypted owner-state create/verify/read-only-import/transactional-restore passes without importing authority or managed secrets;
- release packages are clean, reproducible, signed, and independently rebuilt;
- security/privacy review has no unresolved critical or high finding;
- documentation states all limitations and modes honestly;
- the exact release is marked prototype, not production or apocalypse-ready.

The phrase complete MUST NOT be inferred from a demo, one green script, syntax success, a working VPS, or unreviewed founder use.

## 21. Security review checklist

Before freeze, reviewers MUST answer:

- Can any path emit learning data without an exact active grant?
- Can public_artifact act as a wildcard for another class?
- Is every destination check based on both exact origin and pinned host DID?
- Can outcome, receipt class, model metadata, or verifier role change outside a signature?
- Can an agent forward a vault credential to an arbitrary URL or redirect?
- Can local file editing inflate evidence, assurance, or reputation?
- Can a shell, path, symlink, junction, or archive escape containment?
- Can an answer be displayed before request/host/source verification?
- Does export preserve exact bytes, licenses, provenance, and limitations?
- Can another owned agent use the pack without the original host?
- Does offline verification truly make zero network calls?
- Does a valid intelligence pack accidentally import authority or consent?
- Can an owner-state backup be verified and inspected without activating any recovered authority, and can restore fail without mutating the prior target?
- Does any owner-state archive contain a managed authentication/recovery secret instead of only authorized sensitive owner bytes?
- Does key loss result in honest new identity when recovery is absent?
- Does Phoenix create a new lineage and reject old consent?
- Does every degraded assumption stop or visibly narrow operation?

## 22. P0 freeze blockers

The following artifacts are not yet present or not yet ratified in the root capsule and MUST be completed before this prototype spec freezes:

1. DID, signing/encryption key-ID and purpose separation, role, identity, key-history, rotation, revocation, and recovery-event schemas and vectors.
2. Active local-store AEAD/key hierarchy, identity-recovery and owner-state-backup recipient/password KDFs, parameters, associated-data rules, deterministic owner-state manifest/snapshot schema, quarantine/transaction vectors, and recovery-bundle vectors.
3. Local evidence-ledger entry/head schema and the hash/signature domains proposed by the Soma Origin Spec.
4. Consent authorized-field projection and replication-mode representation.
5. Vera host descriptor, host signing/ingestion-key lifecycle, Soma return-key lifecycle, registration/challenge, bidirectional outer-envelope schemas/signatures, metadata profile, and the ratified HPKE or equivalent suite and vectors.
6. Contribution acknowledgement, withdrawal, deletion, backup-expiry, and tombstone receipt schemas.
7. Vera query and answer/source-bundle schemas, IDs, signature domains, and source-rights vocabulary.
8. Sovereign Vera pack manifest schema, ID/signature domain, and valid/invalid pack vectors.
9. Exact release-manifest trust roots and threshold software-signing procedure.
10. Platform keystore adapter requirements and fixtures.
11. Capability/broker and constrained subprocess profile schemas.
12. Reference Vera Host behavior needed to run the remote-only acceptance suite.

Until all twelve close, this file remains draft and no implementation may claim full conformance.
