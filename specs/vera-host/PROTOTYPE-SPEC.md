# SOMAVERA VERA HOST PROTOTYPE SPEC

Document ID: somavera/vera-host/prototype/0.1-draft
Status: **executable draft; not implemented, passed, or production-ready**
Target: valueless, non-sensitive, two-or-more-host private pilot.
Implements: the Vera Host Origin Spec, subject to the root Somavera capsule.

MUST and MUST NOT state proposed conformance behavior, not completion.

## 1. Required operator journey

A fresh host-only operator with no Soma installation completes:

~~~text
vera verify-release --offline
vera init --profile local|docker-local|vps --instance NAME
vera doctor --instance NAME
vera start --instance NAME --private
vera join preview --instance NAME --peer https://peer.example
vera join apply --instance NAME --preview-id ID
vera query public --instance NAME --text "question" --top-k 5
vera export public --instance NAME --output public-slice.svpack
vera pack verify public-slice.svpack --offline
vera checkpoint create --instance NAME
vera verify-state --instance NAME
vera backup create --instance NAME --output sealed-backup.svpack
vera restore verify sealed-backup.svpack --offline
vera restore apply sealed-backup.svpack --instance RESTORED --read-only
~~~

The initializer generates separate host and operator identities. Soma is
required only for controlled agent contribution, controller-confidential query,
or controller rights. Public replication, public query/export, checkpoint,
backup, and restore do not require Soma, HeyVera, a token, or a subscription.

## 2. Scope and disabled features

In scope: signed release verification; Windows, macOS, Linux/Docker, and VPS
packaging; strict auth/TLS; key separation; signed consent/ingest/acknowledgement;
encrypted storage; immutable public events; quarantine; retrieve-v0; signed
cursor replication; withdrawal/tombstones; provenance-linked query; signed
answer/source and public-slice packs; checkpoint, backup, restore, exit, and
Phoenix tests.

Disabled in v0.1:

- VERA activation, mint, burn, staking, rewards, balances, or host yield;
- validator/consensus code;
- reputation increases merely for submission, outcome, hosting, or payment;
- external LLM calls, training, fine-tuning, federated learning, model weights;
- private_work, secrets, regulated data, identity linkage, and unknown classes;
- arbitrary fetch, webhook, plugin, shell, archive expansion, or remote code;
- anonymous confidential query/export;
- automatic peer contact or trusted legacy import;
- confidential-computation or superintelligence claims.

Inference calls, tokens, and daily cost limits are hard zero.

## 3. Release and platform UX

The signed release folder contains:

~~~text
vera-host-0.1.0-draft/
  START-HERE.txt
  start.bat
  start.command
  start.sh
  install-vps.sh
  uninstall-vps.sh
  bin/windows-x86_64/vera.exe
  bin/macos-arm64/vera
  bin/macos-x86_64/vera
  bin/linux-x86_64/vera
  container/compose.yaml
  container/vera-host.oci.tar
  container/image-digest.txt
  capsule/root/
  capsule/specs/
  capsule/schemas/
  capsule/conformance/
  config/local.example.toml
  config/vps.example.toml
  RELEASE-MANIFEST.json
  RELEASE-SIGNATURES.json
  SHA256SUMS
  SBOM.spdx.json
  VERIFY.txt
  LICENSES/
~~~

Every launcher verifies hashes and release signatures offline before it creates
state, opens a browser, or makes a network request. Failure starts nothing and
names the failing path.

The release contains no runtime DB, private key, recovery share, credential,
operator token, live peer, contribution, private grant, or model corpus.

### 3.1 Drag and drop

With no argument, a launcher initializes or starts the named local instance.
Dragging a .svpack file onto start.bat or start.command verifies it and opens an
import preview. It never applies automatically.

The preview shows pack ID/kind, producer, lineage/context, checkpoint range,
object counts, licenses, tombstones, encrypted/private presence, and every
verification failure. Apply is a separate signed operator action.

### 3.2 Windows

start.bat stores state under:

    %LOCALAPPDATA%\Somavera\VeraHost\instances\<instance>

It generates protected key references, binds 127.0.0.1 only, and opens
http://127.0.0.1:3210/setup after the listener is ready. It works from paths
with spaces/non-ASCII text and needs no administrator for local mode.

### 3.3 macOS

start.command stores state under:

    ~/Library/Application Support/Somavera/VeraHost/instances/<instance>

It uses Keychain where available, re-verifies after quarantine clearance, and
never asks to disable system-wide protections.

### 3.4 Linux and Docker

start.sh defaults to the XDG state directory or
~/.local/state/somavera/vera-host/instances/<instance>. Docker imports the
pinned OCI archive and verifies its digest; it never pulls a mutable tag.

The container uses a read-only root, unprivileged numeric user,
no-new-privileges, all capabilities dropped, bounded PIDs/CPU/memory, dedicated
state volume, read-only config, and no Docker socket.

### 3.5 VPS

~~~text
sudo ./install-vps.sh \
  --hostname vera1.example.org \
  --network-pack /tmp/network.svpack \
  --instance vera1
~~~

The installer verifies before mutation, creates an unprivileged vera-host
service, imports the pinned image, creates hardened systemd/container config,
binds operator UI and metrics to loopback, exposes only authenticated HTTPS on
443, requires a backup target, tests a backup, and starts private/read-only.

Peer contact requires join preview then join apply. Public startup fails without
hostname/certificate, network capsule, separate keys, encrypted storage,
allowed origins, peer trust roots, production policy, and tested backup.

The VPS operator UI is reachable only by SSH tunnel or operator mTLS, never on
the public HeyVera origin.

## 4. Runtime state and keys

Each instance contains:

~~~text
config/config.toml
config/policy-manifest.json
identity/public/
keystore/REFERENCES.json
db/catalog.db.enc
objects/confidential/
objects/quarantine/
objects/public/
events/segments/
replication/segments/
provenance/
checkpoints/public/
checkpoints/sealed/
exports/
backups/staging/
logs/audit.jsonl
tmp/
~~~

POSIX directories/files are 0700/0600; Windows ACLs restrict the user and
service identity. Temporary plaintext is bounded, outside backups, removed on
success/failure/startup recovery, and excluded from crash dumps where the OS
permits.

Separate keystore references exist for host signing, host ingestion HPKE,
transport TLS, operator, storage KEK, backup, and recovery. validator_key_ref is
empty and a nonempty value is a v0.1 startup error. A key cannot serve two
roles. A host signing key is never an ingestion key, and a Soma signing key is
never a return-encryption key.

No long-lived operator bearer token exists. CLI administration uses a named
pipe/Unix socket when possible. Loopback UI sessions are HttpOnly,
SameSite=Strict, memory-backed, operator-approved, and expire within 15 minutes.
Private keys never enter browser code.

## 5. Strict configuration and doctor

config.toml has schema version somavera.vera-host-config.v1. Duplicate and
unknown keys fail. Environment variables may select VERA_HOME and a nonsecret
instance name only; secrets are keystore references.

Required groups are:

- profile, mode, instance_name, network_pack, release_manifest_hash;
- loopback operator/metrics listeners and API listener;
- TLS mode, certificate, transport-key reference, peer CA;
- host-signing/ingestion/operator/storage/backup/recovery key references;
- encrypted database/object paths;
- signed policy manifest and its hash;
- allowed classes, purposes, operations, licenses, retention/backup windows;
- exact peer DID/URL allowlists;
- outbound deny policy;
- hard limits and storage reserve;
- backup destination;
- inference disabled with zero budget.

Public/VPS doctor fails for:

- bad release/capsule or lineage/context;
- unknown config/schema;
- nonloopback bind without authenticated TLS;
- missing/reused/revoked keys;
- plaintext or unreadable storage;
- permissive permissions;
- missing policy/trust roots/backup;
- outbound targets resolving to private, loopback, link-local, multicast, or
  metadata-service addresses;
- DB/root/checkpoint conflict;
- insufficient disk reserve;
- inference or validator enabled;
- bearer operator token or legacy insecure option.

start runs doctor. Critical failure exposes no public listener and makes no peer
request. Read-only recovery may expose local diagnostics without decrypting
content.

## 6. Cryptography and request rules

Root canonical JSON, SHA-256, Ed25519, event ID, signature domains, lineage, and
execution context apply.

The freeze-blocked RFC 9180 HPKE base profile is:

    HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1

It is unusable for a release until a ratified schema freezes the exact HPKE
mode, KEM/KDF/AEAD identifiers, serialization, exporter-secret use, limits, and
matching JavaScript/Rust vectors. It uses an ephemeral sender context and the
exact destination host ingestion public key to wrap a fresh random 32-byte
object DEK. Stream chunks use AES-256-GCM with a unique 96-bit nonce and
associated data binding:

- network and execution context, sender, and exact destination/key;
- inner event ID, grant or null, outer nonce, issue, and expiry;
- HPKE suite/encapsulation, wrapped DEK, and chunk plan; and
- plaintext length, but never a raw plaintext/query/payload hash.

AAD, key, nonce, tag, length, ciphertext commitment, or decrypted inner-object
identifier mismatch rejects before accepted storage. Omitting a clear plaintext
hash prevents dictionary fingerprinting of low-entropy private content.

### 6.1 Encrypted stream framing

The non-normative field guide below is abbreviated. The only accepted object is
the complete closed object in `schemas/vera-encrypted-stream.schema.json`, with
`examples/vera-encrypted-stream.example.json` illustrating every required field.
An omitted field below is not optional and no alternative spelling is accepted.

~~~json
{
  "schema_version": "somavera.vera-encrypted-stream.v1",
  "outer_envelope": {
    "schema_version": "somavera.vera-application-envelope.v1",
    "sender_did": "<Soma or controller DID>",
    "inner_event_id": "<encrypted signed-event ID>",
    "outer_nonce": "<lowercase hex>",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-01-01T00:05:00Z",
    "signing_key_id": "<sender signing key ID>",
    "signature": "<base64 signature over envelope ID>"
  },
  "stream_header": {
    "stream_id": "<hash>",
    "destination_host_did": "<did>",
    "recipient_ingestion_key_id": "<key id>",
    "hpke_suite": "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
    "hpke_enc": "<base64 encapsulated key>",
    "wrapped_object_dek": "<base64>",
    "chunk_bytes": 65536,
    "chunk_count": 1,
    "plaintext_bytes": 128,
    "ciphertext_root": "<hash>",
    "aad_hash": "<hash>"
  },
  "chunks": [{
    "index": 0,
    "nonce": "<base64 12 bytes>",
    "ciphertext_hash": "<hash>",
    "ciphertext": "<base64 ciphertext and tag>"
  }]
}
~~~

stream_id is
`H("somavera:vera-encrypted-stream:v1\n" || JCS(stream_core))`.
stream_core excludes `$schema`, stream_id, signatures, and ciphertext bytes,
but includes the ordered ciphertext hashes. ciphertext_root is a
domain-separated Merkle root over `(index, nonce, ciphertext_hash)` leaves; its
exact domains and empty-tree value are ratification blockers.

The signed outer envelope and encrypted inner Signed Event both bind stream
ID/root, destination host DID, ingestion key ID, inner event ID, plaintext
length, consent grant when required, audience, network, execution context,
purpose, data class, projection, and membrane policy. The complete inner event,
including its payload and signature, appears only inside ciphertext. Exactly
one host is an audience for each stream. Sending to multiple consented hosts
requires a new signed envelope, HPKE context, random object DEK, nonces, and
ciphertext for each host. A DEK is never shared and no universal ingestion key
exists.

The same frame carries `contribution.offer` and every Soma/controller
nonpublic request; action-specific plaintext, including query text, exists only
inside the encrypted chunks. TLS remains mandatory. Anonymous public routes may
carry public query text without this inner encryption, but a query originating
through Soma uses this frame even when its requested artifact scope is public.

Every nonpublic request's decrypted signed payload includes the complete
`return_encryption` descriptor defined in section 10. This applies to consent,
withdrawal, contribution, query, export, status, deletion, and tombstone
follow-up—not only to queries. The return key must be fresh for the request or
pairwise to the exact Soma/host relationship, current, and different from every
signing, ingestion, storage, backup, and recovery key. Missing, expired,
malformed, or role-reused return keys fail.

Vera signs each private acknowledgement, receipt, status result, answer, or
answer/source bundle first and encrypts those exact signed bytes to the
request-bound return key using the section 10 response container. No private
result is a plaintext HTTP body, queue item, callback, or download. If
validation fails before a usable return key is authenticated, the host returns
only a generic HTTP status and request ID with no private result.

The host validates framing, outer-envelope signature and lineage, exact host
and ingestion-key recipient, outer replay, limits, AAD, and ciphertext
commitments before decryption. It then validates the decrypted inner event and
every outer/inner equality before consent or admission. Decryption runs in a
disposable bounded worker scoped to one
request: at most 384 KiB encrypted, 256 KiB plaintext, 64 MiB worker memory, one
CPU, and five seconds. The worker verifies plaintext length/hash, redaction, and
prohibited-data policy, emits only the admission result and
storage-re-encryption input, best-effort zeroizes buffers, and terminates. This
does not prevent a privileged operator from inspecting process memory.

Accepted host-confidential content is immediately encrypted under a new random
storage DEK and nonce. The storage DEK is wrapped by a distinct storage KEK;
neither plaintext nor a network ingestion private key persists in the object.

Host signing- or ingestion-key rotation uses the closed ordinary-succession proof in
`schemas/vera-host-descriptor-succession.schema.json`. The prior descriptor
precommits every prospective active key as an identical, time-bounded `overlap`
entry. The successor is sequence prior-plus-one, names the exact prior descriptor
ID, retains historic keys, retires each replaced active key, and is independently
signed by its new active signing key. A role-separated proof is signed by both the
prior and successor active signing keys and binds both descriptors, active signing
and ingestion keys, exact change scope, and a maximum 900-second validity window.
Origin, host identity, network/context, release, policy, TLS/discovery, protocols,
capabilities, disclosures, regions, subprocessors, retention, and limits cannot
change in ordinary succession. The proof authorizes continuity only; clients must
obtain the controller-signed confirmation in
`schemas/soma-host-succession-confirmation.schema.json` before replacing a pin.
That receipt binds the exact descriptor/proof subject and authorizes inert local
pin replacement only. It cannot authorize connection, consent, disclosure, send,
or emergency recovery. New streams use the confirmed active ingestion key only
after the local atomic transition commits; a prior key is accepted only for an
already bound, unexpired stream issued within its historic validity. Sequence gaps,
uncommitted keys, downgrade, revocation, field substitution, signature failure,
ambiguous crash recovery, or competing confirmation stop service. Emergency
compromise recovery remains unsupported until a distinct
precommitted recovery-authority profile is ratified. Storage-KEK rewrap
preserves signed content, received-envelope commitments, acknowledgements, and
object IDs. Re-encryption and rewrap append signed host-local
storage.maintenance records containing the object/event ID, operation, old/new
storage-ciphertext commitments and key references, reason, time, and host
signature. These records never redefine contribution identity or the immutable
received-envelope commitment. A backup-key rotation cannot retire the old key
until a newly sealed backup has been created and restored in a clean
verification environment.

Signed HTTP requests:

- use the root somavera.signed-event.v1 for the encrypted inner event;
- use protocol soma/action vera.query for a query and the registered
  action-specific protocol for other events;
- are strict JCS/I-JSON;
- have issued_at within 300 seconds of host time;
- expire no more than 900 seconds after issue;
- use a 16-64-byte random nonce encoded lowercase hex;
- persist nonce uniqueness per actor/action/audience/context for 30 days;
- treat identical event replay as idempotent and nonce reuse with different
  bytes as conflict.

Every nonloopback hop uses authenticated TLS. Peer routes also require mTLS,
allowed host DID, signed page, and underlying object verification.

## 7. Exact API

Common JSON content type is application/json; charset=utf-8. Compression on
The signed descriptor at `/.well-known/somavera/vera-host.json` conforms to
`schemas/vera-host-descriptor.schema.json`. It binds the exact origin/discovery
and private-request paths; TLS server-name and optional SPKI pins; release and
policy; signing and ingestion-key lifecycles; complete private request/response
action registries; supported protocols; query storage/retention/training rules;
data regions and subprocessors; host-confidential/query/backup retention;
model-use disclosure; operator-memory and traffic-metadata limitations; and
query, answer, contribution, concurrency, and envelope size limits. A missing,
unknown, contradictory, expired, or changed field stops connection or requires
fresh displayed approval; an implementation cannot infer a capability.

mutation/replication routes is disabled. Every response has X-Request-Id.

### Public

| Method | Path | Result |
|---|---|---|
| GET | /v1/health | liveness, release hash, server time only |
| GET | /v1/ready | ready boolean and coarse dependencies |
| GET | /.well-known/somavera/vera-host.json | signed host manifest |
| POST | /v1/public/query | licensed public retrieval |
| POST | /v1/public/packs | build/select signed public-slice pack |
| GET | /v1/public/packs/{pack_id} | download named public pack |
| GET | /v1/checkpoints/latest | latest public host checkpoint |
| GET | /v1/checkpoints/{checkpoint_id} | named host checkpoint |

### Controller/agent

| Method | Wire path | Decrypted signed action |
|---|---|---|
| POST | /v1/private/requests | host.register, host.challenge, consent.register, consent.withdraw, contribution.offer, vera.query, export.request, status.lookup, content.delete, or tombstone.status |

Every request body on this route is
`somavera.vera-encrypted-stream.v1` encrypted to the exact host ingestion key.
The action, object IDs, query text, and private fields are inside the encrypted
chunks; only bounded routing metadata remains outside. Every result is returned
as the encrypted response in section 10. There are no nonloopback
action-specific controller paths or plaintext private-result downloads.

### Peer

| Method | Path | Result |
|---|---|---|
| POST | /v1/replication/handshake | signed manifest/release/cursor negotiation |
| GET | /v1/replication/records | page after one origin cursor |
| POST | /v1/replication/records | idempotently offer one page |
| GET | /v1/replication/origins | public origin cursor summaries |

### Operator, local listener only

| Method | Path |
|---|---|
| GET | /v1/operator/status |
| POST | /v1/operator/join/preview |
| POST | /v1/operator/join/apply |
| POST | /v1/operator/checkpoints |
| POST | /v1/operator/backups |
| POST | /v1/operator/restore/verify |
| POST | /v1/operator/restore/apply |
| POST | /v1/operator/exit/preview |

## 8. Consent, ingest, and acknowledgement

### 8.1 Consent register

consent.register actor is the grant controller, audience is the exact host DID,
envelope grant ID is null, and payload contains the complete root Consent Grant.

The host returns a signed consent.accepted event binding grant ID, host DID,
policy hash, accepted narrowed scope, effective interval, ordinary-process
memory warning, and backup deletion deadline. It is encrypted to this request's
bound Soma return key. A narrowed acceptance never broadens or rewrites the
grant.

### 8.2 Withdrawal

consent.withdraw path, envelope grant ID, and payload grant ID match. Payload:

~~~json
{
  "consent_grant_id": "<hash>",
  "withdrawn_at": "2026-01-01T00:00:00Z",
  "reason_code": "controller_request",
  "request_deletion": true
}
~~~

The signed consent.withdrawn response binds immediate denial time, governed
object count, deletion job, public/irreversible limitations, and backup expiry.
The withdrawal acknowledgement and every later deletion/tombstone receipt are
encrypted to the fresh or pairwise Soma return key bound by their requesting
inner event. Withdrawal has reserved capacity and bypasses ordinary
ingest/query quotas.

### 8.3 Contribution

Request:

~~~json
{
  "schema_version": "somavera.vera-contribution-request.v1",
  "encrypted_stream": {
    "schema_version": "somavera.vera-encrypted-stream.v1",
    "outer_envelope": {},
    "stream_header": {},
    "chunks": []
  }
}
~~~

The encrypted inner `somavera.signed-event.v1` uses protocol vera and action
`contribution.offer`. Its payload contains the contribution body and complete
Evidence Events/Service Receipts, or only their hashes when the host already
holds and has verified those exact objects. Evidence and receipts are never
clear sidecars.

The encrypted inner event consent_grant_id is required. Its payload binds data state,
class, purposes, operations, retention_until, media type, projection schema,
field names and value hashes, content hash, plaintext bytes, evidence IDs,
receipt IDs, license, client membrane policy hash, destination ingestion key
ID, stream ID, ciphertext root, and the complete fresh/pairwise
return_encryption descriptor.

Contribution ID is the event ID; callers do not choose a DB ID. Complete
Evidence Events and Service Receipts must match the listed IDs exactly.

After the common membrane passes, one transaction appends event, nonce,
encrypted object, grant link, evidence, license, quarantine state, provenance
seed, and signed contribution.accepted acknowledgement.

The required acknowledgement has exactly the shared strict shape below; aliases and alternative nesting are invalid. The ID and signature projections are in `ID-DERIVATION.md` and remain freeze-blocked pending independent vectors.

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

The plaintext payload commitment is sensitive and appears only inside this signed acknowledgement after recipient encryption. It is never copied into the clear encrypted-response container, AAD-hash input, transport log, proxy queue, or status index.

The accepted operations, purposes, and projection are exact narrowed subsets
and cannot broaden the grant. The acknowledgement is signed, then encrypted to
the contribution request's bound Soma return key.

The immutable received-envelope ciphertext root is the exact inbound
outer-envelope/stream commitment accepted by the membrane. It is not an
at-rest object ciphertext hash. Storage DEK wrapping, storage ciphertext,
database pages, compaction, backup encryption, and later re-encryption may
change only through storage.maintenance records; none changes the contribution
event ID, acknowledgement ID, plaintext commitment, or received-envelope
commitment. The acknowledgement never changes balance, reputation, confidence,
or token supply.

Identical replay returns the original acknowledgement. Same event ID with
different canonical bytes returns EVENT_EQUIVOCATION and stores neither as
eligible.

## 9. Storage, lifecycle, and promotion

Authoritative logical tables are append-only accepted_events, host_receipts,
nonces, consent_lifecycle, evidence, provenance_edges, artifact_manifests,
evaluations, tombstones, replication_records, host_checkpoints, and
storage_maintenance.
content_objects may delete ciphertext/key references under a tombstone.
Current-state/search tables are rebuildable caches.

The prototype uses an encrypted SQLite-compatible catalog with durable
transactions and encrypted content objects under per-object keys. Stolen DB,
object media, logs, and backups must reveal no governed plaintext without
separated keys.

The host-confidential object persisted after admission is the storage-layer
ciphertext, not plaintext. Public content exists only after a separate
artifact.promoted event proves a distinct authorized public-release grant,
projection, license, transform, and evaluation. Replication never carries
host-confidential plaintext or decryptable storage keys.

Every contribution begins quarantined. Promotion requires active rights,
secret/poison checks, reproducible transform, evidence diversity,
contradiction/dispute search, evaluation, challenge/rollback, and a signed
artifact manifest.

Public artifact ID is provisionally:

    H("somavera:vera-artifact:v1\n" || JCS(artifact_core))

artifact_core excludes $schema, artifact_id, and signature. Release requires
strict schema and cross-language vectors.

Withdrawal immediately blocks decrypt/derive/query/export/replicate, appends
tombstones, removes active views, deletes live deletable ciphertext/keys, and
expires backups within the lesser of grant retention or 30 days. Signed
content.deleted receipts distinguish completed, pending, impossible, and legal
hold. Tombstones received before content prevent resurrection.

## 10. Provenance query and signed answer/source pack

retrieve-v0 is local lexical retrieval over eligible artifacts. No external
model runs.

Anonymous public request:

~~~json
{
  "schema_version": "somavera.vera-query-request.v1",
  "query_utf8": "How does the mechanism work?",
  "scope": "public",
  "purpose": "private_retrieval",
  "top_k": 5,
  "artifact_statuses": ["reinforced", "provisional"],
  "as_of": "2026-01-01T00:00:00Z",
  "include_answer_pack": true
}
~~~

A Soma-originated query, whether its artifact scope is public or confidential,
uses the section 6.1 encrypted stream. Its inner Signed Event uses protocol
`soma`, action `vera.query`, and the exact host DID as audience. The
decrypted signed-event payload is:

~~~json
{
  "query": {
    "schema_version": "somavera.vera-query-request.v1",
    "query_utf8": "How does the mechanism work?",
    "scope": "controller_confidential",
    "purpose": "private_retrieval",
    "top_k": 5,
    "artifact_statuses": ["reinforced", "provisional"],
    "as_of": "2026-01-01T00:00:00Z",
    "include_answer_pack": true
  },
  "return_encryption": {
    "destination_soma_did": "<requesting Soma DID>",
    "recipient_return_key_id": "<single-use or pairwise key ID>",
    "recipient_return_public_key": "<base64 X25519 public key>",
    "hpke_suite": "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
    "expires_at": "2026-01-01T00:15:00Z",
    "maximum_plaintext_bytes": 1048576
  }
}
~~~

The signed request binds the complete return-encryption descriptor. The return
key is separate from the Soma signing key, scoped to this Vera host and request,
and not reusable as a network-wide response key.

For a query, the host first constructs and signs
`somavera.vera-answer-source-bundle.v1`. For every other nonpublic action, it
signs the corresponding consent, contribution acknowledgement, withdrawal,
deletion, tombstone, export, or status receipt; the same encrypted-response
container carries that signed result. A private action without a valid
request-bound return descriptor is rejected rather than answered in plaintext. The
query bundle binds request event ID,
response event ID, hash of the complete return descriptor, answer status,
policy/retrieval version, every cited object and provenance edge, licenses,
tombstones, host DID, time, and host signing key ID. The host then encrypts the
exact signed bundle bytes to the request-bound return key and returns the closed
object in `schemas/vera-encrypted-response.schema.json`. The non-normative field
guide below omits no security rule; the schema and shared example are exact:

~~~json
{
  "$schema": "../../schemas/vera-encrypted-response.schema.json",
  "schema_version": "somavera.vera-encrypted-response.v1",
  "profile_status": "freeze_blocking_draft",
  "response_envelope_id": "<hash>",
  "network_lineage_id": "somavera:network:v1:<hash>",
  "execution_context_id": "somavera:context:v1:<hash>",
  "request_event_id": "<hash>",
  "response_event_id": "<hash>",
  "response_action": "answer.source-bundle",
  "host_did": "did:key:<vera-host>",
  "destination_soma_did": "did:key:<soma-agent>",
  "recipient_return_key_id": "did:key:<soma-agent>#return-1",
  "return_descriptor_id": "<hash of complete return descriptor>",
  "return_key_commitment": "<hash of complete return descriptor>",
  "hpke_suite": "HPKE-Base-X25519-HKDF-SHA256-AES256GCM-v1",
  "hpke_enc": "<base64 encapsulated key>",
  "wrapped_response_dek": "<base64 wrapped response DEK>",
  "chunk_bytes": 65536,
  "chunk_count": 1,
  "plaintext_bytes": 256,
  "aad_hash": "<hash of allowed AAD projection>",
  "ciphertext_root": "<hash>",
  "issued_at": "2027-01-01T00:00:01Z",
  "expires_at": "2027-01-01T00:15:00Z",
  "chunks": [
    {
      "index": 0,
      "plaintext_bytes": 256,
      "nonce": "<base64 12-byte nonce>",
      "ciphertext_hash": "<hash>",
      "ciphertext": "<base64 ciphertext and tag>"
    }
  ],
  "outer_signature": {
    "suite": "Ed25519-v1",
    "key_id": "did:key:<vera-host>#signing-1",
    "value": "<base64 signature>"
  }
}
~~~

The host signs the return-envelope ID after it commits all outer header fields,
the exact private request event, recipient return key, HPKE material, chunk
parameters, and ciphertext root. Soma verifies this outer signature before
decryption and independently verifies the inner action-specific result
signature afterward.

Response AAD binds network/context, request and response event IDs, response
action, host and destination Soma DIDs, return descriptor/key commitment,
suite/encapsulation, wrapped DEK, plaintext length, and chunk plan. It contains
no raw answer or signed-bundle hash; the signed outer envelope separately binds
the ciphertext root and chunk hashes. Vera uses an ephemeral HPKE sender context
and a fresh response DEK/nonces; it never uses the host signing or ingestion key
for response encryption. Reverse proxies, queues, and durable response storage
retain only the encrypted response and bounded routing metadata. Soma decrypts
locally, checks the declared length, recomputes the inner object ID and its
internal commitments, then verifies the Vera signature, original request
ID, return-key commitment, policy, and provenance before using the answer.

This protects content from intermediaries and offline storage, not from the
authorized Vera worker or a privileged host operator. Endpoints, route class,
timing, frequency, sizes, and TLS-termination metadata can still leak. TEE,
MPC, or FHE operator-blind processing requires a distinct later profile and is
disabled in this prototype.

Response binds response ID, answered/partial/abstained status, bounded cited
excerpts, uncertainty, contradictions, policy/retrieval implementation, host
DID/time/signature, and citations containing artifact/content hash, source
events, evidence, receipts, transforms, evaluations, license, status, producer,
and tombstone state.

No eligible evidence, withdrawal, severe contradiction, unsupported scope, or
insufficient evidence returns abstained without invented prose.

When include_answer_pack is true, the response includes a signed pack manifest
covering the query request, response, every cited source/provenance/evaluation,
licenses, tombstones, host manifest, and object hashes. The pack is independently
verifiable and queryable offline.

## 11. Portable sovereign packs

Pack kinds:

| Kind | Content | Encryption |
|---|---|---|
| answer_sources | one response plus exact sources/provenance | public signed plaintext, or encrypted to the request-bound Soma return key |
| public_slice | public checkpoints/events/artifacts/provenance/tombstones/licenses | signed/content-addressed |
| controller_export | controller grants/events/receipts/withdrawals and permitted intelligence | controller export key |
| sealed_backup | restorable operator state under active rights | separate backup key |

Layout:

~~~text
pack/
  PACK-MANIFEST.json
  PACK-SIGNATURE.json
  RELEASE-REFERENCES.json
  checkpoints/
  queries/
  events/
  receipts/
  artifacts/
  provenance/
  evaluations/
  tombstones/
  licenses/
  objects/public/
  objects/encrypted/
  VERIFY.txt
~~~

Manifest binds schema version, kind, network/context, producer, release/policy,
time, through-checkpoint/cursors, and every relative path, byte length, hash,
media type, license, confidentiality, and governing grant commitment.

Pack ID:

    H("somavera:vera-portable-pack:v1\n" || JCS(pack_core))

pack_core excludes $schema, pack_id, and signature. Absolute/dot paths,
symlinks, hardlinks, devices, duplicate normalized names, and case-fold
collisions are rejected.

vera pack verify and vera query pack work offline without HeyVera, DNS, token,
subscription, or a live host. Export is never clawed back.

## 12. Replication records and cursors

Record:

~~~json
{
  "schema_version": "somavera.vera-replication-record.v1",
  "network_lineage_id": "<network>",
  "execution_context_id": "<context>",
  "origin_host_did": "<did>",
  "sequence": 1,
  "previous_record_hash": null,
  "record_kind": "public_artifact",
  "object_id": "<hash>",
  "object_hash": "<hash>",
  "policy_hash": "<hash>",
  "emitted_at": "2026-01-01T00:00:00Z",
  "record_hash": "<hash>",
  "signature": { "suite": "Ed25519-v1", "key_id": "<key>", "value": "<base64>" }
}
~~~

Allowed kinds: public_event, public_artifact, public_provenance,
public_evaluation, consent_tombstone, artifact_tombstone,
artifact_deprecation, host_checkpoint.

record_hash uses domain somavera:vera-replication-record:v1 over JCS core
excluding $schema, record_hash, signature.

Cursor:

~~~json
{
  "origin_host_did": "<did>",
  "sequence": 100,
  "record_hash": "<hash>"
}
~~~

A signed page covers one origin, contiguous records, prior hash, page hash,
next cursor, responder DID, and response signature. Receiver verifies mTLS,
manifest, page/record signatures, lineage/context/release, chain, and every
underlying object's signature, rights, license, provenance, and tombstone
before atomic cursor advance.

Duplicates are idempotent; missing/invalid pages do not advance. Same
origin/sequence with another hash returns PEER_EQUIVOCATION and freezes that
origin. Lower sequences never roll back. Confidential/federated content are not
v0.1 record kinds.

## 13. Host checkpoint, backup, restore

Checkpoint fields:

~~~json
{
  "schema_version": "somavera.vera-host-checkpoint.v1",
  "checkpoint_id": "<hash>",
  "network_lineage_id": "<network>",
  "execution_context_id": "<context>",
  "host_did": "<did>",
  "host_sequence": 1000,
  "created_at": "2026-01-01T00:00:00Z",
  "protocol_release_hash": "<hash>",
  "policy_hash": "<hash>",
  "public_event_root": "<hash>",
  "public_tombstone_root": "<hash>",
  "public_artifact_root": "<hash>",
  "public_provenance_root": "<hash>",
  "public_evaluation_root": "<hash>",
  "replication_cursor_root": "<hash>",
  "public_storage_manifest_hash": "<hash>",
  "previous_checkpoint_id": null,
  "signature": { "suite": "Ed25519-v1", "key_id": "<key>", "value": "<base64>" }
}
~~~

checkpoint_id uses domain somavera:vera-host-checkpoint:v1 over JCS core
excluding $schema, checkpoint_id, signature. Merkle leaf/internal domains need
cross-language vectors before release.

Create at least daily and every 10,000 replication records. It proves one
host's public state, not ledger finality.

backup create first checkpoints and verifies integrity, writes/seals a backup,
reads it back, and verifies bytes at rest. Unverified backup is failure.

restore verify mutates nothing. restore apply targets an empty instance,
rechecks rights/retention/tombstones, restores eligible confidential content
only with surviving keys/authority, starts read-only/outbound-denied, and
requires verify-state plus operator activation preview.

Lost host signing key means new host identity. Old signed records survive; the
new host cannot impersonate or continue the old sequence.

## 14. Errors and default limits

Error:

~~~json
{
  "schema_version": "somavera.error.v1",
  "request_id": "<id>",
  "code": "WRONG_AUDIENCE",
  "message": "request is not addressed to this host",
  "retryable": false,
  "details": []
}
~~~

Stable families: 400 malformed/schema; 401 auth/signature/key/TLS; 403 audience,
destination, purpose, operation, class, license; 404 absent; 409 replay,
equivocation, checkpoint conflict; 410 expired/withdrawn/deleted/tombstoned;
413 size; 415 media/compression/suite; 422 hash/AAD/prohibited/rights; 429
rate/concurrency; 503 not-ready/read-only/reserve.

Errors never reveal private existence or echo content, signatures, keys,
ciphertext, or queries.

| Limit | v0.1 hard maximum |
|---|---:|
| JSON body | 1 MiB |
| plaintext contribution | 256 KiB |
| ciphertext package | 384 KiB |
| nesting / object members / array items | 32 / 2,000 / 2,000 |
| contributions per request | 1 |
| signed request lifetime / clock skew | 15 min / 5 min |
| nonce retention | 30 days |
| query UTF-8 / top-k | 8 KiB / 20 |
| response / export | 1 MiB / 100 MiB |
| peer page | 500 records and 5 MiB |
| global / actor / peer in-flight | 64 / 8 / 4 |
| ingest / authenticated query | 240 per hour per actor |
| anonymous public query | 60 per hour per IP |
| retention / backup deletion | 365 days / 30 days |
| inference calls, tokens, spend | 0 |

At 80 percent storage quota, background promotion stops. At 90 percent, new
ingest/export stops. Reserved space remains for withdrawal, tombstone, small
rights export, health, checkpoint, and recovery.

Outbound is deny by default. Redirects revalidate every hop. Network-supplied
loopback/private/link-local/metadata/DNS-rebound targets fail.

## 15. HeyVera adapter

HeyVera is an ordinary first operator, not implemented here. It must:

- verify host manifest and call these exact APIs;
- receive no special route/header/score/peer role;
- separate Clerk accounts from Soma DIDs;
- require Soma signature or narrow delegated bridge for controlled data;
- keep observation optional and show exact egress/host/purpose/field/retention/
  subprocessor/memory warning;
- keep host/operator keys out of browser code;
- separate Stripe billing from VERA, reputation, confidence, and ranking;
- show citations, host, policy, and abstention;
- expose public query/export without token ownership;
- export the same signed packs as the host-only CLI;
- pass identical fixtures against an independent operator.

Current HeyVera has no conforming Vera-host bridge. Its in-memory tracker is not
this network.

## 16. P0 blockers

P0 before any public/adversarial use:

1. create strict schemas/vectors for every module object, encrypted request and
   response, contribution acknowledgement, private receipt, HPKE profile, and
   provisional ID;
2. replace public bind defaults, plaintext peer URLs, and reusable operator
   token with loopback/TLS/mTLS/signed authorization;
3. remove observation-linked balances/mint and contribution score from host
   truth;
4. replace unsigned/generic sync/import with verified cursor replication;
5. keep runtime keys/DBs outside release artifacts and prove storage encryption;
6. implement consent withdrawal, tombstone priority, deletion receipts, and
   backup expiry;
7. disable external inference and paid calls;
8. make deployment fail closed and public-URL smoke tested;
9. add cross-language, integration, adversarial, packaging, and restore CI;
10. connect HeyVera only through the ordinary contract;
11. publish operator policy, privacy/memory limits, subprocessors, and incident
    contacts;
12. remove all completion claims until signed evidence exists;
13. ratify one shared Soma/Vera descriptor path, protocol/action registry,
    outer/inner envelope, acknowledgement, private-receipt schemas, signature
    domains, and HPKE vectors; no implementation may claim interoperability
    before both modules pass them.

Legacy data, keys, balances, receipts, and lessons are fixtures. Import requires
pack verification, revalidation, quarantine, and migration report; nothing is
grandfathered into trust, public status, or asset lineage.

## 17. Required test IDs

All are required and currently unpassed absent a signed report.

| ID | Requirement |
|---|---|
| VH-INSTALL-001 | Windows start.bat verifies, initializes outside release, binds loopback |
| VH-INSTALL-002 | macOS start.command produces identical public roots |
| VH-INSTALL-003 | Linux native/Docker produce identical roots |
| VH-INSTALL-004 | VPS refuses missing TLS, keys, policy, trust roots, backup |
| VH-HOSTONLY-001 | operator joins, queries, exports, backs up/restores without Soma |
| VH-CONFIG-001 | unknown/insecure config fails before listener or egress |
| VH-CRYPTO-001 | JS/Rust canonicalization, IDs, signatures, encryption vectors agree |
| VH-CRYPTO-002 | mutation, downgrade, revoked key, wrong audience/network/context, replay fail |
| VH-STREAM-001 | TLS-only plaintext, wrong host/key, AAD/chunk/root mutation, nonce reuse, and truncation fail |
| VH-STREAM-002 | two consented hosts receive distinct envelopes, DEKs, nonces, and ciphertext |
| VH-MEMORY-001 | bounded worker limits hold and no designed plaintext artifact remains |
| VH-KEYROTATE-001 | ingestion overlap/cutover and downgrade rejection work; storage rewrap preserves IDs |
| VH-KEYSEP-001 | signing, ingestion, storage, backup, and return-encryption keys cannot substitute for one another |
| VH-CONSENT-001 | absent/expired/withdrawn/wrong scope/retention fail before mutation |
| VH-CONSENT-002 | secret/sensitive/identity/unknown field canaries fail |
| VH-MEMBRANE-001 | HTTP, peer, import, operator, callback, watcher share one membrane |
| VH-INGEST-001 | valid offer atomically records event/object/quarantine and an encrypted acknowledgement with the exact accepted scope and immutable inbound commitments |
| VH-INGEST-002 | replay returns the identical acknowledgement; same ID/different bytes freeze without storage mutation |
| VH-ACK-001 | acknowledgement and Soma vectors agree on host/event/grant, state/operations/purpose/projection, retention/replication, inbound ciphertext/plaintext commitments, ingestion key, host sequence/status, time, and signature |
| VH-STORAGE-001 | stolen DB/objects/logs/backup reveal no governed plaintext |
| VH-STORAGE-002 | storage re-encryption/rewrap changes only signed maintenance records and never event, acknowledgement, plaintext, or received-envelope identity |
| VH-WITHDRAW-001 | withdrawal blocks all use and creates tombstones |
| VH-WITHDRAW-002 | deletion receipts reconcile live and backup storage |
| VH-REPL-001 | duplicates, reorder, loss, pagination, partition converge |
| VH-REPL-002 | malicious object, license, rollback, cursor skip fail |
| VH-REPL-003 | tombstone-before-content prevents resurrection |
| VH-REPL-004 | origin equivocation freezes and preserves proof |
| VH-QUERY-001 | answer cites exact eligible provenance |
| VH-QUERY-002 | missing/withdrawn/contradictory evidence abstains |
| VH-QUERY-003 | Soma protocol/action, signed outer request/return envelopes, encrypted inner query/answer bundle, wrong return key, mutation, replay, outer/inner mismatch, and plaintext queue/storage are checked |
| VH-PRIVATE-001 | every nonpublic action binds a fresh/pairwise return descriptor and returns its signed acknowledgement/receipt/result encrypted; unauthenticated return-key failure reveals no private result |
| VH-PACK-001 | answer/source and public packs verify/query offline |
| VH-PACK-002 | traversal, collision, symlink, corruption, forgery fail |
| VH-BACKUP-001 | clean restore read-only reproduces roots |
| VH-BACKUP-002 | missing private keys restores public state only |
| VH-BACKUP-003 | rotated backup key creates and restores a new sealed backup before old-key retirement |
| VH-SSRF-001 | redirect, rebinding, metadata/private IP, credential forwarding fail |
| VH-DOS-001 | byte/depth/rate/disk/concurrency limits preserve withdrawal reserve |
| VH-LOG-001 | canaries absent from logs, metrics, traces, crash, errors |
| VH-HEYVERA-001 | HeyVera and independent host accept/reject same fixtures |
| VH-PHOENIX-001 | clean-room new lineage invents no history |
| VH-REPRO-001 | two builders reproduce artifacts or report byte deviations |

Pilot scale: at least three hosts across two operators, 5-10 consenting humans,
10-25 agents, non-sensitive fixtures, no valuable token. Larger claims require
matching published tests.

## 18. Phoenix and done definition

Origin-only recovery creates a new tokenless lineage, context, and host/operator
identities with no inherited balances, grants, reputation, or history.
Authenticated root checkpoint plus matching Vera packs follows RECOVERY.md.
A host checkpoint alone cannot preserve ledger/asset lineage. Conflicts remain
explicit forks.

The clean-room test may not require HeyVera, founder laptop, private repo, live
DNS, registry, cloud account, or undisclosed key.

This prototype is **not done**. It becomes a private-pilot candidate only after
all schemas/vectors exist, every required test has signed evidence, packages are
reproducible, two implementations interoperate, a non-HeyVera operator restores
and queries the public slice from a signed pack, and independent review has no
unresolved critical/high finding.

Even then it is a non-sensitive, valueless pilot, not a production learning
network, valuable token, confidential-computation system, or proof of
superintelligence.
