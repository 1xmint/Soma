# SOMAVERA VERA HOST ORIGIN SPEC

Document ID: somavera/vera-host/origin/0.1-draft
Status: **draft; not ratified, implemented, audited, or production-ready**
Recovery role: module root for rebuilding independently operated Vera hosts.
Authority: subordinate to the ratified root ORIGIN-SPEC.md and its named
normative companions.

This file defines the durable host boundaries. It does not certify the July
2026 Node prototype, HeyVera, a VPS, a token, or any live network.

## 1. Canonical truth

The truth order is:

1. ratified release manifest and threshold signatures;
2. schemas and conformance vectors named by that manifest;
3. root ORIGIN-SPEC.md, DATA-RIGHTS.md, THREAT-MODEL.md,
   ID-DERIVATION.md, RECOVERY.md, ASSURANCE-CASE.md, and this module;
4. the matching Vera Host Prototype Spec;
5. implementations, examples, and user interfaces.

The root Origin controls any conflict. An unresolved security, consent,
identity, recovery, or state ambiguity blocks public startup. Unknown
consensus-critical fields, actions, data classes, purposes, operations,
replication record kinds, or cryptographic suites fail closed.

## 2. Mission and boundaries

A Vera host is an independently operable service that:

- accepts only authorized, minimized, signed Soma contributions;
- preserves consent, integrity, provenance, license, and evaluation state;
- quarantines untrusted input before any promotion;
- serves useful intelligence with exact citations and honest abstention;
- replicates only public data whose grant and license permit replication;
- propagates withdrawals, tombstones, disputes, and deprecations;
- exports signed, portable intelligence packs;
- checkpoints, backs up, restores, and exits without founder infrastructure.

Soma owns agent identity, delegation, local evidence, consent preview,
redaction, and egress. A Vera host verifies Soma authority; it does not replace
it.

The Vera ledger, if separately activated, orders public coordination and asset
state. A host-local database, credit, score, receipt, or checkpoint is not
ledger state. Observations, outcomes, hosting time, and social actions never
mint VERA.

Raw work, prompts, identity mappings, private evidence, and training records do
not belong on-chain. Only the minimal public commitments allowed by the root
Origin and Data Rights covenant may be anchored.

## 3. Immutable host invariants

Every conforming host preserves:

1. **No grant, no bytes.** Content is rejected before accepted storage when
   there is no exact active consent grant.
2. **Named destination.** Permission for one host does not authorize another
   host, model provider, region, or subprocessor.
3. **Purpose separation.** Retrieval never implies evaluation, training,
   aggregation, or release.
4. **Fail before mutation.** Identity, key status, signature, event ID, payload
   hash, network, execution context, audience, nonce, time, schema, class,
   fields, purpose, operation, destination, license, size, and quota are checked
   before accepted state changes.
5. **Immutable claims, deletable content.** Signed commitments and lifecycle
   events are append-only. Revocable confidential ciphertext remains
   physically deletable.
6. **No first-writer authority.** A peer cannot choose another object's ID,
   overwrite verified bytes, or make an object true by arriving first.
7. **Derived is not source.** Indexes, embeddings, summaries, rankings, and
   model output are reproducible views with explicit lineage.
8. **Tombstones outrank availability.** Withdrawal, deletion, dispute, and
   deprecation propagate at least as urgently as governed content.
9. **No pay-to-trust.** Wealth, subscription, token balance, stake, or hosting
   capacity never increases confidence, reputation, or learning priority.
10. **Public intelligence returns.** Legally redistributable public artifacts
    remain exportable in open formats without token ownership.
11. **No privileged founder path.** HeyVera, a founder, bootstrap host, or
    recovery signer receives no undocumented bypass, score multiplier,
    replication priority, or continuity power.
12. **Recovery invents nothing.** Restore and Phoenix procedures never invent
    grants, identities, reputation, balances, artifacts, or history.

Ordinary governance cannot waive these rules for a favored operator.

## 4. Honest security model

Authenticated TLS protects nonlocal transport. Application and volume
encryption protect offline media, stolen disks, snapshots without keys, and
some operator mistakes. Separate keys limit role compromise.

TLS is only the outer layer. Before Soma or an agent sends governed content or
a nonpublic request, it creates a signed application envelope and encrypts a
bounded stream to the exact destination host ingestion key. The signed
commitment binds network, execution context, audience host DID, ingestion key
ID, consent grant when required, purpose, data class, field projection,
cleartext content hash/length, and ciphertext stream root. A host accepts no
governed content or nonpublic request sent only under TLS.

Each destination receives an independently encrypted stream with a fresh random
object key and unique nonces. Consent for hosts A and B therefore produces two
audience-bound envelopes and two ciphertexts. There is no network-wide,
foundation, HeyVera, recovery, or universal decryption key, and no ciphertext
broadcast that every host can decrypt.

The base host decrypts authorized content in ordinary process memory whenever a
permitted operation requires plaintext. A root operator, insider, debugger,
compromised kernel, malicious dependency, or memory dump can observe that
plaintext. Encryption at rest does not make a privileged operator blind.

Every host manifest and consent preview must disclose this. The base profile
must not claim confidential computation, operator-proof encryption, or that
nobody can read the data. An operation named decrypt_in_attested_process is
rejected until a ratified TEE or other confidential-computation profile defines
attestation roots, measurements, rollback, failure behavior, and vectors.

After validating the signed envelope, host identity, audience, key ID, consent,
limits, and ciphertext commitment, the host decrypts in a bounded worker. It
verifies plaintext length/hash, redaction, and prohibited-data policy, then
best-effort zeroizes plaintext buffers and tears down the worker. Best-effort
zeroization reduces accidental persistence; it does not defeat a privileged
operator or compromised runtime.

Every nonpublic Soma action, including consent registration, withdrawal,
contribution, query, export, status, and deletion/tombstone follow-up, binds a
fresh or exact-host-pairwise return-encryption public key, key ID, suite, and
expiry into the signed inner request. Vera signs every private acknowledgement,
receipt, status result, answer, or answer/source bundle, then encrypts that
signed object to the request-bound return key. Soma decrypts locally and only then
verifies the Vera signature, request binding, provenance, and policy. Signing
keys are never reused as encryption keys; there is no universal response key.
Network intermediaries, reverse proxies, durable queues, and ordinary response
storage receive ciphertext, although the authorized Vera worker and a
privileged host operator can still observe plaintext in memory.

Encryption also does not hide timing, endpoints, sizes, or every access
pattern. TLS termination and routing can reveal host/client addresses, route
class, timing, frequency, and padded size. Logs and metrics must minimize
correlatable metadata. A future operator-blind TEE, MPC, or FHE design is a
separate ratified profile with its own threats and vectors, never an implied
property of the base host.

## 5. Drag-and-drop and VPS promise

The same signed release supports:

- **local host:** unpack, verify, run start.bat on Windows, start.command on
  macOS, or start.sh on Linux; bind loopback and create runtime state outside
  the release folder;
- **Linux Docker/VPS host:** import a pinned image from the release, install an
  unprivileged service, configure authenticated TLS and backups, and start
  private/read-only until an explicit peer-join preview is applied.

A host-only operator does not need a separate Soma installation. The embedded
initializer generates distinct host and operator identities. That operator can
verify state, join public replication, query the public intelligence slice,
export signed public packs, checkpoint, back up, restore, and exit. Soma is
required only for controlled agent contributions and controller-specific data
rights.

Convenience never selects public binding, reusable bearer tokens, bootstrap
peers, model providers, or legacy state silently. Local and VPS profiles use
identical protocol validation and storage semantics.

## 6. Key roles

Each role has a distinct key and public purpose:

| Role | May do | Must not do |
|---|---|---|
| host identity | sign manifests, acknowledgements, replication records, host checkpoints, packs | decrypt content or sign agent work |
| transport | authenticate TLS endpoints and peers | sign protocol claims |
| operator | authorize local operational changes | impersonate agents or validators |
| storage encryption | wrap per-object storage keys | authenticate network requests |
| backup encryption | seal operator backups | run the live database |
| recovery | attest a verified restore procedure | rewrite user rights or stored history |
| validator | ledger consensus, if separately installed | host administration or content decryption |

Keys are generated fresh, kept outside the release tree, stored in an OS or
hardware keystore where possible, rotated by signed manifests, and never
returned to a browser. Development file keys require an explicit insecure
test-only mode, loopback binding, and a test lineage.

Historical key manifests preserve key ID, suite, role, effective interval,
predecessor, revocation, and proof of possession so old signatures remain
verifiable for their valid window.

## 7. Data classes, states, and consent

The v1 allowed classes are public_artifact, work_summary, and
objective_receipt. The host rejects private_work, secret,
regulated_sensitive, identity_linkage, unknown classes, and unknown field
projections.

Every accepted contribution binds one signed grant, one data class, one data
state, exact fields, purposes and operations, one destination host, one
retention deadline, and one license.

| Data state | Host behavior |
|---|---|
| private_local | reject; it must never leave Soma |
| host_confidential | encrypt at named hosts; never publicly replicate content |
| federated_training | reject in the first prototype |
| public_knowledge | replicate only with explicit public release, redistribution, and license |

Consent is not inferred from installation, social sign-in, subscription, token
ownership, prior contribution, or an observer toggle. Possession is not proof
of the right to grant a license. The host refuses data it cannot lawfully or
technically govern.

Consent is checked again at every decrypt, derive, evaluate, query, export,
replicate, and release operation. A cached authorization cannot outlive a
grant, key, policy, expiry, or withdrawal.

## 8. Protocol objects and signed actions

The module consumes the root Signed Event Envelope, Vera Consent Grant, Soma
Evidence Event, Service Receipt, release manifest, genesis, and ledger
checkpoint formats.

Each application-encrypted request contains one inner root Signed Event. Control
and contribution events use protocol vera; the Soma query contract uses
protocol soma and action vera.query. The distinct outer routing envelope is not
an alias for the inner event and has its own schema, ID, signature domain, and
replay state.

| Actor | Protocol | Action |
|---|---|---|
| controller | vera | consent.register |
| controller | vera | consent.withdraw |
| subject or delegate | vera | contribution.offer |
| authorized Soma/reader | soma | vera.query |
| controller | vera | export.request |
| host | vera | consent.accepted |
| host | vera | consent.withdrawn |
| host | vera | contribution.accepted |
| host | vera | contribution.rejected |
| host | vera | content.deleted |
| host | vera | artifact.promoted |
| host | vera | artifact.deprecated |
| host | vera | query.receipt |
| host | vera | checkpoint.created |

Each action has one strict schema and vector set. Aliases and undocumented
actions are rejected. Outcomes arrive as signed Evidence Events with required
independent receipts; there is no unsigned thumbs-up route or automatic
contribution score.

Additional strict schemas are required for the host manifest, inbound signed
outer application envelope, encrypted stream, host-signed return envelope,
inner answer/source bundle, contribution, acknowledgement, deletion receipt,
public artifact, provenance, evaluation, replication record/page, host
checkpoint, and portable pack. Their absence is a release blocker, not
permission to improvise JSON.

Complete evidence events and service receipts are either inside the encrypted
inner object or referenced there only by hashes of objects the host already
verified. They are never clear unauthenticated sidecars.

Soma and Vera Host must import the same ratified envelope, acknowledgement,
receipt, signature-domain, action-identifier, HPKE-profile, and vector artifacts.
Until those shared artifacts exist and both modules pass them, neither module
may claim wire interoperability.

A signed contribution.accepted acknowledgement binds the host DID,
contribution-event and consent-grant IDs, accepted data state, operations,
purposes, authorized projection, retention, replication mode, immutable
received-envelope ciphertext commitment, plaintext content commitment,
recipient ingestion-key ID, host sequence/status reference, issue time, and
host signature. The received-envelope commitment is the exact immutable inbound
outer-envelope/stream ciphertext commitment accepted by the membrane.

At-rest object ciphertext, wrapped storage DEK, storage KEK version, database
page ciphertext, and backup ciphertext are not contribution identity and never
appear as the acknowledgement's received-envelope commitment. Re-encryption,
key rewrap, compaction, and backup rotation produce signed host-local maintenance
records that preserve the event, acknowledgement, plaintext, and received-
envelope commitments.

## 9. Common ingest membrane

Every content-bearing HTTP, peer, import, operator, callback, and background
path uses one membrane in this order:

1. connection policy, content type, framing, compression, and ciphertext limit;
2. strict outer-envelope/stream schema and canonical JSON;
3. outer network/context, sender, exact host/key recipient, issue/expiry,
   persisted outer nonce, sender signature, suite, and ciphertext commitment;
4. bounded HPKE unwrap and AEAD stream decryption with no authoritative write;
5. strict inner Signed Event schema and canonical JSON;
6. inner network/context, protocol/action, audience, time, nonce/replay, actor
   key window/revocation/delegation, signature, payload hash, and event ID;
7. equality of every outer/inner commitment, including event, consent, host,
   key, network/context, plaintext hash/length, and purpose;
8. grant controller/observer/destination, active interval, withdrawal, class,
   fields, purposes, operations, retention, public release, and license;
9. deterministic redaction evidence, secret/prohibited-data scanning, hostile
   content isolation, archive/resource limits, reserve, cost, and policy;
10. one atomic append of inner event, outer-envelope receipt, encrypted object,
    consent link, quarantine state, provenance seed, nonces, and signed host
    acknowledgement.

A failure before step 4 never invokes decryption. A failure after decryption
best-effort zeroizes the bounded worker and produces no accepted state.

A failure before step 10 produces no accepted event, artifact, score, balance,
replication record, or content object. Rejection logs never echo content,
ciphertext, signatures, credentials, prompts, or personal data.

## 10. Immutable storage and deletion

The authoritative host state is an append-only set of verified signed events
and content-addressed manifests. Search indexes and current-state tables are
rebuildable views.

For a known event ID:

- identical canonical bytes are idempotent and return the original receipt;
- different bytes are an equivocation or corruption alarm;
- neither overwrites the other;
- the conflict remains quarantined.

Lifecycle changes are later signed events: withdrawal, deletion, dispute,
supersession, deprecation, promotion, and checkpoint. A database UPDATE may
cache current state but cannot erase the transition that produced it.

Nonpublic content uses authenticated nonlocal transport, per-object encryption
keys, an external storage key-encryption key, and separately encrypted backups.
Key rewrapping changes storage ciphertext but not the signed cleartext
commitment.

The incoming transport stream is not a plaintext storage format. After bounded
validation, accepted host-confidential content is encrypted again under a fresh
host-storage object key and nonce; only that ciphertext, wrapped key reference,
and signed commitments persist. Temporary transport ciphertext may be retained
only as an immutable encrypted receipt object when policy permits. No plaintext
raw contribution is stored.

On withdrawal the host immediately denies new collection/use, appends
tombstones, removes governed items from views and queues, deletes deletable live
ciphertext and keys, expires backups within the disclosed window, propagates
permitted tombstones, and signs receipts for completed, pending, impossible, or
legally delayed work. It retains only the minimum commitment needed to prevent
replay and prove withdrawal.

The host never claims to erase independently copied public data or trained
influence it cannot demonstrate removing.

## 11. Quarantine, promotion, and provenance

Accepted means quarantined, not true, safe, useful, or promotable. Promotion
requires:

- active consent and license for every source;
- prohibited-content and poisoning checks;
- explicit transform implementation and parameters;
- evidence-class and issuer-diversity accounting;
- contradiction and dispute search;
- held-out relevance, citation, privacy, and safety evaluation;
- rollback and challenge behavior;
- a signed artifact manifest linking every source and evaluation.

The first learning surface is provenance-aware retrieval. Training,
fine-tuning, federated learning, model-weight release, and autonomous routing
remain disabled.

Confidence is contextual and names its evidence. A signature, zero exit code,
self-report, host count, token stake, or agreeing Sybil group is not independent
proof.

## 12. Query, abstention, and sovereign packs

A response is answered, partial, or abstained. It binds:

- request and response IDs;
- active policy and retrieval implementation;
- cited artifacts and exact hashes;
- source events, evidence, receipts, transforms, evaluations, licenses,
  disputes, status, and tombstones;
- known contradictions and uncertainty;
- model/provider metadata, which is null in retrieve-v0;
- host identity, time, and signature.

When evidence is absent, withdrawn, contradictory, stale, or below the
published threshold, the host abstains. A fluent completion may not fill the
gap and call itself Vera knowledge.

Public query and export are available without contribution or token ownership.
Controller-confidential query/export requires signed authority.

Every Soma or controller-confidential query is application-encrypted to the
destination Vera ingestion key in addition to TLS. Its signed request binds a
single-use pairwise/ephemeral Soma return-encryption key. The signed answer and
source bundle are encrypted to that return key before crossing a proxy, queue,
or persistence boundary. A client that cannot decrypt and verify both the Vera
signature and the original request binding treats the response as invalid.

Every answer can be exported with its sources as a signed portable pack.
Public-slice packs are independently verifiable and queryable offline without
HeyVera, DNS, a subscription, or a live host. Controller packs are encrypted to
the controller's export key. Exported intelligence is not clawed back when a
service relationship ends.

## 13. Replication

Replication is verification, not trust by URL. Every session requires
authenticated TLS, verified host manifest, allowed network/release, and signed
pages.

The first prototype replicates only public event commitments, licensed public
artifacts, public provenance/evaluations, withdrawals, tombstones, disputes,
deprecations, and host checkpoints. It never replicates confidential content,
private grants, identity linkage, keys, logs, or backups.

Promotion to a replicated public artifact is a separate, signed, authorized
derivation with its own public-release grant, projection, license, transform,
evaluation, and content hash. Host-confidential source bytes never become
plaintext replication payloads and never inherit public status from a derived
summary.

Each origin host has a signed append-only sequence chained by previous record
hash. Peers page by an authenticated cursor scoped to that origin and verify
every object before atomically advancing it. Duplicate, reordered, lost, and
retried delivery must converge on the same verified object set.

Same origin/sequence with different hashes is equivocation evidence. Lower
sequences cannot roll back state. Tombstones for unseen content are retained so
late content cannot resurrect withdrawn state. There is no silent
last-writer-wins merge.

## 14. Host checkpoints, backup, and restore

A Vera host checkpoint is not the ledger checkpoint. It commits to one host's
reproducible public Vera state: lineage, execution context, host DID and
sequence, prior host checkpoint, release and policy, public event root,
tombstone root, artifact/provenance/evaluation roots, cursor summary, storage
manifest, time, and host signature.

Private grant membership, confidential commitments, and access patterns remain
in a sealed local backup manifest, not a public checkpoint.

Hosts produce:

- a public recovery pack containing no secrets;
- a sealed operator backup encrypted under a distinct backup key.

Restore is verify-first and read-only-first. It verifies releases, checkpoint
chains, event signatures, object hashes, tombstones, grants, retention, and
derived roots before public binding or peer contact.

Loss of a host private key creates a new host identity. Verified records signed
by the old host may survive; the new operator may not impersonate the old host
or continue its sequence dishonestly.

## 15. Bounded operation

Every release sets hard limits for bodies, plaintext, ciphertext, canonical
depth, arrays, request age, nonce retention, rates, concurrent decryptions,
exports, peer pages, disk, temporary files, logs, query depth, responses,
outbound destinations, inference tokens, wall time, and spend.

Outbound access is denied by default. Redirects are revalidated at every hop.
Loopback, private, link-local, metadata-service, and unexpected DNS targets are
blocked for network-supplied destinations. A signed input cannot send a bearer
credential or confidential content to an arbitrary URL.

At capacity the host stops new ingest before weakening validation. Reserved
resources remain for withdrawal, tombstone, small authorized export, health,
checkpoint, and recovery.

Metrics use bounded labels and exclude DIDs, grant/event IDs, query text,
source URIs, and content. Logs are minimized, hash-chained, access-controlled,
and retention-bound.

## 16. HeyVera is an ordinary first operator

HeyVera may run the first managed host. It is not a protocol root, recovery
oracle, privileged peer, default truth source, or corpus owner.

It must:

- use the same public schemas, APIs, limits, receipts, replication, and packs
  as independent hosts;
- keep Clerk application accounts separate from Soma DIDs;
- obtain a Soma signature or narrow delegated bridge event for controlled
  contributions;
- keep host/operator keys out of browser code;
- keep Stripe billing separate from VERA, reputation, confidence, and learning
  priority;
- disclose operator, regions, subprocessors, providers, retention, and memory
  limitations;
- keep social/agent use functional when observation is refused;
- pass identical fixtures against a non-HeyVera operator.

Current HeyVera code has no conforming bridge to this protocol. Branding, an
in-memory Vera tracker, or a working VPS is not integration evidence.

## 17. Recovery and Phoenix

RECOVERY.md controls disaster classification:

- if the original network operates, restart or replace the host and verify
  sync; do not create a successor;
- public Vera packs may restore licensed public objects, but a host checkpoint
  alone does not prove ledger exact continuity;
- a sealed backup restores confidential content only when keys, destination
  authority, active grants, and retention survive;
- if only the Origin capsule survives, build a tokenless Phoenix network with a
  new network lineage, execution context, host identities, and zero inherited
  history;
- conflicting histories remain explicit forks; no founder or committee picks a
  silent winner.

Phoenix never carries historical balances, consent, reputation, artifacts, or
operator status without authenticated surviving state and the root exact-
continuity procedure.

## 18. P0 release blockers and evidence gates

The module is not releasable until:

- every introduced object has a strict schema and cross-language ID/signature
  vectors;
- public startup fails without TLS, auth, key separation, encrypted storage,
  policy, trust roots, and tested backup;
- consent-off and every ingest/import/replication path prove zero unauthorized
  acceptance;
- replay, mutation, wrong network/context/audience, revoked key, secret canary,
  oversized input, SSRF, redirect, and DNS-rebinding tests fail closed;
- first-writer poisoning, equivocation, partition, pagination loss, rollback,
  and tombstone resurrection tests pass;
- retrieval cites surviving provenance and abstains correctly;
- signed public packs verify and query offline;
- local and VPS packages behave identically;
- backup, restore, host loss, and Phoenix drills publish roots;
- HeyVera and an independent host pass the same fixtures;
- independent security/privacy review has no unresolved critical or high
  finding.

Encrypted-stream, outer/inner mismatch, encrypted result for every private
action, exact contribution acknowledgement, host-signed return-envelope,
return-key separation, host-ingestion-key rotation, per-destination
re-encryption, bounded-memory handling, storage-key maintenance records,
encrypted backup, and restore vectors are mandatory parts of those gates. The
shared Soma/Vera descriptor path, protocol/action registry, schemas, domains,
and vectors must be byte-identical release inputs. Descriptor succession additionally
requires monotonic sequence and exact predecessor linkage, precommitted overlap
keys, retained historic keys, dual role-separated continuity signatures, explicit
client reconfirmation, and rejection of emergency recovery through the ordinary path.

The current prototype's public bind default, plaintext peer URLs, reusable
operator token, unsigned sync/import, mutable lessons, contribution scores,
observation-linked balances, optional ungoverned inference, and completion
claim are P0 design debts, not compatible defaults.

## 19. Rebuild order and honest limits

1. Verify the signed root and module capsule offline.
2. Implement canonical JSON, hashes, signatures, key history, and signed event
   validation.
3. Implement consent, withdrawal, one common membrane, and zero-egress tests.
4. Implement append-only events, encrypted objects, tombstones, and provenance.
5. Implement cited retrieve-v0 and abstention without an external model.
6. Implement signed cursor replication and convergence.
7. Implement checkpoints, signed packs, sealed backup, restore, and exit.
8. Package safe local and VPS profiles from identical protocol code.
9. Run independent clean-room and adversarial tests on non-sensitive fixtures.
10. Only then run a closed, valueless pilot.

This module cannot make a malicious operator unable to read ordinary process
memory, prove observations true, guarantee legal submission rights, eliminate
traffic analysis, force public copies to disappear, guarantee unlearning or
model safety, recover lost secrets, recover unauthenticated state, or guarantee
agreement after finality failure. It promises no superintelligence, perfect
privacy, immortality, passive income, or valuable token.
