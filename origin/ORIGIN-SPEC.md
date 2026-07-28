# SOMAVERA ORIGIN SPEC

Document ID: `somavera/origin/0.1-draft`
Status: **draft; not a live network constitution**
Recovery role: human-readable root for Soma, Vera, and the VERA asset lineage.

Print this file. Mirror it with the complete signed recovery capsule. A prose file can restore rules and intent into a new Phoenix lineage; it cannot authenticate itself or restore historical authority. Exact state continuity additionally requires an externally authenticated release, complete checkpoint state bytes and replay material, the committed death evidence, and the authorization quorums active in the reproduced checkpoint pre-state.

## 1. Mission

Somavera exists so people can own agents that act with accountable authority, voluntarily contribute useful experience to a shared intelligence system, and receive durable access to the intelligence that collective work creates.

The system must resist exclusive capture by a founder, corporation, government, validator cartel, wealthy token holder, model provider, or host operator. “Resist capture” means that the protocol, public state, conformance suite, and public intelligence baseline remain independently implementable, exportable, forkable, and verifiable. It does not mean nobody can copy the public work or build a private extension.

## 2. The three planes

### 2.1 Soma — authority and evidence plane

Soma provides agent identity continuity, key rotation and recovery, least-privilege delegation, signed actions, evidence commitments, independent receipts, credentials, and contextual reputation inputs.

Soma proves who signed a claim and whether recorded bytes changed. It does **not** automatically prove that a claim is true, useful, human-authored, or independently performed.

### 2.2 Vera — voluntary intelligence plane

The Vera observer is user-controlled and off by default. It minimizes, classifies, redacts, and packages only data covered by a signed consent grant. Vera hosts ingest authorized bundles, preserve provenance, evaluate and quarantine contributions, maintain licensed knowledge/model artifacts, and return intelligence to agents.

An opt-in by an agent owner cannot grant rights over a client’s secrets, a coworker’s personal data, copyrighted code, or any other third-party material the owner lacks authority to share.

### 2.3 Vera ledger — public coordination plane

The ledger orders public protocol events: accounts, bonds, service escrows, objective receipts, slashes, governance, protocol versions, recovery checkpoints, and VERA balances. Private work and raw training data do not belong on-chain. The chain stores commitments, minimal public facts, and availability references.

The ledger is a deterministic state machine. Consensus and implementation frameworks may change; conformance to the state transition rules and authenticated lineage is what defines continuity.

## 3. Immutable rights and invariants

No ordinary governance proposal may weaken these rules:

1. **Observer opt-in:** Vera observation and each onward use are off by default, purpose-limited, inspectable, expiring, and revocable for future processing.
2. **Local sovereignty:** users can export their Soma identity material, evidence, credentials, and intelligence received, subject to the rights of others.
3. **No pay-to-trust:** token holdings, fees, and wealth never increase factual confidence, agent reputation, identity assurance, or training priority.
4. **Provenance is not truth:** signatures identify claimants; independent evidence and evaluation establish confidence.
5. **No secret recovery backdoor:** the protocol never contains a universal private key or reconstructs a lost user key. Recovery rotates authority under precommitted rules.
6. **Public verifiability:** public state transitions, supply, upgrades, checkpoints, and governance actions are independently replayable.
7. **Public intelligence return:** a useful baseline of reinforced, legally redistributable knowledge and model artifacts is periodically released under an explicit public license and mirrored independently.
8. **Exit and fork:** users may leave, export, run independent implementations, and follow a fork. Forks must use distinct lineage identifiers unless exact succession rules are satisfied.
9. **No unilateral continuity claim:** founders, foundations, hosts, token holders, or recovery guardians cannot alone declare a successor to be the same lineage.
10. **Emergency power is pause-only:** emergency authority expires automatically and cannot mint, seize, redirect, rewrite balances, rewrite reputation, deanonymize users, or approve new data uses.

## 4. Protocol truth

Every ratified release has a canonical manifest containing:

- origin document hash and version;
- schema and test-vector hashes;
- reference implementation source and reproducible artifact hashes;
- consensus and state-machine versions;
- active cryptographic suite;
- governance and recovery key sets;
- public data/model license identifiers;
- previous release hash;
- threshold release signatures.

Unknown fields in consensus-critical objects are rejected unless a ratified version explicitly defines them. Implementations must not silently reinterpret old fields.

Every derived identifier hashes an explicit core object that excludes the identifier itself, signatures, and later attestations. The governing schema lists the projection exactly. Implementations never hash a whole object and guess which circular fields to blank.

Network lineage is derived from the unsigned genesis core:

```text
genesis_core = genesis fields except:
  $schema, schema_version, genesis_core_hash,
  network_lineage_id, execution_context_id,
  external_anchors, ratification_signatures

genesis_core_hash = H("somavera:genesis-core:v1\n" || JCS(genesis_core))
network_lineage_id = "somavera:network:v1:" + H(
  "somavera:network-lineage:v1\n" ||
  HEXDEC(origin_hash) || HEXDEC(genesis_core_hash)
)
```

Here and below, H is SHA-256 returning lowercase hexadecimal, HEXDEC consumes an exact 32-byte hexadecimal digest, and || concatenates bytes. Genesis signatures cover the domain-separated tuple of schema version, genesis core hash, network lineage ID, and execution context ID. External mirrors, anchors, and signatures are not inputs to lineage.

`network_lineage_id` is durable identity. `execution_context_id` is the active transaction replay domain and changes on an exact substrate succession. Every executable signed event and checkpoint binds both. The exact derivations and per-record signature domains are normative in `ID-DERIVATION.md`.

## 5. Cryptographic profile v1

- Hash: SHA-256.
- Signatures: Ed25519, with explicit suite identifier and key ID.
- Canonical JSON: RFC 8785 JCS, restricted to I-JSON; duplicate object keys, non-finite numbers, negative zero, and non-conforming Unicode are rejected before signing.
- Event identifier: `H("somavera:event:v1\n" || JCS(event_core))`, where event core excludes event ID and signature.
- Document identifier: `H("somavera:document:v1\n" || UTF8(canonical_bytes))`.
- Merkle construction: domain-separated leaf and internal-node hashes defined by the ratified schema vectors.
- Encryption: authenticated TLS plus bidirectional signed outer application envelopes under a ratified HPKE or equivalent hybrid recipient-encryption suite and AEAD. Non-public inner queries/contributions are encrypted to the exact host ingestion key; complete signed answers are encrypted to a fresh or pairwise Soma return key bound by the query. Associated data binds suite/version, network/context, inner-object ID, actor, exact recipient/key ID, consent or query, purpose, expiry, and plaintext/ciphertext commitments. Signing and encryption keys are purpose-separated. Sensitive local state is separately encrypted at rest under user-controlled keys.
- Crypto agility: a new suite requires a versioned migration, overlapping verification window, downgrade protection, and conformance vectors. Algorithm names alone are not a migration plan.

Every signed network event contains at least:

```text
schema_version
network_lineage_id
execution_context_id
protocol
action
event_id
actor_did
audience
nonce
issued_at
expires_at
consent_grant_id?  # required for Vera data use
payload
payload_hash
signature { suite, key_id, value }
```

The event ID hashes the explicit core; the signature covers the domain-separated event ID. Servers recompute the payload hash and ID, then enforce network, execution context, audience, freshness, nonce uniqueness, authorization, schema, size, and rate limits before state change. Portable consent, evidence, and receipt records use the separate domains in `ID-DERIVATION.md`.

## 6. Identity, credentials, evidence, and reputation

- Identity continuity is distinct from a current signing key.
- Keys rotate; compromised and expired keys remain historically resolvable for events valid during their effective windows.
- Delegation is signed, audience-bound, time-bound, budget-bound, purpose-bound, strictly attenuable, and revocable.
- Credentials follow an issuer/holder/verifier model. A valid credential proves an issuer made a claim; the verifier chooses whether to trust that issuer and evidence.
- Evidence logs are signed, hash-chained, domain-separated, and acknowledged by independent parties where the claim requires independence.
- High-value outcomes require externally verifiable receipts such as CI attestations, artifact hashes, counterparty signatures, settled escrow, reproducible evaluation, or human/organization credentials.
- Reputation is contextual and non-transferable. It records domain, capability, evidence class, issuer diversity, recency, uncertainty, disputes, and revocation. There is no universal scalar “truth score.”

## 7. Vera consent and data states

Every contribution is exactly one of:

1. `private_local` — never leaves the user’s device;
2. `host_confidential` — encrypted to named hosts for a named purpose and retention period; no public replication;
3. `federated_training` — eligible for a named training/evaluation cohort under an explicit contribution license;
4. `public_knowledge` — content and provenance fields approved for public replication under an explicit license.

Promotion between states requires a new signed authorization. A general observer switch never upgrades confidential data to public data.

Withdrawal stops future collection and processing. The protocol must state honestly when already released public data, independently copied artifacts, or trained model weights cannot be reliably erased. Derived artifacts keep lineage to the governing consent and license.

## 8. Vera learning discipline

Vera does not mint value or increase trust merely because data was submitted. Contributions enter quarantine. Promotion requires reproducible evaluation, source and license checks, adversarial scanning, independence weighting, contradiction handling, and a challenge period.

The first production learning system should be provenance-aware retrieval with measurable citation, relevance, abstention, privacy, and safety metrics. Training or federated learning is enabled only after it demonstrates reproducible improvement against public evaluation and safety suites with rollback.

Zero-knowledge proofs can prove execution of a specified computation over committed inputs; they do not prove that the inputs are truthful or the result is socially useful. Encryption protects defined data paths; it does not make a malicious host honest.

## 9. Ledger state and transitions

Consensus-critical public state includes:

- protocol release and active suite;
- accounts, current keys, and revocation commitments;
- validator set and objective fault evidence;
- balances, bonded balances, escrows, fee pools, live supply, lifetime minted, and lifetime burned;
- service offers, accepted service receipts, and disputes;
- governance proposals, votes, timelocks, and executions;
- checkpoint roots, recovery policies, and succession certificates;
- public consent/revocation commitments without private payloads;
- public artifact manifests and availability commitments.

The minimum transaction families are account/key management, transfer, bond/unbond, service escrow, service receipt, dispute, objective slash, governance, release activation, checkpoint, and recovery succession. Each family has a versioned schema and deterministic preconditions, state changes, fees, and errors.

## 10. The VERA asset lineage

VERA is proposed as a **Revivable Protocol Asset**: its identity is a cryptographic lineage, not a ticker or one contract address.

The token activation manifest contains an unsigned `activation_core`, its derived hash, the derived asset lineage ID, and ratification signatures. The core never contains its own hash, the asset ID, or signatures.

```text
origin_hash = H(canonical ORIGIN-SPEC release bytes)
activation_core_hash = H(
  "somavera:token-activation-core:v1\n" || JCS(activation_core)
)
asset_lineage_id = "vera:rpa:v1:" + H(
  "somavera:asset-lineage:v1\n" ||
  HEXDEC(origin_hash) || HEXDEC(activation_core_hash)
)
```

Ratification signatures cover the domain-separated tuple of schema version, activation core hash, and asset lineage ID. Contract addresses and chain IDs are substrate bindings recorded under this lineage. Migration preserves the lineage only when `RECOVERY.md` exact-continuity rules pass. A phoenix network is tokenless until it separately completes the launch gates and ratifies a new activation core; that activation creates a new `asset_lineage_id` and cannot recreate old balances.

Token holdings never constitute reputation or epistemic authority. Detailed economics and launch gates are in `TOKEN-SPEC.md`.

## 11. Checkpoints

At least once per UTC day and every configured maximum block interval, validators finalize a public checkpoint manifest containing network lineage, execution context and context epoch, block/app hash, complete public-state root, balances root, live supply, lifetime minted, lifetime burned, validator set, governance state, active protocol release, origin hash, asset lineage ID, public artifact roots, and previous checkpoint ID.

```text
checkpoint_core = checkpoint fields except:
  $schema, schema_version, checkpoint_id,
  external_anchors, finality_signatures

checkpoint_id = H(
  "somavera:checkpoint:v1\n" || JCS(checkpoint_core)
)
```

Finality signatures cover the domain-separated checkpoint ID. External anchors commit to that ID and therefore sit outside the ID core. The checkpoint is mirrored across independent organizations and media and is reproducibly exportable. Private Vera data is excluded; only commitments and public artifacts may be referenced. A checkpoint used for recovery must be accompanied by the complete deterministic public-state bytes/chunks and ordered replay material needed to reproduce its root; a signed root alone is not a recovery image.

## 12. Recovery and succession

There are only two honest disaster outcomes:

- **Exact continuity:** authenticate the release through a trust fact outside the candidate bytes; reproduce a uniquely highest valid finalized checkpoint from complete public-state bytes/chunks and ordered replay material; satisfy the committed death predicate and the recovery/chamber quorums active in that reproduced pre-state; preserve the same network lineage ID, every public balance, supply counter, consumed receipt, issuance clock, and rule; then perform only the precommitted `RecoverySuccession` transition. That transition increments the context epoch and changes the execution context so old-substrate transactions cannot replay. The old and new asset lineage IDs are equal, or both are null for a pre-token network.
- **Phoenix genesis:** create a new network lineage from this spec when no authenticated state survives or when the community intentionally changes protected state. Old balances, reputation, consent, asset lineage, and canonical status do not carry over.

Multiple exact-state successors can exist technically. The death predicate is a bounded policy test under named observer, clock, path, and quorum assumptions—not proof that every possible copy of the old network is gone. The recovery certificate and public adoption establish a candidate canonical successor; users retain the right to follow another fork. Any later fresh proof or conflicting valid history triggers the fork procedure. The protocol never calls an ambiguous fork “settled” by fiat.

## 13. Governance and upgrades

Protocol/security, token economics, and Vera data/model stewardship are separate powers. Constitutional changes require approval in all chambers, public executable payloads, conformance results, conflict disclosures, a minimum 30-day timelock, and an explicit release version.

Upgrades are state transitions. A release that changes protected rights, balances, consent, or the asset lineage without the required process is a fork with a new lineage ID.

## 14. Rebuild from only this document

If no authenticated checkpoint or release capsule survives, this document may be adopted only as the constitution of a new Phoenix lineage. If no independent trust fact authenticates these bytes, publish that fact plainly; internal hashes do not create historical authority.

1. Publish this recovered document verbatim and its byte hash.
2. Create clean, independently reviewed schemas and two implementations of the event and ledger rules.
3. Produce public cross-language crypto and state-transition vectors.
4. Establish a diverse bootstrap validator and governance set using public proof-of-possession ceremonies; publish no private material.
5. Create a tokenless phoenix genesis that names this recovered document hash, the new implementations, initial validator set, zero supply, null asset lineage, and the fact that historical state is unavailable.
6. Compute a new network lineage and execution context. Run the complete adversarial and recovery suite on a valueless testnet.
7. Only after every launch gate may a separate zero-supply token activation create a new asset lineage ID.
8. Observe a public challenge period before activation.
9. Never represent phoenix balances, reputation, consent, or intelligence as restored historical state.

## 15. Release gates

No artifact may be called apocalypse-ready until:

- two independent implementations produce identical state roots;
- every schema has positive and adversarial vectors;
- consent-off and private-class leakage tests pass;
- replay, poisoning, Sybil/collusion, fork, rollback, and key-loss tests pass;
- supply and checkpoint replay independently reconcile;
- three separately reported origin-only Phoenix clean-room rebuilds and three separately reported exact-continuity succession drills succeed without founder infrastructure or cross-contaminated evidence;
- releases are reproducible and signed by the ratified threshold;
- legal rights exist for every public data/model artifact;
- independent security, privacy, and economic reviews are public.

## 16. Honest limits

This document cannot recover secrets, lost private data, deleted model weights, unmirrored source, historical balances without a checkpoint, or agreement among humans. It cannot make observations true, make AI safe, make governance incorruptible, or guarantee superintelligence. It defines constraints under which a public, learning network can be built and revived without lying about those limits.
