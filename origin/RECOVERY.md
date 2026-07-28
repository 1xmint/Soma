# SOMAVERA RECOVERY AND SUCCESSION MANUAL

Status: draft 0.1
Goal: recover public protocol operation without inventing authority, secrets, balances, consent, or history.

## 1. Classify the disaster

| Class | Survives | Action |
|---|---|---|
| R0 service outage | Original chain finality and state | Restart services; no succession |
| R1 node loss | Chain peers/checkpoints | Restore nodes with normal verified sync |
| R2 implementation loss | Chain state + authenticated capsule | Rebuild implementation and replay state |
| R3 substrate death | Authenticated release + unique valid finalized checkpoint + complete state/replay package + death evidence + pre-state authority | Exact-state successor candidate |
| R4 ambiguous fork | Conflicting valid finalized checkpoints | Halt migration; publish fork evidence |
| R5 total state loss | OriginSpec bytes only | Phoenix genesis with a new lineage; disclose whether the bytes have an independent authenticity anchor |

## 2. Required recovery capsule

A complete capsule contains:

- ratified OriginSpec, token, governance, data-rights, and threat-model versions;
- canonical manifest and threshold release signatures;
- schemas and positive/adversarial conformance vectors;
- source and reproducible artifact hashes for at least two implementations;
- toolchain locks, SBOMs, build provenance, and dependency archives or legal mirrors;
- genesis and token-activation manifests;
- genesis/bootstrap authority manifests and the public key history needed to verify releases and state; a current-key snapshot is informational and never overrides checkpoint pre-state;
- the public checkpoint chain, independently mirrored anchors, and the genesis-bound old-network-death policy;
- public model/corpus manifests and licenses;
- restoration and supply-audit tools.

For every exact-continuity attempt or drill, the checkpoint package must additionally contain or content-address:

- the complete canonical public state bytes or every deterministic state chunk needed to reproduce the checkpoint root;
- a chunk manifest fixing paths or content IDs, byte lengths, encodings, compression, hashes, ordering, and the state-root construction;
- the complete ordered block/state-transition log from genesis, or from a separately authenticated replay base, through the checkpoint;
- the checkpoint-era validator set, recovery-policy/key manifest, governance chamber seat manifest, thresholds, revocations, and key history as materialized in that state;
- supply, balance, consent, revocation, tombstone, evidence, receipt, and issuance counters required by the state machine; and
- independent availability locations plus a successful fetch-and-hash transcript for every required chunk.

A root without its reproducible state material is an integrity commitment, not a recovery image. A transition log without the referenced inputs is not replayable. Missing, corrupt, ambiguously encoded, or unavailable required bytes block an exact-continuity claim.

It contains no secret key, mnemonic, recovery share, API credential, raw private work, identity mapping, or private training record.

## 3. Verify before running anything

A document or bundle cannot authenticate itself. Hashes recomputed from recovered bytes prove internal integrity. Original-release authenticity requires at least one independent trust fact acquired outside those bytes, such as a previously trusted release hash/public key, a threshold-signature chain rooted in a separately preserved key, or independently witnessed archive/transparency records. Without that fact, report the release as unauthenticated and do not claim historical authority.

1. Obtain the capsule from at least three independent mirrors.
2. Hash every file and compare it to the signed release manifest.
3. Verify the release threshold against a separately trusted previous release or original genesis trust anchor; a key shipped only inside the candidate bundle is not an external trust fact.
4. Build in a clean, offline-capable, pinned environment.
5. Require artifact hashes and conformance roots to match.
6. Reject a capsule with unknown consensus-critical files, missing signatures, supply mismatch, or an unrecognized algorithm suite.

## 4. Select a checkpoint

A checkpoint candidate is valid only if:

- its origin and active-release hashes are recognized;
- its previous-checkpoint chain verifies to genesis;
- its block/app hash and validator set verify under the active consensus rules;
- it carries the required finality quorum;
- its complete public state bytes/chunks and transition log are available and independently reproduce its public/app root;
- balances root, live supply, lifetime minted, and lifetime burned replay from that exported public state;
- governance chamber seats, recovery keys, thresholds, and revocations match the state at that height;
- no higher valid non-conflicting checkpoint is known after the public discovery window.

Use two or more independent light-client/full-replay paths. A mirror’s filename or host reputation is not verification.

### 4.1 Genesis-bound old-network death predicate

Every genesis and each later valid recovery-policy transition must commit `old_network_death_policy_hash`. The committed policy fixes, in consensus-readable units:

- `finalization_freshness_seconds` and what counts as a valid finality proof;
- accepted clock sources and `maximum_clock_skew_seconds`;
- `observation_window_seconds`, `hold_down_seconds`, and the required discovery publication period;
- minimum independent observers, organizations, jurisdictions, and network paths;
- the signed observation-proof schema and raw evidence that must be retained;
- the conflict rule, which resets the timer on any valid fresh finality or conflicting succession evidence; and
- the successor activation predicate.

The old network is considered dead for protocol purposes only when all committed conditions hold continuously: the newest obtainable valid finality is older than the freshness bound; every required independent observer supplies a signed time/source transcript for the full observation window; clocks agree within the skew bound; the hold-down period completes; no valid fresh or conflicting proof appears; the checkpoint state reproduces exactly; and the checkpoint-era authorization quorum approves the one succession transition. This is a bounded policy predicate, not an absolute death oracle: it cannot distinguish global death from every possible partition, censored observer view, or hidden valid continuation. Silence, DNS failure, operator disappearance, a network partition, or one observer's timeout is not proof of death. A valid fresh finality proof resets the observation and hold-down periods. If the committed policy or its required proof is missing, exact-continuity activation is forbidden. A later valid fresh proof or competing valid succession triggers the ambiguous-fork procedure; no certificate can force universal social adoption.

### 4.2 Authority comes from the pre-state

The candidate checkpoint's reproduced state fixes the authorized recovery guardian keys, guardian threshold, chamber seat manifest, per-chamber thresholds, key purposes, terms, conflicts, and revocations. Only those checkpoint-era authorities may ratify exact succession at those exact thresholds.

Fresh validator, recovery, endpoint, and substrate keys provide proof of possession as proposed transition targets. They cannot sign their own elevation, count toward the authorizing quorum, or replace an unavailable pre-state signer. If the required checkpoint-era recovery and chamber quorums cannot be obtained, operators may reproduce and publish the state read-only, but they may not activate transactions under the old lineage. Any operational restart must instead follow the Phoenix procedure with a new lineage and no inherited economic or governance claims.

## 5. Exact-continuity procedure

1. Publish a recovery notice naming the disaster, old network ID, candidate checkpoint height/hash, OriginSpec hash, state/replay package manifests, death-policy/proof hashes, checkpoint-era authority manifests, and discovery deadline.
2. Satisfy the genesis-bound observation, hold-down, conflict, and challenge periods; never shorten them below 30 days (90 days for a total substrate replacement).
3. Fetch every required state/replay chunk, rebuild two implementations, replay independently, and reproduce the checkpoint state root byte-for-byte.
4. Generate a successor genesis that imports checkpoint state exactly, including old operational key sets. No balance, vesting, delegation, revocation, governance, consent, evidence, consumed-receipt, issuance-clock, or supply-counter change is allowed in the import.
5. Conduct new validator and recovery-key proof-of-possession ceremonies. Old private keys are never reconstructed, transferred to the recovery team, or published. Commit the new public keys and substrate binding to one proposed `RecoverySuccession` transition; those fresh keys do not authorize it.
6. Have the checkpoint-era recovery guardians and every checkpoint-era chamber ratify the certificate at their committed thresholds. Create the `RecoveryCertificate` using `ID-DERIVATION.md`; it commits the checkpoint/state/log manifests, death proof, old authority manifests, new-key proofs of possession, exact imported root, successor binding, before/after roots, transition hash, software hashes, reason, dates, and signatures.
7. Reproduce the imported root first, then execute only the precommitted `RecoverySuccession` transition. That transition may change the execution context, substrate binding, operational validator/recovery keys, endpoints, and old-substrate halt status; it may change nothing else.
8. Run old-context replay, supply, consent-denial, revocation, fork, rollback, and adversarial tests.
9. Start independent archival/light-client nodes before public gateways or Vera training.
10. Activate in read-only mode; let users verify balances, counters, state roots, and the succession transition.
11. After the challenge timelock, enable new-context transactions. Enable Vera training only after host, consent, license, and artifact checks pass.
12. Publish a final report and all evidence across every mirror.

## 6. VERA migration rules

- If the original chain is healthy, the original asset remains authoritative.
- Exact continuity preserves `network_lineage_id`. It preserves `asset_lineage_id`, or keeps both old and new asset IDs null when recovery predates token activation.
- It always changes `execution_context_id`; successor nodes reject old-context transactions and old nodes cannot create successor-context signatures.
- Migration must prevent double-spend between old and new substrates through a ratified permanent halt/finality condition or one-way proof system.
- Users claim or verify balances using public Merkle/state proofs; a custodian spreadsheet is not continuity.
- Unclaimed balances remain assigned to their original accounts. Recovery governance cannot confiscate them.
- A recovery process cannot add a premine, “recovery fee,” new team allocation, or changed vesting while claiming exact continuity.

## 7. Phoenix procedure

Use this only when no authenticated state survives or when the community intentionally starts over.

1. Publish the recovered OriginSpec bytes and hash, inventory any independent authenticity anchors, and label the bytes unauthenticated if none survives.
2. Publicly document which artifacts and history are missing.
3. Build and cross-test new implementations.
4. Ratify a tokenless genesis with a new network lineage ID, context epoch zero, a new execution context, null asset lineage, and zero supply.
5. Begin with zero historical balances and no inherited reputation, consent, evidence, issuance history, or governance power.
6. Use a valueless testnet and complete all release gates. A later token activation receives its own new asset lineage ID.
7. Call the network a phoenix successor, not the restored original.

## 8. Ambiguous fork procedure

If two conflicting histories each appear valid:

1. stop automated bridges, claims, and succession;
2. preserve and publish both histories and signer evidence;
3. do not let an emergency committee choose or rewrite balances;
4. allow independent replay and public analysis;
5. issue distinct network identifiers;
6. let users, hosts, applications, and governance communities choose;
7. retain equivocation evidence for objective slashing where a surviving canonical process exists.

There is no cryptographic rule that can guarantee social agreement after the assumed finality quorum itself fails.

## 9. Drill cadence

- Daily: checkpoint production and multi-mirror verification.
- Monthly: clean-node restore from checkpoint.
- Quarterly: offline build and conformance replay.
- Twice yearly: independent clean-node and operator recovery exercises.
- Annually: a full exact-continuity substrate-death simulation, including state-byte availability, token supply audit, death predicate, checkpoint-pre-state quorums, and governance succession.
- Annually, in a separate pristine environment and report: an origin-only Phoenix rebuild with no checkpoint, state bytes, historical keys, balances, or authority inputs.

A drill that relies on a founder laptop, private cloud account, undocumented DNS, or an unexported model is a failed drill. Passing an origin-only Phoenix drill never proves exact continuity, and passing an exact-continuity drill never proves that the Origin alone is sufficient.

## 10. Recovery authority limits

Checkpoint-era recovery signers and chamber members may attest to a verified state and authorize the one precommitted succession transition. Proposed replacement keys may prove possession but cannot authorize themselves. No recovery actor may:

- reconstruct user secrets;
- mint or redistribute balances;
- change consent or license terms;
- rewrite reputation or evidence;
- approve private data release;
- bypass challenge periods;
- keep permanent emergency control.

Every recovery key has a public term, rotation procedure, organizational affiliation, and automatic expiry.

No recovery certificate reconstructs or endorses external stablecoin reserves, exchange balances, bridges, liquidity, custody, debts, contracts, or market prices. Those claims require their own surviving authorities and evidence.
