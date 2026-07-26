# SOMAVERA RELEASE, GENESIS, ACTIVATION, AND PHOENIX RATIFICATION

Status: **draft 0.1 - not ratified; no release, network, or token is activated**

This document separates four events that must never be collapsed into one:

1. publishing an Origin release;
2. starting a tokenless network lineage;
3. activating an optional zero-supply protocol asset;
4. recovering an existing lineage or adopting Origin in a new Phoenix lineage.

A repository commit, founder statement, example JSON file, deployment, ticker,
contract address, or matching hash is not ratification.

## 1. Artifact states

Every release and activation artifact has exactly one disclosed state.

| State | Meaning | Permitted claim |
|---|---|---|
| Working draft | Content can change without a formal vote | "draft" |
| Candidate | Exact bytes are frozen for a review window | "candidate release" |
| Ratified | The frozen bytes passed their declared gates and signature policy | "ratified release" |
| Activated | A valid state transition made the ratified artifact operational | "active on the named context" |
| Superseded | A later valid release replaced it prospectively | "historical release" |
| Revoked | A ratified emergency or ordinary process rejected future reliance | "revoked; historical evidence only" |

Ratification does not imply activation. Activation does not make an invalid
ratification valid. A candidate that changes by one byte receives a new hash,
new review window, and new signatures.

## 2. Authority cannot authenticate itself

The Origin capsule can prove internal integrity when its files reproduce its
manifest and capsule root. It cannot prove that the recovered bytes are the
historically ratified release when every asserted key, hash, witness, and rule
comes only from those same bytes.

Historical authenticity therefore requires at least one independently retained
trust fact, such as:

- a previously trusted release root;
- a previously trusted ratification key or threshold root;
- a transparency log inclusion proof observed before the loss event;
- independently witnessed archive records that agree on the release root.

Without an external trust fact, a community may adopt the recovered rules only
as a disclosed new constitution. It may not claim exclusive historical
continuity.

## 3. Artifact hierarchy

The following artifacts are separate and content-addressed:

1. **Origin release:** constitutional specifications, schemas, vectors, source,
   and capsule manifest.
2. **Protocol release:** reproducible source, dependency locks, build
   instructions, binaries or contracts, SBOMs, audit evidence, and supported
   execution environments.
3. **Genesis package:** tokenless genesis core, complete referenced authority
   and recovery manifests, protocol release hashes, validator material, and
   external-anchor plan.
4. **Activation evidence package:** parameter decision, economic simulations,
   launch-gate report, legal scope, external-settlement policy, audit reports,
   and abort conditions.
5. **Token activation manifest:** exact signed parameters and transition
   binding. It starts with zero supply.
6. **Checkpoint state package:** complete state and ordered replay material,
   not merely roots or balance lists.
7. **Recovery package:** death-policy evidence, checkpoint package, pre-state
   authority, succession binding, and recovery certificate.

Every hash reference is useless for availability unless the referenced bytes
are independently retrievable. A ceremony transcript lists both the hashes and
the locations from which independent verifiers fetched the bytes.

## 4. Roles and independence

### 4.1 Candidate publisher

The publisher assembles exact bytes and proposes them for review. Publishing
creates no authority to ratify.

### 4.2 Implementers

At least two independently maintained implementations reproduce every
consensus-critical derived identifier and transition root. A fork of one code
base, shared library, or generated client does not count as an independent
implementation for this gate.

### 4.3 Reviewers

Security, privacy/data-rights, distributed-systems, economic, and applicable
legal reviewers publish scope, version, findings, unresolved risks, conflicts,
and funding source. A review badge without its report bytes does not count.

### 4.4 Ratifiers

Genesis ratifiers are the publicly disclosed bootstrap chambers committed by
the unsigned genesis core. Later token ratifiers are only the active,
unexpired, non-revoked seats materialized in the immediately preceding
finalized state.

For both ceremonies:

- one controller or organization occupies at most one seat in one chamber for
  the same vote;
- employment, financing, beneficial control, family control, and material
  conflicts are disclosed;
- each chamber has at least four independently controlled seats;
- quorum and approval are at least 75 percent of active voting weight in every
  chamber;
- every counted key proves possession on the exact ceremony challenge;
- a key or threshold proposed by an artifact cannot authorize that artifact;
- missing, ambiguous, expired, or revoked authority fails closed.

These floors do not prove social decentralization. They are minimum
anti-self-ratification constraints.

## 5. Key ceremony

Before a candidate can be signed:

1. Each ratifier generates a purpose-specific Ed25519 signing key on a device
   they control. Shared seed material and publisher-generated ratifier keys are
   forbidden.
2. The ratifier publishes the public key, key ID, controller, organization,
   chamber, term, expiry, custody profile, recovery policy, and conflicts.
3. The coordinator publishes an unpredictable 32-byte ceremony challenge.
4. Each key signs a domain-separated proof-of-possession message containing the
   challenge, candidate root, role, key ID, and expiry.
5. Independent verifiers reject duplicate controllers, duplicate
   organizations, reused keys across chambers, invalid proofs, and incomplete
   disclosures.
6. Private keys and recovery shares never enter the capsule, transcript, chat,
   source tree, CI secret output, or coordinator machine.

Hardware-backed custody is preferred. It reduces key-extraction risk but does
not prove that controllers are independent or honest.

## 6. Origin release ceremony

An Origin candidate is eligible for ratification only when:

1. its complete file list, byte lengths, file hashes, and capsule root reproduce
   offline;
2. normative and informative material are explicitly separated;
3. every schema example and adversarial conformance vector passes;
4. two implementations reproduce all normative hash and signature domains;
5. prohibited private/runtime material scanning passes;
6. open P0 decisions are either resolved in signed decision records or clearly
   keep the release non-operational;
7. independent security, privacy, recovery, and economic reviews are published;
8. at least two clean-room Origin-only Phoenix drills publish their transcripts;
9. the exact candidate remains frozen for at least 60 days after the last
   material change;
10. all chamber thresholds sign the release-ratification message.

The release is then mirrored on multiple administrative domains and at least
two different media or transparency systems. A mutable Git tag alone is not a
durable anchor.

The current Somavera capsule is a draft. Its manifest proves integrity only; it
has no historical threshold signature set and is not ratified by this section.

## 7. Tokenless Genesis ceremony

Genesis starts a new network lineage. It does not inherit legitimacy, state, or
asset value from a prior brainstorm, repository, testnet, company, or founder.

Before signing:

1. freeze a ratified Origin release and reproducible protocol release;
2. publish the complete bootstrap seat, ratification-authority, validator,
   recovery-guardian, death-policy, and external-anchor manifests;
3. verify that every content hash resolves to the reviewed bytes;
4. derive the genesis core hash, network lineage ID, and execution context ID
   independently with two implementations;
5. confirm `token.activated = false`, null activation and asset IDs, and zero
   genesis supply;
6. confirm that no balance, conversion claim, liquidity position, prelaunch
   point, or future token allocation exists;
7. run a destructive reset/replay drill from the exact package;
8. publish the candidate for at least 30 days;
9. sign only the domain in `ID-DERIVATION.md`;
10. independently verify every signature against the authority committed by the
    unsigned genesis core.

Nodes first start in read-only verification mode. Transaction acceptance begins
only after the announced challenge window and external anchors agree on the
same genesis package. Any mismatch aborts; it is never resolved by choosing the
publisher's copy.

## 8. Token activation ceremony

Token activation is a later G2 state transition. Genesis signatures cannot
pre-authorize it.

The activation proposal must bind:

- the exact token identity and denomination;
- zero genesis supply;
- issuance ceiling, schedule, tail rule, fee split, and objective duty buckets;
- the parameter decision record;
- reproducible economic simulation corpus and results;
- the full token launch-gate report;
- the external-settlement and paymaster boundary;
- objective bond/slash policy;
- governance, data-rights, recovery, and legal-review artifacts;
- protocol release hashes;
- bootstrap validator sunset and terminal-halt behavior;
- complete abort conditions.

The schema enforces constitutional safety constraints and the signed manifest
fixes the selected values. Recommended numbers in `TOKEN-SPEC.md` are simulation
scenario A, not implicit mainnet constants.

Activation fails closed if any bound artifact is missing, unavailable,
placeholder-only, contradicted by newer evidence, or outside its review scope.
All Section 13 gates in `TOKEN-SPEC.md` must pass. The active pre-state chambers
must sign at their exact thresholds, and the transition must occur at the
committed height and consensus time. The first valid state still has zero
supply and empty balances.

No contract deployment, exchange listing, wallet display, market pool, faucet,
test credit, or ticker makes an unratified asset VERA.

## 9. Parameter doctrine

### 9.1 Constitutional invariants

The following cannot be weakened by an activation parameter vote:

- one transferable protocol asset at most;
- tokenless initial Genesis;
- zero token-activation genesis supply and no premine;
- no automatic conversion of points, reputation, credentials, consent, or past
  work;
- reputation, identity assurance, evidence weight, observer consent, search
  rank, and training priority are not token-weighted;
- service price remains the provider's contracted amount;
- issuance is prospective, capped, tied to pre-approved objective duties, and
  never retroactive;
- burns never reopen lifetime mint headroom;
- no passive yield, revenue share, price floor, discretionary buyback, or
  permanent arbitrary mint/seize/freeze key;
- public intelligence, consent controls, identity export, and exit do not
  require token ownership;
- Origin-only Phoenix cannot inherit an old asset lineage or balances.

Changing one of these rules requires a new constitutional Origin release and
cannot silently preserve the old claim.

### 9.2 Ratifiable parameters

Name, symbol, display precision, lifetime ceiling, epoch duration,
schedule anchors, tail rate up to the constitutional cap, duty allocation, fee
split within constitutional bounds, bond values, timeouts, and bootstrap sunset
are selected only by the signed activation manifest after simulation.

The schema-v1 atomic denomination is `grain` because every consensus monetary field uses the `*_grain` suffix. Renaming it requires a new wire schema and migration; an activation vote alone cannot create contradictory units.

Validators enforce the selected manifest exactly. They do not substitute values
from prose, examples, wallet metadata, or a previous candidate.

## 10. Phoenix and exact continuity

### 10.1 Origin-only Phoenix

Origin-only recovery is adoption, not restoration:

- new network lineage;
- new execution context;
- null asset lineage;
- zero supply;
- no inherited balances, reputation, identity mappings, consent, evidence,
  governance seats, issuance history, liquidity, or external claims.

It repeats the Genesis ceremony and, if ever desired, the later token activation
ceremony. It discloses whether the Origin bytes were historically authenticated.

### 10.2 Exact continuity

Exact continuity additionally requires:

- an independently authenticated Origin/protocol release;
- the uniquely highest valid finalized checkpoint;
- complete state bytes and ordered replay material;
- reproduction by at least two independent implementations;
- the precommitted old-network-death policy and qualifying evidence;
- every recovery and chamber threshold active in the reproduced checkpoint
  pre-state;
- a new execution context and old-context replay rejection;
- preservation of asset lineage, balances, supply counters, issuance time,
  escrows, bonds, governed pools, and consumed receipts exactly.

New keys may prove possession but cannot authorize their own succession. If the
old network is still finalizing, recovery aborts. If valid histories conflict,
automatic succession stops and the result is disclosed as a fork.

## 11. Mandatory transcript

Every ceremony publishes:

- purpose, state, start/end time, coordinator, and software environment;
- exact candidate root and every referenced artifact hash;
- fetch locations and independent availability results;
- reproducible build and conformance outputs;
- reviewer reports, scope, unresolved findings, funding, and conflicts;
- signer authority snapshot, proofs of possession, thresholds, counted and
  rejected signatures;
- canonical signed message bytes and signature verification output;
- challenge-window objections and their disposition;
- external anchor receipts;
- aborts, deviations, incidents, and final state;
- an explicit statement of what the ceremony did not prove.

Secrets, raw identity documents, biometrics, private recovery shares, and
non-public user data are excluded.

## 12. Abort rules

A ceremony aborts on any of the following:

- candidate bytes change;
- a P0 gate is open;
- an authority or referenced artifact cannot be resolved;
- implementations disagree on a consensus-critical result;
- a signature, threshold, independence, expiry, or proof-of-possession check
  fails;
- a reviewer withdraws a required opinion or discovers an out-of-scope
  dependency;
- an external anchor records conflicting candidate roots;
- a launch metric is unverifiable or was measured with undisclosed related
  parties;
- a critical vulnerability or legal prohibition remains unresolved;
- old-network liveness or a conflicting finalized history defeats a recovery
  claim.

After an abort, nothing automatically resumes. A corrected candidate receives a
new hash and repeats the applicable review and signature process.

## 13. Current honest status

As of this draft:

- the capsule is integrity-verifiable but not threshold-ratified;
- example Genesis and activation signatures are placeholders;
- no complete Genesis semantic validator or second independent implementation
  exists;
- no economic simulation corpus or launch-gate evidence package exists;
- no valuable VERA asset, balance, pool, or historical continuity claim exists.

The next legitimate milestone is a review-frozen **candidate** Origin release
plus a tokenless test Genesis package. It is not a token launch.
