# SOMAVERA CONSENSUS SUBSTRATE DECISION

Status: **pilot decision draft; not ratified; not a mainnet commitment**
Decision ID: `somavera/consensus-substrate/pilot-0.1`

## 1. Decision

The tokenless multi-host pilot will keep the Somavera application state machine
independent from consensus and expose it through a narrow, replaceable consensus
adapter.

The first multi-validator adapter target is a permissioned CometBFT 0.39 profile
with at least four independently controlled validators. This selects a practical
test vehicle for Byzantine-fault-tolerant ordering. It does not select a
permanent chain, authorize public operation, activate VERA, or make CometBFT part
of Somavera's constitutional identity.

The authoritative application artifact is a deterministic reducer:

```text
(prior committed state, ordered block, execution context) -> (new state, results)
```

The reducer, transaction validity rules, state encoding, application hash, and
checkpoint rules belong to Somavera. Consensus, networking, storage, and
settlement are adapters. Exact succession can replace an adapter only through
the Origin recovery rules and a new execution context.

## 2. Why this is the pilot choice

CometBFT is designed to replicate an arbitrary deterministic state machine and
separates the application through ABCI++. Its fault model and four-node testnet
tooling fit the private pilot. It lets the project test ordering, replay,
finality, checkpointing, host loss, and recovery without inventing consensus.

A minimal reducer plus adapter is preferred over adopting the full Cosmos SDK
now. Somavera does not yet need SDK module, account, token, or governance
machinery, and importing them prematurely would enlarge the consensus and
upgrade surface. This can be reconsidered if measured implementation needs
justify it.

## 3. Alternatives

| Alternative | Pilot disposition | Reason |
|---|---|---|
| Custom consensus | Rejected | Catastrophic research and implementation risk with no Somavera-specific benefit |
| One database or leader-only log | Rejected for Gate D/F | Does not test Byzantine ordering or independent finality |
| Raft | Rejected for adversarial consensus | Crash-fault tolerance is not the claimed Byzantine fault model |
| Full Cosmos SDK chain | Held | Useful later only if its module/store ecosystem offsets the added surface |
| Existing-chain smart contract | Held for mainnet comparison | Gains external settlement security but inherits gas, finality, state, upgrade, and liveness assumptions |
| Optimistic or ZK rollup | Held for mainnet comparison | Adds sequencer, data-availability, bridge, proof, and exit design before the application is stable |
| No consensus adapter | Selected for local unit tests | The pure reducer must run and replay without a network |

No-native-token settlement on an established chain remains a serious candidate
for later valuable operation. The pilot must generate evidence that permits that
choice; it must not quietly foreclose it.

## 4. Pilot consensus profile

`somavera-pilot-cometbft-0.39-abci-v1` requires:

- four or more validators under separately disclosed controllers and
  organizations;
- less than one third of voting power under any known common controller;
- a fixed, tokenless validator set for the private pilot;
- no stake, delegation, rewards, minting, market, or valuable gas asset;
- exact integer and byte-string application arithmetic; no consensus floating
  point;
- deterministic proposal processing and block finalization;
- domain-bound transaction replay protection in the application, independent
  of mempool deduplication;
- atomic persistence at commit and deterministic crash recovery;
- identical application hashes from two independent reducer implementations
  before Gate F;
- authenticated checkpoints and application-verified state-sync snapshots;
- bounded transactions, blocks, proposal work, and query work;
- no production/private data while the wire profile remains freeze-blocking.

Wall clocks, random number generation, map iteration order, thread scheduling,
host-local paths, network results, locale, and platform-dependent serialization
must never affect committed state.

## 5. Adapter boundary

The consensus adapter may:

- receive ordered transactions and consensus metadata;
- call the reducer's proposal and block functions;
- persist the returned state and results at commit;
- expose application hashes, checkpoint material, and read-only queries.

It may not:

- reinterpret signed Somavera bytes;
- invent identity, consent, evidence, reputation, or economic authority;
- make mempool presence equivalent to acceptance;
- introduce a token, fee, balance, or stake field;
- silently change replay domains or application serialization;
- treat consensus finality as factual truth about contributed content.

Every adapter release binds an exact build, dependency, configuration, state
encoding, reducer, and consensus profile hash in the Genesis or successor
substrate manifest.

## 6. Failure and exit tests

The pilot profile is not eligible for Gate F until automated or witnessed tests
cover:

1. deterministic replay on clean machines and both reference languages;
2. proposer mutation, duplicate transaction, stale context, and replay rejection;
3. one validator offline, one Byzantine validator, and invalid-vote isolation;
4. two-validator partition and safe non-finalization;
5. crash before and after application commit;
6. corrupt snapshot, wrong application hash, and rollback-state rejection;
7. validator-key compromise and fixed-set emergency halt;
8. complete state export into a mock successor adapter with a changed execution
   context and no changed application state;
9. ambiguous old/new substrate liveness causing succession rejection;
10. Origin-only Phoenix producing a new lineage and no inherited state or asset.

## 7. Mainnet decision gate

The permanent substrate remains unselected. Before valuable operation, publish a
decision record comparing at least:

- no native token;
- existing-chain settlement contract;
- optimistic and validity-rollup profiles;
- sovereign BFT application chain;
- their data availability, censorship, finality, recovery, upgrade, operator,
  bridge, liquidity, user-cost, and apocalypse-revival assumptions.

The winner must survive independent security and economic review, two-language
state-root reproduction, recovery drills, and the deterministic economic
scenario corpus. Product schedule and sunk implementation cost are not valid
selection criteria.
