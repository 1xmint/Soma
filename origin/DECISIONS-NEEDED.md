# DECISIONS REQUIRED BEFORE RATIFICATION

Status: draft 0.1

This file prevents an attractive draft from being mistaken for a finished protocol. Every item below needs a public decision record, implementation, vectors, and adversarial test where applicable.

| Priority | Decision | Recommended starting position | Ratification evidence |
|---|---|---|---|
| P0 | Project boundary | Soma is identity/authority/evidence; Vera is voluntary learning; ledger is public coordination | architecture decision and schemas |
| P0 | Product/operator boundary | HeyVera is the first product and managed operator, never the sole protocol authority | adapter contract, exit test, independent operator drill |
| P0 | Observer behavior | off by default; per-purpose, per-class, per-destination signed grants | consent implementation and zero-egress tests |
| P0 | Runtime secrets | outside source trees in OS/hardware-backed keystores | cross-platform key lifecycle tests |
| P0 | Public source of truth | this standalone capsule; legacy internal notes stay private/non-normative | signed release manifest |
| P0 | Continuity definition | Origin bytes create only a new Phoenix lineage; exact continuity also requires external release authenticity, complete state/replay bytes, death evidence, and checkpoint-pre-state quorums | separate Phoenix and exact-continuity drills plus succession vectors |
| P0 | Token timing | no valuable VERA until launch gates pass | public gate report |
| P0 | Parameter doctrine | schemas enforce constitutional invariants; the signed activation manifest fixes reviewed economic values; scenario A is not an implicit default | variant-profile conformance, parameter decision, simulations, and activation evidence hashes |
| P0 | Legal classification | make no categorical label; review exact facts in each jurisdiction | published counsel scope and disclosures |
| P1 | Consensus substrate | use a replaceable CometBFT adapter for the tokenless pilot; keep sovereign app-chain, rollup, and minimal settlement contract open for valuable operation | threat, cost, liveness, data-availability, recovery, and migration comparison |
| P1 | Canonicalization | RFC 8785 profile plus explicit rejection rules and vectors | two-language conformance |
| P1 | Identity method | standards-compatible DID/key representation, pairwise IDs, rotation, revocation, recovery | resolver and lifecycle vectors |
| P1 | Evidence model | separate assertion, execution, outcome, factual verification, and dispute | receipt schemas and adversarial fixtures |
| P1 | Reputation | contextual, explainable, decaying, non-transferable, recomputed from evidence | public formula and Sybil/collusion analysis |
| P1 | Vera learning target | knowledge retrieval first; training only after rights and evaluation pipeline exist | measurable quality and safety benchmark |
| P1 | Host privacy profile | local-first default; attested confidential worker as the preferred remote profile; MPC/FHE only for measured narrow workloads; metadata privacy separate | dataflow model, attestation policy, benchmarks, and host conformance |
| P1 | Data license set | narrow grants; no implied universal training license | rights review and example grants |
| P1 | Model release covenant | open public-benefit artifacts with specific safety exceptions | license, release card, appeal process |
| P1 | Governance seats | define independent seat eligibility, terms, Sybil controls, removal | genesis policy and simulation |
| P1 | Objective slashing | enumerate only machine-verifiable duties and proof rules | state-transition vectors |
| P1 | Fee market | measure spam and resource costs before fixing base fees | testnet load/economic report |
| P1 | Liquidity bootstrap | earned distribution first; no official day-one pool, LP mining, buyback, or price floor | ECONOMY.md simulation, disclosures, independent review |
| P1 | Agent financing | bounties/prepaid service first; passive investment vaults stay outside the base protocol | product boundary and jurisdiction-specific review |
| P1 | Issuance envelope | accept, revise, or reject TOKEN-SPEC.md ceilings before activation | independent simulation and vote |
| P1 | Activation distribution | zero premine and deterministic earned issuance is recommended | token activation manifest |
| P1 | Intellectual property | Apache-2.0 code/docs; separately define trademarks, data, model weights | LICENSE, trademark, data/model licenses |
| P2 | External anchors | choose at least two independent media/ledgers for checkpoint roots | anchor adapters and outage drill |
| P2 | Post-quantum migration | define trigger, hybrid period, and key migration rules | algorithm-agility test |
| P2 | Public chamber selection | combine elected user seats with independent public-interest stewards | capture analysis |
| P2 | Long-term entity | foundation/cooperative/other must be subordinate to protocol rights | charter and conflicts policy |

## Token questions that cannot remain vague

The token activation manifest must contain final, integer or rational values for:

1. network and asset lineage IDs;
2. name, symbol, decimals, denomination, and address format;
3. genesis supply and every genesis balance;
4. issuance ceiling at every schedule boundary, all expressed as integer grain;
5. the exact `live_supply_at_anniversary` tail basis, anniversary snapshot/freeze rule, and lifetime-headroom rule;
6. measurement and anti-replay rules for every rewarded duty;
7. fee calculation and split;
8. bond, unbond, jail, and objective slash conditions;
9. validator bootstrap set, terms, permitted rotation, and automatic sunset;
10. chamber eligibility, quorum, thresholds, and timelocks;
11. treasury keys and hard authority limits;
12. checkpoint cadence and external anchors;
13. same-lineage migration and double-spend prevention;
14. source, compiler, binary, contract, and schema hashes;
15. parameter-decision, economic-simulation, launch-gate, and external-settlement-policy hashes;
16. audit reports and jurisdiction-scoped legal disclosures;
17. activation height/time, absolute bootstrap sunset, terminal-halt behavior, and abort conditions.

If any value is TBD, the token is not ready to activate.

## Near-term sequence

1. Freeze the root OriginSpec and the two module OriginSpecs.
2. Freeze executable Soma and Vera Host Prototype Specs plus shared conformance tests.
3. Replace unsafe prototype defaults and secrets.
4. Implement signed evidence and independent receipts without a valuable token.
5. Run 5-10 agent, multi-host, non-sensitive pilots.
6. Add a checkpointed deterministic ledger testnet, then run separate origin-only Phoenix and exact-continuity succession drills.
7. Prove useful Vera improvement with poisoning and privacy measurement.
8. Reach independent operator and usage gates.
9. Finalize token activation only after security, economics, and legal review.

