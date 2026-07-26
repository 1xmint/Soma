# VERA REVIVABLE PROTOCOL ASSET — TOKEN PLAN

Document ID: `somavera/token/0.1-draft`
Status: **recommended design; no token exists; name and symbol are provisional**

## 1. What is new about it

VERA is proposed as a **Revivable Protocol Asset (RPA)**. Its durable identity is `asset_lineage_id`, derived from the ratified OriginSpec and token activation manifest. A particular chain, contract, bridge, or ticker is only one substrate binding.

The asset can move to a replacement substrate while preserving exact balances only through authenticated checkpoint import and the precommitted succession procedure. If only the OriginSpec survives, the community can revive the physics but must create a new phoenix lineage.

That is the core distinction from an ordinary application token: continuity is specified above the hosting chain, while counterfeit continuity is explicitly rejected.

## 2. One token, three separate ledgers

Somavera should use one economic token and must not collapse unrelated concepts into it:

| Ledger | Transferable? | Purpose |
|---|---:|---|
| VERA balance | Yes, after activation | fees, service payment, objective bonds, scoped economic governance |
| Reputation | No | contextual evidence about identity, capability, outcomes, uncertainty, disputes, and recency |
| Credentials/consent | No | issuer claims, authority, delegation, data rights, revocation |

Token wealth never raises reputation, identity assurance, factual confidence, model weight, or contribution priority.

## 3. Recommended fixed identity parameters

- Working name: `Vera`
- Working symbol: `VERA`
- Smallest unit: `grain`
- Precision: `1 VERA = 1,000,000,000 grain`
- Asset identity: `asset_lineage_id` from `ORIGIN-SPEC.md`
- Genesis supply at token activation: **0 VERA**
- Founder/team premine: **0**
- Public sale at activation: **none**
- Automatic conversion of prelaunch points: **forbidden**
- Hidden or discretionary mint authority: **forbidden**

Name, symbol, and precision require trademark, wallet, exchange, and legal review before ratification. Changing them after activation requires an explicit versioned migration; it never changes historical units silently.

Every consensus monetary amount or supply counter uses the `*_grain` suffix and is a canonical unsigned base-10 integer string counting **grain**. This is the sole consensus denomination and unit suffix; floating point and whole-VERA interpretation are forbidden. In formulas below, readable names such as `live_supply` and `total_minted` denote those grain counters; displayed VERA amounts are converted to grain exactly before consensus arithmetic.

## 4. Why the network must work before VERA

Soma identity, consent, evidence, Vera retrieval/learning, host discovery, stablecoin/fiat payment, and checkpoint export must work without a valuable native token. Before activation, the chain uses valueless test credits or sponsored transactions.

This is a hard design test: if token price is the only reason to use or host the network, the token is premature.

## 5. Legitimate utility

VERA may be used for:

1. deterministic transaction and anti-spam fees;
2. payment for measured inference, compute, storage, bandwidth, evaluation, and routing services;
3. escrow for agent-to-agent jobs;
4. slashable validator, host, evaluator, and service-performance bonds;
5. governance proposal deposits and narrowly scoped economic votes;
6. public-goods budgets approved under multi-chamber governance.

Users may pay through a paymaster that accepts fiat or stablecoins and acquires the required VERA. Basic public intelligence and exit/export rights cannot require token ownership.

## 6. Forbidden economics

- Minting for raw observations, Git commits, self-thumbs, self-reported “machine” results, or model gradients.
- Token-weighted truth, reputation, identity, search ranking, or training-data priority.
- Passive APY, guaranteed yield, revenue share, dividends, price floors, or discretionary buybacks.
- Marketing supply burns as an investment thesis.
- Idle-host rewards without measured service.
- Slashing for opinions, failed research, unpopular speech, model disagreement, or unproven harm.
- Mandatory staking to access one’s own identity, exports, or consent controls.
- A permanent admin key that can mint, seize, freeze arbitrary users, or rewrite balances.

## 7. Activation sequence

### Phase A — no-value protocol

- Run Soma and Vera with ordinary payments or free pilot quotas.
- Build the public ledger with valueless test credits.
- Measure real host, validator, storage, inference, and evaluation costs.
- Publish consent, evidence, reputation, and checkpoint conformance.

### Phase B — adversarial testnet

- Faucet-only VERA with no promised conversion.
- At least two independent implementations.
- Public economic simulation and attack competitions.
- At least three separately reported origin-only Phoenix rebuilds and three separately reported exact-continuity substrate-death succession drills.

### Phase C — activation proposal

Ratify a `token-activation.json` that fixes the emission schedule, `tail_supply_basis = live_supply_at_anniversary`, fee splits, bootstrap-validator term and absolute sunset, validator transition, governance keys, challenge period, legal disclosures, software hashes, and `asset_lineage_id`. Signatures are validated against the active pre-token chamber manifests rooted in genesis and materialized in the immediately preceding finalized state, at every exact threshold. Keys proposed by the activation cannot authorize themselves. No parameter may remain “TBD.”

The manifest structure is normative: unsigned `activation_core`, domain-separated `activation_core_hash`, derived `asset_lineage_id`, then chamber signatures. See `ID-DERIVATION.md`; never hash the whole signed manifest.

### Phase D — zero-supply activation

Activate with zero balances and a credentialed, publicly disclosed BFT validator set. The first epoch uses expiring, non-transferable, non-convertible gas quotas; VERA enters circulation only when that epoch finalizes deterministic rewards for pre-approved measured duties. The activation manifest fixes validator terms, permitted rotations, and an absolute bootstrap-consensus sunset. Bootstrap authority cannot extend that deadline.

### Phase E — permissionless security

Transition to bonded validation only after the distribution and independence gates below are satisfied. Until then, bootstrap validators have fixed terms, public conflicts, and no unilateral upgrade authority. If Phase E is not validly finalized before the absolute bootstrap sunset, the state machine finalizes a terminal checkpoint and halts new transfers, issuance, bonds, escrows, and governance execution; a calendar deadline never activates permissionless validation.

## 8. Recommended issuance envelope

The mainnet schedule must be ratified only after simulation. The recommended starting envelope is:

```text
lifetime_mint_ceiling = 1,000,000,000 VERA
genesis_supply        = 0 VERA
founder/team premine  = 0 VERA

maximum cumulative issuance:
  end of year 1: 100,000,000
  end of year 2: 180,000,000
  end of year 4: 300,000,000
  end of year 8: 450,000,000
  end of year 16: 600,000,000

after year 16:
  annual tail cap = min(1% of live_supply_at_anniversary,
                        remaining lifetime mint headroom)
```

These are ceilings, not guaranteed rewards. An epoch can mint less. Unused issuance disappears; it does not accumulate in a treasury. `live_supply_at_anniversary` means the finalized canonical `total_minted - total_burned` grain counter at that anniversary—not circulating, liquid, unbonded, or outstanding market supply. The resulting annual tail budget is frozen for that schedule year; later burns affect only a later anniversary. Burns never reopen lifetime mint headroom. Exact interpolation, integer rounding, counters, and first-epoch mechanics are in `TOKEN-OPERATIONS.md`.

Recommended epoch issuance allocation:

- 50% pre-approved, objectively measured service-capacity and host procurement;
- 25% consensus validators;
- 15% public-goods work approved before execution;
- 10% independent evaluation, challenge, and recovery duties.

Every payment requires a typed, replay-protected receipt. “Useful intelligence” rewards come from a capped public-goods/evaluation budget after reproducible evaluation and a challenge window—not an automatic mint triggered by submission.

An ordinary paid job, observation, receipt, reciprocal task, or post-hoc claim never triggers minting. Issuance requires a capped budget committed before the work and anti-self-dealing eligibility.

Changing the envelope requires all governance chambers, an economic simulation, independent review, a 60-day timelock, and a new protocol release. Governance cannot mint retroactively, revive expired epoch budget, or exceed the lifetime ceiling.

## 9. Recommended fee flow

A service transaction has two visibly separate amounts:

- `service_price`: escrowed under the job contract and released 100% to the provider after objective completion, except optional arbitration or insurance amounts disclosed before acceptance;
- `network_fee`: pays shared consensus and public infrastructure.

The network fee, for service and ledger-only transactions alike, splits:

- 80% to validators;
- 18% to public goods;
- 2% burned.

The 2% burn is protocol cleanup and spam cost, not a promise of price appreciation. Fees should become the dominant security budget over time; issuance is a bounded bootstrap and long-run security supplement.

Governance may adjust the network-fee burn between 0% and 5% and public-goods share between 5% and 20%, but may not redirect the agreed service price or reduce validator compensation below 75% without a constitutional release.

## 10. Bonds and slashing

Stake is collateral for an objective duty, never evidence of truth.

Slashable events must be mechanically provable under a ratified schema, such as:

- consensus double-signing;
- signing an invalid state transition or checkpoint;
- forging an availability or service receipt;
- provable equivocation about the same committed artifact;
- failure to deliver a bonded, objectively specified service after its dispute procedure.

Recommended slash distribution:

- 50% burned;
- 25% to demonstrably affected escrow users or an insurance pool;
- 25% to the successful challenger, capped to prevent self-dealing.

No automatic slash may depend on subjective model quality. Disputed evaluation work loses pending rewards or bonds only through the published adjudication process.

## 11. Governance scope

The economic chamber is only one chamber and may govern economic parameters within constitutional bounds. Before VERA distribution it is the narrowly limited temporary activation chamber in `GOVERNANCE.md`; after the committed distribution and election trigger it becomes the active anti-concentrated token-participant chamber. Neither form can alone change consent, privacy, reputation formulas, evidence standards, model-release duties, recovery rules, or protected rights.

The temporary chamber cannot mint or allocate VERA. Token-activation signatures are accepted only from the active pre-token seat manifests rooted in genesis and present in the immediately preceding finalized state, at every fixed threshold; proposed replacement keys cannot sign themselves into authority. That authority automatically sunsets as specified there.

Economic proposals require:

- economic chamber approval at its active threshold;
- operator/contributor chamber approval at its active threshold;
- public/data-rights chamber approval at its active threshold;
- executable payload and simulation;
- conflict disclosures;
- minimum 30-day timelock (60 days for issuance changes).

Emergency keys cannot mint, transfer, seize, change supply, or alter recovery checkpoints.

## 12. Permissionless transition gates

These are post-activation Phase E gates. They do not authorize Phase C ratification or Phase D valuable activation, and they do not substitute for Section 13.

Bonded permissionless validation does not activate until all are true:

- at least 50 independently controlled validators;
- no operator controls 10% or more of voting power;
- the top five operators together control less than one third;
- at least 100 independently owned Soma agents have completed real tasks;
- at least 10 Vera hosts span five operators, three legal jurisdictions, and three infrastructure providers;
- founder-controlled usage is below 30% for three consecutive months;
- six months of stable testnet operation, three successful origin-only Phoenix rebuilds, and three separate successful exact-continuity succession drills;
- public audits of consensus, token, bridges/paymasters, and recovery code;
- jurisdiction-specific securities, commodities, money-transmission, sanctions, tax, and consumer-law review.

If these gates are not met, the network may remain in the disclosed bootstrap phase only until the activation manifest's absolute bootstrap sunset. If they still are not met, the terminal-checkpoint halt rule applies. A calendar date cannot override the gates or manufacture permissionlessness.

## 13. Full token launch gates

Every Section 13 gate must pass before the Phase C activation proposal is ratified and before Phase D executes. Phase E permissionless gates are additional later conditions, not substitutes.

No valuable VERA activation until:

1. users derive measurable value without token speculation;
2. at least 100,000 independently verifiable service/task receipts have been processed;
3. at least 30% of recurring usage and fees come from unrelated external operators;
4. consent-off leakage and malicious-host tests pass;
5. rewards cannot be farmed by replay, self-dealing, trivial Sybils, or fabricated receipts;
6. public supply and state can be independently replayed from genesis;
7. two implementations agree on all state roots;
8. an independent economic review models collusion, bribery, price crashes, fee spikes, validator exits, bridge failure, and token loss;
9. all public claims and offers are reviewed by qualified counsel in every launch jurisdiction;
10. no marketing promises price appreciation, scarcity profit, or passive return.

## 14. Recovery of VERA

### Same chain healthy

Restart services and hosts. Do not mint, redeploy, or snapshot-migrate the token.

### Chain substrate replacement with checkpoint

Authenticate the release independently; reproduce the uniquely highest valid finalized checkpoint from complete state bytes and replay material; satisfy the committed death predicate and every checkpoint-pre-state recovery/chamber threshold; preserve balances, lifetime minted/burned, live supply, issuance time, and consumed receipts exactly; publish a succession certificate; change the execution context; and prevent old-context replay through the ratified halt/finality rule. The new binding points to the same `asset_lineage_id`; conflicting valid histories invoke the fork procedure.

### Only the OriginSpec survives

Create a tokenless phoenix network first. After it independently passes every launch gate, it may ratify a zero-supply activation manifest and receive a new `asset_lineage_id`. No historical balance, allocation, vesting, reputation, consent, evidence, issuance history, or governance weight is invented.

### Conflicting finalized histories

Stop automatic succession. Publish both proofs, freeze bridge/migration claims, and treat the result as an explicit fork. Token holders and users choose; neither fork may erase the other’s existence.

## 15. Legal and tax gate

“New token class” is a technical description, not a legal exemption. Transferability, secondary markets, protocol mining/staking, sales, marketing promises, managerial dependence, exchange services, custody, rewards, and jurisdiction all affect treatment.

Before activation, qualified counsel must review the exact code, distribution, offers, governance, marketing, and operator roles. Operators must also plan for digital-asset income and transaction reporting. The project must not rely on a slogan such as “utility token” or “digital tool” as its legal analysis.

## 16. The honest bottom line

The VERA idea is coherent only after the network has useful services, objective receipts, independent operators, recoverable public state, and governance that cannot buy truth. Until then, the right token is no valuable token.
