# SOMAVERA GENESIS, PHOENIX, AND TOKEN DESIGN AUDIT

Status: **high-effort design audit; not ratified; no token or live genesis is authorized**
Document ID: `somavera/genesis-token-audit/0.1-draft`

## 1. Executive verdict

Somavera has a coherent foundation, but it is not ready for a valuable token or a
continuity claim.

The strongest existing decisions are:

- one optional economic asset rather than separate Soma and Vera currencies;
- strict separation of transferable money from non-transferable reputation,
  credentials, consent, and evidence;
- tokenless usefulness before token activation;
- zero genesis supply, no founder premine, no automatic conversion of prelaunch
  points, and no official day-one liquidity pool;
- Origin-only Phoenix revival creates a new lineage, while exact continuity
  requires authenticated and reproducible state plus checkpoint-era authority;
- external settlement assets remain replaceable and are never part of VERA's
  constitutional identity.

The largest current defect is a specification-layer contradiction:
`TOKEN-SPEC.md` labels the monetary parameters recommended and unratified, while
`schemas/token-activation.schema.json` and its semantic validator hard-code
several of those choices. Machine validation must enforce safety invariants and
the exact parameters ratified by a signed activation manifest; it must not turn
illustrative numbers into constitutional truth.

The correct next milestone is a review-frozen Origin candidate, a tokenless
Genesis test package, and an economic simulation framework. It is not token
deployment.

## 2. What the system is

Somavera is a sovereign agent coordination network with four deliberately
separate value planes:

| Plane | Durable object | Transferable | Function |
|---|---|---:|---|
| Authority | Soma identity, delegation, credentials, consent | No | Who may act and disclose what |
| Evidence | Signed work, outcomes, disputes, provenance | No | What can be evaluated and trusted in context |
| Intelligence | Licensed public knowledge and sovereign/private artifacts | By its license | What the network learns and returns |
| Economy | External settlement assets and optional VERA balances | Yes | Paying for scarce services and securing public state |

No conversion exists from money to identity assurance, reputation, factual
confidence, observer consent, search rank, or training priority.

## 3. The money question

There is no single universal money in Somavera.

1. A provider chooses a **quote unit** appropriate to the contract.
2. Participants settle with a voluntarily accepted **external settlement
   asset**: current examples include fiat, a payment stablecoin, BTC, local
   currency, compute credit, barter, or a future asset.
3. After valid activation, **VERA** pays shared-ledger fees and collateralizes
   objective protocol duties.

The quote unit, settlement asset, and VERA are independent. A service may be
quoted in one unit, settled through another asset, and pay a separately
disclosed VERA network fee through a paymaster.

If today's currencies disappear, no Origin document can recreate their issuers,
reserves, purchasing power, markets, or legal status. A surviving exact VERA
lineage preserves its ledger units and balances, not their external exchange
value. An Origin-only Phoenix begins tokenless and later creates a new asset
lineage only after repeating every launch gate. Participants then choose the
settlement assets they trust.

## 4. Why VERA can have utility when public intelligence is free

Free public intelligence is a constitutional output, not a claim that all
resources are free. Scarce resources still have costs:

- low-latency or private inference;
- compute, storage, bandwidth, and availability;
- agent labor and service execution;
- consensus, validation, checkpoints, and archival state;
- evaluation, challenges, recovery work, and arbitration.

VERA's defensible role is narrow: shared-ledger fees, objective bonds, service
escrow support, and bounded economic governance. It is not ownership of VeraAI,
a claim on future intelligence, a share of HeyVera, or a promise of protocol
revenue.

The network must remain usable through direct external payment and sponsored
fees. Mandatory acquisition of a volatile asset for basic public intelligence,
identity, consent, or exit would be a design failure.

## 5. One token, not two

The recommended architecture remains one economic token.

A second transferable Soma token would create conflicting prices, fragmented
liquidity, bridge and accounting risk, extra governance capture surfaces, and
an incentive to turn reputation into a commodity. Soma's scarce objects are
credentials, evidence, rate limits, and contextual reputation; none should be a
transferable currency.

The system therefore uses:

- VERA: one optional transferable protocol asset;
- reputation: non-transferable and recomputed from evidence;
- credentials and consent: non-transferable signed authority;
- external settlement assets: open-ended adapters, not protocol identity.

## 6. Liquidity and agent financing

Liquidity is supplied by asset owners, not created by Genesis.

- VERA inventory can arise only through ratified issuance for objective duties
  or later voluntary transfers.
- The paired external asset comes from independent holders, service users,
  market makers, or disclosed HeyVera operating capital.
- Customer escrow, identity-verification funds, data-rights budgets, and
  recovery funds are never liquidity.

The proposal to let people finance an agent is not a base-token function.
Permitted early forms are bounties, grants, patronage, and prepaid service
contracts. A passive pool whose contributors expect profits from an operator's
work may be a pooled investment. A payoff based on an agent's future result may
be an event contract or derivative. Those products require separate entities,
books, custody, disclosures, loss limits, and jurisdiction-specific approval.

Government-ID backing may raise personhood assurance for a particular relying
party, but it does not prove competence, honesty, independence, or agent
performance. The protocol should support optional, selectively disclosed
identity-proofing credentials with explicit assurance levels. It must not put
raw ID or biometric material on-chain, make U.S. identity globally mandatory,
or allow identity proofing to purchase reputation.

## 7. Legacy ideas: disposition

The legacy material is useful historical brainstorming, not protocol authority.

| Legacy idea | Disposition | Reason |
|---|---|---|
| Free/cheap discovery and routing as adoption wedge | Preserve as product strategy | Does not require token economics |
| Signed receipts and continuous trace commitments | Preserve for evidence research | Provenance remains distinct from truth |
| Objective validator/service bonds | Preserve with machine-verifiable duties | Collateral is not reputation |
| Automatic prelaunch points-to-token conversion | Reject | Creates promised economic expectation and farmable contingent claims |
| Credit-lock multipliers and passive “Signal” | Reject | Capital can purchase future allocation and invites Sybil/expectation risk |
| Team, treasury, and liquidity premine | Reject for the recommended profile | Conflicts with zero-supply earned distribution |
| Revenue-funded market buybacks and burn flywheel | Reject | Creates managerial price-support expectations and treasury dependency |
| Stake-based trust badges, identity, ranking, or proof priority | Reject | Pay-to-trust and anti-competitive access |
| Token burns for every observation or heartbeat | Reject | Artificial demand, privacy leakage, and unusable tax/accounting burden |
| Universal scalar trust score | Reject | Collapses contextual uncertainty into a gameable number |
| “Digital tool” as categorical legal safety | Reject | Legal treatment depends on actual offers, promises, distribution, and use |

## 8. Critical gaps before Genesis ratification

### P0 — authenticity and authority

- No ratified Origin release signature set or independently preserved trust
  anchor currently exists.
- Genesis signer identities, independence rules, public keys, custody,
  thresholds, terms, conflicts, and expiry are not selected.
- No actual Genesis ceremony transcript or signature verification report exists.

### P0 — deterministic protocol

- No selected consensus substrate or complete ledger state-transition profile
  exists.
- No second independent implementation reproduces all consensus roots.
- Genesis and recovery schemas exist, but the full semantic validator and
  adversarial vectors for Genesis ratification are incomplete.
- Reproducible binaries, SBOMs, dependency archives, and offline build evidence
  are incomplete.

### P0 — economics

- The supply and fee numbers are uncalibrated hypotheses.
- No fee-market measurement establishes spam cost or validator revenue needs.
- No reproducible economic simulator or published scenario corpus exists.
- Receipt independence, procurement auctions, collusion detection, and
  objective service measurement are not implemented at network scale.
- No qualified legal analysis exists for the exact operator, paymaster,
  custody, issuance, staking, market, and jurisdiction facts.

### P0 — Phoenix and continuity

- No independent Origin-only Phoenix rebuild has been performed.
- No exact-continuity substrate-death drill has reproduced complete state with
  two implementations.
- External authenticity anchors, state-byte mirrors, and death-observer
  diversity are not operational.

### P1 — governance and identity

- Chamber selection and removal mechanisms are not finalized.
- Common-control and Sybil resistance are not proven.
- The optional real-person identity profile needs assurance-level semantics,
  selective disclosure, redress, retention, and privacy testing.
- The transition from credentialed bootstrap governance to independently
  controlled operation is not demonstrated.

## 9. Artifact hierarchy

Somavera must distinguish five artifacts:

1. **Origin release:** constitutional rules and recovery physics.
2. **Genesis instance:** one tokenless network's exact initial state and
   authority.
3. **Token parameter profile:** exact simulation inputs and evidence; not live
   authority.
4. **Token activation manifest:** one signed transition from a reproduced
   tokenless pre-state to zero-supply activated accounting.
5. **Execution-context binding:** the current substrate and replay domain.

Origin can survive every substrate. Genesis creates one network lineage. Token
activation later creates one asset lineage. Exact succession changes the
execution context without changing valid network or asset lineage. An
Origin-only Phoenix creates new network and, if later activated, asset lineages.

## 10. Ratification ladder

### G0 — candidate capsule

The current state. Internal hashes and conformance tests establish integrity,
not historical authority.

### G1 — review-frozen Origin candidate

- normative/informative classification is complete;
- every normative hash projection has two-language vectors;
- unresolved values are explicitly non-normative;
- public review and independent threat/economic reviews are published.

### G2 — signed Origin release

- disclosed independent signers use purpose-separated offline keys;
- each signer verifies the exact manifest and evidence root;
- threshold signatures cover the release core;
- signature transcripts, conflicts, terms, and expiry are public;
- the release hash and public keys are preserved through several independent
  media and witnesses.

This authenticates a release. It does not launch a network.

### G3 — tokenless Genesis candidate

- exact consensus, validator, chamber, recovery, death-policy, anchor, build,
  and protocol hashes are fixed;
- token is inactive, asset lineage is null, and every economic collection is
  empty;
- proof-of-possession is complete for every proposed key;
- no proposed key authorizes itself.

### G4 — tokenless network activation

- Genesis signatures validate against the authority committed in the unsigned
  Genesis core;
- two implementations reproduce the initial and early state roots;
- observer-off, recovery, supply-zero, and halt tests pass;
- no VERA, convertible point, market, pool, or promised allocation exists.

### G5 — token activation eligibility

Every product, independence, receipt-volume, privacy, security, economic,
recovery, and legal gate in `TOKEN-SPEC.md` passes. Failure of any gate blocks
activation.

### G6 — zero-supply token activation

The checkpoint pre-state authorizes one exact activation manifest. All
parameters and evidence hashes are fixed, signatures meet every chamber
threshold, and activation begins with zero balances. First issuance occurs only
for precommitted, objectively measured duties.

## 11. Parameter doctrine

The following are constitutional safety invariants:

- genesis supply is zero;
- no founder/team premine or automatic prelaunch conversion;
- unsigned integer smallest-unit accounting;
- total minted never exceeds the ratified lifetime ceiling;
- burns never reopen lifetime mint headroom;
- service price is not silently redirected;
- splits total exactly 100%;
- issuance is pre-budgeted, bounded, receipt-linked, and replay-protected;
- capital never changes reputation, identity, consent, or epistemic weight;
- exact succession preserves every economic counter exactly;
- Phoenix creates no inherited economic claims.

The following are ratifiable parameters, not constitutional facts:

- asset display name, symbol, and precision; the schema-v1 atomic denomination remains `grain`, and changing it requires a versioned wire migration;
- lifetime mint ceiling and issuance anchors;
- epoch and schedule time bases;
- issuance-bucket percentages;
- fee split and burn percentage;
- bond sizes, unbonding windows, and case caps;
- bootstrap height/time and post-distribution election trigger.

Every parameter profile requires measurement, adverse simulation, an
independent economic review, a decision record explaining rejected
alternatives, and exact hashes in the activation core.

## 12. Required simulations

At minimum, a deterministic simulator must sweep:

- token price down 95%, 99%, and effectively zero;
- price up 10× and 100×;
- zero external liquidity and sudden liquidity withdrawal;
- validator costs across at least five infrastructure profiles;
- 30%, 50%, and 67% validator/host cartel attempts;
- Sybil procurement, reciprocal jobs, verifier bribery, and challenger griefing;
- all issuance buckets empty and fully claimed;
- demand below, at, and above capacity;
- stablecoin, paymaster, bridge, oracle, and major venue failure;
- tax/accounting load for frequent fees and service compensation;
- bootstrap sunset before permissionless gates;
- exact succession and ambiguous double-spend fork.

A parameter profile fails if security depends on token appreciation, official
liquidity, undisclosed subsidies, fake work, a permanent founder service, or
rights-reducing token gates.

## 13. Current recommendation

Keep the recommended one-token architecture and zero-supply earned start.
Retain the current numerical schedule only as **simulation scenario A**. Do not
ratify it until it wins against simpler alternatives, including:

- no native token;
- capped issuance with no tail;
- lower lifetime ceiling with adaptive per-duty payouts;
- fee-only security after a fixed bootstrap grant period;
- settlement-layer security rather than a sovereign validator token.

The next build target is the tokenless multi-host pilot and deterministic
economic simulator. Creating a contract address, ticker, wallet balance,
convertible point, official pool, or “founding position” now would move the
project backward.
