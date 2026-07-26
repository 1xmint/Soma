# VERA DETERMINISTIC TOKEN OPERATIONS

Status: proposed v1 algorithm for simulation and ratification.
Rule: TOKEN-SPEC.md states policy; this file makes the recommended accounting unambiguous.

## 1. Units and counters

- 1 VERA equals 1,000,000,000 grain.
- All ledger arithmetic uses unsigned integer grain. Floating point is forbidden.
- Every consensus monetary amount or supply counter uses the `*_grain` suffix and is a canonical unsigned base-10 integer string counting grain. This is the sole consensus denomination and unit suffix.
- genesis_supply equals zero.
- lifetime_mint_ceiling equals 1,000,000,000 VERA.
- total_minted is cumulative creation and never decreases.
- total_burned is cumulative destruction and never decreases.
- live_supply equals total_minted minus total_burned.

In pseudocode, unsuffixed names are readable aliases for the corresponding consensus `*_grain` counters and always count grain. Display conversion to VERA is non-consensus presentation; implementations never perform ledger arithmetic in decimal VERA.

Wrapped or bridged representations are escrow claims, not additional VERA. Every binding publishes locked, minted, burned, and outstanding amounts so global claims cannot exceed canonical live supply.

## 2. Zero-supply start

For the first epoch, transactions use non-transferable, valueless gas quotas assigned under the public bootstrap policy. Validators and approved public infrastructure accrue claims, then the state machine mints the first VERA at epoch finalization.

Gas quotas:

- cannot transfer or convert into VERA;
- expire at epoch end;
- are rate-limited per independently controlled participant;
- cannot vote, bond, or create a balance;
- are visible in public state.

This solves the mechanical first-transaction problem without a premine or a disguised founder allocation. The activation manifest also fixes an absolute bootstrap-consensus sunset. If the Phase E transition has not validly finalized before it, bootstrap validators finalize the required terminal checkpoint and the state machine rejects new transfers, issuance, bonds, escrows, and governance execution; bootstrap keys cannot extend the deadline.

## 3. Epochs and issuance

The activation manifest fixes activation consensus time T0, epoch duration, annual duration, and `tail_supply_basis = live_supply_at_anniversary`. The recommended values are:

- epoch_seconds = 86,400;
- schedule_year_seconds = 31,557,600;
- maximum timestamp advance and median-time calculation are consensus rules.

Before year 16, cumulative schedule anchors are:

| Elapsed schedule time | Cumulative ceiling |
|---:|---:|
| 0 years | 0 VERA |
| 1 year | 100,000,000 VERA |
| 2 years | 180,000,000 VERA |
| 4 years | 300,000,000 VERA |
| 8 years | 450,000,000 VERA |
| 16 years | 600,000,000 VERA |

Between anchors, C(t) is the integer floor of linear interpolation in grain. For epoch e:

    scheduled_budget_e = C(epoch_end) - C(epoch_start)
    mint_e <= scheduled_budget_e
    total_minted <= lifetime_mint_ceiling

Unused epoch budget expires and can never be minted later.

At each schedule-year anniversary after year 16:

    annual_tail_budget =
      min(
        floor(live_supply_at_anniversary / 100),
        lifetime_mint_ceiling - total_minted
      )

`live_supply_at_anniversary` is the finalized canonical `total_minted - total_burned` grain count at the exact schedule anniversary. It is not market circulating supply, liquid supply, unbonded supply, or a wallet-provider estimate. The annual budget is fixed from that snapshot and drips linearly across that schedule year; later burns do not recompute it. Unused tail budget expires. Issuance permanently stops when total_minted reaches one billion VERA. Burns do not reopen mint capacity.

This is a mint ceiling, not a promise that the ceiling will be reached.

## 4. Issuance buckets

Each epoch’s maximum new issuance is divided:

- 50% approved service-capacity and host obligations;
- 25% consensus validation;
- 15% pre-approved public goods;
- 10% independent evaluation, challenge, and recovery duties.

Integer division rounds down. Remainders and empty buckets stay unminted. Governance cannot move an unused bucket after the epoch begins.

Ordinary paid jobs do not trigger issuance. They pay the provider from the consumer’s escrow. The 50% issuance bucket is available only for procurement commitments published before the epoch: scarce network capacity, open infrastructure, availability, or other objectively measured duties selected under a capped auction or budget. A receipt submitted after performing unapproved work has no mint claim.

Every claim binds:

- a pre-existing budget or procurement ID;
- common-controller disclosures;
- unique request and receipt IDs;
- provider, consumer, verifier, capability, units, and time;
- artifact or availability commitments;
- all required signatures;
- challenge deadline and final state;
- the epoch and exact maximum payout.

The ledger keeps a consumed set. A receipt can settle once. Related parties and reciprocal task rings are ineligible unless the budget explicitly permits and discloses them. A provider cannot be paid more than the procurement cap even if it creates more identities or receipts.

## 5. Service payment and network fee

Do not tax a provider’s agreed service price by 25%.

A service transaction contains two separate amounts:

1. service_price — escrowed for the provider and released according to the job contract;
2. network_fee — pays consensus and public infrastructure.

The service price goes 100% to the provider after objective completion, except amounts explicitly committed beforehand to optional arbitration or insurance. The protocol cannot silently redirect it.

The recommended network-fee split is:

- 80% validator/security pool;
- 18% public-goods pool;
- 2% burn.

For each recipient, compute floor(network_fee × basis_points / 10,000). Any division remainder is burned. Fee parameters can adjust only within TOKEN-SPEC.md governance bounds and apply prospectively after timelock.

Paymasters may accept fiat or stablecoins and acquire VERA transparently. The user sees service price, network fee, exchange spread, and paymaster fee separately.

## 6. Validation rewards

The validator bucket pays deterministic signed-block, finality, availability, and checkpoint duties. It cannot pay for stake alone.

The activation manifest fixes:

- eligible duty counters;
- uptime windows;
- missed-duty treatment;
- commission disclosure;
- minimum self-bond and delegation concentration limits;
- jail and objective slash conditions;
- rounding and unclaimed reward expiry.

Voting power may be bonded, but epistemic claims and agent reputation never use bonded amount.

## 7. Public-goods and evaluation rewards

Public-goods work is approved before execution with a maximum amount, milestones, open-output license, conflicts, and review method. Payments follow verified milestones and a challenge window.

Evaluation and recovery claims require an independently reproducible result. “The model seems smarter,” an uploaded gradient, a self-reported test, or a popular vote is not an objective mint condition.

## 8. Burning

Burning is an accounting operation that makes grain permanently unspendable and increments total_burned. It does not promise price support.

Permitted burn sources are:

- the fixed network-fee share;
- the fixed share of an objective slash;
- voluntary burns signed by the owner.

Treasury market buybacks and discretionary burn campaigns are forbidden.

## 9. Slashing

An automatic slash requires a compact proof that every conforming implementation evaluates identically. Examples are consensus double-signing, an invalid checkpoint signature, or reuse of a consumed receipt.

For a finalized slash:

- 50% burns;
- 25% compensates demonstrably affected users or the ratified insurance pool;
- 25% rewards the successful challenger, subject to a case cap.

Subjective quality disputes can withhold a pending job escrow under its contract, but cannot invoke automatic protocol slashing.

## 10. State invariants

Every block and checkpoint must prove:

    total_minted <= lifetime_mint_ceiling
    live_supply = total_minted - total_burned
    sum(all spendable balances + bonded + escrowed + governed pools) = live_supply
    no receipt ID settles or earns issuance twice
    no epoch mints above its scheduled budget
    no issuance bucket mints above its epoch share
    no bridge claims more VERA than its verified lock

All values are replayable from genesis. A mismatch halts state sync and checkpoint acceptance.

## 11. Recovery

Exact-continuity migration imports total_minted, total_burned, every balance, bond, escrow, governed pool, consumed receipt, schedule time, and remaining current-epoch budget exactly. It cannot restart the schedule or reopen expired issuance.

The old substrate must be provably halted, permanently locked, or rejected by the ratified light-client/finality rule before successor balances become spendable. Otherwise migration creates a double-spend fork and cannot claim one lineage.

A phoenix lineage begins again at zero and receives no old balances or issuance history.

## 12. Simulation questions

Before ratification, publish stress results for:

- VERA price falling 95%;
- VERA price rising 100 times;
- fees insufficient to retain validators;
- validator or host concentration;
- Sybil procurement and reciprocal-job rings;
- bribed verifiers and challengers;
- long periods with unused issuance;
- all buckets fully claimed;
- paymaster and stablecoin failure;
- bridge insolvency;
- network halt and exact migration;
- burn and tail issuance approaching the lifetime ceiling.

If the design cannot retain security without promising appreciation, passive yield, or fake work, activation remains blocked.
