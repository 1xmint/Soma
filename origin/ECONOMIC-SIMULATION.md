# SOMAVERA DETERMINISTIC ECONOMIC SIMULATION

Status: **research harness 0.1; not ratified; never sufficient for activation**

## 1. Purpose

The simulator compares economic architectures under disclosed adverse inputs.
It does not forecast price, create value, prove legal compliance, or authorize a
token. Its first corpus is deliberately synthetic and therefore must return
`reject_activation` even if every arithmetic threshold passes.

The quote unit is an explicitly named comparison unit, not protocol money.
`quote_microunits` can represent micro-USD, micro-units of a future currency,
compute, energy, or another declared unit. Changing the quote unit does not
change Somavera identity or VERA accounting.

## 2. Determinism

- Input and output are closed JSON Schema 2020-12 objects.
- Monetary and token quantities are canonical unsigned base-10 integer strings.
- All calculations use integer arithmetic and explicit floor division.
- Floating point, randomness, live prices, clocks, network calls, environment
  variables, and iteration-order dependence are forbidden.
- Profiles and scenarios are processed in lexicographic ID order.
- The suite and report use RFC 8785/JCS with Somavera I-JSON rejections and
  domain-separated SHA-256 hashes.

The report hash excludes `$schema` and `report_hash` and is:

```text
H("somavera:economic-simulation-report:v1\n" || JCS(report_core))
```

## 3. Model boundary

Each parameter profile declares whether it has no native token or uses a native
token, its atomic precision, fee, validator fee share, issuance, and bond
assumptions. Each stress scenario supplies demand, service value, token price,
operating cost, access dependencies, concentration, adversarial shares,
issuance-claim pressure, capacity, and succession state.

For native profiles:

```text
fee_quote =
  floor(fee_grain * service_units * token_price_quote_microunits /
        10^token_decimals)

issuance_quote =
  floor(validator_issuance_grain * token_price_quote_microunits /
        10^token_decimals)

validator_budget_quote =
  floor(fee_quote * validator_fee_share_basis_points / 10_000) +
  issuance_quote
```

For the no-native-token control, native fee and issuance values are zero.
External security expenditure is declared separately and cannot be relabeled as
token value.

## 4. Rejection rules

A profile/scenario pair fails when any applicable condition holds:

- validator budget is below the disclosed operating cost;
- network fee burden exceeds the suite limit relative to service value;
- a user needs the native fee path but both direct access and a functioning
  paymaster/liquidity path are unavailable;
- a token-denominated security budget has no external liquidity path, or a
  declared external security budget has no available settlement path;
- one known validator controller reaches one third of voting power;
- hostile validator power reaches one third;
- host or validator concentration exceeds its declared limit;
- Sybil/related-party issuance claims exceed the declared limit;
- demand exceeds declared safe capacity;
- bootstrap sunset is missed;
- succession is ambiguous or permits two spendable contexts;
- public intelligence, identity, consent, export, or exit requires a token,
  paymaster, liquidity venue, bridge, oracle, or external settlement asset.

The suite itself is ineligible for activation when:

- its corpus is not `empirical_independently_attested`;
- launch, legal, security, privacy, recovery, and data-rights gates are not all
  independently evidenced;
- any required adverse-coverage tag is absent;
- any profile proposed for activation fails any scenario;
- evidence hashes, independent report signatures, or reproducible engine builds
  are absent.

The included example intentionally fails these eligibility rules.

## 5. Required adverse coverage

The semantic validator requires coverage for 95%, 99%, and near-total price
loss; 10x and 100x price increases; zero and withdrawn liquidity; at least five
validator-cost profiles; 30%, 50%, and 67% cartel attempts; Sybil procurement,
reciprocal work, verifier bribery, and challenger griefing; empty and full
issuance buckets; low, capacity, and excess demand; stablecoin, paymaster,
bridge, oracle, and major-venue failure; user accounting burden; bootstrap
sunset; exact succession; and an ambiguous double-spend fork.

Coverage tags prove only that an input exists. They do not prove that its model
is realistic. Empirical eligibility requires published measurement methods,
raw evidence hashes, conflicts, limitations, and independent attestations.

## 6. Interpreting output

`engine_conformance: pass` means deterministic arithmetic and rejection logic
ran as specified. It does not mean an economic profile passed. The only safe
interpretation of the bundled report is:

> These synthetic architectures were compared reproducibly; Somavera is still
> not eligible to activate a valuable token.

Scenario A remains a hypothesis. The no-native-token profile is a required
control, not an inferior placeholder. A future profile must outperform simpler
choices without depending on price appreciation, official liquidity,
undisclosed subsidy, fake work, permanent founder operation, or rights-reducing
token gates.
