# SOMAVERA NETWORK ECONOMY AND LIQUIDITY DOCTRINE

Document ID: `somavera/economy/0.1-draft`
Status: **recommended design; not ratified; no valuable VERA exists**

## 1. What Somavera is

Somavera is a **sovereign agent network with a shared intelligence commons and an embedded service economy**.

- Soma gives people and agents identity, authority, consent, evidence, and continuity.
- Vera turns authorized contributions and outcomes into a shared, auditable intelligence commons.
- VERA is the optional future network-security and coordination asset described in `TOKEN-SPEC.md`.
- HeyVera is the first human-facing product and commercial operator. It is not the protocol owner and must not become the only host, credential issuer, validator, checkpoint mirror, or user interface.

The mission is not to create a token market and then search for a use. Economic machinery exists to pay for scarce work and secure shared state.

## 2. Four kinds of value must remain separate

| Instrument | What it represents | May trade? | May affect trust? |
|---|---|---:|---:|
| External settlement asset | USD, payment stablecoin, BTC, local currency, compute credit, or another voluntarily accepted asset | Yes | No |
| VERA | Network fees, objective bonds, escrow support, and limited economic coordination | Yes, only after activation | No |
| Reputation and evidence | Contextual history of signed work, outcomes, disputes, and uncertainty | No | Yes, through published evidence rules |
| Credentials and consent | Identity/capability claims and data-use authority | No | Only within their stated scope |

Capital cannot purchase identity assurance, reputation, factual confidence, search rank, training priority, or observer consent.

## 3. What pays for what

Every economic interaction separates the provider's price from the shared network cost:

```text
service_price = amount accepted by the provider for compute, hosting, work, or storage
network_fee   = VERA required for shared-ledger security and public infrastructure
```

Before VERA activation, the network fee is replaced by a valueless quota or sponsored test transaction. A provider may accept any settlement asset. A paymaster may later accept an external asset and acquire the required VERA transparently.

Public Vera knowledge and baseline export rights are not token-gated. Scarce compute, latency, storage, private inference, agent labor, validation, availability, evaluation, arbitration, and priority capacity may be paid services.

## 4. Where liquidity actually comes from

Liquidity is the ability to exchange VERA for another asset without unacceptable delay or price impact. It cannot be declared by a genesis file.

A two-asset market requires both sides:

1. **VERA inventory.** With zero premine and zero sale, the first legitimate VERA can only come from deterministic issuance for pre-approved, objectively verified network duties. Later holders may acquire VERA from those earners on a secondary market.
2. **External inventory.** The other side comes from independent capital: a person's stablecoin or other asset, an agent operator's treasury, an independent market maker, or disclosed HeyVera operating capital. The protocol cannot mint this side.

Buying VERA is demand, not liquidity by itself. A buyer still needs a seller. A trade sends the buyer's external asset to the seller or liquidity pool; it does not automatically fund Somavera or HeyVera.

Providing liquidity means depositing both assets into a market or quoting firm two-sided prices. The provider bears inventory, smart-contract, counterparty, price, and impermanent-loss risk. A liquidity position is not a trust credential or a claim on Vera's intelligence.

## 5. Pool taxonomy

The word "pool" must always name one of these distinct objects:

| Pool | Purpose | Source of funds | Return or payout |
|---|---|---|---|
| Exchange liquidity pool | Let buyers and sellers exchange VERA and another asset | Voluntary LP capital on both sides | Trading fees and market exposure |
| Service escrow | Hold a customer's payment for a specific job | Customer | Provider payment, refund, or disclosed dispute outcome |
| Bond/insurance pool | Collateralize an objective duty or compensate defined loss | Bonded operators or explicit premiums | Return of collateral or defined claims |
| Agent sponsorship vault | Finance an agent or operating entity | Sponsors/investors | Work, access, or, only if lawfully structured, service-revenue participation |
| Public-goods budget | Pay pre-approved open infrastructure and evaluation | Protocol fee share, grants, or bounded issuance | Verified milestone payment, not passive yield |

These pools must never share balances, silently cross-subsidize one another, or treat customer escrow as market liquidity.

## 6. Safe liquidity bootstrap

### Stage L0 - useful product, no valuable token

- HeyVera charges ordinary money for managed agents, compute, storage, private services, and support.
- Soma and Vera use valueless quotas and signed service receipts.
- No sale, promise of conversion, liquidity mining, or official price.
- Measure real costs, external demand, and independently operated capacity.

### Stage L1 - earned distribution, still no official market

- Phase C may be ratified and Phase D may execute only after every Section 13 pre-activation gate in `TOKEN-SPEC.md` passes. Section 12 permissionless-security gates govern the later Phase E transition; they do not authorize or replace pre-activation gates.
- First VERA is earned by independent validators, hosts, evaluators, recovery operators, and pre-approved public infrastructure.
- Keep ordinary-payment, sponsored-transaction, and non-token access paths available while supply distributes; first-epoch gas quotas still expire and never convert to VERA.
- Credentialed bootstrap consensus ends at the activation manifest's absolute sunset. If Phase E gates have not passed, the terminal-checkpoint halt applies; markets do not justify extending bootstrap authority.
- Do not mint to a liquidity treasury or promise recipients that HeyVera will buy their VERA.

### Stage L2 - independent price discovery

- Earned holders may voluntarily sell and service users may voluntarily buy through independently operated, legally reviewed venues.
- A transparent periodic auction may be safer for a thin early market than pretending a tiny automated pool has a reliable price.
- HeyVera may buy VERA for actual network consumption through its paymaster, with the exchange spread and service fee disclosed.
- Market price must not be a consensus input for identity, reputation, evidence, or consent.

### Stage L3 - voluntary exchange liquidity

- Independent LPs may deposit legitimately earned or purchased VERA plus their own external asset.
- The protocol does not mint LP rewards, guarantee an APR, reimburse losses, promise a floor, or perform discretionary buybacks.
- HeyVera may participate only with its own disclosed operating capital and VERA it earned for objective services or bought on the same disclosed terms available to others.
- HeyVera-controlled liquidity, related-party volume, sponsored fees, and organic third-party volume are reported separately.

### Stage L4 - resilient multi-asset markets

- Multiple independent venues and settlement assets reduce dependence on one stablecoin, company, bridge, jurisdiction, or chain.
- No external asset is constitutionally permanent.
- If today's currencies disappear, a revived network can quote VERA against whatever lawful and trusted settlement assets participants then accept.

## 7. Forbidden liquidity shortcuts

- Selling "founding positions" before the network provides measurable utility.
- Minting VERA merely to seed an official pool.
- Using customer deposits, service escrow, identity-verification funds, or data-rights budgets as liquidity.
- Paying inflationary VERA rewards to LPs merely for depositing capital.
- Protocol or treasury buybacks, price floors, loss protection, or guaranteed exit liquidity.
- Undisclosed founder, employee, validator, or related-party trading.
- Reporting wash volume, sponsored paymaster flow, or HeyVera self-purchases as organic adoption.
- Marketing VERA as ownership of VeraAI, a share of future superintelligence, or a right to protocol revenue.

## 8. HeyVera's economic role

HeyVera can create real demand without making speculative promises. It may earn ordinary revenue from managed Soma-agent hosting; compute, storage, availability, backups, and private inference; premium orchestration and coding-agent services; social-network and marketplace services; optional identity-verification processing; enterprise support; and transparent paymaster convenience fees.

Initially these services use ordinary settlement assets. After VERA activation, HeyVera can sponsor a user's network fee and buy VERA as an operating input. That is real consumption. HeyVera must not advertise its own purchases as price support.

Hosting a Soma agent, publishing a social post, verifying an identity, and consenting to Vera observation are four separate user actions. None implies the others.

## 9. Financing agents

The safest early financing mechanisms are bounties, grants, patronage, and prepaid services: a sponsor pays for defined work, public output, access, or capacity.

A passive pool in which people contribute money and expect profits from an agent operator's work may be a security or regulated pooled product. A payoff based on a future agent outcome may also resemble an event contract or derivative. Any such product belongs above the base protocol, behind jurisdiction gating and qualified counsel, with separate books, disclosures, custody, and loss limits.

An Agent Sponsorship Vault must never mint protocol reputation, change search or training priority, receive a protocol guarantee, imply that identity verification proves competence, or commingle investor capital with customer escrow or network liquidity.

## 10. Launch evidence

Before Somavera calls a VERA market healthy, publish market-circulating and bonded supply as non-consensus analytics; canonical live supply and the anniversary tail basis remain the replayed ledger counters defined in `TOKEN-OPERATIONS.md`. Also publish concentration; earned versus purchased distribution; organic versus sponsored demand; related-party volume; HeyVera-controlled inventory; market spread, depth, and price impact; external dependency concentration; and adverse simulations for price collapse, liquidity exit, stablecoin failure, and paymaster failure.

No liquidity date overrides the security, independence, legal, and product-utility gates in `TOKEN-SPEC.md`.

## 11. Regulatory boundary

This document is protocol policy, not legal advice. A non-security crypto asset can still be offered or sold as part of an investment contract depending on the promises and surrounding arrangement. An operator that exchanges or transmits convertible virtual currency for others may have money-transmission obligations. Pool, paymaster, exchange, custody, staking, rewards, and marketing facts require jurisdiction-specific review before launch.
