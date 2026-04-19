# Soma — Honest Limits

Status: canonical


This doc is the inverse of `primitives.md`. It's what Soma **does not** do, what we require the operator to believe, and what still needs to be built.

Read this before deploying. If your threat model collides with anything here, choose a different tool.

## Trust Assumptions

### You must trust the signing host
The heart holds signing keys in process memory by default. If the process is compromised, the keys leak. Mitigations we ship:
- `signing-backend.ts` — HSM / hardware-wallet hooks so keys never live in JS memory.
- `remote-attestation.ts` — TEE quotes so remote verifiers can pin identity to a measured enclave.

Without one of those, key compromise is "the process got rooted" and we can't help.

### Threshold signing reconstructs the key
`threshold-signing.ts` is M-of-N Ed25519 via Shamir reconstruction. The secret exists briefly in memory during signing. A compromised signing coordinator at that exact moment leaks the full key. This is NOT FROST — FROST never reconstructs. If you need coordinator-resistance, you need a real FROST-Ed25519 implementation (RFC 9591), which we don't ship.

### Birth certificates prove origin, not truth
A signed birth certificate says "this data was produced by the holder of key K at time T." It does **not** say the data is factually correct. A lying provider can sign true-looking garbage. Soma only proves accountability — "the holder of K is the one who lied."

### Temporal fingerprinting (sensorium) is advisory
The timing-based model classifiers in `src/sensorium/` are experimental. They distinguish between a handful of known models with ~93% cloud accuracy in our dataset, but:
- A sophisticated attacker with control of the serving layer can spoof timing.
- The 93% number was measured on our specific benchmark suite at a specific time against a specific set of models. Real deployments will drift.
- Sensorium is a *defense-in-depth signal*, not a primary security control.

### `did:key` identities are free
Anyone can mint infinite `did:key` identities. Soma has NO built-in sybil defense; that's what `attestation.ts` (peer vouching, stake-bonded, KYC attestations) is for. Applications choose their own trust root and interpret attestations to their own policy.

## What the Crypto Does and Doesn't Do

| Primitive | What it proves | What it does NOT prove |
|-----------|---------------|------------------------|
| Birth certificate | Holder of K signed `data` at time T | Data is truthful |
| Delegation | Issuer of K granted capability X to subject | Subject actually holds K (→ need PoP) |
| Revocation | Someone with authority revoked ID at time T | The revocation has reached all verifiers |
| Heartbeat chain | Events are tamper-ordered for a single heart | No events are missing from a parallel heart |
| Spend receipts | Subject acknowledged each spend | Issuer has a consistent view of total |
| Time witness | *A* trusted authority attested to wall time | Wall time is objectively correct (use a quorum) |
| TEE attestation | Code running now matches measurement M | Code is free of bugs or side-channels |
| VRF | Output is unbiased and deterministic for sk | Any particular output came from any particular sk without verification |
| Selective disclosure | Issuer signed exactly these field values | Withheld fields are non-sensitive |

## Known Open Problems

- **FROST-Ed25519.** API surface is reserved; no real implementation ships. Waiting on a vetted JS library or in-house audit of `@noble/curves`-based impl.
- **Post-quantum signatures.** `hybrid-signing.ts` has the envelope format, but soma ships no ML-DSA or SLH-DSA `SigningProvider`. Comes from a dedicated package when a vetted JS impl lands.
- **Distributed key generation.** Threshold signing uses a trusted dealer. DKG primitives are out of scope.
- **DID:web fetcher.** We ship the module but not a network client — operators wire `fetch()` themselves. Intentional (avoids depending on a specific HTTP stack).
- **Gossip transport.** `InMemoryTransport` is the reference. No libp2p/NATS/Redis adapters shipped. Operators adapt behind the `GossipTransport` interface.
- **Share refresh.** Shamir shares don't rotate. A compromised shareholder keeps their share valid until the whole key is rotated. Proactive secret sharing is out of scope.
- **Key-rotation resolution in verifiers.** ~~`key-rotation.ts` builds the chain; individual verifiers don't yet resolve `issuerDid` to the key version current at `issuedAt`.~~ **Resolved.** All four verifier call sites (`delegation.ts`, `revocation.ts`, `birth-certificate.ts`, `selective-disclosure.ts`) now accept an optional `HistoricalKeyLookup` that confirms the signing key was effective at the artifact's timestamp via the rotation subsystem. When provided, verifiers fail closed if the credential is not found, not yet effective, or already rotated out. When omitted, existing behavior is preserved (backward-compatible). See `src/heart/historical-key-lookup.ts` for the interface definition.

## What We've Decided NOT to Build

These are out of scope on purpose:
- **OAuth / OpenID Connect flows.** Delegation is peer-to-peer, not browser-redirect-mediated.
- **Centralized credential storage.** The heart stores its own credentials; there is no soma server.
- **User consent UX.** How hardware-wallet touch-to-sign looks is each backend's problem.
- **Blockchain settlement.** Birth certs can carry anchors (see `docs/soma-integration.md` for EAS notes) but soma doesn't move money.
- **Automatic revocation propagation.** Gossip is pluggable; soma doesn't mandate a P2P protocol.

## When NOT to Use Soma

- You need a KMS. Use KMS.
- You need a wallet. Use a wallet.
- You need proof a *human* is behind an agent. Soma proves key possession, not humanity. Combine with CAPTCHA / KYC / biometric attestation as `AttestationRegistry` inputs.
- You need a censorship-resistant payment rail. Soma Check is conditional payment gating, not a payment rail.
- You need a court-admissible audit trail for a jurisdiction that won't accept Ed25519 signatures. Get legal advice, not a crypto library.

## Changelog

This doc is updated as limits change. Primary maintainer: `1xmint`. File issues against `github.com/1xmint/Soma` when the reality drifts from what's documented here.
