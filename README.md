# Soma

Cryptographic trust protocol for the agent-native internet.

Soma provides identity, delegation, spend tracking, and provenance for AI agents and humans. It is not a competing social or identity protocol — it is a **trust layer** that adds cryptographic provenance to existing protocols (AT Protocol, MCP, A2A, ActivityPub).

## What Soma Does

- **Identity** — Ed25519 keypairs, `did:key` identifiers
- **Delegation** — Capability tokens with caveats (ExpiresAt, Budget, MaxInvocations, HostAllowlist, Capabilities, Audience)
- **Spend receipts** — Cryptographic proof of resource consumption
- **Heartbeat chains** — Liveness proofs for agents and nodes
- **Invocation tracking** — Per-delegation usage accounting
- **Revocation** — Persistent delegation revocation with transparency

## Implementations

### Rust (reference implementation)

```bash
cargo add soma
```

Source: [`src/`](src/) | 1,800 lines | Zero platform dependencies

### TypeScript (v1, archived)

The original TypeScript implementation is preserved in [`archive/v1-typescript/`](archive/v1-typescript/).

## Protocol Specs

- [Delegation](spec/SOMA-DELEGATION-SPEC.md)
- [Capabilities](spec/SOMA-CAPABILITIES-SPEC.md)
- [Check](spec/SOMA-CHECK-SPEC.md)
- [Heart Certificate](spec/SOMA-HEART-CERTIFICATE-SPEC.md)
- [Rotation](spec/SOMA-ROTATION-SPEC.md)

## Test Vectors

Protocol conformance test vectors: [`test-vectors/`](test-vectors/)

## Paper

[soma-paper.pdf](soma-paper.pdf)

## Architecture

Soma is the trust layer for the HeyVera platform, but has **zero platform dependencies**. Anyone can `cargo add soma` and build on the protocol.

```
Soma signs:
├── AT Protocol posts      — provenance for social content
├── MCP tool calls         — delegation for agent-tool interactions
├── A2A agent messages     — trust for agent-to-agent collaboration
├── ActivityPub activities — provenance for federated social
├── Marketplace purchases  — receipts for commerce
├── Worker executions      — spend proofs for orchestration
└── Heartbeat chains       — liveness proofs for agents
```

## License

MIT OR Apache-2.0
