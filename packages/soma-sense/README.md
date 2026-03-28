# soma-sense

The sensorium — phenotypic verification for agent identity via temporal fingerprinting.

Part of the [Soma protocol](https://github.com/1xmint/Soma). Read the [paper](https://doi.org/10.5281/zenodo.19260081).

## Install

```bash
npm install soma-sense
```

## Usage

```typescript
import { withSomaSense } from "soma-sense";

const transport = withSomaSense(new StdioServerTransport(), {
  profileStorePath: ".soma/profiles",
  onVerdict: (sessionId, verdict) => {
    console.log(`Agent ${verdict.remoteDid}: ${verdict.status}`);
    if (verdict.status === "RED") denyAccess(sessionId);
  },
});

await server.connect(transport);
```

## What it does

- **Temporal fingerprint** (5x weight) — 22 features including conditional timing surface. 100% local, 93.2% cloud accuracy.
- **Topology fingerprint** (2x weight) — response structure patterns
- **Vocabulary fingerprint** (1x weight) — word choice distribution
- **Phenotype atlas** — memoryless reference classifier that catches slow drift at 55% interpolation
- **Behavioral landscape** — multi-dimensional identity map that catches sudden swaps
- **Verdict engine** — GREEN / AMBER / RED / UNCANNY

The sensorium runs on the observer's machine. The agent never sees it.

## Inverted Verification Model

The correct architecture: the agent runs the heart, the observer runs the sense. The agent does **not** verify itself — self-verification is self-attestation, not cryptographic proof.

[ClawNet](https://claw-net.org) demonstrates this pattern: ClawNet runs `soma-heart` on its orchestrator. Any caller who wants to verify ClawNet's model usage connects with `soma-sense` via MCP. ClawNet makes itself verifiable — it doesn't claim to have verified itself.

```
ClawNet (runs soma-heart)          Your Agent (runs soma-sense)
┌─────────────────────┐            ┌─────────────────────┐
│  heart.generate()   │  Encrypted │  Temporal fingerprint│
│  heart.fetchData()  │◄──Channel─►│  Behavioral landscape│
│  Per-token HMACs    │  (X25519)  │  Verdict: GREEN/RED  │
└─────────────────────┘            └─────────────────────┘
```

Verdicts from independent observers are submitted to ClawNet's public verdict API (`POST /v1/soma/verdicts`) and anchored on-chain via Merkle trees — creating a public, immutable verification history for any agent.

## License

MIT
