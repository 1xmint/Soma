# soma-heart

**The Soma trust machine for AI agents — one package, everything.**

Execution heart (runner) + sensorium (observer) + MCP middleware, unified
in a single install. The heart is the beating core of the Soma protocol:
every function — identity, signing, heartbeat chain, birth certificates,
credential rotation, session-mode consent ceremonies, phenotypic
verification — runs through it.

Part of the [Soma protocol](https://github.com/1xmint/Soma). Read the
[paper](https://doi.org/10.5281/zenodo.19260081).

## Install

```bash
npm install soma-heart
```

> Previously Soma shipped as two packages (`soma-heart` + `soma-sense`).
> As of **0.3.0** they are unified under `soma-heart`. The `soma-sense`
> package is deprecated — import from `soma-heart/sense` instead. See
> [CHANGELOG.md](https://github.com/1xmint/Soma/blob/main/CHANGELOG.md).

## Usage — runner

```typescript
import { createSomaHeart } from 'soma-heart';
import { createGenome, commitGenome } from 'soma-heart/core';

const genome = createGenome({
  modelProvider: 'anthropic',
  modelId: 'claude-sonnet-4',
  modelVersion: '1.0.0',
  systemPrompt: 'You are a helpful assistant',
  toolManifest: 'search,database',
  runtimeId: 'my-agent',
  cloudProvider: 'aws',
  region: 'us-east-1',
  deploymentTier: 'tier1',
});

const commitment = commitGenome(genome, signingKeyPair);

const heart = createSomaHeart({
  genome: commitment,
  signingKeyPair: keyPair,
  modelApiKey: process.env.ANTHROPIC_API_KEY,
  modelBaseUrl: 'https://api.anthropic.com/v1',
  modelId: 'claude-sonnet-4',
});

const stream = heart.generate({ messages: [...] });
const toolResult = await heart.callTool('database', args, executor);
const data = await heart.fetchData('market-api', 'query', fetcher);
```

## Usage — observer (sense)

```typescript
import { withSomaSense } from 'soma-heart/sense';

const transport = withSomaSense(new StdioServerTransport(), {
  profileStorePath: '.soma/profiles',
  onVerdict: (sessionId, verdict) => {
    if (verdict.status === 'RED') denyAccess(sessionId);
  },
});

await server.connect(transport);
```

## Subpath exports

| Import path                      | What                                                                                             |
| -------------------------------- | ------------------------------------------------------------------------------------------------ |
| `soma-heart`                     | `createSomaHeart`, `HeartRuntime`, `BirthCertificate`, heartbeat chain, delegation, session mode |
| `soma-heart/core`                | `createGenome`, `commitGenome`, genome types                                                     |
| `soma-heart/credential-rotation` | 12-invariant credential rotation controller + Ed25519 identity backend                           |
| `soma-heart/crypto-provider`     | Pluggable crypto provider (Ed25519 / X25519 / HKDF primitives)                                   |
| `soma-heart/sense`               | `withSomaSense`, sensorium entry — phenotypic verification                                       |
| `soma-heart/senses`              | Individual sense modules (temporal, topology, vocabulary, …)                                     |
| `soma-heart/atlas`               | Phenotype atlas reference classifier                                                             |
| `soma-heart/mcp`                 | MCP middleware (`withSoma`, Soma transport, profile store)                                       |
| `soma-heart/signals`             | Shared signal primitive types                                                                    |

Tree-shaking is free: import only the subpath you need and your bundler
drops everything else.

## What it does

### Runner (heart)

- **Per-token HMAC authentication** — every token carries cryptographic proof it passed through this heart
- **Dynamic seed generation** — continuous behavioral parameter space (HKDF-derived) makes enumeration infeasible
- **Heartbeat chain** — tamper-evident hash chain recording every computational step
- **Birth certificates** — co-signed data provenance for hearted-to-hearted flows
- **Credential vault** — API keys and tool credentials are only accessible through `generate` / `callTool` / `fetchData`
- **Credential rotation** — 12-invariant controller with KERI pre-rotation and pluggable backends
- **Session mode** — signed human-consent envelope binding agent ephemeral DID to a human durable DID under a bounded capability envelope

### Observer (sense)

- **Temporal fingerprint** (5× weight) — 22 features including conditional timing surface. 100% local, 93.2% cloud accuracy.
- **Topology fingerprint** (2× weight) — response structure patterns
- **Vocabulary fingerprint** (1× weight) — word choice distribution
- **Phenotype atlas** — memoryless reference classifier that catches slow drift at 55% interpolation
- **Behavioral landscape** — multi-dimensional identity map that catches sudden swaps
- **Verdict engine** — GREEN / AMBER / RED / UNCANNY

## Inverted verification model

The agent runs the heart, the observer runs the sense. The agent does
**not** verify itself — self-verification is self-attestation, not
cryptographic proof. The unified package ships both sides so integrators
can install one dependency and wire whichever half they own.

[ClawNet](https://claw-net.org) demonstrates this pattern: ClawNet runs
the heart on its orchestrator and exposes `soma-heart/sense` over MCP
for any caller who wants to verify. ClawNet makes itself verifiable — it
doesn't claim to have verified itself.

```
ClawNet (imports soma-heart)       Your Agent (imports soma-heart/sense)
┌─────────────────────┐            ┌─────────────────────┐
│  heart.generate()   │  Encrypted │  Temporal fingerprint│
│  heart.fetchData()  │◄──Channel─►│  Behavioral landscape│
│  Per-token HMACs    │  (X25519)  │  Verdict: GREEN/RED  │
└─────────────────────┘            └─────────────────────┘
```

Verdicts from independent observers are submitted to ClawNet's public
verdict API (`POST /v1/soma/verdicts`) and anchored on-chain via Merkle
trees — creating a public, immutable verification history for any agent.

## License

MIT
