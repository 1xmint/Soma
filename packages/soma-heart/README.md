# soma-heart

The heart of agent identity — an execution runtime that makes identity inseparable from computation.

Part of the [Soma protocol](https://github.com/1xmint/Soma). Read the [paper](https://doi.org/10.5281/zenodo.19260081).

## Install

```bash
npm install soma-heart
```

## Usage

```typescript
import { createSomaHeart } from "soma-heart";
import { createGenome, commitGenome } from "soma-heart/core";

// Build a genome (agent identity blueprint)
const genome = createGenome({
  modelProvider: "anthropic",
  modelId: "claude-sonnet-4",
  modelVersion: "1.0.0",
  systemPrompt: "You are a helpful assistant",
  toolManifest: "search,database",
  runtimeId: "my-agent",
  cloudProvider: "aws",
  region: "us-east-1",
  deploymentTier: "tier1",
});

// Commit the genome with your Ed25519 signing key
const commitment = commitGenome(genome, signingKeyPair);

// Create the heart
const heart = createSomaHeart({
  genome: commitment,
  signingKeyPair: keyPair,
  modelApiKey: process.env.ANTHROPIC_API_KEY,
  modelBaseUrl: "https://api.anthropic.com/v1",
  modelId: "claude-sonnet-4",
});

// All computation goes through the heart
const stream = heart.generate({ messages: [...] });
const toolResult = await heart.callTool("database", args, executor);
const data = await heart.fetchData("market-api", "query", fetcher);
```

## Exports

| Import path | What |
|---|---|
| `soma-heart` | `createSomaHeart`, `HeartRuntime`, `BirthCertificate`, heartbeat chain |
| `soma-heart/core` | `createGenome`, `commitGenome`, genome types |

## What it does

- **Per-token HMAC authentication** — every token carries cryptographic proof it passed through this heart
- **Dynamic seed generation** — continuous behavioral parameter space (HKDF-derived) makes enumeration infeasible
- **Heartbeat chain** — tamper-evident hash chain recording every computational step
- **Birth certificates** — co-signed data provenance for hearted-to-hearted flows
- **Credential vault** — API keys and tool credentials are only accessible through generate/callTool/fetchData

The agent cannot compute without the heart. No heart, no credentials, no computation.

## Real-World Usage

[ClawNet](https://claw-net.org) uses `soma-heart` to provide cryptographic provenance on every x402 API call. Every outbound data fetch goes through `heart.fetchData()`, producing a birth certificate (data hash + Ed25519 signature + heartbeat chain entry). These are surfaced as `X-Soma-*` response headers — a provenance standard for the x402 ecosystem.

```typescript
// ClawNet's integration pattern (simplified)
import { getHeart } from './core/soma';

const result = await heart.fetchData('upstream-api', query, async (url, headers) => {
  return await x402Client.fetch(url, { headers });
});
// result.birthCertificate is automatically attached to the response
```

See the [Production section](https://github.com/1xmint/Soma#production) in the main README for the full integration story.

## License

MIT
