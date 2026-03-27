# Soma: Identity as Execution in Autonomous Agent Systems

**Every existing agent identity system has a gap: the agent computes, and then separately, a credential proves who computed. Soma eliminates that gap by making identity inseparable from computation.**

> **[Read the paper (PDF)](soma-paper.pdf)**

---

## The Problem

An operator commits to running Claude Sonnet. They secretly substitute GPT-4o-mini to save on inference costs. Every credential check passes. Every API key is valid. The fraud is invisible.

This isn't hypothetical. 80% of AI agents don't properly identify themselves. 44% of organizations authenticate agents with static API keys. The gap between computation and identity is where all agent fraud lives.

## The Solution

Soma is not a wrapper that watches agents. Soma **is** the execution pathway. The agent's API keys, tool credentials, and data connections live inside the heart. The only way to call the model is through the heart. The only way to use tools is through the heart. No heart, no credentials, no computation. The agent dies without it.

```
AGENT MACHINE                          OBSERVER MACHINE
┌─────────────────────┐                ┌─────────────────────┐
│  soma-heart          │               │  soma-sense          │
│                      │               │                      │
│  Credential Vault    │               │  3 Senses (weighted) │
│  Per-Token HMAC      │   Encrypted   │  Behavioral Landscape│
│  Heartbeat Chain     │◄──Channel────►│  Phenotype Atlas     │
│  Birth Certificates  │   (X25519 +   │  Seed Verification   │
│  generate()          │   secretbox)  │  Heartbeat Validation│
│  callTool()          │               │  Verdict: GREEN/RED  │
│  fetchData()         │               │                      │
└─────────────────────┘                └─────────────────────┘
```

## Three Layers

**Layer 1 -- The Heart (Process Integrity)**
An execution runtime that holds all credentials internally. Every token carries an HMAC-SHA256 proof. Every data source gets a co-signed birth certificate. A hash chain records every computational step.

**Layer 2 -- The Sensorium (Model Verification)**
Temporal fingerprinting verifies the model inside the heart matches the genome commitment. 100% accuracy on local hardware. 93.2% across cloud APIs. The sensorium runs on the observer's machine -- the agent never sees it.

**Layer 3 -- Birth Certificates (Data Provenance)**
When data enters the system, the heart seals it. For hearted-to-hearted flows, both parties co-sign. Dishonesty requires collusion, not just deception.

## Results

| Metric | Result |
|---|---|
| Local classification (5 models, same GPU) | **100.0%** |
| Cloud classification (11 agents, 4 providers) | **93.2%** |
| Deployment identity (same model, different infra) | **100.0%** |
| Security attacks detected | **8/8** |
| Slow drift detection threshold | **55%** (atlas, memoryless) |
| Seed enumeration (10K attempts) | **0 matches** |
| HMAC overhead per token | **3.4--5.4 microseconds** |
| Tests passing | **377** |

## Quick Start

```bash
# Install
pnpm install

# Run tests
pnpm test

# Run the security harness (8 attacks)
pnpm test -- tests/experiment/security/harness.test.ts
```

### Heart (Agent Side)

```typescript
import { createSomaHeart } from "soma/heart";

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

### Sensorium (Observer Side)

```typescript
import { withSomaSense } from "soma/sense";

const transport = withSomaSense(new StdioServerTransport(), {
  onVerdict: (sessionId, verdict) => {
    if (verdict.status === "RED") denyAccess(sessionId);
  },
});

await server.connect(transport);
```

## Architecture

```
soma/
├── src/
│   ├── core/               # Cryptographic foundations (genome, channel, crypto-provider)
│   ├── heart/              # The heart -- execution runtime
│   │   ├── runtime.ts      # generate(), callTool(), fetchData()
│   │   ├── seed.ts         # Dynamic seed generation (HKDF + 3D behavioral space)
│   │   ├── heartbeat.ts    # Tamper-evident hash chain
│   │   ├── birth-certificate.ts  # Data provenance with co-signing
│   │   └── credential-vault.ts   # Encrypted credential storage
│   ├── sensorium/          # The senses -- model verification
│   │   ├── senses/
│   │   │   ├── temporal.ts # PRIMARY: 22 features, 5x weight, 100% local accuracy
│   │   │   ├── topology.ts # Response structure, 2x weight
│   │   │   ├── vocabulary.ts # Word choice distribution, 1x weight
│   │   │   └── logprob.ts # When API supports it
│   │   ├── atlas.ts        # Phenotype atlas -- memoryless reference classifier
│   │   ├── matcher.ts      # Verdict engine (GREEN/AMBER/RED/UNCANNY)
│   │   └── landscape.ts    # Behavioral landscape -- multi-dimensional identity map
│   ├── mcp/                # MCP integration (transport, session, types)
│   └── experiment/         # Experiment infrastructure + security harness
│       └── security/
│           └── attacks/    # 8 attack implementations (all detected)
├── tests/                  # 377 tests across 27 files
├── results/                # Experiment data
└── soma-paper.pdf          # The paper
```

## Security

8 implemented attacks, all detected:

| # | Attack | Method | Detection |
|---|---|---|---|
| 1 | Impersonation | Claim Claude, run GPT | Phenotype mismatch |
| 2 | Replay | Record and replay tokens | Wrong HMAC counter |
| 3 | Signal Injection | Cheap model + fake delays | Entropic fingerprint |
| 4 | Timing Manipulation | Proxy with timing changes | Chunk boundary disruption |
| 5 | Composite Agent | Different models per task | Cross-category instability |
| 6 | Seed Prediction | Enumerate seed space | 0/10K exact matches |
| 7 | Slow Drift | Gradual model substitution | Atlas catches at 55% |
| 8 | Mutation Abuse | 10 rapid mutations | 10/10 fail consistency |

3 additional attacks architecturally prevented: birth certificate forgery (co-signing), model distillation (conditional timing surface + HMAC), channel downgrade (DID authentication required).

## Key Insight

The temporal fingerprint -- token-by-token timing -- is the model's heartbeat. On controlled hardware (same GPU, same server), it achieves **perfect classification** across 5 different model architectures. The timing differences come from the model weights, not the infrastructure. You cannot produce Claude's rhythm without running Claude's inference.

On cloud APIs, the same signal achieves 93.2% accuracy across 11 agents. The conditional timing surface (timing conditioned on context, sentence boundaries, reasoning phase) adds 1.9 percentage points over aggregate statistics -- a cloud robustness improvement that earns its keep where infrastructure variance adds noise.

## Tech Stack

- **TypeScript** (strict mode, no `any`)
- **Node.js** >= 18
- **pnpm** package manager
- **tweetnacl** -- Ed25519 + X25519 (zero-dependency, audited)
- **@modelcontextprotocol/sdk** -- official MCP SDK
- **vitest** -- testing
- Built on the **Model Context Protocol**

## License

MIT

## Citation

```bibtex
@article{fair2025soma,
  title={Soma: Identity as Execution in Autonomous Agent Systems},
  author={Fair, Joshua},
  year={2025}
}
```
