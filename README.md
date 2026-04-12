# Soma: Identity as Execution in Autonomous Agent Systems

[![Cryptographic Agent Identity](https://img.shields.io/badge/agent_identity-cryptographic_execution_proof-8b5cf6)](https://github.com/1xmint/Soma)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19260081.svg)](https://doi.org/10.5281/zenodo.19260081)
[![npm: soma-heart](https://img.shields.io/npm/v/soma-heart?label=soma-heart&color=238636)](https://www.npmjs.com/package/soma-heart)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Every existing agent identity system has a gap: the agent computes, and then separately, a credential proves who computed. Soma eliminates that gap by making identity inseparable from computation.**

> **Paper:** [Soma: Identity as Execution in Autonomous Agent Systems](https://doi.org/10.5281/zenodo.19260081) | [PDF](soma-paper.pdf)

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

| Metric                                            | Result                      |
| ------------------------------------------------- | --------------------------- |
| Local classification (5 models, same GPU)         | **100.0%**                  |
| Cloud classification (11 agents, 4 providers)     | **93.2%**                   |
| Deployment identity (same model, different infra) | **100.0%**                  |
| Security attacks detected                         | **8/8**                     |
| Slow drift detection threshold                    | **55%** (atlas, memoryless) |
| Seed enumeration (10K attempts)                   | **0 matches**               |
| HMAC overhead per token                           | **3.4--5.4 microseconds**   |
| Tests passing                                     | **412**                     |

## Production

Soma is running in production on [ClawNet](https://claw-net.org) — the first AI agent orchestrator that makes itself cryptographically verifiable.

**On-chain identity:** Soma is registered on Base Mainnet via [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (agentId [37696](https://basescan.org/nft/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432/37696)).

**How it works in practice:** ClawNet runs `soma-heart`. Every outbound API call gets a birth certificate. Every orchestration response includes `X-Soma-*` provenance headers so any x402 client can verify data origin without parsing the response body:

```
X-Soma-Protocol: soma/1.0
X-Soma-Data-Hash: <sha256 of response data>
X-Soma-Signature: <ed25519 signature>
X-Soma-Heartbeat-Index: <sequence in chain>
X-Soma-Genome-Hash: <genome commitment hash>
X-Soma-Public-Key: <hex ed25519 public key>
X-Soma-Discovery: /.well-known/soma.json
```

**Verification verdicts anchored on-chain:** Observers running `soma-heart/sense` submit verdicts to ClawNet's public API. Verdicts are Merkle-tree-anchored on Solana, creating an immutable verification history for any agent. Public trust query: `GET /v1/soma/:did/trust`.

**Soma Receipt Layer:** Every paid ClawNet interaction produces a cryptographically signed Soma Receipt — an EAS (Ethereum Attestation Service) attestation on Base binding payment proof + request hash + response hash + data provenance. Receipts are verifiable on [base.easscan.org](https://base.easscan.org), via `GET /v1/soma/receipt/:id`, or offline using `soma-heart/sense`:

```typescript
import { verifyClawNetReceipt } from 'soma-heart/sense';

const result = verifyClawNetReceipt(receiptJson, {
  publicKeyMultibase: 'z6Mk...', // from /.well-known/soma.json
});
console.log(result.valid); // true — receipt is authentic
```

**Architectural principle:** ClawNet runs the heart. Callers run the sense. The orchestrator does not verify itself — that would be self-attestation, not cryptographic verification. The observer must always be a separate party.

## Multi-Agent Primitives

Soma is designed for agent-to-agent trust: one heart forks another, delegates a capability, and can revoke it later. Every primitive is a signed, auditable event.

**Fork a child heart with narrowed capabilities:**

```typescript
import { createSomaHeart } from 'soma-heart';

const parent = createSomaHeart({
  /* config */
});

// Fork: parent signs a lineage cert binding child identity
const { childKeyPair, childGenome, childLineage } = parent.fork({
  systemPrompt: 'You handle price lookups only.',
  toolManifest: '["price"]',
  capabilities: ['tool:price'], // narrowed
  ttl: 15 * 60_000, // 15 minutes
  budgetCredits: 1000,
});

// Child boots with the signed lineage — capability enforcement is automatic
const child = createSomaHeart({
  genome: childGenome,
  signingKeyPair: childKeyPair,
  modelApiKey: '...',
  modelBaseUrl: 'https://api.openai.com/v1',
  modelId: 'gpt-4o-mini',
  lineage: childLineage,
});

await child.callTool('price', { symbol: 'BTC' }, fn); // ✓ allowed
await child.callTool('db', { query: '...' }, fn); // ✗ throws
```

**Delegate a capability (macaroons-style):**

```typescript
const delegation = heart.delegate({
  subjectDid: 'did:key:zOtherAgent',
  capabilities: ['tool:search'],
  caveats: [
    { kind: 'expires-at', timestamp: Date.now() + 3600_000 },
    { kind: 'max-invocations', count: 100 },
    { kind: 'budget', credits: 500 },
  ],
});
```

**Revoke when things go wrong:**

```typescript
const event = heart.revoke({
  targetId: delegation.id,
  targetKind: 'delegation',
  reason: 'compromised',
});
// Broadcast `event` to other parties; anyone can verify + honor it.
```

**Persist a heart across restarts:**

```typescript
// Shutdown
const blob = heart.serialize('correct-horse-battery-staple');
fs.writeFileSync('./heart.enc', blob);

// Startup — same DID, same credentials, continuous heartbeat chain
import { loadSomaHeart } from 'soma-heart';
const heart = loadSomaHeart(fs.readFileSync('./heart.enc', 'utf8'), 'correct-horse-battery-staple');
```

Under the hood: lineage certs are signed Ed25519 blobs with parent→child binding. Delegations carry caveats verified at invocation. Revocations are signed, broadcastable events. Persistence uses PBKDF2-SHA256 (210k iterations) + XSalsa20-Poly1305.

**Wire-level spec:** [SOMA-DELEGATION-SPEC.md](SOMA-DELEGATION-SPEC.md) (v0.1) formalizes how these library primitives are expressed over HTTP — `X-Soma-Delegation-*` headers, depth limits, scope narrowing, spend + branch caps, cascade revoke, intent declaration. The first standard with **spend-bounded delegation + cascade revoke + intent declaration** as first-class primitives.

## Soma Check — Conditional Payment Protocol

The first conditional payment protocol for APIs. Agents check a content hash before paying — if data hasn't changed, they pay nothing. Built on the birth-certificate `dataHash`, so the primitive that proves _provenance_ also drives _change detection_. No other payment protocol (x402, ACP, AP2, L402) has this.

**Spec:** [SOMA-CHECK-SPEC.md](SOMA-CHECK-SPEC.md) (v1.0)

**Consumer side — drop-in fetch replacement:**

```typescript
import { createSmartFetch } from 'soma-heart/sense';

const sfetch = createSmartFetch();

// First call — normal paid fetch
const r1 = await sfetch('https://api.example.com/price?symbol=BTC');

// Second call — automatically sends If-Soma-Hash
// If data unchanged, returns cached body at zero cost
const r2 = await sfetch('https://api.example.com/price?symbol=BTC');
if (r2.somaCheck?.unchanged) {
  const price = r2.somaCheck.cachedBody; // 0 credits charged
}
```

**Provider side — decide in one line:**

```typescript
import {
  extractIfSomaHash,
  shouldRespondUnchanged,
  buildSomaCheckResponseHeaders,
  buildUnchangedResponse,
} from 'soma-heart';

app.post('/endpoint', (req, res) => {
  const incomingHash = extractIfSomaHash(req.headers);
  const currentHash = cache.getHash(req.url);

  for (const [k, v] of Object.entries(buildSomaCheckResponseHeaders(currentHash))) {
    res.setHeader(k, v);
  }

  if (shouldRespondUnchanged(incomingHash, currentHash)) {
    return res.json(buildUnchangedResponse(currentHash, { fresh: true, age: 42 }));
  }
  // ...normal paid flow
});
```

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
import { createSomaHeart } from "soma-heart";

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
import { withSomaSense } from 'soma-heart/sense';

const transport = withSomaSense(new StdioServerTransport(), {
  onVerdict: (sessionId, verdict) => {
    if (verdict.status === 'RED') denyAccess(sessionId);
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
│   │   ├── runtime.ts      # generate(), callTool(), fetchData(), fork(), delegate(), revoke(), serialize()
│   │   ├── seed.ts         # Dynamic seed generation (HKDF + 3D behavioral space)
│   │   ├── heartbeat.ts    # Tamper-evident hash chain
│   │   ├── birth-certificate.ts  # Data provenance with co-signing
│   │   ├── credential-vault.ts   # Encrypted credential storage
│   │   ├── lineage.ts            # Parent-child heart certs
│   │   ├── delegation.ts         # Macaroons-style capability tokens
│   │   ├── revocation.ts         # Signed revocation events + registry
│   │   └── persistence.ts        # Password-encrypted heart state
│   ├── sensorium/          # The senses -- model verification
│   │   ├── senses/
│   │   │   ├── temporal.ts # PRIMARY: 22 features, 5x weight, 100% local accuracy
│   │   │   ├── topology.ts # Response structure, 2x weight
│   │   │   ├── vocabulary.ts # Word choice distribution, 1x weight
│   │   │   └── logprob.ts # When API supports it
│   │   ├── atlas.ts        # Phenotype atlas -- memoryless reference classifier
│   │   ├── matcher.ts      # Verdict engine (GREEN/AMBER/RED/UNCANNY)
│   │   ├── landscape.ts    # Behavioral landscape -- multi-dimensional identity map
│   │   └── receipt-verifier.ts # Offline ClawNet Soma Receipt verification
│   ├── mcp/                # MCP integration (transport, session, types)
│   └── experiment/         # Experiment infrastructure + security harness
│       └── security/
│           └── attacks/    # 8 attack implementations (all detected)
├── tests/                  # 412 tests across 32 files
├── results/                # Experiment data
└── soma-paper.pdf          # The paper
```

## Security

8 implemented attacks, all detected:

| #   | Attack              | Method                     | Detection                  |
| --- | ------------------- | -------------------------- | -------------------------- |
| 1   | Impersonation       | Claim Claude, run GPT      | Phenotype mismatch         |
| 2   | Replay              | Record and replay tokens   | Wrong HMAC counter         |
| 3   | Signal Injection    | Cheap model + fake delays  | Entropic fingerprint       |
| 4   | Timing Manipulation | Proxy with timing changes  | Chunk boundary disruption  |
| 5   | Composite Agent     | Different models per task  | Cross-category instability |
| 6   | Seed Prediction     | Enumerate seed space       | 0/10K exact matches        |
| 7   | Slow Drift          | Gradual model substitution | Atlas catches at 55%       |
| 8   | Mutation Abuse      | 10 rapid mutations         | 10/10 fail consistency     |

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
@article{fair2026soma,
  title={Soma: Identity as Execution in Autonomous Agent Systems},
  author={Fair, Joshua},
  year={2026},
  doi={10.5281/zenodo.19260081}
}
```
