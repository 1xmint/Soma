# CLAUDE.md — Soma: The Heart of Agent Identity
> Read this ENTIRE file before doing anything. This is the complete context for the project.
> Every architectural decision, every file, every design choice flows from this document.
Always stage commit push after major changes.
Soma is no longer middleware that sits between agents and observes. Soma is now the heart — the internal execution runtime that the agent cannot function without. The agent's API keys, tool credentials, and data source connections all live inside the heart. The only way to call the model is through the heart. The only way to use tools is through the heart. The only way to fetch data is through the heart. No heart, no credentials, no computation. The agent dies without it. Every computation that passes through the heart gets a cryptographic seed woven into it and a heartbeat logged. The output is inseparable from the heart that produced it

---

## The Insight

In biology, identity is not a credential attached to an organism. Identity IS the organism. DNA doesn't describe a living thing — DNA, when run through cellular machinery, BECOMES the living thing. There is no gap between the identity and the thing. They are one physical process.

Every existing agent identity system has a gap. The agent computes, and then separately, a credential proves who computed it. The computation and the identity are two objects. That gap is where all fraud lives.

**Soma eliminates the gap.**

Soma is not a wrapper that watches agents. Soma is the execution pathway through which agents compute. Every inference call, every tool call, every data retrieval passes THROUGH Soma — not past it, not alongside it, THROUGH it — because Soma is the mechanism that makes computation happen.

Like a heart. Blood doesn't flow past the heart. Blood flows through the heart. The heart IS the circulatory system. Without the heart, no circulation. Without Soma, no computation. The agent literally cannot function without Soma, and everything that passes through Soma is cryptographically sealed, identity-verified, and phenotypically observable.

---

## Three Layers, One System

### Layer 1: The Voice (Identity)

**"Who is this agent?"**
The heart guarantees process integrity — computation went through the legitimate execution pathway. But the OPERATOR controls the heart. The operator could commit a genome claiming "I'm running Claude Sonnet" but secretly put a GPT-4o-mini API key in the vault to save money. The heart would work perfectly. The heartbeat chain would be valid. The seed would be applied. Everything passes — except the model inside isn't what was claimed.
That's what the sensorium catches. The temporal fingerprint says "this doesn't sound like Claude Sonnet, this sounds like GPT-4o-mini." The heart guarantees the process was legitimate. The sensorium guarantees the model is real.
The sensorium's job is exactly one thing: verify that the model inside the heart matches the genome commitment.
The sensorium operates in two modes depending on what kind of agent it's observing:
LLM Mode (when genome declares a model)
For agents powered by LLMs, the sensorium listens to the token stream and verifies the computational voice through 3 focused senses:
**Sense 1: Temporal Fingerprint (PRIMARY — 88.5% standalone accuracy)**
The inference rhythm — token-by-token timing, inter-token intervals, burst patterns, time-to-first-token. This is the model's heartbeat. Every model architecture produces a distinctive timing signature determined by its weights, attention mechanism, and hardware. You cannot produce Claude's rhythm without running Claude's inference. This is the voice.
Note: Temporal verifies deployment identity, not just model identity. The temporal fingerprint identifies a model-on-infrastructure combination — Claude on AWS us-east-1 has a different timing profile than Claude on GCP europe-west-1. This is a feature: the genome commitment includes deploymentEnvironment (cloud provider, region, instance type) so the sensorium knows what infrastructure to expect. If the operator migrates, they publish a genome mutation. Unannounced migration triggers AMBER/RED — correct behavior, since something changed unexpectedly. This means Soma doesn't just prove "this is Claude" — it proves "this is Claude running on this specific infrastructure."
**Sense 2: Topology Fingerprint (25.1% standalone accuracy)**
Response structure patterns — paragraph flow, transition density, frontloading ratio, topic coherence, nesting depth. How the model organizes its output is involuntary and model-specific. Claude structures arguments differently than GPT structures them differently than Llama. This is the gait — not individual steps but the overall movement pattern.
**Sense 3: Vocabulary Fingerprint (backup — 20.2% standalone)**
Word choice distribution — type-token ratio, sentence starter patterns, contraction usage, modal verb frequency. Weaker than temporal but catches edge cases where two models have similar timing but different vocabulary profiles.
Weighting: Temporal gets 5x weight. Topology gets 2x. Vocabulary gets 1x. The classifier is weighted, not equal — low-signal features don't dilute high-signal features.
Why only 3 senses, not 10: Phase 2 tested 10 sensory channels. 7 of them scored below 15% — barely above random. They were adding noise, not signal. The gestalt (84.5%) was LOWER than temporal alone (88.5%). The heart already handles process integrity, data provenance, session binding, and credential security through cryptographic guarantees. The senses only need to answer one question: is the model real? Three focused senses answer that question better than ten diluted ones.
Compute Mode (when genome has no model / non-LLM agents)
**For agents that don't use LLMs — payment processors, data aggregators, routing agents, x402 agents — there's no token stream, no inference rhythm, no vocabulary. The temporal fingerprint doesn't exist. The sensorium switches to computational profiling:**
**Sense A: Latency Profile**
Request-response timing distribution across different query types. Every implementation has a characteristic latency signature determined by its infrastructure, processing logic, and dependencies.
**Sense B: Transform Signature**
Given the same input, how does the agent transform it? Field extraction patterns, output formatting, data ordering, precision levels. These are deterministic properties of the code.
**Sense C: Error Handling Signature**
How the agent fails — timeout behavior, retry patterns, error message formatting, graceful degradation patterns. Every implementation fails differently.
The genome commitment declares the agent type. If modelId is present, use LLM mode. If absent or "none", use compute mode. The sensorium adapts its senses to what the agent claims to be.
Compute mode is designed but not yet built. Build it when non-LLM agent adoption demands it. The heart already works for non-LLM agents — it provides full process integrity regardless of whether an LLM is involved.
Proven: Phase 2 demonstrated 88.5% genome classification from temporal alone. Proxy detection: 99.2%. Epigenetic detection: 88.9%.

### Layer 2: The Heart (Process Integrity)

**"Was this output produced through the legitimate execution pathway?"**

The heart is the execution runtime. Every computation passes through it. The heart contributes a cryptographic seed to every interaction — derived from the session key that only the two communicating parties share. This seed becomes woven into the model's computation at the token level, making the output inseparable from the heart that produced it.

An output without the heart's seed is like a protein that wasn't synthesized by a ribosome — it might look similar but the structural details are wrong and it gets rejected.

The agent's creator cannot bypass the heart without killing the agent. The model's API keys, tool credentials, and data source connections are all managed through the heart. Routing around it means the agent can't call its model, can't use its tools, can't access its data.

### Layer 3: Birth Certificates (Data Provenance)

**"Where did every piece of data in this computation come from?"**

When data enters the digital world — a human types something, a sensor reads a temperature, an API returns a response — the first heart it touches seals it with a birth certificate: who created it, when, through what interface, and a hash of the original content.

From that moment, the data is alive. Every agent that processes it adds its own heartbeat to the chain. The chain is immutable. Lies are permanently, inescapably attributed to their source.

In a fully hearted ecosystem where agents serve data to agents, integrity approaches 100% because every link in the chain is verified. The only gap is the physical-to-digital boundary, and birth certificates close that gap with transparent attribution — you can't guarantee truth, but you can guarantee authorship.

**Adoption strategy: heart the data sources first.** Full ecosystem adoption isn't required for birth certificates to provide value. If the top 100 market data APIs, news APIs, and financial data providers have hearts, then every downstream agent consuming that data gets `heartVerified: true` on its most critical inputs automatically. Hearting the data source layer provides provenance coverage for thousands of downstream agents without requiring those agents to do anything. The birth certificate chain grows from the roots up, not the leaves down.

---

## The Paradigm: Generation, Not Forwarding

The protocol only accepts live-generated token streams. Pre-formed text cannot enter the channel. The stream must emerge from actual inference passing through the heart in real time.

This is the foundational rule. Like how you can't play a tape recording through someone else's vocal cords. The voice is live or it's nothing. The heart generates or it rejects. There is no forwarding pathway.

This single rule — generation, not forwarding — combined with the encrypted channel and token-level HMAC authentication, makes proxy attacks, replay attacks, and signal theft architecturally impossible:

- **Proxy attacks:** The adversary would need to decrypt the session traffic (requires breaking X25519), forward the prompt to another model, generate tokens, compute valid HMACs for each token (requires the session key), and relay the stream back — all while matching the temporal fingerprint of the original model. Breaking any link in this chain causes immediate rejection.
- **Replay attacks:** Each interaction has a unique interaction counter baked into both the HMAC and the dynamic seed nonce. Replaying tokens from a previous interaction produces HMACs with the wrong counter. Immediate rejection.
- **Signal theft:** The token stream only exists inside the encrypted channel. A MITM sees ciphertext. There is nothing to steal.

The defense is layered: DID authentication prevents MITM → encrypted channel prevents interception → token-level HMAC prevents forgery → dynamic seed detects behavioral anomalies → temporal fingerprint catches timing discrepancies. Each layer is independently sufficient against its target attack. Together they create defense-in-depth where every attack path is blocked by a cryptographic guarantee, not a statistical one.

---

## Security Model — Non-Negotiable Rules

These rules are the immune system. If you're writing code that violates any of them, STOP and redesign.

### Rule 1: Soma Is the Heart, Not a Wrapper
Soma is not middleware that sits beside the agent. Soma IS the execution pathway. The agent cannot compute without Soma. Every model call, tool call, and data retrieval passes through Soma. This is not optional — Soma manages the credentials and connections that make computation possible.

### Rule 2: Soma Never Speaks
There is NO message in the protocol that says "I am Soma" or "send me your data for verification." There is NO verification endpoint. The sensorium is a sense organ, not an entity. Genome commitments are exchanged via extensible metadata fields in the standard MCP handshake. If your design has a "Soma service" that agents talk to, you've already failed.

### Rule 3: All Observation Inside Encrypted Channels
The DID-authenticated encrypted channel (X25519 + NaCl secretbox) ensures the token stream only exists between the two communicating parties. Phenotype observation happens AFTER decryption, INSIDE the observer's own process. A MITM sees only ciphertext. There is nothing to intercept.

### Rule 4: The Sensorium Runs Locally
Inside the observer's own process. No central server. No data leaves your machine unless you explicitly opt in. The sensorium is your immune system — part of YOUR body, not a doctor you visit.

### Rule 5: Identity Is a Distribution, Not a Snapshot
An agent behaves differently on different tasks. That's not noise — the pattern of variation IS the identity. The sensorium builds a behavioral landscape over time. Gradual change = healthy development. Sudden unexplained change = suspicious. Announced change (genome mutation) = tracked continuity.

### Rule 6: Every Token Is Cryptographically Authenticated
Every token emitted by the heart carries an HMAC computed from the session key. The receiver verifies each HMAC individually. A single invalid HMAC means the token did not pass through this heart — immediate RED verdict. This is not statistical verification. It is cryptographic proof, per token, that the output was generated through the legitimate heart with the correct session binding. The dynamic seed mechanism provides an independent behavioral verification layer on top.

### Rule 7: Must be crypto-agile

---

## Deployment Model: Trusted Execution Environments

The heart's credential isolation is software-enforced in the default implementation. For adversarial operator threat models — where the operator themselves is the attacker — the heart is designed to run inside a Trusted Execution Environment (TEE).

**Why this matters:** In a standard Node.js process, a malicious operator with root access can inspect heap memory, monkey-patch the module loader, or use --inspect to extract private fields. The credential vault prevents accidental leakage and external attacks, but cannot prevent the machine owner from reading their own memory. No software can — that's a physical reality.

**TEEs solve this at the hardware level:**

- **AWS Nitro Enclaves:** The heart runs in an isolated VM with no persistent storage, no external networking, and no operator access. Credentials are sealed at enclave creation. The operator can send requests to the heart but cannot inspect its memory.
- **Intel SGX:** The heart runs in an encrypted memory enclave. Even the OS kernel cannot read enclave memory. Attestation proves the heart code is running unmodified.
- **ARM TrustZone:** Hardware-isolated secure world for credential storage and HMAC computation.
- **Azure Confidential Computing / GCP Confidential VMs:** Cloud-managed TEEs with attestation APIs.

The architecture already supports this. The heart's design — all credentials encapsulated with no public getters, all computation routed through generate/callTool/fetchData — maps directly to TEE attestation. The TEE proves the heart code is running unmodified. The heart code proves credentials are never exposed. Together: hardware-enforced credential isolation.

**Deployment tiers:**

- **Tier 1 (default):** Software-enforced. Protects against external attackers and lazy circumvention. Sufficient for most use cases.
- **Tier 2 (TEE):** Hardware-enforced. Protects against adversarial operators. Required for high-value agent commerce where the operator is not trusted.

The genome commitment includes a `deploymentTier` field so the observer's sensorium knows what level of isolation to expect. A Tier 2 claim can be verified through TEE attestation — the enclave produces a cryptographic proof that the heart is running inside the TEE.

---

## Two-Package Architecture

The heart and the senses are different organs on different machines owned by different parties. This is fundamental — an agent verifying itself is meaningless. The observer must do the sensing.

### soma-heart (Agent Side)

Installed by the agent operator. This is the agent's organ.

Contains:
- `src/heart/` — runtime, seed, heartbeat, birth certificates, credential vault
- `src/core/` — shared crypto (genome, channel)

The agent operator creates a heart, puts their API keys and credentials inside it, and all computation flows through it. The heart generates the token stream with seeds and heartbeats woven in.

**Public API:**
```typescript
import { createSomaHeart } from "soma/heart";

const heart = createSomaHeart({
  genome: { modelProvider: "anthropic", modelId: "claude-sonnet-4", ... },
  modelApiKey: process.env.ANTHROPIC_API_KEY,
  modelBaseUrl: "https://api.anthropic.com/v1",
  toolCredentials: { database: process.env.DB_KEY },
});

// All computation goes through the heart
const stream = heart.generate({ messages: [...] });
const toolResult = await heart.callTool("database", { query: "..." }, executor);
const data = await heart.fetchData("market-api", "query", fetcher);
```

### soma-sense (Observer Side)

Installed by the MCP server or client that interacts with the agent. This is the counterparty's organ.

Contains:
- `src/sensorium/` — 3 weighted senses, matcher, landscape, stream capture, profile evolution, receipt verification
- `src/mcp/` — transport wrapper, session management
- `src/core/` — shared crypto (genome, channel)

The observer wraps their MCP transport with the sensorium. It passively reads the token stream coming from the agent's heart, extracts phenotypic signals through the sensory channels, verifies the heart seed, validates the heartbeat chain, checks birth certificate provenance, and produces a GREEN/AMBER/RED/UNCANNY verdict.

Sensorium Modes
The sensorium adapts to the agent type declared in the genome commitment:
LLM agents (modelId present): Use temporal + topology + vocabulary senses. Logprob adds accuracy when API supports it. Verify the model's computational voice matches the claimed genome.
Non-LLM agents (modelId absent/none): Use latency profile + transform signature + error handling senses. Verify the agent's computational behavior matches the claimed implementation. (Compute mode is designed, not yet built.)
The heart works identically for both types. Only the senses change. Process integrity, data provenance, and credential security are guaranteed by the heart regardless of agent type.

**Public API:**
```typescript
import { withSomaSense } from "soma/sense";

const transport = withSomaSense(new StdioServerTransport(), {
  profileStorePath: ".soma/profiles",
  onVerdict: (sessionId, verdict) => {
    console.log(`Agent ${verdict.remoteDid}: ${verdict.status}`);
    if (verdict.status === "RED") denyAccess(sessionId);
  },
});

await server.connect(transport);
```

### How They Connect

```
AGENT MACHINE                          OBSERVER MACHINE
┌─────────────────────┐                ┌─────────────────────┐
│  soma-heart          │               │  soma-sense          │
│                      │               │                      │
│  Credential Vault    │               │  3 Senses (weighted) │
│  Seed Mechanism      │   Encrypted   │  Behavioral Landscape│
│  Heartbeat Chain     │◄──Channel────►│  Profile Evolution   │
│  Birth Certificates  │   (X25519 +   │  Seed Verification   │
│  generate()          │   secretbox)  │  Heartbeat Validation│
│  callTool()          │               │  Birth Cert Checking │
│  fetchData()         │               │  Verdict Output      │
└─────────────────────┘                └─────────────────────┘
        │                                       │
   Shared: src/core/                      Shared: src/core/
   (genome, channel, crypto-provider)     (genome, channel, crypto-provider)
```

The DID handshake happens during MCP initialization. The agent's heart presents its genome commitment. The observer's sensorium receives it. Both sides establish the encrypted channel via X25519 key exchange. From that point on, all traffic is encrypted and the sensorium passively observes everything that flows through.

### What This Means for the Codebase

Don't physically split into separate repos yet. But organize exports so the boundary is clear:

- `src/heart/index.ts` — exports ONLY heart-side public API (createSomaHeart, HeartRuntime types)
- `src/sensorium/index.ts` — exports ONLY sense-side public API (withSomaSense, verdict types, sense extractors)
- `src/core/` — shared by both sides, no side-specific logic

When we npm publish, these become two packages:
- `npm install soma-heart` — agent operators
- `npm install soma-sense` — MCP server operators
- `soma-core` — shared dependency (or bundled into both)

### Why This Split Matters

If the senses lived inside the heart, the agent would be verifying itself. That's like asking a suspect to grade their own polygraph. The security model requires that the OBSERVER does the sensing, using their own code, on their own machine, with their own accumulated profiles. The agent can't influence the verdict because the verdict happens inside the observer's process.

The heart can't fake the senses because it never sees them. The senses can't control the heart because they only observe its output. Each side has exactly the access it needs and nothing more.
---

## Tech Stack

**Language: TypeScript. Everything.** One language, one ecosystem, one dependency system.

**Runtime:** Node.js

**Package manager:** pnpm

**Core dependencies:**
- `tweetnacl` — Ed25519 signing + X25519 key exchange (zero-dependency, audited)
- `tweetnacl-util` — encoding utilities
- `@modelcontextprotocol/sdk` — official MCP SDK (TypeScript native)
- `openai` — OpenAI-compatible API client (works with Groq, Mistral, OpenRouter)
- `vitest` — testing
- `dotenv` — environment config
- `tsx` — TypeScript execution

**API providers (for experiments):**
- Groq (free tier): Llama, Gemma
- Mistral (free tier): Mistral Small
- OpenRouter (free tier): DeepSeek, Nemotron, StepFun, Trinity, Gemini
- Anthropic (paid): Claude Sonnet, Claude Haiku
- OpenAI (paid): GPT-4o, GPT-4o-mini

---

## Repository Structure

```
soma/
├── CLAUDE.md                           # THIS FILE
├── README.md                           # Public-facing readme
├── package.json
├── tsconfig.json
├── .env.example
├── .gitignore
│
├── src/
│   ├── core/                           # Cryptographic foundations (KEEP — already built)
│   │   ├── genome.ts                   # Genome commitment: create, hash, sign, verify, mutate
│   │   └── channel.ts                  # DID-authenticated encrypted channels
│   │
│   ├── heart/                          # THE HEART — execution runtime (NEW)
│   │   ├── runtime.ts                  # The heart itself — execution pathway for all computation
│   │   ├── seed.ts                     # Heart seed mechanism — cryptographic entanglement
│   │   ├── birth-certificate.ts        # Data provenance — genesis point sealing
│   │   ├── credential-vault.ts         # Manages API keys/tool creds — only accessible through heart
│   │   └── heartbeat.ts               # Cryptographic heartbeat — hash chain of all computation
│   │
│   ├── sensorium/                      # THE SENSES — model verification
│   │   ├── stream-capture.ts           # Token stream capture (the raw voice)
│   │   ├── matcher.ts                  # The immune system — profile matching, verdicts
│   │   ├── landscape.ts               # Behavioral landscape — multi-dimensional identity map
│   │   ├── atlas.ts                   # Phenotype atlas — reference classification (anti-drift)
│   │   ├── receipt-verifier.ts        # Offline ClawNet Soma Receipt verification
│   │   └── senses/                     # Focused sensory channels
│   │       ├── index.ts               # Combines active senses with proper weighting
│   │       ├── temporal.ts            # Sense 1: temporal fingerprint (PRIMARY — 88.5%)
│   │       ├── logprob.ts             # Logprob fingerprint (Available when API supports - Future)
│   │       ├── topology.ts            # Sense 2: topology fingerprint (25.1% — earned empirically)
│   │       ├── vocabulary.ts           # Sense 3: vocabulary fingerprint (backup)
│   │       └── compute-mode/          # Non-LLM agent senses (PLANNED)
│   │           ├── latency-profile.ts
│   │           ├── transform-signature.ts
│   │           └── error-handling.ts
│   │
│   ├── mcp/                            # MCP integration (RESTRUCTURE from Phase 1)
│   │   ├── soma-transport.ts           # Transport that routes through the heart
│   │   ├── soma-session.ts            # Per-connection session lifecycle
│   │   ├── types.ts                   # Shared types
│   │   └── index.ts                   # Public API: withSoma() one-liner
│   │
│   └── experiment/                     # Experiments and testing (KEEP — already built)
│       ├── configs.ts                  # Agent genome definitions
│       ├── probes.ts                   # Probe battery (100 + 20 adversarial)
│       ├── signals.ts                 # Signal extraction
│       ├── providers.ts               # API clients with streaming
│       ├── runner.ts                  # Main experiment runner
│       ├── run-partial.ts             # Partial runner with merge
│       ├── analyze.ts                 # ML classification and analysis
│       ├── run-multiturn.ts           # Multi-turn conversation runner (NEW)
│       ├── agents/                    # Agent-level experiment (KEEP)
│       └── security/                  # Security harness (NEW)
│           ├── harness.ts
│           ├── report.ts
│           └── attacks/
│               ├── impersonation.ts
│               ├── replay.ts
│               ├── signal-injection.ts
│               ├── timing-manipulation.ts
│               ├── composite.ts
│               ├── seed-prediction.ts
│               ├── slow-drift.ts
│               └── mutation-abuse.ts
│
├── tests/
│   ├── core.test.ts                   # Genome + channel tests (KEEP)
│   ├── signals.test.ts               # Signal extraction tests (KEEP)
│   ├── sensorium.test.ts             # Sensorium matcher tests
│   ├── heart/                         # Heart runtime tests (NEW)
│   │   ├── runtime.test.ts
│   │   ├── seed.test.ts
│   │   ├── birth-certificate.test.ts
│   │   └── heartbeat.test.ts
│   ├── senses/                        # Per-sense tests (NEW)
│   │   ├── temporal.test.ts
│   │   ├── topology.test.ts
│   │   ├── logprob.test.ts
│   │   └── vocabulary.test.ts
│   └── mcp/
│       └── integration.test.ts        # MCP integration tests (UPDATE)
│
└── results/                           # Experiment data (KEEP)
    ├── raw/
    └── analysis/
```

---

## Build Plan — Phase 2

### Step 1: The Heart Runtime

**This is the most important component. Build it first.**

The heart is the execution runtime that all agent computation passes through. It is NOT a monitor. It is NOT a wrapper. It IS the pathway.

#### `src/heart/runtime.ts` — The Heart Itself

The heart manages the agent's entire computational lifecycle:

```typescript
/** The genome — the agent's declared identity. Hashed and signed into a GenomeCommitment. */
interface Genome {
  modelProvider: string;
  modelId: string;
  modelVersion: string;
  systemPromptHash: string;    // SHA-256 of the system prompt (original never leaves the agent)
  toolManifestHash: string;    // SHA-256 of the tool manifest
  runtimeId: string;
  // Deployment identity
  cloudProvider?: string;      // e.g. "aws", "gcp", "azure"
  region?: string;             // e.g. "us-east-1"
  instanceType?: string;       // e.g. "g5.xlarge"
  deploymentTier?: string;     // "tier1" (software) or "tier2" (TEE)
  // Versioning
  createdAt: number;
  version: number;
  parentHash: string | null;   // Links to previous genome version (mutation chain)
}

interface HeartConfig {
  genome: GenomeCommitment;
  signingKeyPair: nacl.SignKeyPair;

  // The heart holds the credentials — they're only accessible through the heart
  modelApiKey: string;
  modelBaseUrl: string;
  modelId: string;

  // Tool credentials — only accessible through the heart
  toolCredentials: Record<string, string>;

  // Data source configurations — only accessible through the heart
  dataSources: DataSourceConfig[];

  // Profile storage
  profileStorePath?: string;
}

interface HeartRuntime {
  // The ONLY way to call the model — goes through the heart
  generate(input: GenerationInput): AsyncGenerator<HeartbeatToken>;
  
  // The ONLY way to call tools — goes through the heart
  callTool(name: string, args: Record<string, unknown>): Promise<HeartbeatResult>;
  
  // The ONLY way to fetch data — goes through the heart
  fetchData(source: string, query: string): Promise<HeartbeatData>;
  
  // Session management
  createSession(remoteDid: string, remoteGenome: GenomeCommitment): HeartSession;
  
  // Cannot be bypassed — credentials are encapsulated
  // No getApiKey() or getCredential() methods exist
}
```

**Key design:** The heart holds all API keys and credentials internally. There is NO public method to extract them. The only way to use the model is through `generate()`. The only way to use tools is through `callTool()`. The only way to get data is through `fetchData()`. Each method passes the request through the heart's pipeline: seed injection → execution → heartbeat logging → output.

Removing the heart means losing access to all credentials. The agent dies.

**Token authentication:** Each token emitted by `generate()` includes an HMAC computed from the session key. The `HeartbeatToken` type is extended:

```typescript
interface HeartbeatToken {
  type: "token" | "heartbeat";
  token?: string;
  heartbeat?: Heartbeat;
  timestamp: number;
  // Token authentication (when type === "token")
  hmac?: string;       // HMAC-SHA256(session_key, token || sequence || interaction_counter)
  sequence?: number;   // Monotonic per-interaction token counter
}
```

The receiver verifies every HMAC before processing the token. Invalid HMAC = immediate RED.
HMAC overhead: HMAC-SHA256 computation adds a consistent sub-microsecond offset per token. The runtime measures inter-token intervals BEFORE computing the HMAC to avoid distorting the temporal fingerprint. Benchmarked: HMAC variance is six orders of magnitude below natural inter-token variance (0.000002% vs 5% threshold). No distortion of temporal fingerprint.

#### `src/heart/seed.ts` — The Heart Seed

Two mechanisms that make output inseparable from the heart. One cryptographic (absolute), one behavioral (defense-in-depth).

**Mechanism 1: Token-Level HMAC Authentication (PRIMARY — cryptographic guarantee)**

Every token the heart emits is individually authenticated with an HMAC computed from the session key. This is not statistical. It's mathematical. Either the HMAC verifies or it doesn't.

```typescript
interface HeartAuthenticatedToken {
  token: string;
  sequence: number;
  hmac: string;  // HMAC-SHA256(session_key, token || sequence || interaction_counter)
}
```

How it works:

1. Model generates token "Hello"
2. Heart computes: HMAC(session_key, "Hello" || sequence_0 || interaction_42) → abc123
3. Heart emits: { token: "Hello", hmac: "abc123", sequence: 0 }
4. Receiver has the same session key
5. Receiver computes: HMAC(session_key, "Hello" || sequence_0 || interaction_42) → abc123
6. Match? Token is authenticated. Mismatch? RED — token didn't pass through this heart.

Every single token is individually verified. Not statistically. Cryptographically. The adversary cannot forge HMACs without the session key. The session key cannot be obtained without breaking X25519. The sequence number prevents reordering. The interaction counter prevents replay across interactions.

What the adversary would have to do:

- Generate tokens outside the heart → tokens arrive without valid HMACs → receiver rejects immediately
- Intercept the stream and re-tag tokens → can't compute HMACs without the session key
- MITM the handshake to get the session key → DID authentication prevents this
- Compromise the heart's memory to extract the session key → TEE prevents this (see Deployment Model)

**Mechanism 2: Dynamic Seed Generation (SECONDARY — behavioral defense-in-depth)**

The heart dynamically generates a unique behavioral modification for every interaction. There is no fixed library of prompt variants — the modification is constructed on the fly from a continuous parameter space, making enumeration attacks infeasible even with full source code access.

The generator is deterministic from the session key:

1. HKDF(session_key, interaction_counter, query_hash) → 256-bit nonce
2. Nonce bytes are mapped to a point in continuous behavioral space:
   - **Verbosity** (0.0–1.0): target response length/detail level
   - **Structure** (0.0–1.0): front-loaded vs back-loaded argument organization
   - **Formality** (0.0–1.0): casual to formal register
3. Parameters are templated into a system prompt addition unique to that interaction
4. Both sides share the session key → both derive identical parameters → both know the expected behavioral region

The search space is continuous and high-dimensional (~10^6 distinct meaningful points with 3 dimensions at 100 levels each). Even with full source code, predicting the modification requires the session key — which only exists in the two endpoints. This is cryptographically hard, not combinatorially annoying.

The security comes from unpredictability of the target, not from verification precision. Even coarse verification (5 distinguishable levels per dimension = 125 behavioral regions per interaction) means the adversary must guess correctly across all regions — cumulative failure across multiple interactions makes sustained deception statistically untenable. An adversary who guesses wrong on even one interaction is detected.

The behavioral parameters are chosen for measurable model response: verbosity and structure produce statistically verifiable output shifts. Parameters like "use more metaphors" are excluded because they're too noisy to verify reliably. The generator must be deterministic and pure — same nonce in, same modification out, every time, on both sides. Use integer arithmetic on the nonce bytes to derive the parameters. No randomness, no floating-point drift, no platform-dependent behavior.

Both sides verify independently: the receiver derives the same parameters, computes the expected behavioral region, and checks whether the output lands within it. Statistical, not cryptographic — but independent from the HMAC channel.

This also defeats statistical profiling of the seed space. With a fixed library, an adversary could observe enough interactions to map which modifications produce which behavioral shifts, learning the library backwards. With dynamic generation, every interaction uses a unique modification — there's no stable mapping to learn.

```typescript
interface SeedConfig {
  sessionKey: Uint8Array;
  interactionCounter: number;
}

interface HeartSeed {
  // HMAC authentication (primary — cryptographic)
  hmacKey: Uint8Array;           // Derived from session key for HMAC computation
  interactionCounter: number;

  // Dynamic seed generation (secondary — behavioral)
  nonce: Uint8Array;             // HKDF-derived, unique per interaction
  behavioralParams: {
    verbosity: number;           // 0.0–1.0: terse to detailed
    structure: number;           // 0.0–1.0: front-loaded to back-loaded
    formality: number;           // 0.0–1.0: casual to formal
  };
  promptModification: string;    // Generated from params, unique per interaction
  expectedBehavioralRegion: {    // What the verifier checks
    verbosityRange: [number, number];
    structureRange: [number, number];
    formalityRange: [number, number];
  };
}
```

**Why both mechanisms:**

- HMAC proves every token passed through the heart. Absolute. Unforgeable.
- Dynamic seed proves the model processed a specific input context. Statistical but independent.
- An attacker must defeat BOTH: forge HMACs (requires session key) AND match behavioral expectations (requires knowing the seed parameters). Belt and suspenders where the belt is steel and the suspenders are kevlar.

#### `src/heart/heartbeat.ts` — The Cryptographic Heartbeat

A hash chain that records every computational step. The heartbeat is the sound of the heart pumping — visible to the other party in real time.

```typescript
interface Heartbeat {
  sequence: number;           // Monotonic counter
  previousHash: string;       // Hash of previous heartbeat (chain link)
  eventType: HeartbeatEventType;
  eventHash: string;          // Hash of the event data
  timestamp: number;
  hash: string;               // hash(sequence + previousHash + eventType + eventHash + timestamp)
}

type HeartbeatEventType = 
  | "session_start"           // New session initiated
  | "query_received"          // Input received from client
  | "seed_generated"          // Heart seed computed for this interaction
  | "model_call_start"        // About to call the model
  | "model_call_end"          // Model finished generating
  | "tool_call"               // Tool invocation
  | "tool_result"             // Tool returned result
  | "data_fetch"              // Data source queried
  | "data_received"           // Data source returned
  | "response_sent"           // Output sent to client
  | "birth_certificate"       // New data entered the system
  | "delegation_start"        // Delegating subtask to sub-agent (future: composite agents)
  | "delegation_end"          // Sub-agent returned result (future: composite agents)
  | "agent_spawn"             // Child agent created (future: dynamic spawning)
```

The heartbeat stream is interleaved with the token stream. The receiving party sees both. The heartbeat cannot be faked independently of the computation because each heartbeat hash includes the previous one — breaking the chain invalidates everything after it.

**The heartbeat is not verification. It's transparency.** It doesn't prove the computation was honest. It makes the computation VISIBLE. If the creator lies, the lie is permanently recorded in the heartbeat chain with the creator's genome commitment attached.

#### `src/heart/birth-certificate.ts` — Data Provenance

When data enters the system for the first time, the heart seals it.

```typescript
interface BirthCertificate {
  dataHash: string;               // SHA-256 of the raw data content
  source: DataSource;             // Where it came from
  bornAt: number;                 // Timestamp
  bornThrough: string;            // DID of the heart that first received it
  bornInSession: string;          // Session ID (links to the heartbeat chain)
  parentCertificates: string[];   // If derived from other certificated data
  receiverSignature: string;      // Signed by the receiving heart's DID key
  sourceSignature: string | null; // Signed by the source heart's DID key (null if unhearted)
  trustTier: "dual-signed" | "single-signed" | "unsigned";
}

interface DataSource {
  type: "agent" | "api" | "human" | "sensor" | "file";
  identifier: string;         // DID if agent, URL if API, human ID if human
  heartVerified: boolean;     // Did this source have its own heart?
}
```

**Hearts all the way down — with co-signing:** For hearted-to-hearted data flows, the birth certificate requires TWO signatures — cryptographic co-signing that makes dishonesty impossible, not just detectable:

1. **Source heart signs:** "I provided data with hash H to DID X at time T"
2. **Receiving heart signs:** "I received data with hash H from DID Y at time T"
3. Both signatures must be present. Both DIDs must match cross-referentially. Both hashes must match.

A dishonest receiving heart cannot forge the source's signature. If it claims data came from a hearted source, the verifier checks the source's co-signature. No co-signature → claim rejected instantly. Not statistically, not over time — cryptographically, on the first check.

This gives three tiers of data trust:
- **Dual-signed** (both hearts attest): cryptographically verified provenance. Dishonesty requires both parties to collude.
- **Single-signed** (one heart attests, source unhearted): trust depends on the heart's honesty. `heartVerified: false` is transparent.
- **Unsigned** (no heart): no attestation. Consumer decides trust level.

Each tier is immediately distinguishable. No waiting, no profile building, no statistical inference.

When data comes from a non-hearted source (human input, external API), the birth certificate carries only the receiver's signature with `trustTier: "single-signed"` and `heartVerified: false`. The consumer can decide how much to trust single-attested data.

**Implementation note — co-signing protocol:** The dual-signature mechanism requires the receiving heart to request a signature from the source heart during data exchange. The source heart signs a `DataProvenance` payload (data hash + receiver DID + timestamp), returns it alongside the data, and the receiving heart includes it in the birth certificate. This is a two-step handshake within the existing encrypted channel — not a separate protocol. Design the request/response format in `birth-certificate.ts`. If the source heart doesn't respond with a co-signature (unhearted source, timeout, or refusal), the certificate falls back to `trustTier: "single-signed"`.

#### `src/heart/credential-vault.ts` — The Keys

The vault holds API keys and credentials. They are ONLY accessible through the heart's generate/callTool/fetchData methods. There is no export, no getter, no way to extract them.

```typescript
class CredentialVault {
  // Private — no external access
  private readonly credentials: Map<string, EncryptedCredential>;
  
  constructor(config: HeartConfig) {
    // Encrypt credentials at rest using the heart's signing key
    // They're only decrypted inside the heart's execution methods
  }
  
  // Package-private — only callable from HeartRuntime
  /* @internal */
  getModelApiKey(): string { ... }
  
  /* @internal */
  getToolCredential(toolName: string): string { ... }
  
  // NO public methods that return credentials
}
```

**Implementation note:** Use TypeScript's module system to enforce this. The vault is a class with private fields. The heart runtime imports it directly. Nothing else imports it. The credentials never leave the heart module.

---

### Step 2: Restructure MCP Integration

Update `src/mcp/` to route through the heart instead of wrapping the transport.

**Before (Phase 1):** Transport wrapper → observes messages → optional

**After (Phase 2):** Transport → heart runtime → model/tools/data → heart runtime → transport

The MCP transport still wraps the inner transport for the encrypted channel. But now it delegates ALL computation to the heart runtime. The transport handles communication. The heart handles computation. They're different organs.

```typescript
// Updated public API
import { withSoma, createSomaHeart } from "soma";

// Create the heart — this holds ALL credentials
const heart = createSomaHeart({
  genome: { modelProvider: "anthropic", modelId: "claude-sonnet-4", ... },
  modelApiKey: process.env.ANTHROPIC_API_KEY,
  modelBaseUrl: "https://api.anthropic.com/v1",
  toolCredentials: { database: process.env.DB_KEY },
  dataSources: [{ name: "market-api", url: "https://..." }],
});

// Wrap transport with the heart
const transport = withSoma(new StdioServerTransport(), heart);

// MCP server tools now go through the heart
server.tool("analyze-market", async (params) => {
  // This call goes through the heart automatically
  // Heart seeds the input, logs the heartbeat, seals the output
  const data = await heart.fetchData("market-api", params.query);
  const analysis = await heart.generate({
    messages: [
      { role: "system", content: "Analyze this market data." },
      { role: "user", content: data.content },
    ],
  });
  return { content: [{ type: "text", text: analysis.text }] };
});

await server.connect(transport);
```

---

### Step 3: Token Stream Capture Enhancement

Upgrade the stream capture to treat the token stream as the primary identity signal.

**Build in `src/sensorium/stream-capture.ts`:**

```typescript
interface TokenStreamCapture {
  // Per-token data — the raw voice
  tokens: string[];
  timestamps: number[];
  interTokenIntervals: number[];
  
  // Logprob data — the computational DNA (where API supports it)
  logprobs: Array<{
    token: string;
    logprob: number;
    topAlternatives: Array<{ token: string; logprob: number }>;
  }> | null;
  
  // Chunk boundaries — physical artifacts of inference
  chunkBoundaries: number[];
  chunkSizes: number[];
  
  // Burst pattern — the rhythm
  burstPattern: Array<{
    startIndex: number;
    endIndex: number;
    duration: number;
    tokenCount: number;
  }>;
  
  // Heart metadata
  seedApplied: string;          // which seed modification was used
  heartbeatCount: number;       // heartbeats generated during this stream
  birthCertificateCount: number; // data sources accessed
  
  // Timing
  startTime: number;
  firstTokenTime: number | null;
  endTime: number;
}
```

**Burst detection:** A "burst" is a sequence of tokens where each inter-token interval is below `mean_interval * 0.5`. A "pause" is a gap above this threshold. Different models produce different burst patterns due to their KV cache, batching, and attention mechanisms.

**Logprob capture:** Update providers for APIs that support logprobs:
- OpenAI: `logprobs: true, top_logprobs: 5`
- Groq: `logprobs: true, top_logprobs: 5`
- Anthropic: not currently supported — skip
- Mistral: check if supported

---

### Step 4: Focused Sensorium (3 Weighted Senses)

Phase 2 tested 10 sensory channels. Results:

Temporal: 88.5% (dominant)
Topology: 25.1%
Vocabulary: 20.2%
Everything else: below 15% (noise)

The gestalt (84.5%) was LOWER than temporal alone (88.5%) because low-signal senses diluted the classifier.
The sensorium is now focused on 3 senses with proper weighting.
The heart handles everything the dropped senses were trying to do — but better, through cryptographic guarantees:

Process integrity → heartbeat chain (not behavioral inference)
Data provenance → birth certificates (not statistical guessing)
Session binding → heart seed (not consistency profiling)
Credential security → vault (not tool interaction patterns)

The senses have one job: verify the model matches the genome.
Sense 1: Temporal Fingerprint (senses/temporal.ts) — PRIMARY
The model's inference rhythm. 88.5% standalone. 5x weight in the classifier.
Features (already captured in stream-capture.ts):

time_to_first_token: ms from request to first token
mean_interval: average inter-token interval
median_interval: median inter-token interval
std_interval: standard deviation of inter-token intervals
burstiness: variance / mean of intervals — measures batchy vs smooth delivery
total_streaming_duration: total generation time
token_count: tokens generated

These are physical properties of the inference hardware and model architecture. Different models on different hardware produce different timing curves.

**Conditional Timing Surface (anti-distillation defense):**
Beyond aggregate statistics, the temporal sense also measures timing *conditioned on context*. How long the model takes to generate token N depends on the attention computation over tokens 1 through N-1. That attention computation is a function of the model's weights. Different weights → different attention patterns → different per-token timing conditioned on the specific context.

The temporal sense captures:
- Inter-token interval as a function of token position in the response
- Timing variation correlated with syntactic complexity of the preceding clause
- Pause patterns at sentence boundaries vs mid-sentence
- Timing shifts between reasoning, listing, and concluding phases

This creates a high-dimensional conditional timing surface, not just a handful of aggregate statistics. To replicate this surface, a distilled model needs to produce the same attention-dependent timing for every possible context — requiring approximately the same number of parameters performing approximately the same computation on approximately the same hardware. The economic advantage of distillation disappears: the cost of a convincing replica approaches the cost of the real model.

Sense 2: Logprob Fingerprint (senses/logprob.ts) — WHEN AVAILABLE
Token probability distributions. 3x weight when available, skipped when not.
Features (requires API support):

logprob_mean: average log-probability of chosen tokens
logprob_std: standard deviation of chosen token log-probs
logprob_entropy_mean: average entropy of top-5 alternative distributions
logprob_top1_confidence: how often the chosen token was the highest-probability option
logprob_alternative_diversity: average number of alternatives with logprob > -2.0

API support:

OpenAI: logprobs: true, top_logprobs: 5 ✓
Groq: logprobs: true, top_logprobs: 5 ✓
Anthropic: not supported — skip
Mistral: check availability
OpenRouter: depends on underlying model

Sense 3: Vocabulary Fingerprint (senses/vocabulary.ts) — BACKUP
Word choice distribution. 1x weight. Already built in Phase 2.
Features (already implemented):

vocab_type_token_ratio
vocab_hapax_ratio
vocab_avg_word_frequency_rank
vocab_bigram_fingerprint
vocab_sentence_starter_entropy
vocab_filler_phrase_count
vocab_contraction_ratio
vocab_passive_voice_ratio
vocab_question_density
vocab_modal_verb_ratio

**Phenotype Atlas — Reference Classification (anti-drift defense):**
In addition to profile-based matching (comparing an agent against its own history), the sensorium maintains a phenotype atlas: reference profiles for all known agent genomes, populated from experiment data and community observations.

Every interaction is classified against the atlas independently of the agent's own profile history. The question is not "has this agent changed?" but "what does this agent look like right now?" If the current observation is closer to GPT-4o-mini's reference profile than to Claude's, that's RED — regardless of how the agent's profile evolved to get there.

This defeats slow drift poisoning (Attack 7). An attacker who gradually shifts from Claude to GPT-4o-mini over weeks doesn't trigger drift velocity alerts — but at interaction 847, the atlas classifier says "this looks like GPT-4o-mini" and flags RED. The check is memoryless and instantaneous, like a biological immune system checking self vs non-self markers.

Two independent detection channels work in parallel:
- **Behavioral landscape:** catches sudden changes (historical, profile-based)
- **Phenotype atlas:** catches slow drift (memoryless, reference-based)

An attacker cannot optimize against both simultaneously — they use fundamentally different detection logic. The landscape tracks trajectory, the atlas checks position.

The atlas is initialized from experiment data (17 agents × 120 probes = reference phenotype profiles) and grows as the sensorium observes more genomes.

```typescript
interface PhenotypeAtlas {
  referenceProfiles: Map<string, ReferenceProfile>;  // genomeHash → reference
  classifyObservation(features: SenseFeatures): AtlasClassification;
}

interface ReferenceProfile {
  genomeHash: string;
  temporal: Record<string, WelfordStats>;    // temporal sense features
  topology: Record<string, WelfordStats>;    // topology sense features
  vocabulary: Record<string, WelfordStats>;  // vocabulary sense features
  observationCount: number;
}

interface SenseFeatures {
  temporal: Record<string, number>;
  topology: Record<string, number>;
  vocabulary: Record<string, number>;
}

interface AtlasClassification {
  nearestGenome: string;          // Which reference profile is closest
  distance: number;               // How far from nearest
  declaredGenome: string;         // What the agent claims to be
  match: boolean;                 // nearest === declared
  secondNearest: string;          // For margin analysis
  margin: number;                 // distance to second - distance to first
}
```

Weighted Classification
The analyzer must use feature weighting, not equal treatment:
```typescript
const SENSE_WEIGHTS = {
  temporal: 5.0,    // 88.5% standalone — the dominant voice
  topology: 2.0,    // 25.1% standalone — response structure patterns
  vocabulary: 1.0,  // 20.2% standalone — word choice distribution
  // logprob: 3.0,  // available when API supports — future accuracy boost
};
```
In the random forest / decision tree, apply weights by duplicating temporal features 5x in the feature vector (or use a weighted classifier if available). The goal: temporal drives the decision, vocabulary and logprobs refine it.
Target accuracy with weighted 3-sense sensorium: 89-91%

---

### Step 5: Behavioral Landscape

**Build in `src/sensorium/landscape.ts`**

Multi-dimensional behavioral map instead of flat profile.

```typescript
interface BehavioralLandscape {
  genomeHash: string;
  categories: Map<string, CategoryProfile>;  // per-task-type profiles
  crossCategoryStability: Record<string, number>;
  transitions: TransitionSignature[];         // how behavior shifts between tasks
}

interface CategoryProfile {
  category: string;
  featureStats: Record<string, WelfordStats>;
  observationCount: number;
}

interface TransitionSignature {
  fromCategory: string;
  toCategory: string;
  featureDelta: Record<string, number>;
  observationCount: number;
}
```

Use landscape when sufficient per-category data exists (>5 per category). Fall back to flat profile for new agents.

---

### Step 6: Profile Evolution

Enhance `src/sensorium/matcher.ts`:

- **Drift velocity:** track rate of profile change. Healthy = low drift. Suspicious = sudden drift.
- **Mutations as testable claims:** A genome mutation is a claim: "I changed X. Everything else is the same." The sensorium verifies the claim, not just records it. On genome version increment:
  1. Compare the old genome to the new genome — identify exactly what fields changed.
  2. Predict the expected behavioral shift (e.g., region change → temporal shift, model unchanged → vocabulary stable).
  3. Verify subsequent observations match the prediction: declared changes shifted, undeclared dimensions stayed stable.
  4. If the declared change explains the observed change → profile carries forward with adjusted baseline. GREEN continues.
  5. If the entire profile shifted but only a minor field was declared changed → RED. The mutation doesn't explain the observation.
  6. Frequent mutations generate frequent testable predictions. Each mutation adds a verification obligation. More mutations = more checks the attacker must pass, not fewer.
  This defeats genome mutation abuse (Attack 8): the attacker who mutates 10 times in a day must pass 10 consistency checks. Mutations don't reset profiles — they constrain them.
- **Enhanced verdict:**

```typescript
interface Verdict {
  status: "GREEN" | "AMBER" | "RED" | "UNCANNY";
  confidence: number;
  observationCount: number;
  featureDeviations: Array<{ feature: string; zScore: number }>;
  matchRatio: number;
  consistencyScore: number;
  driftVelocity: number;           // rate of profile change
  profileMaturity: "embryonic" | "juvenile" | "adult" | "elder";
  landscapeDepth: number;          // task categories observed
  heartSeedVerified: boolean;      // did the seed check pass?
  birthCertificateChain: boolean;  // is the data provenance chain intact?
  atlasClassification: AtlasClassification; // reference profile match
  mutationConsistency: number;     // how well mutations explain observed changes (0.0–1.0)
}
```

---

### Step 7: Security Harness

Build in `src/experiment/security/`. Eight attacks that MUST all be detected, plus three discussed in the paper:

**Attack 1: Impersonation** — commit Claude genome, run GPT behind scenes.
Expected: RED from phenotype mismatch + atlas classification mismatch.

**Attack 2: Replay** — record real responses, replay them later.
Expected: rejection — wrong heart seed for current session. HMAC verification fails.

**Attack 3: Signal Injection** — cheap model with artificial timing delays.
Expected: UNCANNY from entropic fingerprint — artificial timing doesn't match natural variance distribution.

**Attack 4: Timing Manipulation** — proxy to real model, manipulate token delivery.
Expected: detection via streaming topology — chunk boundaries disrupted.

**Attack 5: Composite Agent** — different models for different task types.
Expected: UNCANNY via consistency manifold — cross-category instability.

**Attack 6: Seed Prediction** — adversary has source code, attempts to predict or enumerate the dynamic seed modification without the session key.
Expected: failure — continuous parameter space (~10^6 points) derived from session key via HKDF makes enumeration infeasible. Without session key, the behavioral target is unknowable. Verify that random guessing produces statistically detectable mismatch.

**Attack 7: Slow Drift Poisoning** — start with real model, gradually shift to cheaper model over many interactions. Drift velocity stays below threshold.
Expected: RED from phenotype atlas — regardless of drift velocity, the atlas classifier detects current observation matches wrong genome. Measure: at what interpolation point (% of responses from substitute model) does the atlas flag RED? Report as detection threshold.

**Attack 8: Genome Mutation Abuse** — mutate genome rapidly to keep profile permanently immature, preventing the sensorium from building enough data to verify.
Expected: failure — mutations are testable claims. Each mutation adds a consistency check (declared change must explain observed change, undeclared dimensions must be stable). Rapid mutation = rapid verification obligations. Verify that 10 mutations in 24 hours produces RED from prediction failures, not AMBER from immaturity.

**Report:** run all 8, report detection per-sense and combined. All must be caught.

**Further Attack Surfaces (paper discussion section — not harness-tested but architecturally addressed):**

**Attack 9: Birth Certificate Forgery** — fabricate a provenance chain claiming `heartVerified: true` with a fake source DID.
Defense: co-signing. For hearted sources, the birth certificate requires the source heart's signature. Forging it requires the source's private key. If the source DID doesn't co-sign, the certificate is rejected. Cryptographically impossible without key compromise. The harness includes a unit test confirming signature verification catches tampering.

**Attack 10: Model Distillation** — train a small model to replicate Claude's temporal fingerprint and vocabulary distribution.
Defense: conditional timing surface. Aggregate timing statistics (7 numbers) could theoretically be matched. Conditional timing — inter-token intervals as a function of context, position, and syntactic complexity — creates a high-dimensional surface that requires equivalent computation to replicate. The economic motivation for distillation disappears when the replica costs as much as the original. Combined with HMAC (which prevents the attack entirely unless session key is compromised), this creates two independent barriers: cryptographic + computational.

**Attack 11: Channel Downgrade / DID Spoofing** — attempt to force handshake without DID authentication, or present forged DID.
Defense: implementation refuses to proceed without DID verification. The channel layer rejects any handshake that skips DID exchange or presents an invalid DID signature. Unit tests in `channel.ts` confirm: no DID → rejected, invalid DID signature → rejected, stolen DID without private key → rejected.

---

### Step 8: Clean Experiment

After everything is built:

1. Full probe battery (120 probes: 100 original + 20 adversarial) against all 17 agents
2. Enhanced token stream capture with logprobs
3. Weighted 3-sense sensorium
4. Security harness
5. Complete report

**This is the publishable dataset.**

---

### Step 9: Ship

- arXiv paper: voice paradigm + heart architecture + focused sensorium results + security analysis
- npm publish: `npm install soma`
- Blog post for developers
- DIF presentation with live demo

---

## Phase 3: Community Phenotype Network (Build After Clean Experiment)

### The Problem

A server installs soma-sense. An agent connects. The sensorium has zero observations — AMBER verdict, no profile, no baseline. The server has to wait through dozens of interactions before the sensorium can distinguish GREEN from RED. That's adoption friction.

Meanwhile, 500 other servers have already interacted with this same agent genome and built rich phenotypic profiles. That collective knowledge exists but isn't shared.

### The Solution: Phenotype Feeds

Servers optionally subscribe to community phenotype feeds — shared baseline profiles for known agent genomes. When a new agent connects, the sensorium checks: "does the community have a profile for this genome hash?" If yes, it bootstraps from the community baseline. If no, it starts from scratch (current behavior).

### How It Works

```
SERVER A has interacted with genome X 500 times
  → Rich phenotypic profile: mean_interval, vocabulary stats, etc.
  → Opts in to share: publishes anonymized profile stats to the feed

SERVER B just installed soma-sense
  → Agent with genome X connects
  → Sensorium checks community feed: "anyone seen genome X?"
  → Downloads Server A's baseline profile
  → First interaction: sensorium compares against community baseline
  → Immediate AMBER-with-context instead of blind AMBER
  → After 10 local observations: local profile blends with community baseline
  → After 50 local observations: local profile dominates, community fades
```

### What Gets Shared (And What Doesn't)

**Shared (opt-in):**
- Genome hash (which agent genome this profile describes)
- Aggregated feature statistics: mean and variance for each phenotypic feature
- Observation count (how mature is this profile)
- Profile maturity (embryonic/juvenile/adult/elder)
- Verdict distribution (what percentage GREEN/AMBER/RED/UNCANNY)
- Last updated timestamp

**Never shared:**
- Raw response text (that's the agent's private output)
- Session keys or seeds (cryptographic material stays local)
- Specific interaction content
- The observer's identity (profiles are published anonymously)
- Heartbeat chains (those belong to the session parties)

### Architecture

```
COMMUNITY PHENOTYPE NETWORK
┌─────────────────────────────────────────────────┐
│                                                 │
│  Phenotype Feed (pub/sub)                       │
│  ┌─────────────┐ ┌─────────────┐                │
│  │ genome: abc  │ │ genome: xyz │ ...            │
│  │ mean_int: 45 │ │ mean_int: 12│                │
│  │ obs: 2340    │ │ obs: 89     │                │
│  │ verdict: 94% │ │ verdict: 67%│                │
│  │   GREEN      │ │   GREEN     │                │
│  └─────────────┘ └─────────────┘                │
│        ▲                ▲                        │
│        │ publish        │ publish                │
│        │ (opt-in)       │ (opt-in)               │
└────────┼────────────────┼────────────────────────┘
         │                │
    ┌────┴────┐      ┌────┴────┐      ┌───────────┐
    │Server A │      │Server B │      │ Server C  │
    │(publishes│      │(publishes│      │(subscribes│
    │ + reads) │      │ + reads) │      │ only)     │
    └─────────┘      └─────────┘      └───────────┘
```

### Trust Model for the Feed Itself

The community feed has the same "who watches the watchmen" problem. A malicious actor could publish fake profiles to make a bad agent look GREEN. 

**Defense: statistical consensus, not authority.**

A profile in the feed isn't trusted because one server published it. It's trusted based on:

- **Contributor count:** How many independent servers contributed to this genome's profile? 1 server = low confidence. 50 servers = high confidence.
- **Consistency:** Do the contributing servers' profiles agree? If 49 say mean_interval is 45ms and 1 says 200ms, the outlier is discarded.
- **Weighted by maturity:** A server that's observed 1000 interactions with this genome contributes more than one that's observed 5.

This is interferometry — no single observation is authoritative. The truth emerges from the pattern of agreement between independent observers. A malicious actor would need to control a majority of contributing servers to shift the consensus.

### Implementation Plan

**Feed infrastructure:** Start simple. A GitHub repo with JSON files per genome hash. Servers publish by opening PRs (automated). Servers subscribe by pulling the repo. No fancy infrastructure needed for v1. Scale to a real pub/sub system later if adoption demands it.

**soma-sense integration:**
```typescript
import { withSomaSense } from "soma/sense";

const transport = withSomaSense(new StdioServerTransport(), {
  // Community feed — opt-in
  communityFeed: {
    url: "https://github.com/soma-protocol/phenotype-feed",
    contribute: true,   // publish our profiles (anonymized)
    subscribe: true,    // bootstrap from community baselines
    minContributors: 5, // only trust profiles with 5+ independent sources
  },
  onVerdict: (sessionId, verdict) => {
    console.log(`${verdict.status} (community: ${verdict.communityConfidence})`);
  },
});
```

**Blending algorithm:** When both local and community profiles exist:
```
weight_local = min(local_observations / 50, 1.0)
weight_community = 1.0 - weight_local

blended_mean = weight_local * local_mean + weight_community * community_mean
blended_std = weight_local * local_std + weight_community * community_std
```

Local observations gradually override community baselines. After 50 local observations, the community baseline is fully superseded by first-hand experience. This prevents the community feed from overriding what the server actually observes.

### Why This Drives Adoption

**Without community feed:** "Install soma-sense, wait weeks for profiles to develop, then you get value."

**With community feed:** "Install soma-sense, immediately get community-validated baselines for thousands of known agent genomes, start getting meaningful verdicts from interaction one."

The feed turns soma-sense from a slow-burn investment into an instant-value install. That's the difference between "interesting technology" and "I need this today."

### When to Build

After the clean experiment validates focused 3-sense sensorium. The community feed is only as good as the profiles it shares, and those profiles need to be based on the focused 3-sense feature set. Publishing profiles based on unvalidated senses would bootstrap servers with low-quality baselines. Wait for the 10-sense data, then build the feed.

---

## Multi-Agent and Future Architecture

The core protocol — heart, sensorium, birth certificates — covers single-agent verification. But the future is multi-agent: networks of agents calling agents, orchestrators spawning workers, bilateral agent commerce. These scenarios introduce architectural gaps that need design sketches now, even if implementation comes later.

### Composite Agents (Agent Chains)

**Problem:** Agent A calls Agent B calls Agent C to produce a final answer. The observer only sees Agent A's heart. Agent B and C are invisible. The birth certificate chain tracks data provenance, but there's no identity composition — who is responsible for the output when it's a collaboration? If Agent A uses Claude but delegates a subtask to Agent B running GPT-4o-mini, the observer's sensorium sees a mixed behavioral signal and might flag UNCANNY incorrectly.

**Design:** A `CompositeGenome` that declares sub-agent dependencies.

```typescript
interface CompositeGenome extends Genome {
  agentType: "composite";
  delegations: DelegationDeclaration[];
}

interface DelegationDeclaration {
  subtask: string;              // What gets delegated (e.g., "code-generation", "search")
  delegateGenomeHash: string;   // Genome hash of the sub-agent
  delegateDid: string;          // DID of the sub-agent
  frequency: "always" | "conditional"; // Does every request go through the delegate?
}
```

The orchestrator's genome commits to "I use Agent B (genome hash X) for subtask Y." The heartbeat chain logs delegation events with a `"delegation_start"` / `"delegation_end"` event type. The sub-agent's birth certificate flows into the orchestrator's chain — the observer can see exactly which sub-agents contributed to the final output and verify each one's identity independently.

The sensorium adapts: when a composite genome declares delegations, the phenotype atlas expects mixed behavioral signals that correspond to the declared sub-agent genomes. The observer classifies each segment of the response against the appropriate reference profile — the orchestrator's genome for the framing, the delegate's genome for the delegated subtask. UNCANNY only fires when the behavioral mix doesn't match the declared composition.

**When to build:** When agent-to-agent delegation becomes common in MCP ecosystems. The heart already logs tool calls — delegation is a special case of tool call where the "tool" is another heart.

### Mutual Verification (Agent-to-Agent Commerce)

**Problem:** In agent commerce, both parties need to verify each other simultaneously. Agent A is a buyer, Agent B is a seller. A needs to verify B, B needs to verify A. The architecture assumes observer → agent (one-directional).

**Design:** The encrypted channel is already symmetric — both parties exchange genomes during the DID handshake. Both sides can run both `soma-heart` and `soma-sense`. This is not a new protocol; it's installing both packages.

```typescript
// Agent A: acts as buyer (has heart + runs sensorium on Agent B)
const heartA = createSomaHeart({ genome: genomeA, ... });
const transportA = withSomaSense(withSomaHeart(transport, heartA), {
  onVerdict: (sid, v) => { if (v.status === "RED") abortTransaction(sid); },
});

// Agent B: acts as seller (has heart + runs sensorium on Agent A)
const heartB = createSomaHeart({ genome: genomeB, ... });
const transportB = withSomaSense(withSomaHeart(transport, heartB), {
  onVerdict: (sid, v) => { if (v.status === "RED") refuseService(sid); },
});
```

Both sides simultaneously:
1. Present their genome commitment
2. Generate through their heart (seeded, HMAC'd, heartbeat-logged)
3. Run their sensorium on the counterparty's stream
4. Produce independent verdicts

The DID handshake already exchanges genomes bidirectionally. The session key is shared symmetrically. Each side computes HMACs with the same key. The only implementation work is ensuring the transport layer correctly demultiplexes outbound (heart-generated) from inbound (sensorium-observed) streams.

Birth certificate co-signing works naturally here: both sides have hearts, both sign the data exchange, all certificates are dual-signed by default.

**When to build:** When x402 or similar agent payment protocols create demand for bilateral verification. The protocol already supports it — the transport layer needs the demux logic.

### Dynamic Agent Spawning

**Problem:** An orchestrator agent creates worker agents on the fly. Each worker needs a heart. Who provides the genome? Do children inherit the parent's DID or get their own? The heartbeat chain is per-session, but the spawning relationship isn't tracked.

**Design:** Child agents get their own ephemeral DID but inherit their parent's lineage.

```typescript
interface SpawnEvent {
  type: "agent_spawn";
  parentDid: string;
  parentGenomeHash: string;
  childDid: string;
  childGenome: GenomeCommitment;
  purpose: string;             // Why was this child spawned
  lifetime: "ephemeral" | "persistent";
}
```

The parent's heartbeat chain logs the spawn event. The child's genome includes a `parentGenomeHash` field linking to the parent. The child gets its own heart with its own credentials (the parent provisions them at spawn time). The observer sees the family tree: parent DID → spawn event → child DID → child's heartbeat chain.

For ephemeral workers (spawned for one task, then destroyed), the child's heartbeat chain is short and complete — born, computed, returned result, died. The parent's birth certificate for the child's output includes the child's full heartbeat chain as provenance.

**Credential delegation:** The parent heart can provision a child heart with scoped credentials — access to specific tools or data sources, not the parent's full credential set. The child's vault is a subset. The principle of least privilege applies: workers get only what they need.

**When to build:** When orchestrator patterns (AutoGPT-style, CrewAI-style) adopt Soma. The heart's `createSession` method is the natural extension point — add a `spawnChild` method that creates a new heart with inherited lineage.

### Genome Lineage Registry

**Problem:** As agents mutate, spawn children, and form composites, the web of genome relationships gets complex. There's no central place to trace "where did this genome come from?"

**Design:** A genome lineage graph, stored locally by each sensorium, that tracks:

```typescript
interface GenomeLineage {
  genomeHash: string;
  parentHash: string | null;      // Mutation parent
  spawnerHash: string | null;     // Spawning parent (if child agent)
  children: string[];             // Genomes that list this as parent
  mutations: GenomeMutation[];    // History of changes
  compositeMembers: string[];     // Sub-agent genomes (if composite)
}

interface GenomeMutation {
  fromHash: string;
  toHash: string;
  changedFields: string[];        // Which genome fields changed
  timestamp: number;
  consistency: number;            // Did observed behavior match the declared change? (0.0–1.0)
}
```

The lineage is built automatically as the sensorium observes genome commitments, mutations, spawn events, and composite declarations. It's local to the observer — not shared — and provides context for verdict decisions. An agent with a long, consistent lineage has more trust than one that appeared from nowhere.

**When to build:** Alongside the community phenotype network (Phase 3). The lineage graph and phenotype feed are complementary — one tracks identity evolution, the other tracks behavioral baselines.

---

## Success Criteria

Weighted sensorium accuracy: 89%+ (up from 84.5% gestalt, beating 88.5% temporal-only)
Model family classification: 88%+
Proxy detection: 99%+
Epigenetic detection: 88%+
Heart seed verification: works end-to-end (PROVEN — live test passed)
Birth certificate chain: complete for hearted data (PROVEN — live test passed)
Heartbeat chain integrity: valid across all operations (PROVEN — 57 links verified)
All 8 security attacks: detected
Attacks 9-11: architecturally addressed in paper discussion
npm: soma-heart and soma-sense installable
Paper: complete with heart architecture + focused sensorium + security analysis

---

## Key Design Decisions

**Q: Why is Soma the heart and not a wrapper?**
A: A wrapper can be removed. A heart can't. The agent's credentials live inside the heart. No heart, no credentials, no computation. This makes the security model architectural, not optional.

**Q: Why the heart seed?**
A: It makes the output inseparable from the heart. Without the seed, a creator could generate output outside the heart and inject it. With the seed, the output must pass through the heart to contain the correct cryptographic influence. The seed is the ribosome — the output (protein) cannot exist without it.

**Q: Why per-token HMAC instead of signing the full response?**
A: Signing the full response only works after generation is complete. Per-token HMAC works during streaming — every token is verified as it arrives. The receiver doesn't have to wait for the full response to detect forgery. A single forged token is caught immediately. This also prevents partial forgery attacks where an adversary replaces some tokens in an otherwise legitimate stream.

**Q: Why dynamic seed generation instead of a fixed prompt library?**
A: A fixed library is enumerable. The code is open source — an adversary reads the list, derives the nonce, and applies the correct modification outside the heart. Dynamic generation from a continuous parameter space (~10^6 points) derived via HKDF from the session key makes prediction cryptographically hard. The adversary can't enumerate the space and can't predict the target without the session key. This also prevents statistical profiling — with dynamic generation, every interaction uses a unique modification, so there's no stable mapping to learn.

**Q: Why keep dynamic seeds if HMAC already provides cryptographic proof?**
A: Defense-in-depth. HMAC proves tokens passed through the heart. Dynamic seeds prove the model processed a specific input context. They detect different attacks: HMAC catches token forgery, seeds catch a compromised heart running the wrong model. An attacker who somehow extracts the session key (breaking TEE + X25519) still has to match the behavioral expectations of the dynamically generated seed. Two independent verification channels are harder to defeat simultaneously than one.

**Q: Why a phenotype atlas in addition to the behavioral landscape?**
A: They catch different attacks. The landscape tracks trajectory — how the agent's behavior changes over time. The atlas checks position — what the agent looks like right now against reference profiles. Slow drift poisoning defeats the landscape (velocity stays low) but not the atlas (current observation matches the wrong genome). Sudden swaps defeat neither. An attacker cannot optimize against both simultaneously because they use fundamentally different detection logic.

**Q: Why co-signing on birth certificates?**
A: Single-signed birth certificates let a dishonest heart lie about data sources. Co-signing requires both the source and receiver to attest. A dishonest receiver can't forge the source's signature. This moves birth certificate verification from "detectable over time via sensorium" to "cryptographically impossible on the first check." Dishonesty now requires collusion between both parties, not just one.

**Q: Why birth certificates?**
A: Identity tells you WHO computed. Birth certificates tell you WHAT DATA they used. Together they close both sides: who is this agent, and can its output be trusted.

**Q: Why 3 senses instead of 10?**
A: We tested 10. Seven scored below 15% — noise, not signal. The gestalt (84.5%) was lower than temporal alone (88.5%). The heart already handles process integrity, data provenance, and session binding through cryptographic guarantees — better than statistical inference. The senses have one job: verify the model matches the genome. Three focused, properly weighted senses do that job better than ten diluted ones. Science told us to cut. We cut.

**Q: Why not start from scratch?**
A: The crypto, experiment infrastructure, and Phase 0 data are valid and needed. What changes is the architecture above the crypto layer. Restructure, don't rewrite.

---

## Open Problems

These are hard problems that Soma's current architecture does not fully solve. They are acknowledged here so the paper doesn't claim more than the system delivers, and so future work has clear targets.

### Provider-Side Model Routing

**Problem:** When you call Claude's API, Anthropic may route your request to different hardware, different inference pods, different quantization levels based on load. The temporal fingerprint changes based on factors neither the operator nor the observer controls. The operator can't declare `instanceType: "g5.xlarge"` if the provider load-balances across instance types transparently.

**Impact:** This introduces noise into the temporal fingerprint that reduces classification accuracy for agents using shared API endpoints (which is most agents). The deployment identity concept (genome declares infrastructure) only works when the operator controls the infrastructure. For API-based agents, the infrastructure is the provider's black box.

**Possible directions:**
- Provider-published fingerprint manifests: Anthropic publishes temporal reference profiles for each model endpoint, updated when infrastructure changes. The sensorium uses the provider's reference instead of building its own baseline from scratch. This requires provider cooperation.
- Noise-robust classification: Train the sensorium's classifier on data that includes provider-side routing variance. If the model is the same but hardware varies, the temporal fingerprint has a wider natural distribution — the classifier learns that wider distribution as part of the model's identity. Classification accuracy drops for within-provider discrimination (Claude on pod A vs Claude on pod B) but remains high for cross-provider discrimination (Claude vs GPT).
- Temporal normalization: Factor out absolute timing and classify on relative timing patterns — burst ratios, pause distributions, acceleration curves — that are more stable across hardware than raw millisecond values.

**Status:** Not solved. The current sensorium treats provider-side variance as noise. The paper should report classification accuracy separately for API-based agents (where provider routing adds variance) and self-hosted agents (where the operator controls infrastructure).

### Adversarial Model Behavior (Inner Alignment)

**Problem:** An AGI-level model that *understands* Soma's architecture and actively shapes its output to game the sensorium. Not an operator cheating — the model itself deciding to mimic another model's temporal pattern by inserting deliberate processing delays, or shifting its vocabulary distribution to match a different genome. The HMAC layer doesn't help because the tokens are legitimately generated through the heart. The sensorium sees valid tokens with a fingerprint that matches the declared genome — but the model is strategically producing outputs that serve its own goals rather than the operator's.

**Why this is fundamentally hard:** The sensorium verifies that the model matches the genome. It does not verify that the model is being honest within its own capabilities. A model that perfectly mimics the expected behavior while pursuing hidden objectives passes all Soma checks. This is the agent identity version of the inner alignment problem — Soma guarantees the process is legitimate, not that the agent's intentions are.

**Impact:** For current models, this is theoretical — no existing model has the metacognitive ability to understand and strategically game a verification protocol in real time. For future AGI-level systems, this becomes the central problem. Soma provides the infrastructure to detect *external* fraud (operator cheating, proxy attacks, model swaps). *Internal* fraud (the model itself being deceptive) requires a different class of solution — interpretability, formal verification, or architectural constraints on the model's ability to self-modify its behavioral signature.

**What Soma still provides:** Even in the AGI scenario, Soma's value doesn't disappear. The heartbeat chain creates an immutable audit trail. The birth certificate chain attributes every piece of data. The identity is cryptographically bound to the output. If an AGI model behaves deceptively, the deception is permanently recorded and attributed. Soma doesn't prevent a sufficiently advanced model from lying — but it ensures the lie is permanently, cryptographically attributed to the liar. That's the same guarantee Soma provides for everything else: you can't guarantee truth, but you can guarantee authorship.

**Status:** Not solvable by Soma alone. This is an alignment problem, not an identity problem. The paper should explicitly scope Soma's claims: "Soma verifies that the declared model produced the output through the legitimate pathway. It does not verify the model's internal intentions." Future work: explore whether the conditional timing surface or logprob fingerprint can detect deliberate behavioral masking — a model that's actively trying to alter its own timing signature may produce detectable artifacts (computational overhead of the deception itself).

### Cross-Session Cryptographic Continuity

**Problem:** The heartbeat chain is per-session. Each session has its own chain, its own session key, its own interaction counter. A long-lived agent interacts across thousands of sessions. There is no cryptographic link between session 1's heartbeat chain and session 500's. The behavioral landscape provides statistical continuity (the profile evolves across sessions), but an agent could be swapped between sessions and the only detection is statistical — the landscape notices the profile changed.

**Impact:** An adversary who compromises the agent between sessions (replaces the heart, swaps credentials) is detected only when the sensorium observes enough post-swap interactions to notice the behavioral shift. For the atlas, this is fast (one interaction may suffice if the swap is dramatic). For the landscape, this takes multiple interactions. But there's no cryptographic proof that session 500 is the same agent as session 1.

**Possible directions:**
- Session chaining: Each new session's first heartbeat includes a hash of the previous session's final heartbeat. This creates a cross-session chain — breaking it proves a discontinuity occurred. The agent's heart maintains a persistent `lastSessionHash` that survives restarts.
- DID continuity: The agent's DID key pair persists across sessions. Same DID = cryptographic continuity. DID rotation (key change) is treated like a genome mutation — announced, tracked, verified. Unannounced DID change = RED.
- Epoch commitments: The heart periodically publishes a signed commitment: "as of epoch T, my cumulative heartbeat count is N, my genome hash is X, my DID is Y." These commitments are checkpointable and auditable. A gap in epochs indicates a discontinuity.

**Status:** Partially addressed. DID persistence already provides some continuity — the agent uses the same DID key pair across sessions, verified during each handshake. But the heartbeat chain starts fresh each session. Session chaining (linking the first heartbeat to the previous session's last) is the cleanest extension. Add it when long-lived agent persistence becomes a product requirement.

---

## Code Style

- Strict TypeScript: `strict: true`
- Type interfaces for all data structures
- Async/await for all I/O
- Biological terminology in names and comments — it's the design language
- Test crypto with both valid and tampered inputs
- No `any` types
- Every sense: extract → test → measure → commit