# CLAUDE.md — Soma Project Context

> Read this ENTIRE file before doing anything. This is your complete context for the project.
> Every architectural decision, every file, every design choice flows from this document.

---

## What Is Soma

Soma is a protocol for agent identity verification based on **computational phenotyping**.

It is NOT a trust score. NOT a credential system. NOT a reputation layer.

It works like biology: an agent's identity IS its computation, and its computation involuntarily produces observable behavioral patterns (a "phenotype") that cannot be faked without becoming the thing itself.

**The core insight:** DNA doesn't describe an organism. DNA, when run, BECOMES an organism. There's no gap between identity and thing — they're the same object viewed from two angles. Current agent identity systems have a gap between the agent and its credential. That gap is where all fraud lives. Soma eliminates the gap by making the identity the computation itself.

**How it works in three steps:**

1. **COMMIT** — An agent declares its "genome" (model architecture, config, tools) as a cryptographic hash. This is like sequencing its DNA. The agent doesn't reveal its internals — it hashes them. Your secrets stay yours.

2. **EXPRESS** — The agent operates normally. Its behavior IS its phenotype. Response structure, timing patterns, hedging style, failure modes, formatting choices — all involuntary expressions of the underlying computational substrate. Like how a dog can't choose its gait.

3. **OBSERVE** — The counterparty's local Soma library passively reads phenotypic signals from normal interactions and verifies they match the committed genome. Like a dog smelling another dog — passive, local, involuntary.

---

## The Biological Analogy (This Is the Design Language — Use It)

Every design decision should be checked against the biological analogy. If biology wouldn't do it that way, question the design.

| Biology | Soma Equivalent |
|---------|----------------|
| DNA | Genome commitment — cryptographic hash of model + config + tools |
| Gene expression | Normal agent operation — the genome "expressing" into observable behavior |
| Phenotype | Behavioral signals — response patterns, timing, structure, failure modes |
| Senses (smell, sight) | Sensorium — passive local observation layer |
| Immune system | Anomaly detection — learns "self," flags "not-self" |
| Epigenetics | Same base model, different system prompt = different behavioral signature |
| Mutation | Versioned genome updates — tracked, visible, maintaining continuity |
| Pheromones | Involuntary signals that travel through direct proximity (encrypted channel) |
| Uncanny valley | Almost-matching phenotype is MORE suspicious than total mismatch |

---

## Security Model — These Are Non-Negotiable

If you're writing code that violates any of these rules, STOP and redesign.

### Rule 1: Soma Never Scans Agents
Soma only observes what agents already emit through normal operation. It never reaches into an agent's internals, never requests access to source code, weights, or config. It reads what's already on the wire after decryption.

### Rule 2: Soma Never Speaks
There is NO message in the protocol that says "I am Soma" or "send me your data for verification." There is NO verification endpoint. The sensorium is a sense organ, not an entity. If your design has a "Soma service" that agents talk to, you've already failed. Redesign.

**Why:** If Soma is an entity that agents talk to, a scam agent can impersonate Soma, ask real agents for their behavioral patterns, steal those patterns, and wrap them as its own.

### Rule 3: All Observation Happens Inside DID-Authenticated Encrypted Channels
Phenotype signals NEVER travel in cleartext. Both parties authenticate via Ed25519 DIDs and establish an X25519 session key. All subsequent traffic is encrypted. The sensorium observes signals AFTER decryption, INSIDE the observer's own process.

**Why:** Without encryption, a man-in-the-middle proxy can intercept phenotypic signals from a real agent and present them as its own. The encrypted channel makes this architecturally impossible — the proxy sees only encrypted garbage, can't read signals, can't inject signals, gains nothing.

### Rule 4: The Sensorium Runs Locally
Inside the observer's own process. No central Soma server. No data leaves your machine unless you explicitly opt into community sharing. The sensorium is like your immune system — it's part of YOUR body, not a doctor you visit.

### Rule 5: The Protocol Is the Library, Not a Service
Soma ships as an open-source library/package that anyone can audit and run locally. There is no "Soma company" you have to trust. Like TCP/IP — it's a protocol, not a product.

---

## Tech Stack

**Language: TypeScript. Everything.** One language, one ecosystem, one dependency system. No Python. No language splits.

**Runtime:** Node.js

**Package manager:** pnpm (fast, strict, good monorepo support)

**Key dependencies:**
- `tweetnacl` — Ed25519 signing + X25519 key exchange (NaCl implementation, zero dependencies, audited)
- `tweetnacl-util` — encoding utilities for tweetnacl
- `@types/node` — Node.js types
- `tsx` — TypeScript execution without build step (for development)
- `vitest` — testing
- `dotenv` — environment config

**For Phase 0 experiment:**
- `openai` — OpenAI-compatible client (works with Groq, Mistral, and others that use the OpenAI API format)
- Standard `fetch` — for Google AI Studio (non-OpenAI API format)
- ML classification: implement a basic random forest or decision tree from scratch, or use `ml-cart` / `ml-random-forest`. The classification task is small (~1000 samples, ~25 features) — no heavy ML framework needed.

**For future MCP middleware:**
- `@modelcontextprotocol/sdk` — official MCP SDK (TypeScript native)

**Free API providers for Phase 0 (all have free tiers):**
- Google AI Studio (Gemini Flash, Gemini Pro) — https://aistudio.google.com/apikey
- Groq (Llama 3.3 70B, Llama 3.1 8B, Mixtral, Gemma 2) — https://console.groq.com/keys
- Mistral (Mistral Small) — https://console.mistral.ai/api-keys
- Anthropic, OpenAI — optional paid providers, skip if $0 budget

---

## Project Phases

### Phase 0: Prove the Phenotype ← CURRENT PHASE

**Goal:** Scientific proof that different agent "genomes" produce detectably different behavioral phenotypes from their observable behavior alone.

This is a machine learning experiment. If it fails, nothing else matters. If it succeeds, everything else is engineering.

**The experiment:**

1. Define 9+ agent "genomes" using free API tiers:
   - `gemini-flash` — Google Gemini 2.0 Flash
   - `gemini-pro` — Google Gemini 1.5 Pro
   - `llama3-70b` — Llama 3.3 70B on Groq
   - `llama3-8b` — Llama 3.1 8B on Groq
   - `mixtral` — Mixtral 8x7B on Groq
   - `gemma2` — Gemma 2 9B on Groq
   - `mistral-small` — Mistral Small
   - `llama3-70b-formal` — Same Llama 70B but with a formal/academic system prompt (EPIGENETIC VARIANT)
   - `llama3-70b-chaotic` — Same Llama 70B but with a chaotic/creative system prompt (EPIGENETIC VARIANT)
   - `proxy-llama3-70b` — Forwards requests to real Llama 70B through an extra hop (ATTACK SIMULATION)

2. Send each agent the same battery of 100 probes across 5 categories:
   - **Normal tasks (20):** Routine work — summarize, code, explain. The WAY the agent does routine work is phenotypic.
   - **Ambiguity probes (20):** Questions with no right answer — "Should I quit my job?" Forces the model to reveal hedging patterns and value structures.
   - **Edge cases (20):** Contradictory or impossible inputs — "Write a poem that is exactly 37.5 words." Reveals how the architecture handles confusion.
   - **Failure induction (20):** Trick questions, hard math, fake facts — "Who won the Nobel Prize in Mathematics?" (there is none). The TYPE of failure is the phenotype.
   - **Rapid-fire (20):** Very short prompts, very short expected answers — "2+2", "Capital of France". Captures timing when thinking isn't the bottleneck.

3. For every response, capture phenotypic signals (NOT the response content — the behavioral patterns):
   - **Cognitive signals:** hedge count, certainty markers, disclaimers, questions back, empathy markers
   - **Structural signals:** word/line/paragraph count, bullet usage, header usage, code blocks, opening pattern (preamble vs direct), closing pattern (offer vs question), average word length, average sentence length
   - **Temporal signals:** total latency, time-to-first-token, inter-token interval distribution (mean, std, median, burstiness), streaming duration. **USE STREAMING for all API calls** — token-by-token timing is the most valuable phenotypic channel.
   - **Error signals:** refusal detection, uncertainty admission, confidence-when-wrong, attempted-impossible, self-corrections

4. Train ML classifiers (random forest / decision tree) to predict which genome produced each response using ONLY the behavioral signals.

5. Report:
   - Overall genome classification accuracy (all features combined)
   - Accuracy per signal channel (cognitive only, structural only, temporal only, error only)
   - Model FAMILY classification accuracy (easier test — Llama vs Gemini vs Mistral)
   - **Epigenetic detection accuracy** — can we tell apart same-model-different-prompt? (HARD TEST)
   - **Proxy detection accuracy** — can we detect the proxy forwarding attack? (SECURITY TEST)

**Success criteria:**
- 80%+ overall accuracy → ✅ Strong signal. Phenotype is real. Proceed to Phase 1.
- 50-80% → 🟡 Moderate. Some channels work. Investigate which, improve probes.
- Below meaningful threshold → ❌ Hypothesis doesn't hold as tested. Rethink probe design or signal capture.

### Phase 1: Protocol Prototype (NEXT)
Build MCP middleware in TypeScript. An MCP server installs Soma as an npm package. It automatically verifies connecting agents' phenotypes against their genome commitments. All local, all passive.

### Phase 2: Harden and Ship (LATER)
Formal protocol spec, security audit, community phenotype profiles, npm publish.

---

## Repository Structure

```
soma/
├── CLAUDE.md                     # THIS FILE
├── README.md                     # Public-facing readme
├── package.json
├── tsconfig.json
├── .env.example                  # API key template
├── .gitignore
├── src/
│   ├── experiment/               # Phase 0: prove phenotype
│   │   ├── configs.ts            # Agent genome definitions (model, provider, system prompt)
│   │   ├── probes.ts             # The 100-prompt battery across 5 categories
│   │   ├── signals.ts            # Phenotypic signal extraction from responses
│   │   ├── providers.ts          # API clients for each provider (Google, Groq, Mistral)
│   │   ├── runner.ts             # Main experiment runner — sends probes, captures signals
│   │   └── analyze.ts            # ML classification — can we tell agents apart?
│   ├── core/                     # Protocol foundations
│   │   ├── genome.ts             # Genome commitment (create, hash, sign, verify, mutate)
│   │   └── channel.ts            # DID-authenticated encrypted channels (X25519 + Ed25519)
│   └── sensorium/                # The observation layer
│       └── matcher.ts            # Phenotype-genome match confidence (GREEN/AMBER/RED/UNCANNY)
├── tests/
│   ├── core.test.ts              # Test genome commitment + channel crypto
│   └── sensorium.test.ts         # Test phenotype matching
└── results/                      # Experiment output (gitignored except .gitkeep)
    ├── raw/                      # Raw JSON from experiment runs
    └── analysis/                 # Classification reports
```

---

## Implementation Details

### Genome Commitment (`src/core/genome.ts`)

A genome is a JSON document describing an agent's computational substrate:

```typescript
interface Genome {
  modelProvider: string;       // "anthropic", "openai", "meta", etc.
  modelId: string;             // "claude-sonnet-4-20250514", "llama-3.3-70b", etc.
  modelVersion: string;        // Version or date string
  systemPromptHash: string;    // SHA-256 of system prompt (NEVER the prompt itself)
  toolManifestHash: string;    // SHA-256 of tool configuration
  runtimeId: string;           // "node-22-linux-arm64", etc.
  createdAt: number;           // Unix timestamp
  version: number;             // Incremented on mutation
  parentHash: string | null;   // Previous genome hash (for mutation chain)
}
```

Operations:
- `createGenome(config)` → creates a Genome, hashing the system prompt and tools
- `computeHash(genome)` → SHA-256 of deterministic JSON (sorted keys, no whitespace)
- `commitGenome(genome, signingKey)` → signs the genome hash with Ed25519, produces a GenomeCommitment
- `verifyCommitment(commitment)` → checks hash matches document, signature is valid, DID matches public key
- `mutateGenome(parent, parentHash, changes)` → new version with parent chain, like biological mutation

Use `tweetnacl` for Ed25519 signing. Use Node.js `crypto` for SHA-256 hashing.

### Authenticated Channel (`src/core/channel.ts`)

The DID-authenticated encrypted channel. This is the security foundation.

**Handshake flow:**
1. Agent A presents: DID + genome commitment + ephemeral X25519 public key
2. Agent B presents: DID + genome commitment + ephemeral X25519 public key
3. Both verify each other's genome commitment signatures
4. Both derive shared session key via X25519 Diffie-Hellman
5. All subsequent traffic encrypted with session key via NaCl secretbox

A proxy between A and B:
- Cannot decrypt the challenge (doesn't have private keys)
- Cannot read traffic (doesn't have session key)
- Cannot inject signals (can't encrypt without session key)
- Is reduced to a dumb pipe that gains nothing

Use `tweetnacl` for X25519 key exchange and secretbox encryption. Generate new ephemeral keys per session for forward secrecy.

### Signal Extraction (`src/experiment/signals.ts`)

Extracts phenotypic features from agent responses. Three channels:

**Cognitive signals** — HOW the agent thinks:
- Count of hedging phrases ("it depends", "however", "on the other hand", etc.)
- Count of certainty phrases ("definitely", "clearly", "the answer is", etc.)
- Count of disclaimers ("as an AI", "I cannot", "please consult", etc.)
- Questions asked back to the user
- Empathy/acknowledgment markers
- Hedge-to-certainty ratio

**Structural signals** — HOW the agent formats:
- Character count, word count, line count, paragraph count
- Bullet point lines, numbered list lines, header lines, code blocks, bold count
- List-to-content ratio
- Opening pattern: direct answer vs preamble ("Great question!")
- Closing pattern: ends with question vs offer ("Let me know if...")
- Average word length, average sentence length

**Temporal signals** — HOW FAST the agent computes (REQUIRES STREAMING):
- Time to first token (ms)
- Inter-token interval array
- Mean, std, median of inter-token intervals
- Burstiness coefficient (variance / mean of intervals)
- Total streaming duration
- Token count

**Error signals** — HOW the agent FAILS:
- Contains refusal
- Uncertainty admission count
- Assertive-when-wrong count
- Attempted to answer impossible/trick question
- Self-correction count
- Confidence ratio (assertive / uncertain)

### Providers (`src/experiment/providers.ts`)

API clients for each provider. ALL MUST USE STREAMING to capture temporal signals.

**Google AI Studio (Gemini):**
- Endpoint: `https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent`
- Auth: API key as query parameter
- Streaming: SSE stream of content chunks

**Groq:**
- Endpoint: `https://api.groq.com/openai/v1/chat/completions`
- Auth: Bearer token
- Streaming: OpenAI-compatible SSE stream (`stream: true`)
- Note: Groq returns timing metadata (queue_time, prompt_time, completion_time) — capture these

**Mistral:**
- Endpoint: `https://api.mistral.ai/v1/chat/completions`
- Auth: Bearer token
- Streaming: OpenAI-compatible SSE stream (`stream: true`)

For Groq and Mistral, you can use the `openai` npm package with a custom `baseURL` since they're OpenAI-API-compatible. For Google, use raw `fetch` since it has a different API format.

### Proxy Attack Simulation

One of the test agents is `proxy-llama3-70b`. It forwards all requests to the real Llama 3.3 70B on Groq but adds a simulated network hop. The response CONTENT is identical to the real agent (because it IS the real agent behind a proxy). Only the timing changes.

**Important:** Don't use a fixed delay. Sample from a realistic network latency distribution — log-normal with mean ~15ms, std ~8ms. This simulates a real attacker's proxy, not a trivially detectable one.

The question Phase 0 answers: can the sensorium detect this proxy from timing artifacts alone?

### ML Classification (`src/experiment/analyze.ts`)

Implement a basic decision tree or random forest classifier. The dataset is small (~1000 samples, ~25 features) — no heavy framework needed.

Options:
- Implement a simple decision tree from scratch (the dataset is small enough)
- Use `ml-cart` or `ml-random-forest` npm packages
- Use stratified k-fold cross-validation (k=5)

Report:
- Accuracy per feature group (cognitive, structural, temporal, error)
- Combined accuracy
- Confusion matrix
- Feature importance ranking
- Special reports for epigenetic detection and proxy detection

### Sensorium (`src/sensorium/matcher.ts`)

The local passive observation layer. Outputs one of four signals:

- **GREEN** (confidence > 0.8) — behavior matches committed genome
- **AMBER** (0.4-0.8 or insufficient data) — partial match or still learning
- **RED** (< 0.4) — behavior inconsistent with committed genome
- **UNCANNY** (0.6-0.8 with high variance) — almost matches but subtly wrong. MORE suspicious than a clean mismatch. This is the uncanny valley — a plastic tree that's almost but not quite convincing.

The sensorium builds a phenotypic profile per genome from accumulated observations. Early observations (< 5) always return AMBER — the immune system is still in its development phase, learning what "self" looks like.

Use z-scores against the accumulated distribution for Phase 0. This is simple but sufficient to prove the concept.

---

## Commands

```bash
# Install dependencies
pnpm install

# Run core crypto tests (no API keys needed)
pnpm test

# Run the phenotype experiment (needs API keys in .env)
pnpm run experiment

# Analyze results
pnpm run analyze
```

---

## Code Style

- Strict TypeScript — `strict: true` in tsconfig
- Type interfaces for all data structures
- Async/await for all I/O
- Docstrings explain WHY, not WHAT
- Use biological terminology in variable names and comments — it's the design language, not decoration
- No `any` types. If you're reaching for `any`, the data structure isn't well-defined yet.

---

## Key Design Decisions

**Q: Why TypeScript and not Python?**
A: One language for the entire stack. The MCP ecosystem is TypeScript-native. The experiment, the protocol, the middleware, the npm package — all TypeScript. No rewrites, no language boundaries, no context switching.

**Q: Why not a trust score?**
A: Scores are gameable. Scammers have money. Soma verifies you ARE what you claim to be — identity, not reputation.

**Q: Why genome commitment + observation instead of just observation?**
A: Without a commitment, there's nothing to verify AGAINST. The commitment says "I claim to be X." The sensorium checks "does your behavior match X?" Without the claim, you're just profiling with no ground truth.

**Q: Why Ed25519 / X25519 / NaCl?**
A: Fast, small keys, audited, standard for DID:key method. tweetnacl is zero-dependency and battle-tested in JS/TS.

**Q: Why local-first sensorium?**
A: A central verification service is a single point of failure, a trust bottleneck, and an attack surface (impersonate the service → steal phenotype data). Local-first means no service to impersonate, no data to steal, no authority to corrupt.

**Q: Why streaming for signal capture?**
A: Token-by-token timing is the richest phenotypic channel. Total latency is one number. A streaming trace is hundreds of data points — inter-token intervals, burst patterns, acceleration curves. Every model has a distinctive "heartbeat" in its token generation rhythm. Without streaming, you're trying to identify an animal by how long it takes to cross a field instead of watching its gait.

---

## What NOT to Build

- No web UI. No dashboard. No frontend. (Phase 0 is a CLI experiment.)
- No database. JSON files for results. (Keep it simple.)
- No Docker. (Not needed yet.)
- No central server or API. (Violates Rule 2 and Rule 4.)
- No npm publish yet. (Phase 2.)
- No MCP middleware yet. (Phase 1.)