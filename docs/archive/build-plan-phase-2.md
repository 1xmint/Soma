Status: archived
See instead: docs/proposals/roadmap.md

# Soma Build Plan — Phase 2

Status: archived


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
