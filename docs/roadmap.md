# Soma Roadmap

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
