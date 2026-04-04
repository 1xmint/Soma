# Soma Philosophy

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
