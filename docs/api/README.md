# soma-heart API Reference

API reference for all public subpath exports of the `soma-heart` package.

**Install:** `pnpm add soma-heart`

---

## Table of Contents

- [`.` — Heart Runtime](#-heart-runtime)
- [`./core` — Genome Primitives](#core--genome-primitives)
- [`./credential-rotation` — Rotation Lifecycle](#credential-rotation--rotation-lifecycle)
- [`./crypto-provider` — Crypto Abstraction](#crypto-provider--crypto-abstraction)
- [`./sense` — Sensorium](#sense--sensorium)
- [`./senses` — Individual Sense Modules](#senses--individual-sense-modules)
- [`./atlas` — Phenotype Atlas](#atlas--phenotype-atlas)
- [`./mcp` — MCP Middleware](#mcp--mcp-middleware)
- [`./certificate` — Certificate Module](#certificate--certificate-module)
- [`./signals` — Experimental Signals](#signals--experimental-signals)
- [`./supply-chain` — Supply Chain](#supply-chain--supply-chain)

---

## `.` — Heart Runtime

```ts
import { createSomaHeart, HeartRuntime } from 'soma-heart'
```

The execution heart: holds all credentials, routes computation, and weaves
cryptographic seeds and heartbeats into every output. This is the primary
entry point for agent operators.

### Functions

| Name | Signature | Description |
|---|---|---|
| `createSomaHeart` | `(config: HeartConfig) => HeartRuntime` | Create and initialize a heart from config |
| `loadSomaHeart` | `(state: HeartState, password: string) => Promise<HeartRuntime>` | Restore a heart from encrypted persisted state |
| `createDelegation` | `(heart, opts) => Delegation` | Issue a capability delegation token |
| `attenuateDelegation` | `(d: Delegation, caveats) => Delegation` | Narrow a delegation with additional caveats |
| `verifyDelegation` | `(d, pk, ctx, opts?) => DelegationVerification` | Verify a delegation signature and caveats |
| `verifyDelegationChain` | `(chain, opts?) => ChainVerificationResult` | Walk a delegation chain leaf-to-root, verifying all links |
| `checkCaveats` | `(caveats, ctx, evaluator?) => boolean` | Evaluate a delegation's caveat set against a context |
| `createLineageCertificate` | `(parent, child, opts) => LineageCertificate` | Create a signed parent→child lineage certificate |
| `verifyLineageCertificate` | `(cert, pk) => LineageVerification` | Verify a lineage certificate signature |
| `verifyLineageChain` | `(chain) => LineageVerification` | Verify an entire lineage chain from root |
| `forkCeremony` | `(opts: ForkCeremonyOptions) => ForkCeremonyResult` | Offline lineage provisioning ceremony |
| `createRevocation` | `(key, target, reason) => RevocationEvent` | Create a signed revocation event |
| `verifyRevocation` | `(event, pk) => RevocationVerification` | Verify a revocation event signature |
| `signReceipt` | `(payload, keyPair) => SignedReceipt` | Sign a reception receipt for accountability |
| `verifyReceipt` | `(receipt, pk) => boolean` | Verify a signed reception receipt |
| `receiptCanonical` | `(payload: ReceiptPayload) => string` | Canonical JSON serialization of a receipt |
| `checkKeyEffective` | `(lookup, pk, ts) => HistoricalKeyLookupResult` | Check if a public key was effective at a given timestamp |
| `splitSecret` | `(secret, n, k, opts?) => SecretShare[]` | Split a secret into N shares, K required to reconstruct |
| `reconstructSecret` | `(shares: SecretShare[]) => Uint8Array` | Reconstruct a secret from threshold shares |
| `evaluateVrf` | `(input, secretKey) => VrfOutput` | Evaluate a verifiable random function |
| `verifyVrf` | `(input, output, pk) => VrfVerification` | Verify a VRF output |
| `serializeHeart` | `(heart, password) => Promise<EncryptedBlob>` | Encrypt and serialize heart state to disk |
| `loadHeartState` | `(blob, password) => Promise<HeartState>` | Decrypt heart state from an encrypted blob |
| `deriveSeed` | `(config: SeedConfig) => HeartSeed` | Derive a cryptographic seed from heart config |
| `applySeed` | `(seed, data) => string` | Apply seed entanglement to output data |
| `generateThresholdKeyPair` | `(opts) => ThresholdKeyPair` | Generate a threshold M-of-N Ed25519 key pair |
| `thresholdSign` | `(shares, message) => ThresholdSignature` | Produce a threshold signature from key shares |
| `generateHybridKeyPair` | `(algs) => HybridKeyPair` | Generate a hybrid (multi-algorithm) key pair |
| `hybridSign` | `(keyPair, message, policy?) => HybridSignature` | Sign with all algorithms in the hybrid pair |
| `createBirthCertificate` | `(data, keyPair, opts?) => BirthCertificate` | Create a data provenance birth certificate |
| `verifyBirthCertificate` | `(cert, pk) => boolean` | Verify a birth certificate's signature and integrity |
| `issueTimeWitness` | `(keyPair, opts?) => TimeWitness` | Issue a signed time witness |
| `verifyTimeWitness` | `(witness, pk) => WitnessVerification` | Verify a signed time witness |
| `issueChallenge` | `(opts?) => Challenge` | Issue a proof-of-possession challenge |
| `proveChallenge` | `(challenge, keyPair) => PossessionProof` | Prove possession of a private key |
| `verifyProof` | `(challenge, proof, pk) => ProofVerification` | Verify a proof-of-possession response |
| `initiateSession` | `(keyPair, opts?) => SessionInit` | Initiate a mutual session handshake |
| `acceptSession` | `(init, keyPair) => SessionAccept` | Accept a mutual session handshake |
| `confirmSession` | `(accept, init, keyPair) => SessionConfirm` | Confirm a mutual session handshake |
| `buildSomaCheckResponseHeaders` | `(data, keyStore) => Headers` | Build Soma Check response headers for conditional payment |
| `verifyDataHashConsistency` | `(cert, header) => boolean` | Compare a birth-certificate dataHash against X-Soma-Hash header |
| `evaluateLadder` | `(input, ladder?) => CeremonyTier` | Evaluate a tier ladder against provided factors |


### Key Types

| Type | Description |
|---|---|
| `HeartConfig` | Runtime configuration: genome commitment, signing key, model API settings |
| `HeartRuntime` | The live heart instance — call `.generate()`, `.callTool()`, `.fetchData()` |
| `Delegation` | Macaroon-style capability token with caveats |
| `Caveat` | A restriction on a delegation (time, audience, capability scope) |
| `CustomCaveatEvaluator` | Callback for evaluating `custom` caveat types; unhandled caveats fail closed |
| `ChainVerificationResult` | Result of walking a delegation chain leaf-to-root |
| `SignedReceipt` | Accountability receipt attesting a verifier's evaluation outcome |
| `ReceiptOutcome` | `"pass" \| "fail" \| "inconclusive"` |
| `EVIDENCE_SUMMARY_MAX` | Constant (512 chars) — maximum evidence summary length |
| `SOMA_CHECK_MIN_HASH_LENGTH` | Constant (16 hex chars) — minimum acceptable Soma Check hash length |
| `HeartSeed` | Cryptographic seed derived from genome + environment |
| `ThresholdKeyPair` | M-of-N Ed25519 key pair with individual shares |
| `HybridKeyPair` | Multi-algorithm key pair for post-quantum migration |
| `BirthCertificate` | Data provenance record with source signature and data hash |
| `HistoricalKeyLookup` | Interface for rotation-aware key validity checks |

### Usage Examples

**Create and use a heart:**
```ts
import { createSomaHeart } from 'soma-heart';

const heart = createSomaHeart({
  genome: commitment,
  signingKeyPair: keyPair,
  modelApiKey: process.env.ANTHROPIC_API_KEY,
  modelBaseUrl: 'https://api.anthropic.com/v1',
  modelId: 'claude-sonnet-4-20250514',
});

const result = await heart.generate({ messages: [{ role: 'user', content: 'Hello' }] });
```

**Issue and verify a delegation:**
```ts
import { createDelegation, verifyDelegation } from 'soma-heart';

const delegation = createDelegation(heart, {
  subject: recipientDid,
  capabilities: ['read:data'],
  expiresAt: Date.now() + 3600_000,
});

const result = verifyDelegation(delegation, issuerPublicKey, {
  now: Date.now(),
  audience: myDid,
});
```

**Verify a delegation chain:**
```ts
import { verifyDelegationChain } from 'soma-heart';

const result = verifyDelegationChain([leaf, mid, root], {
  now: Date.now(),
  trustedRoots: [rootPublicKey],
});
if (result.ok) console.log('Chain valid, effective caps:', result.capabilities);
```

**Persist and restore a heart:**
```ts
import { serializeHeart, loadSomaHeart } from 'soma-heart';

const blob = await serializeHeart(heart, 'strong-password');
// ... later ...
const heart2 = await loadSomaHeart(blob, 'strong-password');
```

---

## `./core` — Genome Primitives

```ts
import { createGenome, commitGenome, verifyCommitment } from 'soma-heart/core'
```

Core genome types and operations. A genome is the agent's immutable identity
declaration — model, system prompt hash, tool manifest hash, runtime metadata.
Committing a genome binds it to a key pair and creates a verifiable `did:key`.

### Functions

| Name | Signature | Description |
|---|---|---|
| `createGenome` | `(config) => Genome` | Create a genome from agent configuration |
| `computeHash` | `(genome: Genome, provider?) => string` | Compute the canonical hash of a genome |
| `commitGenome` | `(genome, keyPair, provider?) => GenomeCommitment` | Sign a genome hash to produce a verifiable commitment |
| `verifyCommitment` | `(commitment, provider?) => boolean` | Verify hash integrity, signature, and DID match |
| `mutateGenome` | `(parent, parentHash, changes) => Genome` | Create a new genome version linked to its parent |
| `publicKeyToDid` | `(publicKey, provider?) => string` | Encode a public key as a `did:key` identifier |
| `didToPublicKey` | `(did, provider?) => Uint8Array` | Decode a `did:key` back to raw public key bytes |
| `sha256` | `(data: string, provider?) => string` | Hash a string, returning hex digest |

### Key Types

| Type | Description |
|---|---|
| `Genome` | Agent identity: model, prompt hash, tool hash, runtime metadata, version chain |
| `GenomeCommitment` | Signed genome: genome + hash + signature + public key + DID |
| `SignKeyPair` | `{ publicKey: Uint8Array, secretKey: Uint8Array }` |

### Usage Examples

**Create and commit a genome:**
```ts
import { createGenome, commitGenome, verifyCommitment } from 'soma-heart/core';

const genome = createGenome({
  modelProvider: 'anthropic',
  modelId: 'claude-sonnet-4-20250514',
  modelVersion: '1.0',
  systemPrompt: mySystemPrompt,
  toolManifest: JSON.stringify(tools),
  runtimeId: 'prod-us-east-1',
});

const commitment = commitGenome(genome, keyPair);
console.log(commitment.did); // did:key:z6Mk...

const valid = verifyCommitment(commitment);
```

---

## `./credential-rotation` — Rotation Lifecycle

```ts
import { CredentialRotationController } from 'soma-heart/credential-rotation'
```

Credential rotation lifecycle with twelve invariants from the rotation
architecture spec. The `CredentialRotationController` is the only
user-facing rotation API.

### Functions & Classes

| Name | Signature | Description |
|---|---|---|
| `CredentialRotationController` | `class` | Manages the full rotation lifecycle with policy enforcement |
| `Ed25519IdentityBackend` | `class` | Ed25519 credential backend for identity keys |
| `MockCredentialBackend` | `class` | In-memory backend for testing |
| `computeManifestCommitment` | `(manifest: CredentialManifest) => string` | Hash a credential manifest to a commitment string |
| `verifyRotationChain` | `(events: RotationEvent[]) => boolean` | Verify the integrity of a rotation event chain |
| `DEFAULT_POLICY` | `ControllerPolicy` | Default rotation policy (recommended starting point) |
| `DEFAULT_TTL_POLICY` | `TtlPolicy` | Default TTL policy for credential expiry |
| `POLICY_FLOORS` | `object` | Minimum enforced values for policy parameters |

### Error Classes

`BackendNotAllowlisted` · `ChallengePeriodActive` · `CredentialExpired` ·
`DuplicateBackend` · `InvariantViolation` · `NotYetEffective` ·
`PreRotationMismatch` · `RateLimitExceeded` · `StagedRotationConflict` ·
`SuiteDowngradeRejected` · `VerifyBeforeRevokeFailed`

### Key Types

| Type | Description |
|---|---|
| `ControllerOptions` | Constructor options: backends, policy, clock |
| `ControllerPolicy` | Rotation policy: challenge period, rate limits, allowed suites |
| `Credential` | A credential record: key material, algorithm suite, effective period |
| `CredentialBackend` | Interface for pluggable credential storage backends |
| `CredentialManifest` | Snapshot of current credentials and rotation state |
| `RotationEvent` | A single rotation step in the append-only event log |
| `AlgorithmSuite` | `"ed25519"` or other registered algorithm identifier |
| `HistoricalCredentialLookupResult` | Result of looking up a credential effective at a past timestamp |

### Usage Examples

**Create a controller and rotate:**
```ts
import { CredentialRotationController, Ed25519IdentityBackend, DEFAULT_POLICY } from 'soma-heart/credential-rotation';

const controller = new CredentialRotationController({
  backends: [new Ed25519IdentityBackend()],
  policy: DEFAULT_POLICY,
});

await controller.stage();        // stage the pre-rotation key
await controller.commit();       // commit after challenge period
await controller.revokePrevious(); // revoke the old credential
```

---

## `./crypto-provider` — Crypto Abstraction

```ts
import { getCryptoProvider, setCryptoProvider } from 'soma-heart/crypto-provider'
```

Algorithm-agnostic cryptographic abstraction layer. The default provider
uses Ed25519 / X25519 / NaCl secretbox / SHA-256. Swap in post-quantum
algorithms by providing a custom `CryptoProvider`.

### Functions

| Name | Signature | Description |
|---|---|---|
| `getCryptoProvider` | `() => CryptoProvider` | Get the currently active global crypto provider |
| `setCryptoProvider` | `(provider: CryptoProvider) => void` | Replace the global provider (affects all subsequent calls) |

### Key Interfaces

| Interface | Description |
|---|---|
| `CryptoProvider` | Full provider: signing, keyExchange, encryption, hashing, hmac, encoding, random |
| `SigningProvider` | `generateKeyPair()`, `sign()`, `verify()` + `algorithmId`, `multicodecPrefix` |
| `KeyExchangeProvider` | `generateKeyPair()`, `deriveSharedKey()` |
| `SymmetricEncryptionProvider` | `encrypt()`, `decrypt()`, `nonceLength` |
| `HashingProvider` | `hash()`, `deriveKey()` (HKDF) |
| `HmacProvider` | `compute()`, `verify()` |
| `EncodingProvider` | `encodeBase64()`, `decodeBase64()`, `encodeUTF8()`, `decodeUTF8()` |
| `SignKeyPair` | `{ publicKey: Uint8Array, secretKey: Uint8Array }` |
| `BoxKeyPair` | `{ publicKey: Uint8Array, secretKey: Uint8Array }` (key-exchange pair) |

### Usage Examples

**Custom provider swap (post-quantum migration):**
```ts
import { setCryptoProvider } from 'soma-heart/crypto-provider';
import { dilithiumProvider } from './my-pq-provider';

setCryptoProvider(dilithiumProvider);
// All subsequent heart operations use Dilithium signing
```

**Direct crypto operations:**
```ts
import { getCryptoProvider } from 'soma-heart/crypto-provider';

const p = getCryptoProvider();
const keyPair = p.signing.generateKeyPair();
const sig = p.signing.sign(message, keyPair.secretKey);
const valid = p.signing.verify(message, sig, keyPair.publicKey);
```

---

## `./sense` — Sensorium

```ts
import { withSomaSense, getVerdict } from 'soma-heart/sense'
```

The observer's organ — wraps an MCP transport with passive behavioral
verification. Extracts phenotypic signals from the token stream, maintains
an agent profile, and produces GREEN/AMBER/RED/UNCANNY verdicts.

### Functions

| Name | Signature | Description |
|---|---|---|
| `withSomaSense` | `(inner: Transport, config: SomaConfig) => SomaTransport` | Wrap an MCP transport with Soma sensory verification |
| `getVerdict` | `(transport: Transport) => SomaVerdict \| null` | Get the current verdict from a sense-wrapped transport |
| `isSomaEnabled` | `(transport: Transport) => boolean` | Check if a transport has Soma sensing active |
| `createSomaIdentity` | `(genomeConfig) => SomaIdentity` | Generate a key pair + genome commitment identity |
| `verifyClawNetReceipt` | `(receipt, opts?) => ReceiptVerificationResult` | Verify a ClawNet accountability receipt |
| `fetchAndVerifyReceipt` | `(url, opts?) => Promise<ReceiptVerificationResult>` | Fetch and verify a receipt from a URL |
| `createProfile` | `(signals) => PhenotypicProfile` | Create an initial behavioral profile from signals |
| `updateProfile` | `(profile, signals) => PhenotypicProfile` | Update a profile with new observations (Welford online) |
| `match` | `(profile, signals) => Verdict` | Match signals against a profile, returning a verdict |
| `createSmartFetch` | `(config: SmartFetchConfig) => SmartFetch` | Create a Soma-Check-aware fetch client |
| `buildSomaCheckRequestHeaders` | `(url, keyStore) => Headers` | Build Soma Check request headers |

### Key Types

| Type | Description |
|---|---|
| `SomaConfig` | Sensorium config: genome, signingKeyPair, profileStorePath, onVerdict callback |
| `SomaVerdict` | Verdict result: status, score, remoteDid, sessionId |
| `VerdictStatus` | `"GREEN" \| "AMBER" \| "RED" \| "UNCANNY"` |
| `PhenotypicProfile` | Online behavioral profile built from Welford statistics |
| `EnhancedVerdict` | Extended verdict with drift velocity and category awareness |

### Usage Examples

**Wrap an MCP transport (observer mode):**
```ts
import { withSomaSense, getVerdict } from 'soma-heart/sense';

const transport = withSomaSense(new StdioServerTransport(), {
  genome: identity.commitment,
  signingKeyPair: identity.keyPair,
  onVerdict: (sessionId, verdict) => {
    if (verdict.status === 'RED') denyAccess(sessionId);
  },
});

await server.connect(transport);
```

---

## `./senses` — Individual Sense Modules

```ts
import { extractTemporalSignals, SENSE_WEIGHTS } from 'soma-heart/senses'
```

Individual sensory channel extractors. Three primary senses (temporal,
topology, vocabulary) plus logprob are used in the focused classifier.
Seven legacy senses are exported for backward compatibility with
experiment infrastructure.

### Primary Senses

| Name | Signature | Description |
|---|---|---|
| `extractTemporalSignals` | `(trace: StreamingTrace) => TemporalSignals` | Extract timing fingerprint signals (5× weight, 88.5% standalone accuracy) |
| `temporalToFeatureVector` | `(signals) => number[]` | Convert temporal signals to a feature vector |
| `extractTopologySignals` | `(text: string) => TopologySignals` | Extract response structure signals (2× weight, 25.1%) |
| `topologyToFeatureVector` | `(signals) => number[]` | Convert topology signals to a feature vector |
| `extractVocabularySignals` | `(text: string) => VocabularySignals` | Extract word-choice distribution signals (1× weight, 20.2%) |
| `vocabularyToFeatureVector` | `(signals) => number[]` | Convert vocabulary signals to a feature vector |
| `extractLogprobSignals` | `(logprobs) => LogprobSignals` | Extract token log-probability signals (3× weight when available) |
| `SENSE_WEIGHTS` | `const` | `{ temporal: 5, logprob: 3, topology: 2, vocabulary: 1 }` |

### Legacy Senses (backward compatibility)

`extractCapabilityBoundarySignals` · `extractToolInteractionSignals` ·
`extractAdversarialSignals` · `extractEntropySignals` ·
`extractConsistencySignals` · `extractContextUtilizationSignals` ·
`extractCalibrationSignals` · `extractMultiTurnSignals`

Each follows the pattern `extract<X>Signals(input) => <X>Signals` and has a
corresponding `<x>ToFeatureVector` and `<X>_FEATURE_NAMES` constant.

---

## `./atlas` — Phenotype Atlas

```ts
import { PhenotypeAtlas, DEFAULT_SENSE_WEIGHTS } from 'soma-heart/atlas'
```

Reference classification — memoryless anti-drift defense. Maintains
reference profiles for known agent genomes and classifies observations
against them independently of the agent's own history.

### Classes & Constants

| Name | Description |
|---|---|
| `PhenotypeAtlas` | Reference classifier; maintains profiles and classifies observations |
| `DEFAULT_SENSE_WEIGHTS` | `{ temporal: 5, topology: 2, vocabulary: 1 }` |

### `PhenotypeAtlas` Methods

| Method | Signature | Description |
|---|---|---|
| `setProfile` | `(profile: ReferenceProfile) => void` | Add or replace a reference profile |
| `updateProfile` | `(hash, label, features) => void` | Update a profile with one new observation (Welford) |
| `classifyObservation` | `(features, declaredGenome) => AtlasClassification` | Classify observation against all reference profiles |
| `getProfile` | `(hash: string) => ReferenceProfile \| undefined` | Retrieve a reference profile by genome hash |
| `size` | `number` | Number of reference profiles in the atlas |

### Key Types

| Type | Description |
|---|---|
| `ReferenceProfile` | Reference stats for one known genome: temporal/topology/vocabulary feature stats |
| `AtlasClassification` | Classification result: nearest genome, distance, margin, match flag |
| `SenseFeatures` | Features organized by sense: `{ temporal, topology, vocabulary }` |
| `SenseWeights` | Per-sense weight multipliers for the classifier |

### Usage Examples

**Classify an observation:**
```ts
import { PhenotypeAtlas } from 'soma-heart/atlas';

const atlas = new PhenotypeAtlas();
atlas.setProfile(claudeReferenceProfile);
atlas.setProfile(gpt4ReferenceProfile);

const result = atlas.classifyObservation(extractedFeatures, agentGenomeHash);
if (!result.match) {
  console.warn(`Agent claims ${result.declaredGenome} but looks like ${result.nearestLabel}`);
}
```

---

## `./mcp` — MCP Middleware

```ts
import { withSoma, createSomaIdentity } from 'soma-heart/mcp'
```

MCP transport middleware with Soma identity verification. Integrates the
heart into MCP servers. Phase 1 (observation only) wraps any transport;
Phase 2 (heart-integrated) routes computation through the heart.

### Functions

| Name | Signature | Description |
|---|---|---|
| `withSoma` | `(inner: Transport, config: SomaConfig) => SomaTransport` | Wrap an MCP transport with Soma identity + optional heart |
| `createSomaIdentity` | `(genomeConfig) => SomaIdentity` | Generate key pair + genome commitment for a new server |
| `getVerdict` | `(transport: Transport) => SomaVerdict \| null` | Get the current verification verdict |
| `getHeart` | `(transport: Transport) => HeartRuntime \| null` | Get the heart runtime from a Soma transport |
| `isSomaEnabled` | `(transport: Transport) => boolean` | Check if a transport has Soma active |
| `createSomaHeart` | `(config: HeartConfig) => HeartRuntime` | Re-export: create a heart (same as root entry) |

### Key Types

| Type | Description |
|---|---|
| `SomaIdentity` | `{ keyPair: SignKeyPair, commitment: GenomeCommitment }` |
| `SomaConfig` | Transport config: genome commitment, signing key, optional heart, profile store |
| `SomaVerdict` | Verification verdict from the sensorium |
| `SomaMetadata` | Per-message metadata injected by the heart |

### Usage Examples

**Phase 1 — observation only:**
```ts
import { withSoma, createSomaIdentity } from 'soma-heart/mcp';

const identity = createSomaIdentity({ modelProvider: 'anthropic', ... });
const transport = withSoma(new StdioServerTransport(), {
  genome: identity.commitment,
  signingKeyPair: identity.keyPair,
});
await server.connect(transport);
```

**Phase 2 — heart-integrated:**
```ts
import { withSoma, createSomaHeart } from 'soma-heart/mcp';

const heart = createSomaHeart({ genome: commitment, signingKeyPair, modelApiKey, ... });
const transport = withSoma(new StdioServerTransport(), {
  genome: commitment,
  signingKeyPair,
  heart,
});
await server.connect(transport);
const analysis = await transport.getHeart().generate({ messages });
```

---

## `./certificate` — Certificate Module

```ts
import { canonicalizePayload, evaluatePolicy } from 'soma-heart/certificate'
```

Gate 6 public surface of the certificate module. Covers canonicalization,
vector conformance, vocabulary validation, failure modes, verifier policy,
Soma Check binding, payment rail binding, chain evaluation, disclosure
enforcement, and heart-to-heart verification. 12 functional areas total.

Internal rotation lookup and signature verification primitives are
**not** exported from this subpath.

### Areas 1–3: Canonicalization

| Name | Description |
|---|---|
| `canonicalizePayload` | Deterministically serialize a certificate payload |
| `computeCertificateId` | Derive a canonical certificate ID from a payload |
| `computeSignatureInput` | Compute the bytes-to-sign for a certificate |
| `computeSignatureInputHash` | Hash the signature input |
| `CanonicalisationError` | Error class for canonicalization failures |
| `SignerRole` | Type: `"issuer" \| "subject" \| "witness"` |

### Area 4: Vector Loading

| Name | Description |
|---|---|
| `loadManifest` | Load a test vector manifest from disk |
| `VectorLoadError` | Error class for manifest loading failures |
| `Manifest` · `Vector` · `VectorSignatureInput` · `VectorVerifierPolicy` · `RotationFixtureIdentity` | Vector conformance types |

### Areas 5–7: Vocabulary Validators

| Name | Description |
|---|---|
| `validateProfile` | Validate a certificate profile identifier |
| `validateClaimKind` | Validate a claim kind against the registry |
| `validateEvidenceKind` | Validate an evidence kind against the registry |
| `Disposition` | `"accepted" \| "rejected" \| "unknown"` |
| `VocabularyResult` | `{ disposition, reason? }` |

### Area 8: Verifier Policy Evaluator

| Name | Description |
|---|---|
| `evaluatePolicy` | Evaluate a certificate against a verifier policy |
| `VerifierPolicy` | Policy: required claims, forbidden profiles, min evidence count |
| `PolicyCertificateInput` | Certificate input for policy evaluation |
| `PolicyEvalResult` / `PolicyEvalOk` / `PolicyEvalFail` | Union result type |
| `PolicyViolation` | A specific policy violation record |

### Area 10: Soma Check Binding

| Name | Description |
|---|---|
| `bindSomaCheckEvidence` | Bind a Soma Check receipt into certificate evidence |
| `SomaCheckReceiptInput` · `FreshnessClaimBinding` · `EvidenceReferenceBinding` | Binding input types |
| `SomaCheckBindingResult` / `Ok` / `Fail` | Union result type |

### Area 11: Payment Rail Binding

| Name | Description |
|---|---|
| `bindPaymentRailEvidence` | Bind payment rail evidence into certificate evidence |
| `PaymentRailReceiptInput` · `PaymentClaimBinding` · `PaymentEvidenceBinding` | Binding input types |
| `PaymentRailBindingResult` / `Ok` / `Fail` | Union result type |

### Area 12: Failure Modes

| Name | Description |
|---|---|
| `FAILURE_MODES` | Registry of all defined failure mode strings |
| `isFailureMode` | Type guard: checks if a string is a known failure mode |
| `createFailure` | Construct a `CertificateFailure` from a mode and context |
| `FailureMode` | Union type of all failure mode string literals |
| `CertificateFailure` | `{ mode: FailureMode, message: string, context? }` |

### §12: Policy Ref Validator

| Name | Description |
|---|---|
| `validatePolicyRef` | Validate the shape of a `policy_ref` field |
| `PolicyRef` · `PolicyRefValidResult` / `Ok` / `Fail` | Types |

### §11.3: Certificate Chain Evaluator

| Name | Description |
|---|---|
| `evaluateChain` | Evaluate a certificate chain from leaf to root |
| `CertificateChainLink` · `CertificateChainInput` | Chain input types |
| `CertificateChainResult` / `ChainEvalOk` / `ChainEvalFail` | Union result type |

### §16: Disclosure Enforcement

| Name | Description |
|---|---|
| `validateDisclosure` | Validate privacy/disclosure field requirements |
| `DisclosureField` · `DisclosureCertificateInput` | Input types |
| `DisclosureValidResult` / `Ok` / `Fail` | Union result type |

### §5: Heart-to-Heart Verifier

| Name | Description |
|---|---|
| `verifyHeartToHeartSignatures` | Verify both issuer and subject signatures on a certificate |
| `HeartToHeartCertificateInput` | Input: certificate + issuer public key + subject public key |
| `HeartToHeartResult` / `Ok` / `Fail` | Union result type |

### Usage Examples

**Validate a certificate vocabulary then evaluate policy:**
```ts
import { validateProfile, validateClaimKind, evaluatePolicy } from 'soma-heart/certificate';

const profileResult = validateProfile(cert.profile);
if (profileResult.disposition !== 'accepted') throw new Error(profileResult.reason);

const policyResult = evaluatePolicy(cert, myVerifierPolicy);
if (!policyResult.ok) console.error('Policy violations:', policyResult.violations);
```

**Evaluate a certificate chain:**
```ts
import { evaluateChain } from 'soma-heart/certificate';

const result = evaluateChain({ links: [leaf, mid, root] });
if (!result.ok) console.error('Chain failure:', result.reason);
```

---

## `./signals` — Experimental Signals

```ts
import { extractCognitiveSignals, extractStructuralSignals } from 'soma-heart/signals'
```

Experimental phenotypic signal extraction from agent text responses.
These helpers analyze *how* an agent writes — cognitive hedging patterns,
structural layout, temporal streaming stats — rather than what it says.

> **Status:** Experimental. Interfaces may change between minor versions.

### Functions

| Name | Signature | Description |
|---|---|---|
| `extractCognitiveSignals` | `(text: string) => CognitiveSignals` | Count hedge, certainty, disclaimer, and empathy markers |
| `extractStructuralSignals` | `(text: string) => StructuralSignals` | Extract layout metrics: word count, list ratio, header count, etc. |
| `extractTemporalSignalsLegacy` | `(trace: StreamingTrace) => TemporalSignals` | Extract streaming timing metrics from a raw trace |
| `extractErrorSignals` | `(text: string) => ErrorSignals` | Detect refusals, uncertainty admissions, self-corrections |
| `extractPhenotypicSignals` | `(text, trace?, senses?) => PhenotypicSignals` | Full signal extraction: cognitive + structural + temporal + error + optional senses |

### Key Types

| Type | Description |
|---|---|
| `CognitiveSignals` | Hedge count, certainty count, disclaimer count, empathy markers |
| `StructuralSignals` | Word/line/paragraph counts, list ratio, header lines, code blocks |
| `TemporalSignals` | Inter-token intervals, mean/std/median, burstiness, total duration |
| `ErrorSignals` | Refusal flag, uncertainty admissions, self-corrections, confidence ratio |
| `PhenotypicSignals` | All four signal groups combined |
| `StreamingTrace` | Raw token timestamps captured during an API streaming call |

### Usage Examples

**Extract signals from a response:**
```ts
import { extractCognitiveSignals, extractStructuralSignals } from 'soma-heart/signals';

const cognitive = extractCognitiveSignals(agentResponse);
console.log(cognitive.hedgeToCertaintyRatio); // > 1.0 = more hedging than certainty

const structural = extractStructuralSignals(agentResponse);
console.log(structural.listToContentRatio);   // high = list-heavy response
```

---

## `./supply-chain` — Supply Chain

```ts
import { ReleaseLog, verifyInstalledPackage } from 'soma-heart/supply-chain'
```

Supply-chain attestation for provable release integrity. Lets consumers
verify that an installed `soma-heart` tarball matches a maintainer-signed
entry in an append-only release log. Closes audit limit #10.

### Functions & Classes

| Name | Signature | Description |
|---|---|---|
| `ReleaseLog` | `class` | Append-only, tamper-evident chain of release entries |
| `verifyInstalledPackage` | `(log, packagePath, opts?) => InstallVerification` | Verify an installed package tarball against the release log |
| `detectReleaseFork` | `(log, opts?) => ReleaseForkProof \| null` | Detect if the release log has been forked (equivocation) |
| `createUpdateCertificate` | `(entry, maintainerKey) => UpdateCertificate` | Create a signed update certificate for a release |
| `addAuthorization` | `(cert, authorizerKey, role) => UpdateCertificate` | Add an additional authorization signature to a certificate |
| `verifyUpdateCertificate` | `(cert, opts) => UpdateCertificateVerification` | Verify all signatures on an update certificate |
| `computeUpdateCertificateSigningInput` | `(cert) => Uint8Array` | Compute the canonical bytes-to-sign for a certificate |
| `computeUpdateCertificateHash` | `(cert) => string` | Hash an update certificate |
| `verifyPackageProvenance` | `(provenance, opts) => PackageProvenanceVerification` | Verify a package provenance record |

### Key Types

| Type | Description |
|---|---|
| `ReleaseEntry` | A single signed entry in the release log: version, hash, timestamp, signature |
| `ReleaseChainHead` | The current head of the release chain (hash + entry count) |
| `ReleaseVerification` | Result of verifying an entry: `{ ok, entry?, reason? }` |
| `ReleaseForkProof` | Evidence of two conflicting entries for the same version |
| `InstallVerification` | Result of matching an installed tarball to the log |
| `UpdateCertificate` | Multi-sig certificate authorizing a package update |
| `UpdateAuthorization` | A single authorization signature + role |
| `AuthorizerRole` | `"maintainer" \| "auditor" \| "witness"` |
| `PackageProvenance` | Provenance record linking a package to its build and release |
| `UpdateCertificateVerification` | Result of certificate verification: `{ ok, violations? }` |

### Usage Examples

**Verify an installed package:**
```ts
import { ReleaseLog, verifyInstalledPackage } from 'soma-heart/supply-chain';

const log = await ReleaseLog.load('./release-log.json');
const result = verifyInstalledPackage(log, './node_modules/soma-heart', {
  trustedMaintainerKeys: [maintainerPublicKey],
});
if (!result.ok) throw new Error(`Supply chain verification failed: ${result.reason}`);
```

**Create and verify an update certificate:**
```ts
import { createUpdateCertificate, addAuthorization, verifyUpdateCertificate } from 'soma-heart/supply-chain';

const cert = createUpdateCertificate(releaseEntry, maintainerKeyPair);
const certified = addAuthorization(cert, auditorKeyPair, 'auditor');
const result = verifyUpdateCertificate(certified, { requiredRoles: ['maintainer', 'auditor'] });
```
