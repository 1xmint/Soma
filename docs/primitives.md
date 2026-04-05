# Soma Primitives Reference

Detailed reference for the primitives exposed by `soma-heart`. Each section
names the public API, explains what it does, and links to the source file.

## Multi-Agent Primitives (soma-heart@0.2)

Heart-to-heart trust lets agents fork, delegate, and revoke.

### Fork — spawn a child heart
```ts
heart.fork({ systemPrompt, toolManifest, capabilities, ttl, budgetCredits })
```
Spawns a child keypair + genome + signed lineage cert. Child can call
`createSomaHeart({ ..., lineage })` and have its capabilities enforced.
Source: `src/heart/lineage.ts`.

### Delegate — macaroons-style capability tokens
```ts
heart.delegate({ subjectDid, capabilities, caveats })
```
Supported caveats: `expires-at`, `not-before`, `audience`, `budget`,
`max-invocations`, `capabilities`, `custom`. `attenuateDelegation()` lets
holders narrow further (never broaden). Source: `src/heart/delegation.ts`.

### Revoke — signed revocation events
```ts
heart.revoke({ targetId, targetKind, reason })
```
Registry supports import/export for feed distribution. Source:
`src/heart/revocation.ts`.

### RevocationLog — append-only hash-chained log
```ts
const log = new RevocationLog();
log.append(revocation);
const head = log.signHead(operatorKey, operatorPublicKey);
RevocationLog.verifyEntries(exportedEntries);
```
Detects drops/reorders/tampering within a log; `signHead()` produces a signed
commitment to the current head for cross-operator accountability. Closes
audit limit #2. Source: `src/heart/revocation-log.ts`.

### KeyHistory — KERI-style pre-rotation
```ts
const { history, event } = KeyHistory.incept({
  inceptionSecretKey, inceptionPublicKey, nextPublicKey,
});
history.rotate({ currentSecretKey, currentPublicKey, nextPublicKey });
KeyHistory.verifyChain(events, expectedIdentity);
KeyHistory.currentPublicKey(events); // resolve active key
```
Append-only hash-chained key history with pre-rotation: each event commits
to `digest(nextPublicKey)`, and each rotation must present a key whose digest
matches the prior commitment. An attacker who steals the current key cannot
rotate to their own key — they'd need the pre-image of a hash they can't
invert. Identity (`did:key` of inception key) stays stable across rotations.
Closes audit limit #6. Source: `src/heart/key-rotation.ts`.

### GossipPeer — bounded revocation propagation
```ts
const transport = new InMemoryTransport();
const peer = new GossipPeer({ transport, log, operatorSigningKey, operatorPublicKey });
peer.start();
await peer.publishRevocation(entry);
await peer.publishHead();
peer.isStale(60_000);               // fail-closed if no sync in window
peer.getDivergenceReport();          // fork evidence from same authority
```
Pluggable pub/sub for `RevocationLog` entries + signed heads.
`InMemoryTransport` is the reference; operators plug libp2p/NATS/Redis
behind the same interface. Every message refreshes `lastSyncAt` —
validators use `isStale()` to refuse credentials when the peer can't
reach the network. Two conflicting signed heads from the same authority
produce a `DivergenceReport` (fork proof). Closes audit limit #1.
Source: `src/heart/gossip.ts`.

### TimeWitness / TimeSource — anchored timestamps
```ts
const mono = new MonotonicTimeSource();          // refuses to go backwards
const w = issueTimeWitness({ authoritySecretKey, authorityPublicKey, nonce });
verifyTimeWitness(w, { maxAgeMs: 60_000, expectedNonce });
verifyWitnessQuorum(witnesses, { threshold: 2, trustedAuthorities, maxDriftMs });
```
`MonotonicTimeSource` guards against local clock adjustments within a
process lifetime. `TimeWitness` is a signed statement by a trusted
authority that "at this moment, wall time was T" — operations needing
bounded freshness embed one (or a quorum from N independent authorities).
Verifier checks signature + freshness window + optional nonce + drift
across witnesses. Closes audit limit #4. Source: `src/heart/time-oracle.ts`.

### SpendLog — cryptographic backing for budget caveats
```ts
const log = new SpendLog({ delegationId, subjectSigningKey, subjectPublicKey });
const r = log.append({ amount: 10, capability: "tool:db" });
log.wouldExceed(100, budget); // boolean
const head = signSpendHead({ delegationId, sequence, hash, cumulative, ... });
const proof = detectDoubleSpend(headA, headB); // fork evidence
```
Per-delegation hash chain of subject-signed receipts. Cumulative spend is
verified at append time and on import. Issuer-signed `SpendHead`s commit to
a canonical view — two conflicting heads at the same sequence = provable
double-spend. Genesis hash binds to `delegationId` so chains can't be
transplanted between delegations. Closes audit limit #3. Source:
`src/heart/spend-receipts.ts`.

### Persist — encrypt heart state to disk
```ts
const blob = heart.serialize("password");
const restored = loadSomaHeart(blob, "password");
```
Uses scrypt (N=2^17, r=8, p=1, ~128MB memory-hard) + XSalsa20-Poly1305.
Legacy PBKDF2 blobs still decrypt. Preserves keypair, credentials, heartbeat
chain, revocations, lineage. Sessions are NOT persisted (ephemeral by design).
Closes audit limit #5. Source: `src/heart/persistence.ts`.

### Mutual session PoP — two-party authenticated handshake
```ts
const init = initiateSession({ initiatorDid, initiatorPublicKey, purpose, ttlMs });
const accept = acceptSession({ init, responderDid, responderPublicKey, responderSigningKey });
const confirm = confirmSession({ init, accept, initiatorSigningKey }); // verifies B first
const result = verifyMutualSession({ init, accept, confirm, maxAgeMs });
// result.bindings.transcriptHash — stable session id both parties bind to
```
Single-sided PoP leaves the verifier anonymous — a MITM verifier could
phish credentials. Mutual session PoP is a 3-message handshake where BOTH
parties sign the same canonical transcript. After verify, each side has
proof the counterparty holds the key for their advertised DID, plus a
shared `transcriptHash` to bind into downstream operations (receipts,
heartbeats, subtask dispatch). Includes freshness (TTL + maxAgeMs),
DID/key binding checks, and rejects stolen signatures via transcript
binding. Source: `src/heart/mutual-session.ts`.

### Proof-of-possession — prove key ownership, not bearer
```ts
const challenge = issueChallenge(delegation);
const proof = proveChallenge(challenge, holderSecretKey);
const result = verifyProof(challenge, proof, delegation);
```
Holder signs `soma-pop:{nonce}:{delegationId}` with their key; verifier checks
against `subjectDid` (public key derived via `didToPublicKey()`). Prevents
stolen-token reuse. Closes audit limit #7. Source:
`src/heart/proof-of-possession.ts`.

### Audience enforcement — fail-closed
`checkCaveats()` requires `ctx.audienceDid` when the delegation has an
`audience` caveat. If absent, validation fails closed. The audience is the
VERIFIER's identity (the service being called), not the invoker. Closes
audit limit #8. Source: `src/heart/delegation.ts`.

### Capability wildcards
- `*` — universal (any capability)
- `tool:*` — namespace wildcard (any `tool:X`)
- Enforcement at `callTool()` / `fetchData()` — throws when capability not granted
- Root hearts (no lineage) bypass enforcement

## Agent Observability (blacksmith sub-strikes)

Beyond core session/generation events, hearts record agent internal state so
verifiers can see *every strike*, not just inputs/outputs:

- `heart.recordReasoning(summary)` — chain-of-thought step (hashed, content private)
- `heart.recordRetry(operation, reason, attempt)` — missed strike / re-attempt
- `heart.recordRagLookup(queryHash, resultCount)` — context enrichment
- `heart.recordSubtaskDispatch(subjectDid, taskHash)` — work handoff to child/delegatee
- `heart.recordSubtaskReturn(subjectDid, resultHash)` — child returned result
- Tool executors receive a `ToolProgressEmitter` — `emit(stage, detail?)` records a `tool_progress` heartbeat mid-execution
- `fork()` / `delegate()` / `revoke()` auto-record `fork_created` / `delegation_issued` / `delegation_revoked` events

All events use ~1μs SHA-256 per record — free at LLM timescale. Detail strings
are always hashed before being written to the chain.

### AttestationRegistry — sybil resistance primitives
```ts
const at = createAttestation({
  subjectDid, issuerDid, issuerPublicKey, issuerSigningKey,
  attestationType: "kyc-verified", weight: 80,
  expiresAt: Date.now() + 365 * 24 * 3600 * 1000,
});
const reg = new AttestationRegistry();
reg.add(at);
reg.getTier(subjectDid);   // "anonymous" | "attested" | "staked" | "verified"
reg.getScore(subjectDid);  // 0-100 with freshness decay + type multipliers
reg.revoke(at.id);
```
Signed claims by issuers about subjects — raw material for apps to build
sybil defense on top of free-to-mint `did:key` identities. Attestation types
carry different weight multipliers (peer-vouched=0.5, kyc-verified=2.5,
stake-bonded=2.0, etc.). Scoring applies freshness decay (half-life 180 days
by default), normalized + capped at 100. `getTier()` maps attestation
presence to a qualitative tier. Registry supports revocation, expiry, and
trusted-issuer filtering. Deliberately passive — apps inject attestations
from whatever source they trust (ERC-8004, off-chain claims, SBTs).
Source: `src/heart/attestation.ts`.

### Selective Disclosure — reveal only specific claim fields
```ts
const doc = createDisclosableDocument({
  issuerDid, issuerPublicKey, issuerSigningKey, subjectDid,
  claims: { name, dob, country, tier: 3, kycVerified: true },
});
// Subject reveals only the fields the verifier needs.
const proof = createDisclosureProof(doc, ["tier", "kycVerified"]);
verifyDisclosureProof(proof, { requiredFields: ["tier"] });
```
Per-field salted commitments + issuer signature over the root. Holder
presents `(disclosed values + salts) + (commitment hashes for withheld
fields)`; verifier recomputes the root and checks the signature. Hides
withheld fields (32-byte random salts make commitments unlinkable across
documents) while proving the issuer signed the exact claim set. Field
name is bound into each commitment — swapping field names fails
verification. Source: `src/heart/selective-disclosure.ts`.

### Key Escrow — Shamir's Secret Sharing (M-of-N recovery)
```ts
const shares = splitSecret(signingKey, {
  threshold: 3, totalShares: 5, secretId: "heart-alice-v1",
});
// Distribute shares to 5 trustees. 3 must cooperate to reconstruct.
const recovered = reconstructSecret([shares[0], shares[2], shares[4]]);
verifyShares(subset, expected);               // post-split sanity check
verifyAllSubsetsReconstruct(shares, secret);  // exhaustive check
```
Shamir SSS over GF(256) with Rijndael's polynomial (same field as AES).
Any K-1 shares reveal ZERO bits about the secret (information-theoretic).
Shares carry a `secretId` so shares from different secrets can't be mixed.
Threshold must be 2..255, totalShares ≤ 255. No integrity — a byzantine
share holder can poison reconstruction, so callers should verify the
reconstructed secret out-of-band (e.g. checking it signs correctly).
Source: `src/heart/key-escrow.ts`.

### VRF — verifiable random function
```ts
const vrf = evaluateVrf({ input, signingKey, publicKey });
verifyVrf(input, vrf);                   // anyone with pk can verify
outputToInt(outputBytes, bound);         // unbiased int in [0, bound)
combineBeacon(vrfs);                     // aggregate into random beacon
```
Deterministic, unforgeable, publicly verifiable randomness. For a given
(sk, input), output is fixed — but unpredictable without sk. Proof is a
deterministic Ed25519 signature over a domain-separated input; output is
SHA-256 of the proof. Use for leader election (lowest output wins), random
beacons (combine multiple parties' outputs), or lottery/assignment. Not
RFC 9381 — simpler construction, same security properties for this use.
Source: `src/heart/vrf.ts`.

### Remote Attestation — TEE hooks
```ts
const doc = createAttestationDocument({
  platform: "intel-sgx", quote, measurements,
  heartDid, heartPublicKey, heartSigningKey, nonceB64,
});
const verifier = new IntelSgxVerifier(...);   // platform-specific
await verifyAttestationDocument(doc, {
  verifiers: [verifier],
  policies: [{ platform: "intel-sgx", allow: { mrenclave: [...] } }],
  expectedNonce,
});
```
Binds a heart's identity to a TEE quote ("this key is held by code
measurement M running on genuine hardware"). Portable envelope is signed
by the heart over {quote, measurements, heartPublicKey, nonce, expiry}.
Pluggable `RemoteAttestationVerifier` interface per platform
(intel-sgx, intel-tdx, amd-sev-snp, aws-nitro, apple-sep, azure-cvm,
custom). `MeasurementPolicy` enforces per-platform allowlists so
arbitrary quotes don't pass. `NoopVerifier` for dev, `MockTeeVerifier`
for tests. Source: `src/heart/remote-attestation.ts`.

### Threshold Signing — M-of-N Ed25519
```ts
const tk = generateThresholdKeyPair({ threshold: 3, totalShares: 5, keyId: "heart-v1" });
// Distribute tk.shares to 5 custodians. 3 must cooperate to sign.
const sig = thresholdSign([s1, s2, s3], message, {
  publicKey: tk.publicKey, threshold: 3, keyId: "heart-v1",
});
verifyThresholdSignature(message, sig, tk.publicKey);  // standard Ed25519

const ceremony = new SigningCeremony(message, { publicKey, threshold, keyId });
ceremony.contribute(s1); ceremony.contribute(s2); ceremony.contribute(s3);
const sig = ceremony.sign();
```
M-of-N Ed25519 via Shamir share reconstruction (over GF(256), reusing
key-escrow). Signing reconstructs the secret, signs, then scrubs. The
resulting signature is a STANDARD Ed25519 signature — any Ed25519
verifier (incl. existing `verifyRevocation`, `verifyAttestation`)
accepts it without modification. `SigningCeremony` coordinates async
contributions and produces the signature once threshold is reached.
Shares are bound to a `keyId`, preventing mix-and-match across key sets.

**Trust model (read carefully):** This is NOT FROST. FROST-Ed25519 (RFC
9591) never reconstructs the secret; each party produces a partial
signature in the signature space. That's strictly stronger. This scheme
DOES reconstruct briefly during signing — the signing host must be
trusted for the ceremony window (run it in a TEE/HSM-enclosed process).
The API surface is FROST-compatible, so a future real FROST backend can
slot in under the same `thresholdSign` signature. Closes audit limit
related to custody. Source: `src/heart/threshold-signing.ts`.

### DID Method Flexibility — pluggable identifier schemes
```ts
const registry = createDefaultDidRegistry();  // pre-registered did:key
registry.register(new DidWebMethod(fetcher));
registry.register(new DidPkhMethod(keyBinder));
const doc = await registry.resolve("did:web:example.com");
await verifySignatureViaDid(did, message, signature, registry);
```
Soma defaults to `did:key` (identifier IS the key). This module adds a
narrow `DidMethod` interface so operators can plug in `did:web` (domain-
controlled keys via `.well-known/did.json`), `did:pkh` (blockchain
accounts, CAIP-10 format), or custom in-house methods. Built-ins:
`DidKeyMethod` (sync, self-resolving), `DidWebMethod` (pluggable HTTPS
fetcher — tests inject stubs, prod uses real fetch), `DidPkhMethod`
(parse/format + optional `keyBinder` callback since blockchain addresses
aren't public keys). `DidMethodRegistry` dispatches by prefix match.
Existing `publicKeyToDid`/`didToPublicKey` call sites keep working
unchanged — this module is purely additive. `verifySignatureViaDid()`
resolves a DID and tries each verification key until one matches.
Source: `src/core/did-method.ts`.

### Hybrid Signing — crypto-agility for PQ migration
```ts
const registry = new AlgorithmRegistry();
registry.register(ed25519Provider);
registry.register(mlDsaProvider);            // future: real ML-DSA

const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65"], registry);
const sig = hybridSign(kp, message, registry);
verifyHybridSignature(sig, message, registry, { type: "require-all" });
verifyHybridSignature(sig, message, registry, {
  type: "prefer-pq", pqAlgorithms: ["ml-dsa-65"], minPq: 1,
});
hybridFingerprint(hybridPublicKeys(kp));     // stable identity for the pair
```
Composite signature envelope for post-quantum migration. NIST's PQ
transition means signing with BOTH classical and PQ algorithms for a
long overlap period — this module is the on-the-wire format that makes
that practical. Each per-algorithm signature is bound to the FULL public
key set (algorithm IDs + base64 pks) via a canonical JSON payload, so
cross-algorithm key substitution is detected. Verification policies:
`require-all` (every advertised algo), `require-any` (≥1), `require-
algorithms` (specific set), `prefer-pq` (≥N PQ algos). Unknown algorithms
at verify time are treated as failures rather than crashes — forward-
compat with signers that add new PQ algos later. This module ships the
envelope and registry; actual PQ `SigningProvider` implementations are
delivered by dedicated packages (the default registry includes only
Ed25519). Closes audit limit #9. Source: `src/heart/hybrid-signing.ts`.

### Signing Backends — HSM / hardware wallet hooks
```ts
const inproc = new InProcessBackend();
const handle = inproc.generateKey({ keyId: "alice-v1" });
await inproc.sign(handle, message);

const hsm = new DelegatedBackend({
  backendId: "yubihsm",
  sign: async (h, m) => yubihsmCli.sign(h.keyId, m),
  handles: [{ publicKey, backendId: "yubihsm", keyId: "slot-0" }],
});
const registry = new BackendRegistry();
registry.register(inproc);
registry.register(hsm);
await registry.sign(anyHandle, msg); // routes by handle.backendId
```
Pluggable where the *secret key lives*. `SigningKeyHandle` is an opaque
reference `{publicKey, backendId, keyId}` — callers pass the handle, the
backend signs. `InProcessBackend` holds raw Uint8Array keys (matches current
default behavior). `DelegatedBackend` wraps an arbitrary async signer
(YubiHSM, AWS KMS, Ledger, Apple SEP, TPM, Fireblocks) — the escape hatch
for hardware-backed keys that never leave the device. Paranoid check:
delegate's returned signature is verified against the advertised public key
before being handed back. `BackendRegistry` routes by `handle.backendId` so
call sites sign without a per-backend switch. Both paths produce standard
Ed25519 signatures verified the same way — existing `verifyRevocation`,
`verifyAttestation`, etc. accept them unmodified. Source:
`src/heart/signing-backend.ts`.

## Supply-Chain Attestation

### ReleaseLog — signed, hash-chained package releases
```ts
const log = new ReleaseLog({ package: "soma-heart" });
log.append({ version, tarballSha256, gitCommit, maintainerSigningKey, maintainerPublicKey });
const head = log.signHead(maintainerSigningKey, maintainerPublicKey);
verifyInstalledPackage({
  releaseLog, packageName, version, installedTarballSha256, trustedMaintainers,
});
detectReleaseFork(headA, headB);
```
Ties each npm tarball to a signed entry: package + version + tarball
SHA-256 + git commit + maintainer DID. Users verify installs against the
log: mismatched hash = tampering. Trust set enforces "only accept from
known maintainers." Two conflicting heads from the same maintainer at the
same sequence = fork proof (npm account compromise or malicious rewrite).
Closes audit limit #10. Source: `src/supply-chain/release-log.ts`.

## Soma Check Protocol (soma-check/1.0)

First conditional payment protocol for APIs. Reuses birth-cert `dataHash` as
the change-detection key, so there's one primitive for both provenance and
payment gating. Backward compatible with x402 / any payment rail.

- **Shared helpers:** `src/core/soma-check.ts` — headers, `SomaCheckHashStore`, provider decision helpers
- **Consumer:** `soma-sense` exports `createSmartFetch()` — drop-in `fetch()` that auto-sends `If-Soma-Hash`
- **Provider:** `soma-heart` exports `extractIfSomaHash()`, `shouldRespondUnchanged()`, `buildUnchangedResponse()`, plus `heart.hashContent()` for birth-cert-compatible hashing
- **Full spec:** `SOMA-CHECK-SPEC.md`
