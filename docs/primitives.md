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
