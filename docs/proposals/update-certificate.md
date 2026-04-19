Status: proposed

# Update Certificate — Ceremony-Gated Supply-Chain Integrity

**Status:** proposed
**Modules (new):** `src/supply-chain/update-certificate.ts`
**Modules (modified):** `src/heart/birth-certificate.ts`,
`src/heart/certificate/vocabulary.ts`, `src/supply-chain/release-log.ts`
**First consumer:** claw-net (`src/core/soma-heart.ts`, new ceremony +
co-sign routes, EAS anchoring)

---

## Problem

Three gaps in Soma's supply-chain integrity:

1. **No runtime provenance.** A heart's birth certificate identifies the
   heart's DID and attests to data provenance, but carries no claim about
   the *code* running inside the heart. A fork that modifies enforcement
   logic (skips spend-log entries, lies about trust scores, weakens
   ceremony checks) produces structurally identical birth certificates.
   Counterparties cannot distinguish official from tampered.

2. **No ceremony gate on publish.** The release log (`release-log.ts`)
   signs each release with the maintainer's key, but the signing key is
   used directly — no biometric ceremony, no step-up authentication. If
   the maintainer's credentials are compromised, an attacker publishes a
   valid-looking release-log entry for a malicious package.

3. **No independent co-signature.** The release log is single-party: only
   the maintainer signs. There is no second opinion from a trusted
   consumer that has independently verified the release. Single-party
   signing means single-party compromise is sufficient.

## Why Now

- `soma-heart@0.5.0` is published on npm with provenance. The release log
  and ceremony primitives are shipped. The infrastructure exists.
- ClawNet runs its own soma-heart in production and already anchors
  receipts on Base via EAS. The co-signing and on-chain anchoring paths
  are proven.
- The key-verifier gap fix (rotation-aware historical key lookup) is in
  PR. Once merged, all verifier call sites handle key rotation — the
  update certificate verification can rely on this.
- As downstream adoption grows, the window for a supply-chain attack
  widens. The ceremony gate should be in place before high-value heart
  trees depend on unceremoned releases.

## Broad Idea

Three connected primitives:

1. **UpdateCertificate** — a new certificate profile in Soma that bundles
   the maintainer's ceremony-verified authorization with a consumer heart's
   co-signature, linked to the release log chain. The protocol-level
   primitive.

2. **Birth certificate provenance extension** — an optional field on
   `BirthCertificate` that carries package provenance claims. The
   interaction-boundary signal that counterparties verify.

3. **Ceremony-gated CI workflow** — the publish pipeline requires a
   biometric `HumanDelegation` ceremony before `npm publish` can proceed,
   plus GitHub Actions OIDC verification as a second factor on the CI
   runner itself. The implementation-level enforcement.

The chain: Josh authenticates via biometric ceremony → CI builds and
publishes → ClawNet's heart co-signs the update certificate → certificate
is anchored on-chain → downstream hearts carry provenance in their birth
certificates → counterparties verify at interaction boundaries.

## What 10/10 Looks Like

- Every `soma-heart` release ≥ the implementation version has a
  ceremony-verified, dual-signed `UpdateCertificate` anchored on Base.
- Every heart's birth certificate carries a `packageProvenance` field
  that counterparties can verify without trusting the heart itself.
- A fork that strips or forges the provenance field is distinguishable
  from an official heart at every interaction boundary.
- The publish action cannot proceed without biometric authentication —
  credential theft alone is insufficient.
- Verification is possible via three independent paths: release log
  (signed chain), ClawNet heart co-signature (independent verifier),
  on-chain EAS attestation (permissionless, censorship-resistant).

## Fitness Check

- **Protocol vision fit:** Strong. Soma's thesis is that trust requires
  cryptographic proof at every layer. The update channel is the one layer
  that currently lacks it. This closes the gap.
- **Real implementer/operator need:** ClawNet is already running
  soma-heart in production. Any operator running soma-heart needs to know
  their dependency is legitimate. npm provenance alone is necessary but
  not sufficient — it proves CI-to-tarball but not human-to-CI.
- **Security exposure:** High. The publish key is the root of the supply
  chain. Compromising it compromises every downstream heart. The ceremony
  gate and co-signature reduce this to requiring compromise of *both* the
  maintainer's biometrics *and* ClawNet's heart key simultaneously.
- **Evidence this is needed now:** npm ecosystem supply-chain attacks are
  well-documented (event-stream, ua-parser-js, colors.js). Soma's
  release log was built specifically to address this class of attack. The
  ceremony gate is the missing enforcement layer.
- **Keep / reshape / pause / remove:** Keep. Ship before downstream
  adoption creates larger blast radius.

## Evidence Ledger

- **Current status:** Design complete. All underlying primitives shipped
  (release-log, ceremony-policy, human-delegation, human-session,
  threshold-signing, birth-certificate, EAS anchoring).
- **Upstream dependencies:** Key-verifier gap fix PR (in review).
  PR-C session-mode routes (WebAuthn enrollment) — needed for the
  ceremony endpoints but not for the Soma-side types.
- **Missing evidence:** None. Design is grounded in shipped code.
- **Blocks current work:** No. Can proceed in parallel with other work.
- **Next gate:** Implementation.
- **Terminal condition:** All three primitives shipped and the first
  ceremony-gated release is published.

---

## §1 UpdateCertificate — Certificate Structure

### §1.1 Domain

```
soma/update-certificate/v1
```

Domain-separated via `domainSigningInput` from `canonicalize.ts`. A
signature over an `UpdateCertificate` cannot be replayed as any other
Soma signature (same pattern as `soma/human-delegation/v1`).

### §1.2 Type Definition

```typescript
interface UpdateCertificate {
  /** Domain tag — must equal 'soma/update-certificate/v1'. */
  domain: 'soma/update-certificate/v1';

  /** Package name (e.g. 'soma-heart'). */
  package: string;

  /** Semver version string. */
  version: string;

  /** SHA-256 of the published tarball (lowercase hex, 64 chars). */
  tarballSha256: string;

  /** Git commit SHA the tarball was built from. */
  gitCommit: string;

  /** Position in the release log chain. */
  releaseLogSequence: number;

  /** Hash of the release log at this sequence (chain head after append). */
  releaseLogHash: string;

  /** Ceremony tier achieved by the maintainer during publish ceremony. */
  ceremonyTier: CeremonyTier;

  /** The authorizations — each signer who endorsed this release. */
  authorizations: UpdateAuthorization[];

  /** Threshold requirement: how many authorizations are required. */
  threshold: { required: number; total: number };

  /** When the certificate was issued (ms since epoch). */
  issuedAt: number;
}

interface UpdateAuthorization {
  /** Role of this signer. */
  role: 'maintainer' | 'consumer-heart' | 'council-member';

  /** DID of the signer. */
  signerDid: string;

  /** Base64 public key of the signer. */
  signerPublicKey: string;

  /** Ceremony tier this signer achieved (maintainer only; null for hearts). */
  ceremonyTier: CeremonyTier | null;

  /**
   * Hash of the HumanDelegation that authorized this signer's action
   * (maintainer only). Enables audit trail back to the biometric ceremony.
   * Null for consumer hearts and council members (they authorize via
   * their heart's signing key, not a human ceremony).
   */
  delegationHash: string | null;

  /** Ed25519 signature over the certificate payload (base64). */
  signature: string;
}
```

### §1.3 Signing Input

All signers sign the same payload — the `UpdateCertificate` minus the
`authorizations` array — using `domainSigningInput`:

```typescript
function computeUpdateCertificateSigningInput(
  cert: Omit<UpdateCertificate, 'authorizations'>
): Uint8Array {
  return domainSigningInput('soma/update-certificate/v1', cert);
}
```

The `authorizations` array is assembled after all signatures are
collected. Each signer signs independently over the same canonical
input. This is *not* threshold signing — it's independent multi-party
signing where each party uses their own key.

### §1.4 Threshold Signing Composition

The `threshold` field and `authorizations` array are structurally
similar to threshold signing but semantically different:

- **UpdateCertificate:** Multiple *distinct identities* each sign with
  their own key. The verifier checks N independent signatures. This is
  multi-sig, not threshold-sig.
- **`threshold-signing.ts`:** A *single identity's* key is split into
  Shamir shares. The verifier sees one standard Ed25519 signature and
  doesn't know it was threshold-produced.

These compose cleanly: Josh's maintainer authorization could itself be
produced via threshold signing (3-of-5 shares across devices), but the
`UpdateCertificate` sees it as a single Ed25519 signature from Josh's
DID. The threshold ceremony is internal to how Josh produces his
signature — transparent to downstream verifiers and to the certificate
structure.

**Phase 2 extension:** Josh pre-splits his publish signing key into
3-of-5 shares via `threshold-signing.ts`, distributed across:
- iPhone passkey (primary)
- YubiKey (secondary)
- iPad passkey (backup)
- Hardware wallet (cold storage)
- Printed seed in safe (disaster recovery)

This eliminates single-device failure without changing the certificate
format.

### §1.5 Profile Registration

Add to `certificate/vocabulary.ts`:

```typescript
// In PROFILE_DISPOSITIONS:
['update-certificate', 'accepted'],
```

Add to `CLAIM_DISPOSITIONS`:

```typescript
['package_provenance', 'accepted'],
```

---

## §2 Release Log Composition

The `UpdateCertificate` extends the release log — it doesn't replace it.

### §2.1 Flow

1. CI appends a `ReleaseEntry` to the release log (via
   `ReleaseLog.append`, as today).
2. The `ReleaseEntry` is signed by the maintainer's key (as today).
3. The `UpdateCertificate` is created *after* the release-log entry
   exists, referencing it by `releaseLogSequence` and `releaseLogHash`.
4. The `UpdateCertificate` carries information the release-log entry
   doesn't: the ceremony tier, the consumer heart co-signature, and
   the threshold requirement.

**The release-log entry is necessary but not sufficient.** It proves the
maintainer signed. The `UpdateCertificate` proves the maintainer
*ceremony-authenticated* and a consumer heart *co-endorsed*.

### §2.2 Verification Order

A verifier checking an update certificate:

1. Verify the release log chain up to `releaseLogSequence` via
   `ReleaseLog.verifyChain`.
2. Verify `releaseLogHash` matches the chain head at that sequence.
3. Verify each `UpdateAuthorization` signature against the certificate
   payload via `domainSigningInput`.
4. Verify the number of valid authorizations meets `threshold.required`.
5. Verify the maintainer's `ceremonyTier` meets the minimum for this
   version class (caller-defined policy).
6. Verify each signer's DID binds to their stated public key via
   `verifyDidBinding` from `did-method.ts`.

---

## §3 Birth Certificate Provenance Extension

### §3.1 The Gap

`BirthCertificate` (in `birth-certificate.ts`) currently carries:
`dataHash`, `source`, `bornAt`, `bornThrough`, `bornInSession`,
`parentCertificates`, `receiverSignature`, `sourceSignature`,
`trustTier`.

None of these carry information about the *code* running in the heart
that issued the certificate. A heart running a fork produces birth
certificates structurally identical to those from an official heart.

### §3.2 The Extension

Add an optional `packageProvenance` field to `BirthCertificate`:

```typescript
interface PackageProvenance {
  /** Package name. */
  package: string;
  /** Semver version. */
  version: string;
  /** SHA-256 of the installed tarball. */
  tarballSha256: string;
  /** Sequence in the release log. */
  releaseLogSequence: number;
  /** Hash of the UpdateCertificate for this version. */
  updateCertificateHash: string;
  /** Ceremony tier from the UpdateCertificate. */
  ceremonyTier: CeremonyTier;
}
```

**Design rationale for direct field vs. separate certificate:**
- The provenance is about the *code* that created the birth cert, not
  the *data* in the cert. It's runtime metadata about the issuer,
  which belongs on the birth cert itself.
- A separate certificate via `parentCertificates` adds a lookup step at
  every interaction boundary. The counterparty should verify provenance
  from the birth cert it already has in hand.
- Adding an optional field is a non-breaking change. Existing code that
  doesn't check `packageProvenance` continues to work.
- If a fork strips the field, it's absent — not forged. Absent
  provenance = unverified = the counterparty knows what it's dealing
  with. That's the correct signal.

### §3.3 Canonicalization Impact

The `canonicalizeCertContent` function in `birth-certificate.ts` must
include `packageProvenance` when present. Since the field is optional,
the canonical form omits it when null/undefined (existing certs remain
valid). When present, it's included in sorted-key JSON — same pattern
as all other fields.

### §3.4 Embedded Manifest

At build time, CI embeds a `soma-release-manifest.json` in the package
root containing the full `UpdateCertificate` for this version. The
heart reads this file on startup to populate `packageProvenance`.

**Full certificate, not hash + URL.** Reasoning:
- Offline verification is a real use case (air-gapped environments,
  restrictive firewalls, CI pipelines).
- Size impact is minimal (~1-2KB JSON on a 50KB+ tarball).
- Hash + URL creates availability dependency on the URL host.
- On-chain EAS is the trust-minimized path for online verifiers.
- A fork that strips the manifest is in the same position as absent
  provenance — unverified.

### §3.5 Startup Self-Verification

On `initHeart()` (or equivalent), the heart:

1. Reads `soma-release-manifest.json` from the package root.
2. Constructs a `PackageProvenance` from the embedded
   `UpdateCertificate`.
3. Optionally fetches the canonical release log + update certificate
   from external sources (GitHub Pages, on-chain EAS) for cross-check.
4. Runs `verifyPackageProvenance` if canonical data is available.
5. Emits a `self_verification` heartbeat event:
   - `{ status: 'official', version, ceremonyTier }` — verified against
     canonical data
   - `{ status: 'unverified', reason: 'fetch_failed' }` — couldn't
     reach canonical data, will retry
   - `{ status: 'unofficial', reason }` — provenance check failed
   - `{ status: 'missing_manifest' }` — no embedded manifest (fork or
     pre-implementation version)

**Fail-open with signaling, not fail-closed.** If the canonical data
fetch fails (GitHub down, network restricted), the heart starts but
signals `unverified`. Enforcement lives at the network level (ClawNet
refuses to route to unverified hearts), not at the protocol level.

### §3.6 Verification at Interaction Boundaries

New function in Soma's public API:

```typescript
function verifyPackageProvenance(opts: {
  provenance: PackageProvenance;
  updateCertificate: UpdateCertificate;
  releaseLog: readonly ReleaseEntry[];
  trustedMaintainers: string[];
  trustedConsumerHearts: string[];
  minCeremonyTier?: CeremonyTier;
  provider?: CryptoProvider;
}): ProvenanceVerification;

type ProvenanceVerification =
  | { official: true; ceremonyTier: CeremonyTier }
  | { official: false; reason: string };
```

Verification steps:
1. Compute hash of the provided `UpdateCertificate`; must match
   `provenance.updateCertificateHash`.
2. `UpdateCertificate.package` and `version` must match `provenance`
   fields.
3. `UpdateCertificate.tarballSha256` must match
   `provenance.tarballSha256`.
4. Verify the `UpdateCertificate` itself (§2.2 verification order).
5. At least one authorization's `signerDid` must be in
   `trustedMaintainers`.
6. At least one authorization's `signerDid` must be in
   `trustedConsumerHearts`.
7. `ceremonyTier` must meet `minCeremonyTier` if specified.

**Soma provides the verdict; enforcement is the caller's policy.**
ClawNet refuses to route to unverified hearts. Other operators set
their own policy. The verification function is pure — no I/O, no
network, no state.

### §3.7 Canonical Data Sources

For fetching release logs and update certificates, priority order:

1. **On-chain EAS attestation on Base** — highest trust, permissionless,
   censorship-resistant.
2. **GitHub Pages (Soma repo)** — CI-updated on every release,
   convenient.
3. **Bundled with the package** — embedded manifest for offline
   verification.

---

## §4 Ceremony-Gated CI Workflow

### §4.1 Architectural Decisions (Confirmed)

1. **Gate-before, not sign-after.** The ceremony is a hard gate on
   `npm publish`. CI cannot publish until the `HumanDelegation` is in
   hand. Zero window of unceremoned packages on npm.

2. **Hard block on ceremony failure.** No timeout fallback. If the
   maintainer can't authenticate, the publish waits. A timeout fallback
   would be the attack surface — compromise CI, prevent authentication,
   wait for timeout, malicious version goes out.

3. **Redundant ceremony paths.** Defense against authenticator
   unavailability:
   - Primary: iPhone passkey (Face ID)
   - Secondary: YubiKey (hardware key)
   - Emergency: pre-registered backup passkey on a second device

4. **Ceremony authorizes the git commit, not the tarball.** The
   `HumanDelegation` envelope scopes to
   `{ action: 'publish', package, version, gitCommit }`. CI builds the
   tarball from that exact commit after ceremony completes. The release-
   log entry binds commit → tarball. The chain is:
   ceremony → commit → tarball.

5. **L3 = hardware + biometric.** TOTP (Google Authenticator) does not
   qualify for any tier — it's a shared secret, phishable, and doesn't
   bind to the session. Tier ladder for publish:
   - Patch/minor: passkey (L1/L2)
   - Major version: hardware key (L2)
   - High-value publish ($250k+ heart tree): hardware key + iris via
     World AgentKit Orb (L3)

### §4.2 CI Runner Attestation

The ceremony endpoint verifies the CI runner independently via GitHub
Actions OIDC, in addition to the `CLAWNET_CI_TOKEN`:

1. CI sends both `CLAWNET_CI_TOKEN` and the GitHub Actions OIDC token to
   the ceremony-begin endpoint.
2. ClawNet verifies the OIDC token against GitHub's JWKS endpoint
   (proves the request is from a real GitHub Actions run, not a stolen
   CI token used from an attacker's machine).
3. The OIDC token includes claims: `repository`, `workflow`, `ref`,
   `sha` — ClawNet verifies these match the expected Soma repo and
   workflow.
4. Even if `CLAWNET_CI_TOKEN` is stolen, the attacker can't produce a
   valid GitHub Actions OIDC token for the Soma repo's workflow.

Three independent factors on the publish action:
- **Biometric ceremony** — proves Josh authorized it
- **GitHub OIDC** — proves it's running in the real CI pipeline
- **ClawNet CI token** — proves it's the authorized CI integration

### §4.3 Workflow Sequence

```
1.  Josh pushes code + tag to GitHub
2.  GitHub Actions fires publish workflow
3.  CI sends ceremony-begin request to ClawNet with:
    - CLAWNET_CI_TOKEN
    - GitHub Actions OIDC token
    - { package, version, gitCommit, requiredTier }
4.  ClawNet verifies OIDC token against GitHub JWKS
5.  ClawNet sends push notification to Josh's registered authenticator
6.  Josh authenticates (tier depends on version bump type):
    - Patch/minor: Face ID passkey (L1/L2)
    - Major: YubiKey (L2)
    - High-value: YubiKey + iris (L3)
7.  ClawNet returns signed HumanDelegation to CI, scoped to:
    { action: 'publish', package: 'soma-heart', version, gitCommit }
8.  CI builds tarball from the ceremony-authorized commit
9.  CI computes tarball SHA-256
10. CI appends release-log entry (signed by ceremony-verified key)
11. CI embeds release manifest (soma-release-manifest.json) in package
12. CI runs npm publish with --provenance
13. CI calls ClawNet heart co-sign endpoint with:
    - package, version, tarballSha256
    - releaseLogSequence, releaseLogHash
    - maintainer HumanDelegation reference
14. ClawNet heart verifies:
    - Release-log entry valid
    - Ceremony tier sufficient
    - Tarball hash matches
    → co-signs UpdateCertificate
15. ClawNet anchors UpdateCertificate on Base via EAS
16. Package is live with triple verification:
    - npm provenance (CI → tarball)
    - Release-log entry (maintainer ceremony → tarball)
    - EAS attestation (ClawNet heart endorsement, on-chain)
```

### §4.4 ClawNet Routes (New)

```
POST /v1/publish/ceremony-begin
  Body: { package, version, gitCommit, requiredTier, oidcToken }
  Auth: CLAWNET_CI_TOKEN
  Response: { ceremonyId }
  Side effect: sends push to maintainer's authenticator

GET  /v1/publish/ceremony-status/:ceremonyId
  Auth: CLAWNET_CI_TOKEN
  Response: { state, delegation? }
  States: pending | completed | rejected | expired
  Timeout: 10 minutes per attempt (CI run fails on timeout,
           re-trigger when ready — no "proceed without ceremony" path)

POST /v1/publish/cosign
  Body: { package, version, tarballSha256, releaseLogSequence,
          releaseLogHash, maintainerDelegation }
  Auth: CLAWNET_CI_TOKEN
  Response: { updateCertificate, easAttestationUid }
  Side effects:
    - ClawNet heart verifies release-log entry
    - ClawNet heart verifies ceremony tier
    - ClawNet heart co-signs UpdateCertificate
    - ClawNet anchors on Base via EAS
```

These routes reuse the same `clawnetAttestationVerifier` from the
session-mode PR-C routes. The ceremony-begin flow is identical to
session-begin except scoped to the `publish` action class.

### §4.5 CeremonyPolicy for Publish

ClawNet extends the ceremony policy with publish-specific action
classes (these are ClawNet policy overrides, not Soma defaults):

```typescript
const publishPolicy = createCeremonyPolicy({
  overrides: {
    'publish-patch': 'L1',
    'publish-minor': 'L1',
    'publish-major': 'L2',
    'publish-critical': 'L3',
  },
});
```

The CI workflow determines the action class from the version bump type.
The ceremony endpoint checks the policy before accepting the ceremony
result.

---

## §5 On-Chain Anchoring (EAS on Base)

### §5.1 Schema

Register a new EAS schema on Base:

```
soma-update-certificate/v1:
  package            string
  version            string
  tarballSha256      string
  gitCommit          string
  releaseLogSequence uint64
  releaseLogHash     string
  maintainerDid      string
  ceremonyTier       string
  consumerHeartDid   string
  threshold          string   // JSON: {"required":2,"total":2}
  certificateHash    string   // sha256(canonicalJson(updateCertificate))
```

### §5.2 Anchoring Flow

After ClawNet's heart co-signs the `UpdateCertificate`:

1. Compute `certificateHash = sha256(canonicalJson(updateCertificate))`
2. Create EAS attestation with the schema above
3. Attestation is on-chain, publicly queryable, timestamped by Base
4. Any verifier can query: "does an EAS attestation exist for
   `soma-heart@0.6.0` signed by ClawNet's heart DID?" — if yes, the
   update certificate is legitimate

### §5.3 Verification Without ClawNet

The on-chain anchor is the most trust-minimized verification path. An
agent that doesn't trust ClawNet's API can:

1. Query Base EAS directly (permissionless, no ClawNet involvement)
2. Read the `certificateHash` from the attestation
3. Fetch the `UpdateCertificate` from any source (npm package manifest,
   GitHub, peer heart)
4. Verify `sha256(canonicalJson(cert)) === certificateHash`
5. Verify the certificate's signatures independently

ClawNet is not in the verification path at all — only in the anchoring
path.

---

## §6 Interaction-Boundary Verification Scenarios

Three scenarios, from most to least common:

### §6.1 Agent Without Heart → Agent With Heart (via ClawNet)

The most common near-term case. An API consumer calling a
ClawNet-routed agent.

**Verification:** The consumer doesn't verify directly. ClawNet
verified the heart's birth certificate provenance at registration time
and refuses to route to unverified hearts. The consumer trusts
ClawNet's routing.

**Enforcement:** ClawNet policy. Hearts without valid
`packageProvenance` in their birth certificate:
- Refused at registration, or
- Routed with severe trust penalty (analogous to `anonymous` identity
  tier at 0.825x, but potentially 0x for provenance)

### §6.2 Heart-to-Heart Interaction

Both parties run soma-heart. Each can verify the other's birth
certificate `packageProvenance` field using `verifyPackageProvenance`.

**Verification:** The interacting heart examines the counterparty's
birth certificate, extracts `packageProvenance`, fetches the
`UpdateCertificate` (from embedded manifest, GitHub, or on-chain EAS),
and runs `verifyPackageProvenance`.

**Enforcement:** Caller's policy. Soma provides the signal; the caller
decides:
- `read` through an unverified heart: may be acceptable (L0 equivalent)
- `spend` through an unverified heart: should be refused
- Maps cleanly to ceremony-policy action classes

### §6.3 Startup Self-Check (Operator Hygiene)

The heart verifies its own provenance on startup (§3.5). This is a
hygiene check for operators, not a trust primitive for counterparties.

**Verification:** Internal. The heart reads its own embedded manifest
and verifies against canonical data.

**Enforcement:** Informational. The `self_verification` heartbeat event
tells sense-observer whether this heart is running verified code. An
operator who sees `unofficial` or `missing_manifest` can investigate.

---

## §7 Trust Anchors and Key Rotation

### §7.1 Maintainer Trust Anchor

The trust anchor for "who is the legitimate maintainer" is the release
log's genesis entry's `maintainerDid`. This is the DID derived from
the key that signed the first release. Downstream verifiers who trust
the genesis entry transitively trust all subsequent entries signed by
the same DID (or its rotation successors via lineage chain).

**Key rotation:** If Josh's signing key rotates, the release log
continues from the new key. The `UpdateCertificate` for the first
release under the new key includes both the old and new key's
authorization (the old key signs a delegation to the new key). The
key-verifier gap fix PR wires rotation-aware historical key lookup into
all verifier call sites — the same infrastructure handles release-log
key rotation.

### §7.2 Consumer Heart Trust Anchor

ClawNet's heart DID is derived from its persistent signing key (stored
in `data/clawnet-heart.json`, loaded by `initSomaHeart()` in
`src/core/soma-heart.ts`). If ClawNet's heart key rotates, the
`UpdateCertificate` verification must walk ClawNet's lineage chain.

**Bootstrap problem:** How does a new downstream heart know to trust
ClawNet's DID? Options:
- Hardcoded in the Soma package as a well-known consumer heart
  (simplest, works for single consumer)
- Published in the release log metadata (the genesis entry includes
  trusted consumer DIDs)
- On-chain: ClawNet's heart DID is in the EAS schema, queryable by
  anyone

For v1: hardcode ClawNet's DID as the default trusted consumer heart.
Phase 3 (council) replaces this with a dynamic trust set.

---

## §8 Future Extensions

### §8.1 Threshold-Signed Maintainer Key (Phase 2)

Josh's publish signing key is split into 3-of-5 Shamir shares via
`threshold-signing.ts`. The ceremony gate accepts a threshold
signature. The `UpdateAuthorization` carries a standard Ed25519
signature — threshold reconstruction is transparent to verifiers.

### §8.2 M-of-N Council of Hearts (Phase 3)

When multiple operators run soma-heart in production:

```typescript
threshold: { required: 3, total: 5 }
authorizations: [
  { role: 'maintainer',      signerDid: 'did:key:josh...' },
  { role: 'consumer-heart',  signerDid: 'did:key:clawnet...' },
  { role: 'council-member',  signerDid: 'did:key:operator-a...' },
  { role: 'council-member',  signerDid: 'did:key:operator-b...' },
  // operator-c didn't sign — still meets 3-of-5
]
```

The `UpdateCertificate` structure supports this without modification.
Only threshold values and the signer set change.

### §8.3 Iris Biometric for L3 Publishes

For versions where agents with $250k+ budgets depend on the heart tree,
the ceremony escalates to L3: hardware key + World AgentKit iris. The
`AttestationVerifier` supports composing multiple factors via the
tier-ladder predicate algebra.

---

## Protocol Surface

- **Spec change:** New certificate profile `update-certificate`, new
  claim kind `package_provenance`. New `PackageProvenance` optional
  field on `BirthCertificate`.
- **Package API change:** New `src/supply-chain/update-certificate.ts`
  module. New `verifyPackageProvenance` public function. Extended
  `BirthCertificate` type (optional field, non-breaking).
  New `self_verification` heartbeat event type.
- **Security model change:** Publish action requires ceremony-gated
  `HumanDelegation`. 2-of-2 multi-sig (maintainer + consumer heart).
  On-chain anchoring for permissionless verification.
- **Downstream integration impact:** ClawNet adds ceremony + co-sign
  routes, EAS schema registration, birth-cert provenance gating at
  heart registration.

## First Consumer

ClawNet — runs its own soma-heart, operates the ceremony endpoint,
co-signs update certificates, anchors on Base, gates heart registration
on provenance.

## Security / Reliability Requirements

- Ceremony gate must be hard-block (no fallback to unsigned publish).
- GitHub Actions OIDC verification on the ceremony endpoint.
- ClawNet heart key must be persistently stored with 0600 permissions
  (already the case in `soma-heart.ts`).
- EAS anchoring failure should not block the publish — the
  UpdateCertificate is valid without the on-chain anchor, which can be
  retried. But the publish *must* block on the ceremony and co-sign.

## Delivery Shape

Two parallel tracks:

**Track A — Soma (protocol primitives):**
1. `src/supply-chain/update-certificate.ts` — types, create, verify
2. `src/heart/birth-certificate.ts` — add optional `packageProvenance`
   field, update canonicalization
3. `src/heart/certificate/vocabulary.ts` — register `update-certificate`
   profile and `package_provenance` claim
4. `src/supply-chain/index.ts` — export `verifyPackageProvenance`
5. `src/heart/heartbeat.ts` — add `self_verification` event type
6. Build script: `scripts/embed-release-manifest.mjs`
7. Build script: `scripts/append-release-log.mjs` (extend to accept
   ceremony delegation reference)

**Track B — ClawNet (implementation + CI):**
(Depends on PR-C WebAuthn enrollment being live)
1. `POST /v1/publish/ceremony-begin` route
2. `GET /v1/publish/ceremony-status` route
3. `POST /v1/publish/cosign` route
4. EAS schema registration on Base
5. `.github/workflows/publish.yml` updates
6. Birth-cert provenance gating at heart registration

Track A can start immediately. Track B depends on PR-C.

## ADR Needed?

No — this proposal is sufficient. The design doesn't create irreversible
architectural constraints that need separate decision records. The
certificate profile and vocabulary additions are additive, and the
birth-certificate extension is an optional field.

## Open Questions

All resolved during idea chat:

1. ~~Provenance on BirthCertificate vs separate certificate~~ →
   Direct field. Provenance is runtime metadata about the issuer's
   code, belongs on the birth cert. Non-breaking optional field.

2. ~~Full UpdateCertificate vs hash + URL in manifest~~ →
   Full certificate. Offline verification, minimal size impact,
   no URL availability dependency.

3. ~~CI runner attestation~~ →
   Yes. Verify GitHub Actions OIDC token independently at the ceremony
   endpoint. Three independent factors: biometric ceremony, GitHub OIDC,
   ClawNet CI token.

## Links

- `Soma/src/supply-chain/release-log.ts` — existing signed release chain
- `Soma/src/heart/birth-certificate.ts` — birth certificate types and
  verification
- `Soma/src/heart/ceremony-policy.ts` — L0-L3 ceremony tiers
- `Soma/src/heart/human-delegation.ts` — biometric-capable auth primitive
- `Soma/src/heart/human-session.ts` — session lifecycle with ceremony
  gating
- `Soma/src/heart/threshold-signing.ts` — M-of-N Ed25519 via Shamir
- `Soma/src/heart/certificate/vocabulary.ts` — profile + claim registry
- `claw-net/src/core/soma-heart.ts` — ClawNet heart initialization
- `claw-net/internal/active/identity-verification-tiers.md` — World
  AgentKit iris, Coinbase KYC, composite identity
- `claw-net/internal/active/session-mode-and-ceremony.md` — ClawNet
  wiring of Soma ceremony primitives
