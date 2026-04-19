Status: proposed

# Lineage Fork Ceremony — Cross-Repo Heart Parentage

**Status:** design. No implementation changes.
**First consumer:** Pulse (heart persistence workstream, PR #38).
**Covers:** how independently-deployed hearts establish cryptographic
parent-child lineage, what a fork ceremony is, who runs it, what
artifacts it produces, and where the scope boundary falls between
Soma protocol and downstream integration.

---

## 0. Problem

Soma hearts can be created (`createSomaHeart`) and persisted
(`serializeHeart`/`loadHeartState`). The lineage subsystem
(`src/heart/lineage.ts`) already supports signed parent-child
certificates, chain verification, capability attenuation, TTL, and
budget credits. Attack test #14 (lineage grafting) validates the
cryptographic defenses. The persistence format already carries
`lineageChain` and `lineageRootDid` fields.

But there is no ceremony — no defined protocol for how two
independently-booted hearts (e.g. ClawNet's operator heart and
Pulse's operator heart) establish a lineage relationship. Today:

- ClawNet boots its heart via `createSomaHeart()` — no parent.
- Pulse boots its heart via `createSomaHeart()` — no parent.
- Both hearts are cryptographic strangers.

Pulse already forks *sub-agent* hearts from its own operator heart
(`forkAgentHeart` in `hosted/heart-client.ts`), but the operator
heart itself has no lineage. There is no cryptographic evidence that
Pulse's heart was authorized by the same operator who controls
ClawNet's heart. An observer cannot distinguish "your Pulse agent"
from "a stranger's Pulse agent."

The pulse-heart-persistence checkpoint (G2, PR #38) escalated this
as: "Lineage chain design touches pulse, claw-net, and soma-heart
repos." This proposal defines the Soma-side protocol; downstream
repos document their integration.

## 1. Why Now

- Pulse PR #38 merged heart persistence. The next natural step is
  lineage, and the checkpoint explicitly calls for idea-chat review.
- The lineage primitive is already built and tested in Soma. The gap
  is the ceremony, not the cryptography.
- Without lineage, heart identity is meaningless across repo
  boundaries — any agent can claim to be "the Pulse agent" and there
  is no way to verify the claim against a trust root.
- The persistence pattern (env secret + encrypted blob + 0o600) is
  now shared by ClawNet and Pulse. A third adopter is plausible. The
  ceremony should be defined before the pattern proliferates without
  lineage.

## 2. What a Lineage Chain Proves

Independent hearts prove: "I exist and I can sign things."

A lineage chain proves:

1. **Provenance.** Who spawned this heart and when. The full ancestry
   back to the root is verifiable by any observer holding the chain.
2. **Capability attenuation.** Each link can only narrow capabilities,
   never widen. A child heart cannot grant itself permissions its
   parent lacks. This is enforced by `effectiveCapabilities()`.
3. **Revocability.** The parent can revoke the lineage certificate,
   killing the child's authority. Pulse already uses this:
   `revokeAgentHeart()` calls `heart.revoke({targetKind: 'lineage'})`.
4. **Accountability.** Reputation and blame flow up the lineage tree.
   If a child heart misbehaves, the parent's identity is on the chain.

Without lineage between ClawNet and Pulse, property (1) is missing
entirely — there is no cryptographic evidence linking them to the
same operator.

## 3. Broad Idea — The Offline Fork Ceremony

The ceremony is a provisioning step, not a runtime protocol. It runs
once per parent-child relationship, at deployment time, by an operator
who has access to both hearts. It is analogous to TLS certificate
provisioning — you don't negotiate certificates at request time.

### Ceremony Protocol

```
Inputs:
  - Parent heart blob (encrypted)  OR  running parent heart
  - Parent heart secret (password)
  - Child heart blob (encrypted)   OR  child genome config
  - Child heart secret (password)
  - Capabilities to grant (string[])
  - Optional: TTL, budget credits

Steps:
  1. Decrypt parent heart blob → obtain parent GenomeCommitment
     and signing key.
  2. If child blob exists: decrypt it → obtain child GenomeCommitment.
     If child blob does not exist: generate a fresh keypair, build
     genome, create a new heart.
  3. Call createLineageCertificate({
       parent: parentCommitment,
       parentSigningKey: parentSecretKey,
       child: childCommitment,
       capabilities,
       ttl,
       budgetCredits,
     }).
  4. Build the child's HeartLineage:
       { did: childDid, rootDid: parentDid, chain: [cert] }
     If the parent itself has lineage, prepend the parent's chain:
       { did: childDid, rootDid: parent.lineageRootDid,
         chain: [...parent.lineageChain, cert] }
  5. Patch the child's HeartState to include lineageChain and
     lineageRootDid.
  6. Re-encrypt the child heart blob with the child's secret.
  7. Write the patched child blob to disk.
  8. Wipe all secrets from memory.

Outputs:
  - Patched child heart blob (with lineage chain embedded)
  - Lineage certificate ID (for revocation reference)
  - No changes to the parent heart blob (parent state unchanged)
```

### What Goes in the Birth Certificate (Lineage Certificate)

The `LineageCertificate` type already defines this (no changes needed):

- `id` — opaque cert ID for revocation reference
- `parentDid` / `parentGenomeHash` — who signed
- `childDid` / `childGenomeHash` — who was authorized
- `capabilities` — what the child can do (empty = inherit all)
- `issuedAt` / `expiresAt` — temporal bounds
- `budgetCredits` — optional economic constraint
- `nonce` — replay prevention
- `signature` — parent's Ed25519 signature over canonical payload
- `parentPublicKey` — for self-contained verification

The parent signs: everything above except `signature` itself,
domain-separated under `soma/lineage/v1`.

### CLI Tool Interface (Sketch)

```
soma-heart fork \
  --parent-blob ./data/clawnet-heart.json \
  --parent-secret-env CLAWNET_HEART_SECRET \
  --child-blob ./data/pulse-heart.json \
  --child-secret-env PULSE_HEART_SECRET \
  --capabilities "content:post,content:reply,content:schedule" \
  --ttl 90d \
  --output ./data/pulse-heart.json
```

Flags:
- `--parent-blob` / `--parent-secret-env`: parent heart source
- `--child-blob` / `--child-secret-env`: existing child heart
- `--child-new`: alternative to `--child-blob`; generate fresh child
- `--capabilities`: comma-separated capability strings
- `--ttl`: human-readable duration (e.g. `90d`, `24h`, `none`)
- `--budget`: optional credit budget
- `--output`: where to write the patched child blob (defaults to
  overwriting `--child-blob`)
- Secrets come from env vars, never from CLI arguments (no shell
  history leaks)

## 4. What 10/10 Looks Like

- An operator can provision lineage between any two Soma hearts in
  under 30 seconds using a single CLI command.
- The patched child heart boots normally via `loadSomaHeart()` and
  carries its full lineage chain. No code changes in the child's
  boot path.
- Any observer can call `verifyLineageChain()` on the child's
  lineage to prove it was authorized by the parent.
- Capability attenuation works across the fork boundary — the child
  cannot exceed the capabilities granted at ceremony time.
- The parent can revoke the child's lineage cert without access to
  the child's heart.
- Key rotation on either side does not break existing lineage proofs
  (see §6).
- The ceremony tool never persists secrets and operates in a
  locked-down context. Secrets are wiped from memory after use.

## 5. Alternatives Considered

**Runtime ceremony (rejected).** ClawNet exposes a fork endpoint;
Pulse calls it at boot. Creates a hard runtime dependency, a new
network attack surface, and means Pulse cannot start without ClawNet
being up. Worse: the fork endpoint would need to accept an
unauthenticated child's public key — chicken-and-egg problem since
the child has no lineage yet to prove it's authorized to request a
fork.

**Shared-secret derivation (rejected).** Both hearts derive lineage
from a shared operator seed. Loses the parent-child model entirely:
no capability attenuation, no directed revocation, no asymmetric
authority. Two hearts derived from the same seed are peers, not
parent and child.

**Registry/broker ceremony (premature).** A third service brokers
the fork. Over-engineered for the current scale (two consumers). The
registry itself becomes a new trust anchor that must be secured. May
be appropriate later for N-party dynamic forking, but not now.

**Genesis-only lineage (insufficient).** Mark one heart as "root"
and derive all others from it at first-boot time. This is what
`forkAgentHeart` does within Pulse, but it requires the parent heart
to be running in the same process. Does not solve the cross-repo
deployment case.

## 6. Key Rotation Interaction

The lineage certificate embeds `parentPublicKey` and the signature
is made with the parent's key at ceremony time. When the parent
rotates keys:

- **Existing lineage certs remain valid.** The signature was made by
  the old key, and `parentPublicKey` records the old key. Signature
  verification succeeds against the recorded key.
- **Verifiers need historical key resolution.** To confirm the old
  key legitimately belonged to the parent at `issuedAt`, verifiers
  should use `HistoricalKeyLookup` — the same pattern
  `verifyBirthCertificate` already uses.
- **Compromised (not just rotated) keys are a revocation problem.**
  If the parent's key is compromised, lineage certs signed by that
  key should be revoked. This is handled by the existing revocation
  subsystem, not by lineage itself.

### Proposed Change

`verifyLineageChain` should accept an optional `HistoricalKeyLookup`
parameter. When provided, each certificate's `parentPublicKey` is
checked against the rotation subsystem for validity at `issuedAt`.
When omitted, current behavior is preserved (self-contained
verification against the embedded key). This mirrors the existing
pattern in `verifyBirthCertificate`.

This is a non-breaking, additive change to the existing API.

## 7. Fitness Check

- **Protocol vision fit:** Yes. Lineage is already a Soma protocol
  primitive with types, signing, verification, and attack tests. The
  ceremony completes the primitive by defining how lineage is
  established across deployment boundaries.
- **Real implementer/operator need:** Yes. Pulse PR #38 checkpoint
  explicitly escalated this. ClawNet and Pulse are the two current
  consumers, and a third adopter of the persistence pattern is
  plausible.
- **Security exposure:** Medium. The CLI tool handles two hearts'
  secrets simultaneously. Mitigated by: secrets from env vars only,
  memory wipe after use, no network access needed, no persistence of
  secrets.
- **Evidence this is needed now:** Pulse heart persistence is merged.
  Lineage is the next natural step. The checkpoint marks it as
  blocked on idea-chat review.
- **Keep / reshape / pause / remove:** Keep. The primitive exists;
  the ceremony is the missing piece.

## 8. Evidence Ledger

- **Current status:** `lineage.ts` is 237 lines, fully tested,
  attack-tested. Persistence carries lineage fields. No ceremony
  exists.
- **Upstream dependencies:** None — lineage uses only Soma's own
  crypto provider and genome primitives.
- **Downstream dependencies:** Pulse (`heart-client.ts`) and
  ClawNet (heart initialization). Both would consume the ceremony
  tool's output (patched heart blobs) but require no code changes
  to their boot paths.
- **Missing evidence:** ClawNet's heart-client source was not
  accessible during this review. Need to verify ClawNet's heart
  initialization pattern matches the ceremony's assumptions.
- **Blocks current work:** Not a hard blocker. Hearts function
  without lineage. But lineage is required for cross-repo trust,
  which is required for meaningful multi-agent authority.
- **Next gate:** Proposal review → ADR (if accepted) → implementation.
- **Terminal condition:** Ceremony is shipped in `soma-heart` package
  with CLI tool, tests, and documentation. Downstream repos document
  their integration. ADR records the protocol decision.

## 9. Protocol Surface

- **Spec change:** No — lineage cert format is unchanged. The
  ceremony is an operational protocol, not a wire format change.
- **Package API change:** Yes — new exported function(s) for
  ceremony orchestration (decrypt parent, create cert, patch child,
  re-encrypt). New CLI entry point. Optional `HistoricalKeyLookup`
  parameter added to `verifyLineageChain`.
- **Security model change:** No new trust assumptions. The ceremony
  requires the same secrets that `loadHeartState` already requires.
  The CLI tool is a composition of existing primitives.
- **Downstream integration impact:** Downstream repos receive
  patched heart blobs. No changes to `loadSomaHeart()` or heart
  boot paths. Downstream repos document when and how to run the
  ceremony in their deployment guides.

## 10. Scope Boundary

### Soma Owns

- The ceremony protocol (steps 1-8 in §3)
- The CLI tool implementation
- The `HistoricalKeyLookup` integration in `verifyLineageChain`
- Tests: ceremony happy path, re-ceremony (re-forking), multi-level
  chains, capability attenuation across ceremony boundary
- Package surface: exported ceremony function(s) + CLI

### Downstream Repos Own

- When to run the ceremony (at image build, at deploy, at first boot)
- How to store and rotate the parent heart secret in their infra
- Deployment documentation for their specific topology
- CI/CD integration (if any)

### Explicitly Out of Scope

- N-party dynamic forking (registry-brokered ceremonies)
- On-chain anchoring of lineage chains
- Gossip-based lineage distribution
- Lineage-based reputation scoring
- Automatic re-forking on parent key rotation

## 11. First Consumer

Pulse. The deployment would be:

1. Operator boots ClawNet (creates or loads ClawNet's heart)
2. Operator runs `soma-heart fork` CLI against ClawNet's heart blob
   and Pulse's heart blob
3. Pulse boots normally via `loadSomaHeart()` — lineage chain is
   already in its blob
4. Pulse's sub-agent forks (`forkAgentHeart`) now produce two-link
   chains: ClawNet → Pulse → sub-agent

## 12. Security / Reliability Requirements

- CLI tool MUST read secrets from env vars, never from CLI arguments
- CLI tool MUST wipe all key material from memory after use
- CLI tool MUST NOT make network requests
- CLI tool MUST NOT persist secrets or intermediate state
- CLI tool MUST validate both heart blobs before modifying either
- CLI tool MUST fail-fast on invalid blobs, wrong passwords, or
  mismatched crypto providers
- Patched child blob MUST be verifiable by `verifyLineageChain`
  immediately after ceremony
- Ceremony MUST be idempotent: re-running with same inputs produces
  a new cert (new nonce, new timestamp) but does not corrupt the
  child's existing state

## 13. Delivery Shape

1. **Ceremony library** — exported functions in `soma-heart`:
   `forkCeremony(opts)` that orchestrates steps 1-8. Composition of
   existing primitives (`loadHeartState`, `createLineageCertificate`,
   `serializeHeart`).
2. **CLI tool** — `packages/soma-heart/bin/soma-heart-fork.ts` or
   similar. Thin wrapper around the ceremony library.
3. **verifyLineageChain enhancement** — optional `HistoricalKeyLookup`
   parameter (non-breaking).
4. **Tests** — unit tests for ceremony library, integration test
   that creates two hearts, runs the ceremony, and verifies the
   child's chain.
5. **Docs** — ceremony protocol in `docs/how-to/` or
   `docs/reference/`. Downstream repos link to it from their
   deployment guides.

## 14. ADR Needed?

Likely yes. The ceremony adds to `soma-heart`'s package surface (new
exports, new CLI entry point) and defines a new operational protocol
for establishing trust relationships. This meets the AGENTS.md
threshold: "if an idea changes identity semantics, credential rotation
semantics, delegation, verification, security posture, or public
package API, require a proposal and likely an ADR/spec update before
implementation."

Recommended: accept this proposal first, then promote the ceremony
protocol section to ADR-0006 before implementation begins.

## 15. Open Questions

1. **Should lineage be required for production hearts?** Currently
   hearts function without lineage. Should `soma-heart` emit a
   warning on boot if no lineage chain is present? Or is lineage
   strictly opt-in?

2. **Multi-level ceremony.** If ClawNet's heart itself has lineage
   (e.g. operator → ClawNet → Pulse), the ceremony must prepend the
   parent's chain. The protocol in §3 handles this, but should the
   CLI tool enforce a maximum chain depth?

3. **Ceremony audit log.** Should the CLI tool emit a signed receipt
   of the ceremony (timestamp, parent DID, child DID, cert ID) for
   the operator's records? This is not the lineage cert itself but a
   separate operational artifact.

4. **ClawNet heart-client verification.** ClawNet's source was not
   accessible during this review. Need to verify that ClawNet's heart
   initialization pattern (blob path, secret env var, boot sequence)
   is compatible with the ceremony's assumptions about heart blob
   format.

5. **Revocation distribution.** If the parent revokes a child's
   lineage cert, how does the child (or observers) learn about it?
   This is the same distribution problem as general revocation gossip
   and should not block the ceremony design, but the proposal should
   acknowledge it.

## 16. Links

- `src/heart/lineage.ts` — existing lineage primitive
- `src/heart/persistence.ts` — heart serialization (carries lineage)
- `src/heart/key-rotation.ts` — KERI-style pre-rotation
- `src/heart/historical-key-lookup.ts` — rotation-aware key validity
- `tests/attacks/14-lineage-grafting.test.ts` — lineage grafting defense
- `pulse/hosted/heart-client.ts` — Pulse's heart init + fork/revoke
- Checkpoint: `_agent-system/checkpoints/pulse-heart-persistence.md`
- Checkpoint: `_agent-system/checkpoints/pulse-heart-integration.md`
