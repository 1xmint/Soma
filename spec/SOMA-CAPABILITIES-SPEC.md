# Soma Capabilities — Delegation Protocol

**Version:** `soma-capabilities/1.1`
**Status:** Draft
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

> 1.1 is additive over 1.0: new caveat kinds, a step-up primitive, a pluggable factor registry, and a deployment-configurable tier ladder. The wire format of existing caveats and delegations is unchanged. A 1.0 verifier encountering a 1.1-only caveat kind falls through to the unknown-kind path and FAILS CLOSED, so mixed-version deployments are safe as long as upgrades roll forward.

## Motivation

Agents need to hand other agents a narrow slice of their authority — not a raw API key, not a bearer token that broadcasts forever, but a signed, chainable, attenuable capability. The resulting model should answer three questions without a central authorization server:

1. **Can the holder of this token do X?** (capability grant)
2. **Under what conditions?** (caveats: time, budget, audience, etc.)
3. **Who is allowed to show it to me?** (proof of key ownership)

The macaroons model (Google, 2014) nailed chainable attenuation but relies on per-site HMAC chains. In an agent economy where every actor already owns a keypair, it's cleaner to bind delegations to DIDs and sign each link with the issuer's signing key. That's what this spec describes.

## Non-Goals

- **Replacing OAuth.** Soma Capabilities doesn't define user consent flows, login, or token storage. It defines the on-the-wire delegation format.
- **Defining what capabilities mean.** `tool:db:read` is just a string — the verifying service decides what it grants. This spec only defines how capability strings match and narrow.
- **Central revocation.** A Soma Capability is valid until it expires or is revoked via the Soma Revocation primitive. The spec integrates with revocation; it doesn't mandate a registry.

## Terminology

| Term | Meaning |
|------|---------|
| **Issuer** | Party signing a delegation. Must control a keypair. |
| **Subject** | Party receiving the delegation. Identified by DID. |
| **Holder** | Party currently presenting the delegation. |
| **Capability** | String naming an authority (e.g. `tool:db:read`, `api:weather`). |
| **Caveat** | Condition attached to a delegation that must hold at use-time. |
| **Attenuation** | Creating a new delegation that narrows a parent's scope. |
| **Chain** | Sequence of delegations from root issuer to current holder. |

## Capability Strings

Capability strings are opaque to the protocol. By convention they use colon-separated namespaces: `<namespace>:<resource>:<action>`.

Two wildcard forms are reserved:

| Pattern | Matches | Example |
|---------|---------|---------|
| `*` | Any capability | Root authority |
| `<prefix>:*` | Anything with this prefix | `tool:*` matches `tool:db`, `tool:api:call`, etc. |

Any capability not matching a grant fails closed.

## Delegation Structure

### Wire Format

A delegation is a JSON object with the following fields:

```json
{
  "id": "dg-<base64 random>",
  "issuerDid": "did:key:z6Mk...",
  "subjectDid": "did:key:z6Mk...",
  "capabilities": ["tool:db:read", "tool:db:write"],
  "caveats": [ ... ],
  "issuedAt": 1712345678901,
  "nonce": "<base64 16-byte random>",
  "parentId": null,
  "issuerPublicKey": "<base64 32-byte Ed25519 public key>",
  "signature": "<base64 64-byte Ed25519 signature>"
}
```

### Canonical JSON for Signing

The signature covers every field EXCEPT `signature` itself, serialized via JCS-style canonical JSON (recursive alphabetical key sort, no whitespace, `undefined` fields omitted). Implementations MUST use the same canonicalization as `src/core/canonicalize.ts`.

Signing input bytes:
```
utf8(canonicalJson({
  id, issuerDid, subjectDid, capabilities, caveats,
  issuedAt, nonce, parentId, issuerPublicKey
}))
```

Signature algorithm: Ed25519. `issuerDid` MUST be the `did:key` derivation of `issuerPublicKey` under the current signing provider's multicodec prefix.

## Caveat Types

All caveats use the shape `{ "kind": "<type>", ... }`. Every caveat MUST be checked at verification time; unknown `kind` values MUST fail closed.

### `expires-at`
```json
{ "kind": "expires-at", "timestamp": 1712349278901 }
```
Unix millisecond timestamp. Use fails if `now > timestamp`.

### `not-before`
```json
{ "kind": "not-before", "timestamp": 1712345678901 }
```
Unix millisecond timestamp. Use fails if `now < timestamp`.

### `audience`
```json
{ "kind": "audience", "did": "did:key:z6MkVerifier..." }
```
The DID of the service/verifier the delegation is intended for. Verifiers MUST pass their own DID in `InvocationContext.audienceDid` or the caveat FAILS CLOSED. This prevents a phishing verifier from accepting credentials meant for another service.

### `budget`
```json
{ "kind": "budget", "credits": 1000 }
```
Cumulative spending cap. Requires the verifier to track `cumulativeCreditsSpent` externally. Use fails if `cumulativeCreditsSpent + creditsSpent > credits`.

### `max-invocations`
```json
{ "kind": "max-invocations", "count": 50 }
```
Cap on number of times the delegation can be exercised. Verifier must track `invocationCount` externally.

### `capabilities`
```json
{ "kind": "capabilities", "allow": ["tool:db:read"] }
```
Narrows the capability set to a subset of what was granted. Wildcards apply as usual.

### `custom`
```json
{ "kind": "custom", "key": "ip-range", "value": "10.0.0.0/8" }
```
Opaque extension mechanism. Verifiers MUST recognize the `key` and apply the semantics, or FAIL CLOSED if they don't.

### `requires-stepup` *(1.1)*
```json
{ "kind": "requires-stepup", "minTier": 2, "maxAgeMs": 300000 }
```
Invocation requires a fresh `StepUpAttestation` (see §Step-Up, below) whose `subjectDid` equals the invoker, whose `tierAchieved` is at least `minTier`, and whose `acceptedAt` is no older than `maxAgeMs` (if set). Verifiers MUST have already cryptographically verified the attestation before placing a summary into `InvocationContext.stepUpAttestation`. If the field is absent, the caveat FAILS CLOSED.

### `host-allowlist` *(1.1)*
```json
{ "kind": "host-allowlist", "hosts": ["prod.example.com", "staging.example.com"] }
```
Invocation is valid only when `InvocationContext.host` is exactly one of the listed strings. No glob or regex matching — the surface is deliberately small. Missing `ctx.host` FAILS CLOSED.

### `command-allowlist` *(1.1)*
```json
{
  "kind": "command-allowlist",
  "patterns": [
    { "exact": ["ls", "-la"] },
    { "prefix": ["git", "log"] }
  ]
}
```
Invocation is valid only when `InvocationContext.commandArgv` matches at least one pattern. `exact` requires equal length and element-wise equality. `prefix` requires `commandArgv` to start with the listed elements. Shell interpolation is NEVER applied — matching is over the literal argv array. Missing `ctx.commandArgv` FAILS CLOSED.

### `time-window` *(1.1)*
```json
{
  "kind": "time-window",
  "windows": [
    { "startHourUtc": 9, "endHourUtc": 17 },
    { "startHourUtc": 22, "endHourUtc": 6 }
  ]
}
```
Invocation is valid only when the current UTC hour falls inside at least one window. A window with `startHourUtc <= endHourUtc` is `[start, end)`. A window with `startHourUtc > endHourUtc` wraps midnight (e.g. `22..6` means 22:00–05:59 UTC). Hours are 0–23 integers. No minute precision — the window is intended as a coarse curfew, not a rate limiter.

## Attenuation Rules

A holder MAY produce a new delegation that:

1. Has `parentId` set to the previous delegation's `id`.
2. Copies all of the parent's caveats **unchanged**, possibly adding more.
3. Has `capabilities` that are a **subset** of the parent's (no new capabilities).
4. Is signed by the attenuator's own signing key; the attenuator becomes the new `issuerDid`.

Any attenuation that broadens scope is invalid. Verifiers check this by walking the chain and asserting each `capabilities` array is a subset of its parent's and `caveats` includes every parent caveat.

## Verification Algorithm

Given a delegation `D` presented with invocation context `C`:

1. **Signature check.** Verify `D.signature` over the canonical JSON of `D` (excluding `signature`) against `D.issuerPublicKey`. Derive `did:key` from the public key; assert it equals `D.issuerDid`.
2. **Subject match.** Assert `D.subjectDid == C.invokerDid`.
3. **Proof of possession.** Assert the invoker controls the keypair for `C.invokerDid` (see §Proof of Possession).
4. **Capability match.** Assert `C.capability` is in `D.capabilities` or matches a wildcard.
5. **Caveat iteration.** For each caveat in `D.caveats`, apply the check from §Caveat Types. If any fails, reject.
6. **Chain walk (if `D.parentId != null`).** Fetch parent delegation, verify its signature, assert attenuation rules hold, recurse from step 1 with the parent as the new root.
7. **Revocation check.** Consult the revocation registry for every link in the chain. If any is revoked, reject.

All steps fail closed.

## Proof of Possession

A delegation names a `subjectDid` but says nothing about who is showing it to the verifier. A bearer-token model would accept anyone who has the JSON blob. Soma requires the holder to prove key ownership:

1. Verifier issues a challenge: `{nonce, delegationId, issuedAt}`.
2. Holder signs `"soma-pop:" + nonce + ":" + delegationId` with their signing key.
3. Verifier checks the signature against the public key derived from `subjectDid`.

Challenges MUST be single-use (track `nonce`) and short-lived (≤ 5 minutes). See `src/heart/proof-of-possession.ts`.

For two-party authenticated sessions where the verifier's identity also matters, use **Mutual Session PoP** (`src/heart/mutual-session.ts`) — a 3-message handshake where both parties sign the same transcript.

## Revocation Integration

Delegations carry `id`. Revocation events target IDs. The flow:

1. Any party in the chain may publish a `RevocationEvent` for a delegation they issued.
2. Events carry `targetKind: "delegation"`, `targetId: <delegation.id>`, and reason.
3. Verifiers consult a `RevocationRegistry` (in-process or gossiped per `src/heart/gossip.ts`).
4. A revoked delegation — or any delegation whose chain contains one — MUST fail verification.

Revocation events are themselves signed and hash-chained in a `RevocationLog` for tamper evidence.

## Security Considerations

- **Failing closed.** Unknown caveat kinds, missing context fields, unparseable signatures — every error path rejects.
- **Clock skew.** Time caveats depend on local clock trust. For cross-party contexts, embed a `TimeWitness` (`src/heart/time-oracle.ts`) or require a witness quorum.
- **Replay.** `nonce` in every delegation + short PoP challenges prevent simple replay. For replay across verifiers, use `audience` caveats.
- **Chain length.** There is no protocol-level bound on chain depth, but verifiers SHOULD cap it (recommended: 16) to bound work and prevent DoS.
- **Canonical JSON matters.** Any deviation in key ordering or whitespace breaks signatures. Implementations MUST use the shared `canonicalJson` utility.
- **Key rotation.** If an issuer rotates their key mid-chain (`KeyHistory`, `src/heart/key-rotation.ts`), verifiers MUST resolve `issuerDid` to the key version that was current at `issuedAt` — not the latest key.

## Factor Registry *(1.1)*

The factor registry is a per-heart mapping from `subjectDid` to the set of authentication factors that subject has proven possession of. It is the durable half of step-up: long-lived records of which device / key / channel the subject can approve on.

A `RegisteredFactor` has:

| Field | Meaning |
|------|---------|
| `factorId` | Opaque ID unique per `(subjectDid, factorId)` (e.g. a WebAuthn credential ID). |
| `factorType` | String identifying the factor family. Well-known values in `WELL_KNOWN_FACTOR_TYPES`; any string is accepted. |
| `subjectDid` | The DID this factor belongs to. |
| `publicMaterial` | Base64 public verification material (e.g. WebAuthn COSE public key). |
| `attestation` | Optional base64 attestation blob (e.g. FIDO2 attestation statement). |
| `isSecret` | `true` if the registry entry itself contains shared secrets (e.g. TOTP seed). Implementations SHOULD encrypt these at rest. |
| `metadata` | Free-form string map. `deviceId` is conventional, used by the tier ladder's `distinct-device-count` predicate. |
| `registeredAt` / `lastUsedAt` / `revokedAt` | Lifecycle timestamps. |

Registry operations: `register`, `get`, `listActive`, `listAll`, `markUsed`, `revoke`, `isActive`, `countActiveByType`, `toJSON` / `fromJSON`. Revocation preserves the original `revokedAt` on double-revoke. The registry returns defensive copies — callers cannot mutate state via `get`.

Well-known factor types (strings; registry is open):

```
webauthn-platform     webauthn-roaming     totp
email-magic-link      sms-otp              apple-app-attest
android-key-attest
```

Reference: `src/heart/factor-registry.ts`.

## Step-Up *(1.1)*

Step-up is the live half. A delegation's `requires-stepup` caveat says "before each invocation of this capability, get a human to approve *this specific action* on a registered factor". The flow:

1. A verifier (SSH guard, API middleware) about to honor a delegation sees a `requires-stepup` caveat. It computes a canonical **action digest** over whatever it's authorizing (host + argv, HTTP request shape, DB query plan — the verifier chooses the format; the helper `computeActionDigest(action)` hashes the canonical JSON).
2. The verifier asks the heart for a challenge: `StepUpService.createChallenge({ subjectDid, actionDigest, minTier, ttlMs? })`. The heart returns a signed `StepUpChallenge` and tracks it in its outstanding set.
3. The challenge reaches the human via a `StepUpOracle` (web push, email magic link, native app, CLI prompt — orthogonal to the crypto). An oracle that fails to deliver is a LIVENESS failure, not a safety one; the oracle never touches factor private keys.
4. The human approves on their factor device, producing a `FactorAssertion` over `challenge.actionDigest`.
5. The verifier calls `StepUpService.submitAttestation(assertion)`. The heart rejects unknown challenges, expired challenges, replayed challenges, missing/revoked factors, type mismatches, verifier-invalid assertions, and tiers below `challenge.minTier`. On success it marks the factor used, consumes the challenge (single-use), and returns a signed `StepUpAttestation`.
6. At use time, the verifier calls `verifyStepUpAttestation` (signature, action digest match, subject match, tier, age, optional trusted-heart key pinning) and then passes a summary to `checkCaveats` via `InvocationContext.stepUpAttestation`.

### `StepUpChallenge` wire format
```json
{
  "id": "su-<base64 random>",
  "protocol": "soma-stepup/1",
  "subjectDid": "did:key:z6Mk...",
  "actionDigest": "<verifier-chosen canonical hash>",
  "minTier": 2,
  "issuedAt": 1712345678901,
  "expiresAt": 1712345738901,
  "nonce": "<base64 16-byte random>",
  "heartDid": "did:key:z6MkHeart...",
  "heartPublicKey": "<base64 32-byte Ed25519 public key>",
  "signature": "<base64 64-byte Ed25519 signature>"
}
```

### `StepUpAttestation` wire format
```json
{
  "protocol": "soma-stepup/1",
  "challengeId": "su-...",
  "actionDigest": "<copy of challenge.actionDigest>",
  "subjectDid": "did:key:z6Mk...",
  "factorType": "webauthn-platform",
  "factorId": "<credential id>",
  "tierAchieved": 2,
  "assertedAt": 1712345679000,
  "acceptedAt": 1712345679050,
  "heartDid": "did:key:z6MkHeart...",
  "heartPublicKey": "<base64 public key>",
  "signature": "<base64 Ed25519 signature>"
}
```

Both are signed the same way as delegations: canonical JSON over all fields EXCEPT `signature`, Ed25519 by the heart's signing key.

Factor verification is pluggable. `FactorVerifierRegistry` maps `factorType` → `FactorAssertionVerifier`. Implementations live outside this module (`@soma/stepup-webauthn`, `@soma/stepup-totp`, etc.) so the heart has no dependency on WebAuthn libraries or TOTP implementations.

Reference: `src/heart/stepup.ts`, `src/heart/stepup-oracle.ts`.

## Tier Ladder *(1.1)*

The tier ladder is the deployment-specific piece of step-up. A solo developer and a regulated enterprise can share the same `FactorRegistry` and `StepUpService` code but disagree on what "tier 2" means. The ladder is pure config: an ordered list of `TierRule`s, each naming a numeric tier and a boolean predicate over a `TierEvalInput`.

Evaluation walks the ladder from highest tier to lowest and returns the first matching rule, or tier `0` if none match.

### Predicate algebra

```ts
type TierPredicate =
  | { kind: 'factor-type'; types: string[] }
  | { kind: 'min-factor-tier'; tier: number }
  | { kind: 'user-verification' }
  | { kind: 'hardware-attested' }
  | { kind: 'registered-count'; count: number; factorType?: string }
  | { kind: 'distinct-device-count'; count: number }
  | { kind: 'and'; of: TierPredicate[] }
  | { kind: 'or'; of: TierPredicate[] }
  | { kind: 'not'; of: TierPredicate };
```

`distinct-device-count` counts by `metadata.deviceId`, falling back to `factorId` when no device ID is set. Unknown predicate kinds FAIL CLOSED (evaluator returns `false`).

### Shipped ladders

**`DEFAULT_LADDER`** — sensible for developer setups:

| Tier | Condition |
|------|----------|
| 3 | hardware-attested AND user-verification AND ≥2 distinct devices |
| 2 | (hardware-attested AND UV) OR (UV AND ≥2 distinct devices) |
| 1 | WebAuthn (platform or roaming) AND UV |
| 0 | fallback |

**`PARANOID_LADDER`** — requires hardware attestation for any non-zero tier:

| Tier | Condition |
|------|----------|
| 3 | hardware-attested AND UV AND ≥3 distinct devices |
| 2 | hardware-attested AND UV AND ≥2 distinct devices |
| 1 | hardware-attested AND UV |

Reference: `src/heart/tier-ladder.ts`.

## Invocation Context additions *(1.1)*

The `InvocationContext` passed to `checkCaveats` gains three optional fields for 1.1 caveats. All three FAIL CLOSED when the corresponding caveat is present but the field is missing:

| Field | Required when caveat | Meaning |
|------|----------------------|--------|
| `host` | `host-allowlist` | The target host for the current invocation. |
| `commandArgv` | `command-allowlist` | The argv the verifier is about to execute, as a literal array. |
| `stepUpAttestation` | `requires-stepup` | `{ subjectDid, tierAchieved, acceptedAt }` — a summary of a step-up attestation the verifier has ALREADY cryptographically verified. |

## Reference Implementation

- `src/heart/delegation.ts` — `Delegation`, `Caveat`, `createDelegation`, `attenuateDelegation`, `verifyDelegation`, `checkCaveats`
- `src/heart/factor-registry.ts` — `FactorRegistry`, `RegisteredFactor`, `WELL_KNOWN_FACTOR_TYPES` *(1.1)*
- `src/heart/stepup.ts` — `StepUpService`, `StepUpChallenge`, `StepUpAttestation`, `FactorVerifierRegistry`, `verifyStepUpAttestation`, `computeActionDigest` *(1.1)*
- `src/heart/stepup-oracle.ts` — `StepUpOracle`, `BaseStepUpOracle`, `CliPromptOracle`, `OracleChain` *(1.1)*
- `src/heart/tier-ladder.ts` — `TierPredicate`, `TierRule`, `TierLadder`, `evaluateLadder`, `DEFAULT_LADDER`, `PARANOID_LADDER` *(1.1)*
- `src/heart/proof-of-possession.ts` — challenge/proof flow
- `src/heart/revocation.ts` — revocation events and registry
- `src/heart/revocation-log.ts` — append-only log with signed heads
- `src/core/canonicalize.ts` — JCS-style canonical JSON

## Versioning

The protocol identifier is `soma-capabilities/1.1`. Breaking changes MUST bump the major version. Adding new caveat kinds is additive (new verifiers reject unknowns, so an old verifier with a new caveat still fails closed) and does NOT require a version bump, but SHOULD be documented in the changelog below.

## Changelog

### 1.1
- Added `requires-stepup`, `host-allowlist`, `command-allowlist`, `time-window` caveat kinds.
- Added `InvocationContext.host`, `InvocationContext.commandArgv`, `InvocationContext.stepUpAttestation` — all fail-closed when the corresponding caveat is present.
- Added `FactorRegistry` primitive for per-DID authentication factor storage.
- Added `StepUpService`, `StepUpChallenge`, `StepUpAttestation`, `FactorVerifierRegistry`, and the `soma-stepup/1` sub-protocol for live human approval of individual invocations.
- Added `StepUpOracle` interface and `CliPromptOracle` / `OracleChain` reference implementations for pluggable challenge delivery.
- Added `TierLadder` DSL for deployment-configurable factor-to-tier policy, with `DEFAULT_LADDER` and `PARANOID_LADDER` shipped.
- Wire format for existing 1.0 delegations and caveats is unchanged.

### 1.0
- Initial draft. `Delegation`, attenuation, `expires-at` / `not-before` / `audience` / `budget` / `max-invocations` / `capabilities` / `custom` caveats, proof-of-possession, revocation integration.
