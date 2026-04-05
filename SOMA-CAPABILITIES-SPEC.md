# Soma Capabilities — Delegation Protocol

**Version:** `soma-capabilities/1.0`
**Status:** Draft
**Author:** Joshua Fair (`1xmint`)
**Repository:** [github.com/1xmint/Soma](https://github.com/1xmint/Soma)

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

## Reference Implementation

- `src/heart/delegation.ts` — `Delegation`, `Caveat`, `createDelegation`, `attenuateDelegation`, `verifyDelegation`, `checkCaveats`
- `src/heart/proof-of-possession.ts` — challenge/proof flow
- `src/heart/revocation.ts` — revocation events and registry
- `src/heart/revocation-log.ts` — append-only log with signed heads
- `src/core/canonicalize.ts` — JCS-style canonical JSON

## Versioning

The protocol identifier is `soma-capabilities/1.0`. Breaking changes MUST bump the major version. Adding new caveat kinds is additive (new verifiers reject unknowns, so an old verifier with a new caveat still fails closed) and does NOT require a version bump, but SHOULD be documented in a changelog.
