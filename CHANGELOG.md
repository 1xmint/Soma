# Changelog

All notable changes to published Soma packages are documented here.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 releases (`0.x.y`) may include breaking changes between minor versions;
this will be called out explicitly in release notes.

Each published package has its own version line (e.g. `soma-heart@0.3.0`).
Entries are grouped by package and dated.

---

## soma-heart@0.3.0 — 2026-04-11

### Package restructure

- **`soma-heart` is now the single source of truth.** All sensorium code
  lives inside `soma-heart` as subpath exports. `soma-sense` remains on
  npm as a thin re-export of `soma-heart/sense` — install it if you only
  want observer-side verification without interacting with the heart
  directly. Both `import { withSomaSense } from 'soma-heart/sense'` and
  `import { withSomaSense } from 'soma-sense'` work.
- **New subpath exports on `soma-heart`:** `./sense`, `./senses`,
  `./atlas`, `./mcp`, `./signals`. Tree-shaking keeps bundle size flat —
  import only the subpath you need and your bundler drops the rest.
- **New runtime dependency:** `@modelcontextprotocol/sdk >=1.0.0` (pulled
  in from the merged sensorium/MCP middleware).
- **Ship artifact cleanup:** the prior two-package build duplicated
  `dist/heart/` and `dist/core/` inside the `soma-sense` tarball. The
  unified build emits one `dist/` with zero duplication.

### Added

- **Credential rotation primitive** (`soma-heart/credential-rotation`) — 12-invariant controller with KERI pre-rotation, L1/L2/L3 layered verification, pluggable backends, challenge-period gating, and Ed25519 identity backend. Exported as a subpath.
- **HumanDelegation primitive** (`src/heart/human-delegation.ts`) — signed consent payload binding an agent ephemeral DID to a human durable DID under a bounded capability envelope. Reuses the existing `Caveat` vocabulary from `delegation.ts`. Attestation verification is pluggable (`AttestationVerifier`) so Soma stays free of WebAuthn / platform-crypto dependencies. Canonical signing under `soma/human-delegation/v1` domain; challenge hash binds attestation to `(envelope, session, agent pubkey)` to defeat replay.
- **Ceremony policy engine** (`src/heart/ceremony-policy.ts`) — pure lookup from action class to required ceremony tier (L0–L3). Fail-safe defaults: `read=L0`, `write=L1`, `spend/deploy=L2`, `admin=L3`, unknown=L2. Extensible via `PolicyOverrides`.
- **Human session registry** (`src/heart/human-session.ts`) — runtime handle wrapping a verified `HumanDelegation` with mutable budget / invocation counters. Enforces envelope caveats + policy on every invoke. Idempotent `open` by sessionId. Terminal states: `expired`, `revoked`, `budget-exhausted`, `invocations-exhausted`.
- **Heartbeat event types** — `consent_required` and `consent_granted` flow through the existing chain so observers see the ceremony handshake with no new plumbing.
- **Hacker-audit hardening** — see prior hardening commit for chain restore verification, strict signature verification, PoP enforcement, and session TTL.
- **Design doc** — `docs/design/session-mode.md` covers the session-mode architectural blueprint end-to-end.

### Changed

- `DEFAULT_POLICY` from ceremony-policy is now exported as `DEFAULT_CEREMONY_POLICY` to avoid ambiguity with the credential-rotation `DEFAULT_POLICY`. (Breaking vs. session-mode primitives shipped in source but not yet published — no external consumer impact.)
- `soma-heart` package description now lists credential rotation + session mode as top-level capabilities.
- `publishConfig.provenance` enabled — all future publishes will generate npm provenance attestations when published via GitHub Actions with trusted publishing.

### Package metadata

- SemVer: pre-1.0 — minor bumps may include breaking changes until the API surface stabilizes at `1.0.0`.
- Exports: `.`, `./core`, `./credential-rotation`, `./crypto-provider`, `./sense`, `./senses`, `./atlas`, `./mcp`, `./signals`.

---

## soma-heart@0.2.0 — prior

Initial public release. Per-token HMAC, birth certificates, heartbeat chain,
delegation (macaroons-style), proof-of-possession, step-up attestation,
hybrid signing, credential vault, revocation log, mutual session, gossip,
lineage, and remote attestation primitives. Credential rotation and
crypto-provider subpaths added in a point release.

---

## soma-sense@0.1.0 — deprecated

Initial pre-release. Temporal fingerprinting, behavioral landscape, and
phenotype atlas primitives for phenotypic verification of agent identity.
**Superseded by `soma-heart@0.3.0`** — install `soma-heart` and import
from `soma-heart/sense` instead. The `soma-sense` package will receive
no further releases.
