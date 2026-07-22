# Soma Reference Implementation Status

Date: 2026-07-22
Contract source: Somavera Origin local commit `07a4e89`
Release status: **early Windows-first slice; not protocol-conforming or production-ready**

## Implemented in this slice

- Dependency-free Node 22 CLI with local state, evidence, consent-preview,
  host-pin, and inert host-succession-preview commands.
- Offline release file-set and SHA-256 verification before state creation.
- Honest `self_manifest_integrity_only_untrusted` authenticity label.
- Atomic fresh-home creation with rollback after failed post-rename validation.
- Absolute external home requirement and parent link/reparse resolution checks.
- Windows current-user DPAPI protection for controller, agent, observer, and
  Vera private-reply key material plus the future local root store key.
- Windows ACL restricted to the current user and SYSTEM, recursively verified
  across every state path by `doctor`.
- Observer off, telemetry off, automatic updates/retries off, no watchers, no
  connected hosts, no grants, no queued work, no wallet, and no token state.
- Provisional pre-network signed evidence events, hash-chained canonical JSONL,
  controller-signed heads, strict key-window verification, and explicit
  `local_only_unanchored` rollback limits.
- Explicit `none` recovery choice; unratified offline recovery fails closed.
- Offline consent preview with exact field projection, lifecycle consistency,
  proposed DID/origin destinations, exact replication targets, deterministic
  commitments, controller rights attestation, secret/identity canary blocking,
  and redacted denial records.
- Offline Vera Host descriptor schema/semantic/signature verification and
  controller-signed inert pinning with exact out-of-band bindings.
- Bounded overlap keys as non-authoritative precommitments plus verification and
  controller-signed storage of one inert ordinary-succession candidate per host;
  no candidate can replace a pin, connect, consent, disclose, or send.
- Dynamic zero-egress sentinel and static production network-import scan.
- Idempotent initialization and observer-tamper rejection.

## Not implemented

- Ratified portable network evidence, independent receipts, external head
  anchors, and any reputation computation.
- Network host discovery, authenticated TLS connection/challenge, application
  encryption, query/response, or contribution flows.
- Controller-confirmed succession, atomic pin replacement/history, candidate
  consumption, and emergency host recovery.
- Signed consent grants, sends, withdrawals, deletion, acknowledgements, or
  tombstone tracking.
- Sovereign Vera export/import/search.
- Identity recovery or encrypted owner-state backup/restore.
- macOS or Linux production keystore support.
- Signed release authenticity, SBOM, provenance, or reproducible binary bundle.
- Vera Host, replication, learning, reputation, ledger, wallet, or token logic.

The root store key is provisioned but no sensitive content body is accepted in
this slice. Artifact preview is limited to bytes attested as already public, and
evidence preview is limited to the minimized local ledger projection. Therefore
this release demonstrates protected authority secrets and the
future encryption-key boundary; it does not yet claim a complete encrypted
local content store.
