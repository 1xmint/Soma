# Soma Reference Implementation Status

Date: 2026-07-22
Contract source: Somavera Origin local commit `bdc7fb2`
Release status: **early Windows-first slice; not protocol-conforming or production-ready**

## Implemented in this slice

- Dependency-free Node 22 CLI with `init`, `doctor`, `status`, and provisional
  `evidence record` / `evidence verify` commands.
- Offline release file-set and SHA-256 verification before state creation.
- Honest `self_manifest_integrity_only_untrusted` authenticity label.
- Atomic fresh-home creation with rollback after failed post-rename validation.
- Absolute external home requirement and parent link/reparse resolution checks.
- Windows current-user DPAPI protection for controller, agent, observer, and
  Vera private-reply key material plus the future local root store key.
- Windows ACL restricted to the current user and SYSTEM, recursively verified
  across every state path by `doctor`.
- Observer off, telemetry off, automatic updates/retries off, no watchers, no
  hosts, no grants, no queued work, no wallet, and no token state.
- Provisional pre-network signed evidence events, hash-chained canonical JSONL,
  controller-signed heads, strict key-window verification, and explicit
  `local_only_unanchored` rollback limits.
- Explicit `none` recovery choice; unratified offline recovery fails closed.
- Offline consent preview with exact field projection, lifecycle consistency,
  proposed DID/origin destinations, exact replication targets, deterministic
  commitments, controller rights attestation, secret/identity canary blocking,
  and redacted denial records.
- Dynamic zero-egress sentinel and static production network-import scan.
- Idempotent initialization and observer-tamper rejection.

## Not implemented

- Ratified portable network evidence, independent receipts, external head
  anchors, and any reputation computation.
- Host discovery, connection, encrypted query/response, or contribution flows.
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
