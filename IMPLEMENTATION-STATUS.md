# Soma Reference Implementation Status

Date: 2026-07-16
Contract source: Somavera Origin local commit `bdc7fb2`
Release status: **early Windows-first slice; not protocol-conforming or production-ready**

## Implemented in this slice

- Dependency-free Node 22 CLI with `init`, `doctor`, and `status`.
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
- Empty evidence ledger and public-only identity/key-history records.
- Explicit `none` recovery choice; unratified offline recovery fails closed.
- Dynamic zero-egress sentinel and static production network-import scan.
- Idempotent initialization and observer-tamper rejection.

## Not implemented

- Signed evidence append/verification and independent receipts.
- Host discovery, connection, encrypted query/response, or contribution flows.
- Consent preview, grants, withdrawals, deletion, or tombstone tracking.
- Sovereign Vera export/import/search.
- Identity recovery or encrypted owner-state backup/restore.
- macOS or Linux production keystore support.
- Signed release authenticity, SBOM, provenance, or reproducible binary bundle.
- Vera Host, replication, learning, reputation, ledger, wallet, or token logic.

The root store key is provisioned but no sensitive content body exists in this
slice. Therefore this release demonstrates protected authority secrets and the
future encryption-key boundary; it does not yet claim a complete encrypted
local content store.
