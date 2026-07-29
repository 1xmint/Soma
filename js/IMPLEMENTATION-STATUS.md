# Soma Reference Implementation Status

Date: 2026-07-26
Contract source: Somavera Origin commit `b64d7794ad368f5e690596e50dd0c11ef2f73072`, capsule `48e45cb82cf27e0b3ad94d492c92cb6249ed7dc69734171e86c34ea424aed243`
Release status: **early Windows-first slice; not protocol-conforming or production-ready**

## Implemented in this slice

- Dependency-free Node 22 CLI with local state, evidence, consent-preview, host-pin, and inert ordinary host-succession commands.
- Offline release file-set and SHA-256 verification before state creation, labeled honestly as `self_manifest_integrity_only_untrusted`.
- Atomic fresh-home creation with rollback, absolute external-home enforcement, parent link/reparse checks, current-user DPAPI secret protection, and recursively verified Windows ACLs.
- Observer, telemetry, updates, retries, watchers, connections, grants, queued work, wallet, and token features absent/off.
- Provisional signed evidence with canonical hash chaining and explicit `local_only_unanchored` rollback limits.
- Explicit `none` recovery choice; unratified offline recovery fails closed.
- Offline consent preview with exact projections, deterministic commitments, controller rights attestation, canary blocking, and redacted denials.
- Complete offline Vera Host descriptor validation and controller-signed inert out-of-band pinning.
- Bounded ordinary-succession preview with dual-signature/precommitment validation and one inert controller-signed candidate per host.
- Exact controller-confirmation receipt, version-2 inert pin, signed transition history, atomic current-pin replacement, deterministic crash recovery, idempotency, and per-host race serialization.
- Fault injection at every transaction boundary and a 100-identical-plus-one-competing confirmation race.
- Complete controller-signed portable host-trust capsule v2 exports, full dual-signed controller-history verification from an independently expected initial key, historical host-signature verification, controller-and-host prefix comparison, rollback/fork detection, legacy v1 verification, exclusive output creation, and explicit non-anchor/non-restore authority.
- Ordinary offline Soma controller-key rotation with immutable proposal commitment, DPAPI-protected pending successor, old/new role-separated signatures, stable controller DID, authenticated public history, one identity commit point, deterministic restart recovery, historic signature verification, and successor-only live controller private-key state.
- Controller-rotation fault injection at each transaction boundary and a 100-identical-plus-one-competing confirmation race under the zero-egress sentinel.
- Current-only new pinning plus explicitly supported immediately prior Origin-profile verification and succession compatibility.
- Dynamic zero-egress sentinel and static production network-import scan.

## Not implemented

- Ratified portable network evidence, external rollback anchors, or reputation computation. Reputation computation is not pending: it is deliberately excluded, because identities are free and any global aggregate can be inflated by manufacturing attesters.
- Independence classification for receipts. Counter-signed receipts are implemented; deciding whether an attester is unrelated to the subject needs lineage, which is not stored here.
- Network discovery, authenticated TLS connection/challenge, application encryption, query/response, or contribution flows.
- External host-history anchor adapters, independent publication receipts, host-trust restore/import, or emergency host recovery.
- Signed consent grants, sends, withdrawals, deletion, acknowledgements, or tombstone tracking.
- Sovereign Vera export/import/search.
- Identity recovery, compromised-key recovery, encrypted owner-state backup/restore, controller revocation, or non-controller key rotation.
- macOS or Linux production keystore support.
- Signed release authenticity, SBOM, provenance, or reproducible binary bundle.
- Vera Host runtime, replication, learning, reputation, ledger, wallet, or token logic.

The root store key is provisioned but no sensitive content body is accepted in this slice. Artifact preview is limited to bytes attested as already public, and evidence preview is limited to the minimized local ledger projection. This release demonstrates protected local authority secrets and a future encryption-key boundary; it does not claim a complete encrypted local content store or network protocol.
