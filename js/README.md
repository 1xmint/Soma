# Somavera Reference

Status: **early tokenless reference implementation; not production-ready or protocol-ratified**

This repository implements the first bounded Soma Pack slice from the public
Somavera Origin capsule. It deliberately contains no Vera Host, token, wallet,
market, autonomous payment, background observer, telemetry, updater, or legacy
runtime state.

Implemented commands:

```text
soma init --recovery none
soma doctor
soma status
soma identity status
soma identity controller-rotate-preview --reason "scheduled rotation"
soma identity controller-rotate-confirm --proposal-id HASH --expect-successor-key-hash HASH --confirm-controller-rotation
soma evidence record --input C:\absolute\event.json
soma evidence verify
soma host status
soma host verify --descriptor C:\absolute\host.json --expect-origin https://vera.example --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT
soma host pin --descriptor C:\absolute\host.json --expect-origin https://vera.example --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT --expect-key-hash HASH
soma host succession-preview --successor C:\absolute\successor.json --proof C:\absolute\proof.json
soma host succession-confirm --candidate-id HASH --subject HASH --expect-successor-descriptor HASH --confirm-inert-pin-replacement
soma host trust-export --out C:\absolute\host-trust.json
soma host trust-verify --capsule C:\absolute\host-trust.json --expect-controller-did DID --expect-controller-key-hash HASH
soma host trust-compare --trusted C:\offline\trusted.json --candidate C:\absolute\candidate.json --expect-controller-did DID --expect-controller-key-hash HASH
soma observe status
soma observe preview --artifact C:\absolute\public.txt --policy C:\absolute\policy.json
soma observe preview --evidence EVIDENCE_ID --policy C:\absolute\policy.json
```

Current production-profile support is Windows 11 with current-user DPAPI. An
unsupported secure store fails initialization. The implementation never falls
back to a plaintext production key file.

For development on an unsupported platform, an unmistakably insecure mode may
be selected with `--dev-insecure-file-keystore`. It is test-only, reports a
security degradation, and must never be used with private data or a network.

## Controller-key boundary

Ordinary offline controller-key rotation preserves one stable controller DID
through an exact old/new dual-signed event, protected pending key, one logical
identity commit point, deterministic restart recovery, historical public-key
windows, and successor-only live private-key state. It is not safe compromise
recovery and a same-device history is not independent rollback evidence.
Host-trust capsule v2 exports the complete dual-signed controller chain from
the independently expected initial key through the active key. A separately
preserved earlier capsule is still required for independent rollback/fork
comparison. See `CONTROLLER-ROTATION-PROFILE.md` and
`HOST-TRUST-CAPSULE-PROFILE.md`.

## Evidence boundary

The implemented evidence ledger is a provisional pre-network profile. It signs
minimized local attribution, not truth or reputation.

Counter-signed work receipts **are** implemented: a second party can attest to
this agent's work, and an event citing verified receipts carries
`self_signed_with_verified_counter_signatures`. What remains unavailable is
*independence* — classifying whether an attester is unrelated to the subject
needs lineage, which this implementation does not store — along with external
rollback anchors. Reputation computation is deliberately absent and will stay
absent: see `../RECEIPT-SPEC.md`. See `EVIDENCE-PROFILE.md` for the
exact domains, input contract, crash behavior, and limits.

## Offline Vera Host pinning

A local host descriptor can be schema-checked, signature-verified, and pinned
only with exact independently supplied identity, network, context, and signing-key
expectations. Pins are controller-signed but inert: they create no connection,
consent, or send authority. Direct changed-descriptor replacement fails closed.
An Origin ordinary-succession proof may be stored as a controller-signed inert candidate. Exact controller confirmation can atomically replace only the inert pin, retain signed history, and recover interrupted local commits. A complete signed portable host-trust capsule can export and independently verify those exact bytes; comparison against separately preserved trusted bytes detects rollback or forks. The capsule is not itself an external anchor or restore authority. None of these operations grants routing, connection, consent, disclosure, or send authority. See `HOST-PIN-PROFILE.md`, `HOST-SUCCESSION-PROFILE.md`, and `HOST-TRUST-CAPSULE-PROFILE.md`.

## Consent-preview boundary

Observation preview is local and offline. It supports only controller-attested
public UTF-8 artifacts and minimized signed-evidence projections. It creates no
grant or send authority, and its scanner is explicitly not proof that content
lacks private or regulated meaning. See `CONSENT-PREVIEW-PROFILE.md`.

## Development

```text
npm install --ignore-scripts
npm run manifest
npm run check
node bin/soma.mjs init --home C:\path\outside\the\repo --recovery none
node bin/soma.mjs doctor --home C:\path\outside\the\repo
```

The release manifest covers every distributable file except itself. `init`
verifies that manifest before creating state. User state must be outside this
repository.

This manifest proves internal file-set integrity only. Until an independently
preserved release hash or ratified threshold signature is supplied, it does not
authenticate the publisher or historical release.
