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
soma evidence record --input C:\absolute\event.json
soma evidence verify
soma host status
soma host verify --descriptor C:\absolute\host.json --expect-origin https://vera.example --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT
soma host pin --descriptor C:\absolute\host.json --expect-origin https://vera.example --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT --expect-key-hash HASH
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

## Evidence boundary

The implemented evidence ledger is a provisional pre-network profile. It signs
minimized local attribution, not truth or reputation; independent receipts and
external rollback anchors remain unavailable. See `EVIDENCE-PROFILE.md` for the
exact domains, input contract, crash behavior, and limits.

## Offline Vera Host pinning

A local host descriptor can be schema-checked, signature-verified, and pinned
only with exact independently supplied identity, network, context, and signing-key
expectations. Pins are controller-signed but inert: they create no connection,
consent, or send authority. Changed descriptors fail closed because the rotation
proof is not yet ratified. See `HOST-PIN-PROFILE.md`.

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
