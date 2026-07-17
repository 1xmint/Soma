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
```

Current production-profile support is Windows 11 with current-user DPAPI. An
unsupported secure store fails initialization. The implementation never falls
back to a plaintext production key file.

For development on an unsupported platform, an unmistakably insecure mode may
be selected with `--dev-insecure-file-keystore`. It is test-only, reports a
security degradation, and must never be used with private data or a network.

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
