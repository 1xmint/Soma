# Portable Host-Trust Capsule

Status: **v2 implemented offline portable copy with complete controller history; not an external anchor and not restore authority**

This slice implements `somavera.soma-host-trust-capsule.v2` from Somavera Origin commit `cabc10eb889def42c395735bf701b16c18105628` and capsule root `4ef5a42ab4b330678f8c52a822d90c105b267751da6227c31c54a50c67bf67e0`. New exports use v2. Legacy v1 capsules remain standalone-verifiable under their exact supported Origin bindings.

## Commands

```text
soma host trust-export --out ABSOLUTE_CAPSULE.json --home ABSOLUTE_HOME
soma host trust-verify --capsule ABSOLUTE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH
soma host trust-compare --trusted TRUSTED_CAPSULE.json --candidate CANDIDATE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH
```

All three commands perform zero network actions. `trust-verify` and `trust-compare` are standalone: they do not require or inspect a Soma home. None of the commands installs state, changes a pin, connects to a host, grants consent, discloses data, sends work, or authorizes emergency recovery.

## Complete portable bytes

Export first verifies release integrity, every current host pin, every signed succession transition, and every complete predecessor chain. It then embeds the exact canonical bytes of:

- each current controller-signed inert host pin; and
- every committed controller-signed ordinary-succession transition required to reproduce its chain; and
- the complete ordered, dual-signed Soma controller-key rotation chain from the initial key through the active key.

The capsule contains sorted, unique normalized paths, object kind, byte length, SHA-256, and canonical JSON bytes. Per-host summaries bind the current pin and descriptor plus ordered transition IDs. Domain-separated history, current-set, object-set, capsule-ID, and controller-signature commitments cover the complete package.

The output is bounded to 16 MiB and each object to 2 MiB. Export uses exclusive creation and never overwrites an existing path. An interrupted write can leave an invalid partial output, but it cannot be mistaken for a valid capsule; verification rejects it and the owner must select a new output path or remove it deliberately.

No managed secret, private signing key, keystore blob, recovery share, consent record, evidence body, question, answer, intelligence record, queue item, credential, or connection state is exported.

## Independent controller expectation

Standalone verification requires both:

- the exact expected controller DID; and
- SHA-256 of the raw 32-byte Ed25519 **initial** controller public key.

Those values must come from an independent record or authenticated channel. Copying them from the capsule being verified proves only self-consistency. Verification derives the initial key hash independently, validates both signatures and exact validity intervals for every controller rotation, authenticates the capsule with the resulting active key, verifies every embedded pin and host transition at its historical signing-key interval, reconstructs every chain, and recomputes all counts, roots, and identifiers.

## Rollback and fork comparison

`trust-compare` treats the exact `--trusted` bytes as separately preserved evidence supplied by the caller. It accepts:

- the identical capsule; or
- a later capsule in which the trusted controller-rotation IDs and every trusted host transition list are exact prefixes of the candidate chains.

Added hosts and strict valid controller or host descendants are allowed. A dropped v2 history, missing host, shorter chain, changed prefix, unexplained active-controller change, or different current pin at equal chain length fails as `HOST_TRUST_CAPSULE_ROLLBACK_OR_FORK`. This detects even a newer controller-signed same-height fork when compared with the preserved prior bytes.

## Origin-profile compatibility

New pinning accepts only the current Origin profile. Stored pins from the immediately prior supported Origin profile remain verifiable, exportable, and capable of ordinary succession under their unchanged descriptor release binding. This prevents a documentation/specification capsule update from silently invalidating existing trust while still blocking new downgrade pinning. Expanding the supported set requires an explicit reviewed release change.

## Honest limitations

- Creating a capsule on the same device does not create independent rollback protection.
- A separately stored hash detects changed bytes but cannot reconstruct unavailable pin/history bytes.
- A capsule does not prove host honesty, availability, confidentiality, or current network reachability.
- If an attacker controls the controller key and no earlier capsule or fingerprint survives independently, the attacker can create a self-consistent alternative local history.
- Restore is intentionally unimplemented. A later restore profile must specify controller-key lifecycle, conflict handling, quarantine, atomic installation, and authority boundaries before any import command exists.
- The independently preserved initial controller DID and raw-key hash remain the trust root. If both are lost, a self-contained capsule can prove only internal consistency.
- V2 exports carry the full controller chain and support post-rotation state, but they remain bounded portable evidence--not consensus, publication, notarization, or proof that the device was never rolled back.
