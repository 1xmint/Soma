# Provisional Offline Vera Host Verification and Pin Profile

Status: **implemented local draft; no discovery request, connection, grant, encryption, send path, or network**

This slice verifies a Vera Host descriptor supplied as a local canonical JSON
file and can create a controller-signed, inert local pin. It does not fetch the
descriptor. It never treats a descriptor's self-signature as proof that the
operator is the host the controller intended.

## Commands

```text
soma host status --home ABSOLUTE_HOME
soma host verify --descriptor ABSOLUTE_DESCRIPTOR.json --expect-origin ORIGIN --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT [--expect-key-hash HASH] --home ABSOLUTE_HOME
soma host pin --descriptor ABSOLUTE_DESCRIPTOR.json --expect-origin ORIGIN --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT --expect-key-hash HASH --home ABSOLUTE_HOME
```

All commands perform zero network actions. `verify` is read-only. `pin` writes
one controller-signed local trust record but sets `connected` to false and
creates no consent, session, queue, observation, encryption, or send authority.

## Why the expected values are separate

A malicious descriptor can generate a key, name itself, and correctly sign its
own bytes. That establishes internal integrity only. Verification therefore
requires the user to supply the exact expected HTTPS origin, host DID, network
lineage, and execution context independently of the descriptor.

Read-only verification may omit the expected active signing-key hash, but the
result is labeled `self_signature_only_not_operator_authenticated_not_pin_eligible`.
Pinning requires the SHA-256 of the raw 32-byte active Ed25519 public key from a
separate authenticated source. Examples of a future acceptable source include
an authenticated Origin release, a transparency proof, a verified organization
channel, or a ratified network proof. Copying the hash from the same untrusted
descriptor does not improve identity assurance.

## Descriptor checks

The implementation imports the complete Origin
`vera-host-descriptor.schema.json` contract and additionally enforces semantic
invariants that JSON Schema cannot express:

- canonical UTF-8 JSON and a 256 KiB file ceiling;
- exact descriptor identifier and Ed25519 signature domains;
- exact expected origin, DID, network, context, and optional signing-key hash;
- exact descriptor sequence/predecessor and closed rotation-policy shape;
- the capsule root `ee8bb4f2a851ecd103a84db988e24eb2241ec702c9f0743045a2e83008f89e7d` from Origin commit `07a4e89`;
- issuance, expiry, active-key windows, and coherent revocation fields;
- unique signing and ingestion key identifiers and public keys;
- usable X25519 ingestion material through a local derivation sanity check;
- strict signing/encryption role separation;
- exact TLS server-name and HTTPS-origin agreement;
- the private application protocol and fixed private endpoint profile;
- agreement between duplicated query, retention, and size limits;
- declared regions for every subprocessor and unique processor identifiers;
- explicit operator-memory and traffic-metadata disclosures; and
- zero overlap-key acceptance until a rotation-policy proof is ratified.

The current host and HPKE profiles remain marked `freeze_blocking_draft` by the
Origin contract. A pin is therefore preparation for later interoperability, not
permission to send production traffic.

## Commitments

The descriptor domains are inherited exactly from Origin:

```text
descriptor_core = every descriptor field except $schema, descriptor_id, signature

descriptor_id =
  H("somavera:vera-host-descriptor:v1\n" || JCS(descriptor_core))

descriptor_signature_message =
  "somavera:vera-host-descriptor-signature:v1\n" || HEXDEC(descriptor_id)
```

The local pin is separately controlled by the Soma owner:

```text
pin_core = every pin field except pin_id and signature

pin_id =
  H("soma:host-pin:provisional-v1\n" || JCS(pin_core))

pin_signature_message =
  "soma:host-pin-signature:provisional-v1\n" || HEXDEC(pin_id)
```

The controller-signing key signs the pin message. `doctor`, `status`, and every
later command revalidate the pin identifier, controller signature, complete
descriptor signature, original expectations, and storage filename.

The fixed positive vector is
`conformance/vera-host-descriptor-provisional-v1.json`; its generator is
`scripts/generate-host-descriptor-vector.mjs` and uses the published RFC 8032
test key only.

## Rotation and descriptor changes

Automatic replacement is forbidden. Re-pinning the identical descriptor and
expectations is idempotent. Any changed descriptor IDâ€”including a new signing
key, ingestion key, origin, region, subprocessor, policy, disclosure, release,
limit, or expiryâ€”fails with `HOST_DESCRIPTOR_CHANGE_UNSUPPORTED`.

This is deliberate. Origin commit `07a4e89` now defines and tests a freeze-blocking ordinary-succession proof, but this reference slice does not ingest that proof, persist a candidate successor, display a change diff, or obtain the separate controller confirmation. Therefore even a cryptographically valid succession proof remains non-authoritative here. A later bounded implementation must add that complete state machine and its no-network/no-consent tests before descriptor replacement can be enabled; emergency compromise recovery remains separately unsupported.

## Security limits

- Offline verification does not validate DNS, TLS certificates, routing, or
  possession of the ingestion private key.
- Issuance, expiry, and key-window decisions depend on the local system clock;
  authenticated network time is not implemented.
- An out-of-band hash is only as trustworthy as the channel that supplied it.
- A local pin does not prove the host is honest, confidential, available, or
  legally compliant.
- The disclosed ordinary-process profile explicitly means a host operator may
  access plaintext while the process handles it. Attested confidential compute
  requires a separate profile and acceptance evidence.
- Application encryption does not hide IP address, timing, approximate size, or
  route class. The descriptor must disclose those metadata exposures.
- Local controller signatures detect accidental or unauthorized byte changes;
  without an independent external anchor they do not defeat full device
  compromise or rollback by an attacker controlling the filesystem and keys.
