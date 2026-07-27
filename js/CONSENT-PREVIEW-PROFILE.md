# Provisional Consent Membrane and Preview Profile

Status: **implemented local draft; no grant authority, no send path, no network**

This slice implements the first enforceable privacy choke point without enabling
observation. It accepts only two narrow source profiles:

- controller-attested public UTF-8 artifacts; and
- minimized fields from a locally verified signed evidence event.

Private work, secrets, regulated-sensitive data, identity linkage, objective
receipts, arbitrary files, binary content, grants, queues, host registration,
and transmission remain unavailable.

## Commands

```text
soma observe status --home ABSOLUTE_HOME
soma observe preview --artifact ABSOLUTE_FILE --policy ABSOLUTE_POLICY.json --home ABSOLUTE_HOME
soma observe preview --evidence EVIDENCE_ID --policy ABSOLUTE_POLICY.json --home ABSOLUTE_HOME
```

Policy input must be valid UTF-8 canonical JSON conforming to
`schemas/observation-preview-policy.provisional.schema.json`; malformed byte
sequences fail before parsing or hashing. Preview performs
zero network actions. There is deliberately no `observe grant`, `observe send`,
blanket observer-on command, background watcher, retry, or queue consumer.

## Exact authorization projection

Every policy binds:

- source kind and allowed data class;
- subject, controller, and observer DIDs;
- exact sorted field allow-list;
- proposed host DID and credential-free HTTPS origin;
- sorted purposes and operations;
- data state, retention, redistribution, and replication mode;
- every exact named replication host DID and origin;
- training and public-release booleans;
- license identifier and version;
- expiry, withdrawal mode, policy version, and source-size ceiling;
- for an artifact, media type, title, public source URI, rights basis, and an
  explicit controller rights attestation.

The attestation is not cryptographic proof that publication or licensing is
lawful. It records who is taking responsibility for that claim. A later host
must perform its own rights checks.

The allowed artifact projection fields are:

```text
artifact_hash
byte_length
content_base64
license_identifier
license_version
media_type
source_uri
title
```

The allowed evidence projection fields are:

```text
artifact_hashes
assurance
capability
claim_hash
domain
evidence_id
kind
occurred_at
task_id
```

Everything else is rejected or deterministically omitted and listed in the
decision as `not_in_exact_authorized_projection`. An evidence signature,
issuer field, controller field, raw prompt, code, stdout, stderr, environment,
or secret cannot be added through policy.

## State consistency

The engine rejects contradictory or silently broader terms:

- `host_confidential` forbids training, public release, redistribution, and
  replication;
- `federated_training` requires the training purpose, train operation, training
  boolean, no public release, and either no replication or exact named hosts;
- `public_knowledge` requires the public-dataset purpose, redistribute
  operation, public-release boolean, public replication, licensed-artifact
  redistribution, and an allow-listed open-license identifier;
- the training boolean must exactly match both its purpose and operation;
- the public-release boolean must exactly match both its purpose and operation;
- public release accepts only exact reviewed identifier/version pairs: `Apache@2.0`,
  `BSD-2-Clause@N/A`, `BSD-3-Clause@N/A`, `CC-BY@4.0`, `CC-BY-SA@4.0`,
  `CC0@1.0`, `MIT@N/A`, and `ODC-BY@1.0`; lookalike, noncommercial,
  no-derivatives, or unknown license strings fail closed;
- named replication must include the primary destination and every target must
  bind both DID and origin.

No local configuration, host response, plugin, or future queue may broaden
these fields. A future consent grant and host acknowledgement must bind and
recompute the exact `field_projection_hash`. The eventual send engine must recompute and compare every term.

## Commitments

`H` is SHA-256 and `JCS` is the bundled Somavera RFC 8785/I-JSON profile.

```text
policy_hash = H(JCS(policy))

projection_core = {
  schema_version,
  source_kind,
  data_class,
  system_fields,
  authorized_fields
}

field_projection_hash =
  H("soma:authorized-field-projection:provisional-v1\n" ||
    JCS(projection_core))

payload_hash = H(JCS(payload))

preview_id =
  H("soma:observation-preview:provisional-v1\n" ||
    JCS(decision_core))
```

`decision_core` is the complete closed approved-decision object except
`preview_id`. It includes the payload and policy hashes, source commitment,
projection and its separate field-projection hash, lifecycle terms, scan and
rights results, warnings, and creation time. `payload.jcs` contains exactly the
bytes committed by `payload_hash`. `policy.jcs` contains the complete canonical
policy committed by `policy_hash`, so the destination, replication scope,
purposes, operations, lifecycle terms, rights assertion, and field authorization
can be independently inspected and recomputed.

A scan denial stores no payload or matched value:

```text
denial_id =
  H("soma:observation-preview-denial:provisional-v1\n" ||
    JCS(denial_core))
```

The denial contains only a local source commitment, policy hash, finding codes,
field names, and offsets. Denial records are local-only diagnostic state and
must not later be exported or transmitted as observation data.

The deterministic positive vector is
`conformance/observation-preview-provisional-v1.json`; its generator is
`scripts/generate-preview-vector.mjs`.

## Secret and prohibited-identity scanning

The current high-confidence profile blocks recognized private-key PEM,
credential assignments, authorization headers, credentialed URLs, AWS,
GitHub, OpenAI, Slack and JWT-shaped tokens, recovery labels, email/phone/SSN
identifiers, and common wallet addresses. Findings retain codes and positions,
never the matched value.

This scanner cannot prove that content is safe. It cannot reliably infer legal
rights, private-work status, health meaning, protected-class meaning, encoded
or encrypted secrets, steganography, every future credential format, or every
identity relationship. For that reason:

- secret scanning is never represented as a confidentiality proof;
- raw private work remains unsupported even when no pattern matches;
- an artifact must be explicitly attested as already public and rights-held;
- evidence preview uses only the fixed minimized ledger projection;
- future broader profiles require separate schemas, taint tests, review, and
  new acceptance vectors.

## Storage boundary

Approved artifact bytes may be stored in the preview only because this profile
requires them to be attested as already public. Evidence previews contain only
the minimized fields already present in the local evidence ledger. No private
content body is accepted or stored. A future profile that handles private or
host-confidential bodies must first implement authenticated local encryption
under the user-controlled store key.

The proposed host identity and origin are displayed but not pinned or trusted
in this release. Host discovery and descriptor verification are later P0 work.
