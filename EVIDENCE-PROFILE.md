# Provisional Local Evidence Profile

Status: **implemented draft; not ratified, portable network evidence, truth, or reputation**

This profile closes a practical pre-network gap without inventing a network
lineage. The Origin portable evidence schema requires a real
`network_lineage_id`, but no Somavera genesis or token activation has occurred.
Soma therefore records local evidence under a distinct local context. A future
portable projection must be a new signed record that identifies its source; it
must not silently relabel these bytes as old network evidence.

## Commands

```text
soma evidence record --home ABSOLUTE_HOME --input ABSOLUTE_EVENT.json
soma evidence verify --home ABSOLUTE_HOME
```

Input must be one canonical JSON value conforming to
`schemas/local-evidence-input.provisional.schema.json`, with at most one final
LF. Requiring canonical input makes duplicate keys, imprecise integers,
negative zero, lone surrogates, and alternate spellings fail before signing.

Example:

```json
{"artifact_hashes":[],"capability":"code.review","claim_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","domain":"software.security","kind":"execution","occurred_at":"2026-07-16T12:00:00.000Z","receipt_ids":[],"schema_version":"soma.local-evidence-input.provisional-v1","supersedes":null,"task_id":"review-001"}
```

`receipt_ids` must be empty. Factual verification is unavailable until the
receipt schema, signer roles, key windows, and independent-verifier validation
are implemented. This prevents a caller from converting an unverified string
into apparent objective evidence.

## Exact provisional domains

All JSON below uses the bundled RFC 8785/Somavera I-JSON canonicalizer. `H` is
SHA-256 and `HEXDEC` converts a lowercase 64-character hash to 32 bytes.

The local context is:

```text
"soma:local-context:v1:" +
H("soma:local-evidence-context:v1\n" || UTF8(agent_did))
```

For the local event, `event_core` is every closed-schema field except
`evidence_id` and `signature`:

```text
evidence_id =
  H("soma:local-evidence:provisional-v1\n" || JCS(event_core))

event signature input =
  "soma:local-evidence:provisional-v1:signature\n" ||
  HEXDEC(evidence_id)
```

For each ledger entry, `entry_core` contains exactly `schema_version`,
`sequence`, `previous_entry_hash`, `evidence_event`, `recorded_at`, and
`signer_key_id`:

```text
entry_hash =
  H("soma:local-evidence-entry:v1\n" || JCS(entry_core))

entry signature input =
  "soma:local-evidence-entry:signature:v1\n" ||
  HEXDEC(entry_hash)
```

For the controller-signed head, `head_core` is every closed-schema field except
`head_hash` and `signature`:

```text
head_hash =
  H("soma:evidence-head:provisional-v1\n" || JCS(head_core))

head signature input =
  "soma:evidence-head:signature:provisional-v1\n" ||
  HEXDEC(head_hash)
```

The agent key signs events and entries. The controller key signs heads. Every
signature is checked against the exact key validity interval recorded in local
public-key history.

## Storage and recovery

`ledger.jsonl` contains one canonical entry plus LF per record. Writers use an
exclusive lock, verify the full existing chain, append and synchronize the
ledger, then atomically replace the signed head. Concurrent writers serialize.

Recovery may remove only a final unterminated byte sequence that cannot parse
as canonical JSON. A complete invalid object is retained and verification
fails. A fully valid entry left after interruption is verified before a new
controller-signed head is written.

The current assurance is always `local_only_unanchored`, and status always
reports `independent_truncation_detection: false`. An attacker able to roll
back both the ledger and every local head can hide tail history. Backups, Vera
acknowledgements, or external anchors are not implemented by this profile.

## What a valid record means

A valid record shows that the holder of the named local agent key signed a
specific minimized claim and that the checked local chain has not been
internally changed. It does not prove the work happened, the claim is true, the
agent is competent or unique, a human controls it, or any reputation increase
is deserved. Raw prompts, source code, stdout, stderr, environment, secrets,
and tool bodies are not accepted fields.
