# SOMAVERA TOKENLESS DETERMINISTIC REDUCER

Status: **pilot-only kernel draft 0.1; not ratified; not production authority**
Profile: `somavera-tokenless-reducer-pilot-v1`

## 1. Scope

This profile freezes the smallest application-state kernel that a consensus
adapter can replicate without introducing money, reputation, governance, private
data, or hidden framework state.

It proves:

- exact transaction bytes, identifiers, and signatures;
- network, execution-context, audience, sequence, nonce, and time replay rules;
- sequential proposal evaluation with atomic block acceptance;
- deterministic public state, result, block, and application hashes;
- tokenless counters and an empty balance set;
- one deliberately narrow public-commitment lifecycle for non-sensitive pilot
  fixtures.

It does not implement full Somavera ledger state. Account recovery, key rotation,
consent authority, credentials, evidence, reputation, validators, governance,
checkpoints, recovery succession, fees, bonds, escrows, receipts, disputes,
slashing, token activation, and every private Vera object remain unsupported.
Unknown actions are rejected. Passing this profile is not permission to launch a
public network.

## 2. Pure function

The consensus-critical operation is:

```text
evaluate_block(prior_state, proposed_block)
  -> accepted(new_state, block_result)
  | rejected(error_code, transaction_index?, unchanged_prior_state)
```

The function performs no file, network, clock, environment, locale, randomness,
logging, database, or process access. Its only inputs are the prior state and
proposed block. Consensus time is an authenticated block field.

`evaluate_block` deep-copies the state, processes transaction bytes in their
declared order, and commits only if every transaction succeeds. One failure
rejects the whole proposal and returns no partially mutated state. The caller
must compare the returned pre-state root with its current committed root before
persisting. Persistence and crash atomicity belong to the adapter.

Mempool admission is advisory. A transaction accepted by a mempool may become
invalid after an earlier transaction in the proposed block. Proposal evaluation
always replays the complete ordered block against one exact prior state.

## 3. Integer and byte rules

- Consensus counters and millisecond times are canonical unsigned base-10
  strings.
- JavaScript numbers, JSON fractional numbers, negative values, exponents,
  leading zeroes, NaN, and infinity are forbidden in consensus quantities.
- JSON uses the Somavera RFC 8785/I-JSON profile.
- Consensus transaction bytes are exactly canonical UTF-8 JSON with no BOM,
  newline, compression, or `$schema` field.
- Base64 is canonical padded RFC 4648.
- SHA-256 outputs 64 lowercase hexadecimal characters.
- Ed25519 public keys are canonical base64 for exactly 32 bytes.
- Ed25519 signatures are canonical base64 for exactly 64 bytes.
- Arrays whose order is state representation rather than transaction order are
  sorted by their named primary key before hashing.

## 4. Transaction domain

The transaction core contains every field except `$schema`,
`transaction_id`, and `signature`.

```text
transaction_id =
  H("somavera:tokenless-transaction:v1\n" || JCS(transaction_core))

signature_message =
  "somavera:tokenless-transaction-signature:v1\n" ||
  HEXDEC(transaction_id)
```

`$schema` may appear in a documentation example but is forbidden in submitted
consensus bytes. This prevents a transport locator from becoming transaction
malleability.

The active state resolves `actor_key_id`. The resolved key must name the same
actor, have purpose `pilot_ledger_signing`, use `Ed25519-v1`, be active, and
cover the block consensus time. A retired or revoked key cannot authorize a new
transaction in this pilot profile.

`issued_at_ms` must be strictly earlier than `expires_at_ms`, and their
difference may not exceed 900,000 ms. Consensus time is valid on the closed
transaction interval (`issued_at_ms <= time <= expires_at_ms`) and on the
half-open key interval (`valid_from_ms <= time < valid_until_ms`).

For each actor, `sequence` equals the state's exact `next_sequence`. Successful
application increments it once. The nonce replay key is:

```text
H(
  "somavera:tokenless-nonce-key:v1\n" ||
  JCS({
    network_lineage_id,
    execution_context_id,
    actor_did,
    actor_key_id,
    audience,
    action,
    nonce
  })
)
```

Transaction IDs and nonce keys remain consumed for the lifetime of this pilot
state. Production pruning is unresolved and cannot be inferred from this draft.

## 5. Block domain

Block transaction order is authoritative and never sorted.

```text
block_core = all block fields except $schema and block_id

block_id =
  H("somavera:tokenless-block:v1\n" || JCS(block_core))
```

Each `transactions[]` entry is canonical base64 of one canonical transaction
byte string. A decoder rejects noncanonical base64, invalid UTF-8, invalid JSON,
noncanonical JSON, `$schema`, unknown fields, or a body larger than 64 KiB.

A block is accepted only when:

- its network and execution context equal state;
- height equals prior height plus one;
- `prior_app_hash` equals state;
- consensus time is strictly later than the previous time;
- time advance does not exceed the state's fixed maximum;
- there are at most 256 transactions;
- every transaction is valid in sequential state order.

Empty blocks are valid and advance height/time. A block with a duplicated or
conflicting transaction is rejected atomically.

## 6. Pilot actions

### `pilot.public-commitment.register`

The payload contains `object_id`, `content_hash`, `license_hash`, and
`source_event_id`. It carries commitments only—never content, identity linkage,
private consent, prompts, work, or model data.

```text
object_id =
  H(
    "somavera:pilot-public-commitment:v1\n" ||
    JCS({
      owner_did: actor_did,
      content_hash,
      license_hash,
      source_event_id
    })
  )
```

The object ID must not already exist. Registration creates an active record
owned by the actor. It does not assert truth, consent completeness, licensing
validity, reputation, availability, intelligence quality, or economic value.

### `pilot.public-commitment.tombstone`

The payload contains an existing `object_id` and reason:
`owner_withdrawal`, `superseded`, or `invalid_fixture`.

Only the recorded owner may tombstone an active commitment. The signed
transaction ID becomes its tombstone event ID. The original commitments remain
to prevent replay and to disclose that erasure of independently copied public
data is not guaranteed.

## 7. State and roots

The state is a closed object containing:

- lineage, context, context epoch, audience, height, and consensus time;
- active Origin and protocol-release hashes;
- the last block and result roots;
- authorized pilot signing keys and next actor sequences;
- consumed transaction IDs and nonce keys;
- public commitment/tombstone records;
- an empty balance set and tokenless economic counters.

```text
state_core = all state fields except $schema, state_root, and app_hash

state_root =
  H("somavera:tokenless-state:v1\n" || JCS(state_core))

app_hash =
  H("somavera:tokenless-app-hash:v1\n" || HEXDEC(state_root))

empty_balances_root =
  H("somavera:tokenless-empty-balances:v1\n")
```

The transaction result's `state_change_hash` commits its complete deterministic
effect object. The ordered block result root is:

```text
block_result_root =
  H("somavera:tokenless-block-results:v1\n" || JCS(transaction_results))
```

Before computing the post-state root, the reducer stores the accepted block ID,
result root, new height/time, consumed replay records, next sequences, and action
effects. Therefore replay from the bootstrap state reproduces the same state
root and application hash.

## 8. Error contract

Consensus errors are stable uppercase identifiers. Human prose, stack traces,
platform errors, and object enumeration order are not consensus output.

At minimum the conformance suite fixes rejection of:

- malformed/noncanonical transaction bytes or base64;
- wrong lineage, context, audience, height, prior app hash, or time;
- transaction ID, block ID, payload hash, object ID, or signature mutation;
- missing, wrong-purpose, retired, revoked, or out-of-window keys;
- actor/key mismatch, stale or skipped sequence, replayed ID, or reused nonce;
- duplicate registration, missing object, wrong owner, or second tombstone;
- unknown action, unknown field, oversize transaction, and oversized block;
- any mutation that would otherwise leave partial state.

Implementations may expose diagnostics, but acceptance depends only on the
stable code and exact prior bytes.

## 9. Adapter mapping

For the CometBFT pilot:

- `CheckTx` may run transaction decoding and a current-state simulation but
  creates no authority and performs no mutation;
- `PrepareProposal` selects bounded candidate bytes;
- `ProcessProposal` runs `evaluate_block` and accepts only a fully valid block;
- `FinalizeBlock` reruns the same pure function over the exact accepted bytes;
- `Commit` atomically persists the returned state and application hash;
- query endpoints read one immutable committed snapshot.

An adapter may not repair, reorder, normalize, drop, or reinterpret proposed
transactions. A mismatch between proposal evaluation and finalization halts the
node.

## 10. Ratification blockers

This profile remains pilot-only until:

1. a Rust implementation reproduces every positive and negative vector;
2. the full account/key lifecycle and Genesis authority mapping are frozen;
3. consent, governance, recovery, and checkpoint transitions are separately
   specified and implemented;
4. snapshot encoding and authenticated state-sync vectors exist;
5. crash-before/after-commit tests pass against the selected adapter;
6. denial-of-service limits and long-run state growth are measured;
7. independent consensus and cryptographic review has no unresolved critical or
   high finding.

Token code cannot be added by extending the pilot action enum. It requires the
separate activation ladder and a versioned state-machine profile.
