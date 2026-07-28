# SOMAVERA IDENTIFIER AND SIGNATURE DOMAINS

Status: normative companion draft 0.1

This file removes circular hashes and cross-substrate replay ambiguity. Consensus implementations must reproduce these bytes exactly.

## 1. Common notation

- H(bytes) is SHA-256, returned as 64 lowercase hexadecimal characters.
- HEXDEC(text) accepts exactly 64 lowercase hexadecimal characters and returns 32 bytes.
- UTF8(text) is strict UTF-8; invalid Unicode is rejected.
- UINT64BE(n) is an unsigned eight-byte big-endian integer.
- JCS(value) is the Somavera RFC 8785/I-JSON profile.
- || concatenates bytes.

Derived IDs, signatures, and post-finality anchors never occur inside their own hash core.

## 2. Network lineage

The flat genesis schema projects:

    genesis_core = all genesis fields except:
      $schema
      schema_version
      genesis_core_hash
      network_lineage_id
      execution_context_id
      external_anchors
      ratification_signatures

    genesis_core_hash =
      H("somavera:genesis-core:v1\n" || JCS(genesis_core))

    network_lineage_id =
      "somavera:network:v1:" ||
      H(
        "somavera:network-lineage:v1\n" ||
        HEXDEC(origin_hash) ||
        HEXDEC(genesis_core_hash)
      )

Genesis ratification signatures sign:

    "somavera:genesis-ratification:v1\n" ||
    JCS({
      "schema_version": schema_version,
      "genesis_core_hash": genesis_core_hash,
      "network_lineage_id": network_lineage_id,
      "execution_context_id": execution_context_id
    })

The unsigned genesis core commits the complete bootstrap ratification-authority and chamber manifests, including keys, purposes, exact thresholds, terms, and absolute expiry. Validators verify the signature set against those committed manifests; keys or thresholds supplied outside the core do not count. Because genesis has no ledger pre-state, this is an explicit new-lineage bootstrap ceremony, not a continuity claim.

Initial and phoenix genesis are tokenless: activated is false, activation_core_hash and asset_lineage_id are null, and genesis supply is zero.

## 3. Execution context

Network lineage is durable across exact substrate succession. Execution context is not.

    execution_context_id =
      "somavera:context:v1:" ||
      H(
        "somavera:execution-context:v1\n" ||
        UTF8(network_lineage_id) ||
        UINT64BE(context_epoch) ||
        HEXDEC(substrate_binding_hash)
      )

At genesis, context_epoch is zero and substrate_binding_hash is genesis_core_hash. Exact recovery increments context_epoch by one and uses the successor binding manifest hash. A normal software upgrade that stays on the same substrate does not change context unless the ratified release explicitly replaces the transaction replay domain.

Every transaction, signed request, mempool entry, and checkpoint binds execution_context_id. Nodes accept only the active context. This prevents a valid old-chain transaction from replaying on a successor while network and asset lineage remain durable.

## 4. Signed event

    event_core = all signed-event fields except:
      $schema
      event_id
      signature

    event_id =
      H("somavera:event:v1\n" || JCS(event_core))

The payload is present in event_core and payload_hash equals H(JCS(payload)). The actor signs:

    "somavera:event-signature:v1\n" ||
    HEXDEC(event_id)

The signature therefore binds schema version, network, execution context, protocol, action, actor, audience, nonce, times, consent grant, payload, and payload hash.

## 5. Portable signed records

Portable records are not executable transactions. They retain the network lineage under which they were issued, but transport envelopes bind the active execution context.

For each record:

| Record | ID field | Excluded from core | Hash domain |
|---|---|---|---|
| consent grant | consent_grant_id | $schema, consent_grant_id, signature | somavera:consent-grant:v1 |
| evidence event | evidence_id | $schema, evidence_id, signature | somavera:evidence:v1 |
| service receipt | receipt_id | $schema, receipt_id, signatures | somavera:service-receipt:v1 |

The ID is:

    H(hash_domain || "\n" || JCS(record_core))

Each required signer signs:

    hash_domain || ":signature\n" || HEXDEC(record_id)

Service receipt validation additionally requires exactly one provider signature and at least one signature from the consumer or a ratified independent verifier. Duplicate roles or signer DIDs do not satisfy the threshold.

## 6. Token activation and asset lineage

The token manifest already contains a nested unsigned activation_core.

    activation_core_hash =
      H(
        "somavera:token-activation-core:v1\n" ||
        JCS(activation_core)
      )

    asset_lineage_id =
      "vera:rpa:v1:" ||
      H(
        "somavera:asset-lineage:v1\n" ||
        HEXDEC(origin_hash) ||
        HEXDEC(activation_core_hash)
      )

Each chamber signs:

    "somavera:token-ratification:v1\n" ||
    JCS({
      "schema_version": schema_version,
      "activation_core_hash": activation_core_hash,
      "asset_lineage_id": asset_lineage_id
    })

Activation signatures are valid only for the active pre-token chamber manifests materialized in the immediately preceding finalized state, at each exact chamber threshold. The activation core may name future keys, but those keys cannot authorize their own elevation. Expired, revoked, absent, duplicate, wrong-purpose, or threshold-minus-one signatures fail.

## 7. Checkpoints

    checkpoint_core = all checkpoint fields except:
      $schema
      schema_version
      checkpoint_id
      external_anchors
      finality_signatures

    checkpoint_id =
      H("somavera:checkpoint:v1\n" || JCS(checkpoint_core))

Validators sign:

    "somavera:checkpoint-finality:v1\n" ||
    HEXDEC(checkpoint_id)

External anchors record checkpoint_id after finality and are not circular inputs.

## 8. Recovery certificate

    certificate_core = all certificate fields except:
      $schema
      schema_version
      certificate_id
      ratification_signatures

    certificate_id =
      H(
        "somavera:recovery-certificate:v1\n" ||
        JCS(certificate_core)
      )

Recovery and chamber signers sign:

    recovery_ratification_signature_core = {
      certificate_id,
      role,
      authority_source,
      authority_manifest_hash,
      key_id,
      controller_id,
      suite
    }

    "somavera:recovery-ratification-signature:v1\n" ||
    JCS(recovery_ratification_signature_core)

`value` is excluded from its own signature core. The core binds the claimed role and checkpoint-pre-state authority metadata so a valid signature cannot be relabeled between guardians or chambers. Ratification signatures remain excluded from `certificate_core`, preventing a certificate-ID/signature cycle.

For exact continuity, recovery and chamber signatures are counted only against the recovery-key and chamber-seat manifests active in the reproduced checkpoint pre-state, at every exact threshold. Proposed successor keys are proof-of-possession targets only and never authorizers.

For exact continuity:

- old and new network lineage IDs are identical;
- old and new execution context IDs differ;
- new context_epoch equals old context_epoch plus one;
- old and new asset lineage IDs are identical or both null;
- the imported checkpoint state is reproduced exactly;
- the certificate commits to one narrow RecoverySuccession transition.

A Phoenix does not issue a `RecoveryCertificate`, because that object asserts an exact-continuity transition. It uses the new-genesis derivation in Sections 2 and 3: network lineage and execution context are new, no checkpoint or state is imported, asset lineage is null at genesis, and a later gated activation creates a new asset lineage.

## 9. RecoverySuccession transition

Exact import first reproduces checkpoint state byte-for-byte. The first successor-only transition may change only:

- active execution context ID and context epoch;
- substrate binding manifest;
- operational validator keys and voting powers named in the certificate;
- recovery public keys named in the certificate;
- successor endpoints and external anchors;
- old-substrate transaction acceptance to permanently halted.

It cannot alter balances, total minted, total burned, issuance time, consumed receipts, vesting, delegations, revocations, consent, reputation, evidence, treasury ownership, governance membership, or protected rights.

The transition hash and complete before/after state roots are committed by the recovery certificate before activation.


## 10. Shared Soma/Vera wire profile

Status: **freeze-blocking cryptographic draft**. Sections 10 through 18 define one coherent provisional profile so implementations cannot silently choose incompatible projections. They are not release-ratified until independent Rust and JavaScript implementations reproduce positive and negative vectors, a cryptographic review accepts the HPKE composition and nonce rules, and the schema hashes are placed in a ratified release manifest.

Additional notation:

- `B64DEC(text)` accepts canonical padded RFC 4648 base64 only and returns bytes; noncanonical spellings fail.
- `UINT32BE(n)` is an unsigned four-byte big-endian integer.
- `KEYID(text)` is `UTF8(text)` after strict schema validation; key-ID aliases are forbidden.
- `SIGKEY(record)` is the public key resolved from the exact signed key ID and its valid, non-revoked lifecycle interval.

The strict schemas use `additionalProperties: false`. Therefore “all fields except” below is an exact projection over a closed field set, not permission for extensions. `$schema` is transport help and is never an authenticated field. A new field requires a new schema and domain.

The clear request and response containers deliberately contain no raw plaintext content hash. A hash of a low-entropy private query or result would permit dictionary testing by an intermediary. Plaintext integrity is verified after decryption by recomputing the encrypted inner signed-object identifier and its internal commitments. Any future clear keyed commitment requires a separately reviewed construction whose key is unavailable outside the recipient process.

### 10.1 Mandatory key separation

The following are distinct key IDs, distinct public keys, and distinct private-key objects:

- Soma/controller Ed25519 signing;
- Soma X25519 private-response decryption;
- Vera Ed25519 descriptor/private-response signing;
- Vera X25519 private-request ingestion;
- TLS transport;
- storage KEK/DEK, backup, recovery, operator, and validator keys.

A verifier rejects a descriptor, request, response, or acknowledgement if a signing key ID or public key equals an encryption key ID or public key in the same trust context. A key changing purpose requires a new key pair and key ID. Algorithm labels do not waive role separation.

### 10.2 Ordinary Soma controller-key rotation

The closed event in `soma-controller-key-rotation.schema.json` rotates only a live, uncompromised controller-signing key. The controller DID is a stable identity anchor and MUST NOT change. The successor key has a distinct DID-derived key ID, but the signed rotation chain authorizes it to act for that stable controller. A key compromise is not ordinary rotation: because an attacker holding the prior key could authorize an attacker-chosen successor, suspected compromise requires a separately precommitted recovery authority and remains unsupported by this profile.

Preview first commits the immutable proposal projection. It contains the schema/profile, stable controller, sequence/predecessor, prior key identity and original validity start, complete successor public key, preparation time, reason, decision, key disposition, rollback claim, and authority object; it excludes the not-yet-known effect time, lifecycle results, signatures, and final event ID:

    proposal_id =
      H("somavera:soma-controller-key-rotation-proposal:v1\n" ||
        JCS(controller_key_rotation_proposal_core))

The rotation core is every final event field except `$schema`, `rotation_id`, and `signatures`; it includes that `proposal_id`, the exact effect time, and resulting lifecycle windows:

    rotation_id =
      H("somavera:soma-controller-key-rotation:v1\n" ||
        JCS(controller_key_rotation_core))

The currently active controller key signs:

    "somavera:soma-controller-key-rotation-prior-signature:v1\n" ||
    HEXDEC(rotation_id)

The fresh successor proves possession in a distinct role domain:

    "somavera:soma-controller-key-rotation-successor-signature:v1\n" ||
    HEXDEC(rotation_id)

Sequence is exactly prior plus one; `previous_rotation_id` is the authenticated prior head or null only for sequence one. The prior key and its original `valid_from` must exactly match authenticated current history. Its `valid_until` and the successor's `valid_from` both equal `effective_at`; the former becomes `retired`, the latter becomes the only `active` controller key, and neither a gap nor overlap is permitted. The successor is fresh Ed25519 material with a correct raw-key SHA-256. `effective_at` cannot precede `prepared_at` or exceed it by more than 900 seconds.

Preparation is offline and stores the successor private key only in protected pending storage. Confirmation displays the stable controller DID, sequence/predecessor, both key IDs and fingerprints, effective time, reason, old-key destruction rule, rollback limitation, and every authority exclusion. The user must supply the exact proposal ID and successor key hash plus an explicit controller-rotation flag. The final effect time, resulting event ID, and both signatures are created only after that confirmation; preview never claims that an unconfirmed key is already active.

One serialized transaction durably prepares the final identity, public history, rotation event, and protected successor keystore. Exactly one atomic current-identity replacement or pointer change is the commit point. Before it, recovery restores the prior identity and protected pending proposal; after it, recovery finalizes exact history and the successor keystore before destroying the prior private key. A third state or mismatched prepared bytes is quarantined. Concurrent identical confirmation is idempotent and competing confirmation conflicts. Old public bytes and validity windows remain; the old private key does not.

This event authorizes only controller-key replacement. It grants no agent/observer rotation, identity or emergency recovery, connection, consent, disclosure, send, token, or governance act. Its signed local chain proves consistency, not independent rollback resistance. Rollback assurance requires exact history or a compatible trust capsule preserved outside the candidate device.

## 11. Vera host descriptor

The only v1 discovery target is the exact HTTPS origin plus:

    /.well-known/somavera/vera-host.json

The request method is `GET`, redirects are forbidden, and the returned media type is `application/json`. The signed descriptor repeats those facts and the exact private request path `/v1/private/requests`; the client rejects a mismatch rather than following server behavior.

    host_descriptor_core = all descriptor fields except:
      $schema
      descriptor_id
      signature

    descriptor_id =
      H("somavera:vera-host-descriptor:v1\n" || JCS(host_descriptor_core))

The active Vera host-signing key signs:

    "somavera:vera-host-descriptor-signature:v1\n" ||
    HEXDEC(descriptor_id)

`signature.key_id`, `active_host_signing_key_id`, and one active, time-valid `host_signing_keys[].key_id` are identical. `active_ingestion_key_id` resolves to one active, time-valid ingestion key. Signing and ingestion key-ID/public-key sets are disjoint. A revoked key has non-null `revoked_at` and `revocation_reference`; a non-revoked key has both null. `overlap` is accepted only during its published interval and only when rotation policy permits it. Retired and revoked keys cannot receive new traffic.

The descriptor ID, signature, TLS identity, expected host DID, origin, network, context, active keys, release, policy, exact action registries, supported protocols, query policy, regions, subprocessors, retention, model-use disclosure, metadata/operator-memory disclosure, and every capability limit all validate before a host is pinned. Duplicated bounds agree exactly, every subprocessor region is declared, and a changed field requires a new descriptor ID and fresh policy handling.

### 11.1 Ordinary descriptor succession

Every descriptor carries a monotonic `descriptor_sequence`, the exact `previous_descriptor_id` (null only at sequence zero), and the closed `rotation_policy`. Ordinary succession is the only transition defined here. It covers renewal and precommitted signing and/or ingestion-key rotation; it does not cover emergency recovery after compromise.

    host_descriptor_succession_core = all succession-proof fields except:
      $schema
      succession_id
      signatures

    succession_id =
      H(
        "somavera:vera-host-descriptor-succession:v1\n" ||
        JCS(host_descriptor_succession_core)
      )

The prior active signing key signs:

    "somavera:vera-host-descriptor-succession-signature:v1\nprior\n" ||
    HEXDEC(succession_id)

The successor active signing key signs the distinct role domain:

    "somavera:vera-host-descriptor-succession-signature:v1\nsuccessor\n" ||
    HEXDEC(succession_id)

The successor sequence is exactly prior plus one and its predecessor is the recomputed prior descriptor ID. Network lineage, execution context, host DID, origin, discovery/TLS identity, release, policy, protocols, capabilities, regions, subprocessors, disclosure, retention, limits, and rotation policy are byte-identical. Only descriptor identifiers, sequence/predecessor, key inventories and active pointers, issue/expiry times, and signature may change.

A newly active key must already appear with identical key ID, purpose, suite, and public bytes as an unexpired `overlap` key in the prior descriptor. The former active key becomes `retired`; historic keys cannot disappear, change identity, reactivate, or be smuggled through this profile as revoked. Each overlap interval is bounded by `maximum_overlap_seconds`; each descriptor lifetime is bounded by `maximum_descriptor_lifetime_seconds`. The proof lasts at most 900 seconds, lies within both descriptor validity windows, binds both active signing and ingestion key IDs, and declares the exact change scope.

Both descriptors, both descriptor IDs/signatures, the proof ID, and both role-separated proof signatures validate. Even then the result is only continuity evidence: it authorizes no connection, consent, disclosure, traffic, or emergency recovery. A Soma controller must display the exact change and separately confirm the successor before replacing its pin. A silent auto-follow is forbidden. Total signing-key compromise has no safe ordinary-rotation shortcut and remains blocked until a distinct precommitted recovery-authority profile is ratified.

### 11.2 Controller confirmation and atomic inert-pin adoption

The closed confirmation receipt is defined by `soma-host-succession-confirmation.schema.json`. Its subject is the exact ordinary succession, independent of any implementation-specific candidate filename or database row:

    host_succession_confirmation_subject_core = {
      network_lineage_id, execution_context_id, host_did, origin,
      prior_descriptor_id, prior_descriptor_sequence,
      successor_descriptor_id, successor_descriptor_sequence,
      succession_id, change_scope,
      successor_active_host_signing_key_id,
      successor_active_host_signing_key_sha256,
      successor_active_ingestion_key_id,
      successor_active_ingestion_key_sha256
    }

    subject_id =
      H("somavera:soma-host-succession-confirmation-subject:v1\n" ||
        JCS(host_succession_confirmation_subject_core))

The confirmation core is every closed receipt field except `$schema`, `confirmation_id`, and `signature`:

    confirmation_id =
      H("somavera:soma-host-succession-confirmation:v1\n" ||
        JCS(host_succession_confirmation_core))

The active Soma controller-signing key identified inside that core signs:

    "somavera:soma-host-succession-confirmation-signature:v1\n" ||
    HEXDEC(confirmation_id)

The verifier recomputes the subject directly from the pinned prior descriptor, verified successor, and verified succession proof. Both successor active-key hashes are SHA-256 over the canonical decoded 32-byte public key. Receipt creation and the atomic current-pin commit both occur within the proof validity window with no grace period; the receipt names the active controller DID and signing key and has the sole decision `replace_inert_pin_only`. It authorizes pin replacement and explicitly authorizes no connection, consent, disclosure, send, or emergency recovery. A local candidate commitment MUST bind the same `subject_id`; a UI label, alias, filename, or database identifier cannot substitute for it.

Adoption serializes per host and revalidates the exact current prior pin, candidate, proof, controller key, confirmation, and successor while holding the lock. Before the commit point it durably prepares a controller-authenticated transition containing the complete prior pin/descriptor, proof, confirmation, and successor pin. Exactly one atomic replacement of the authoritative current-pin file or pointer is the commit point. History publication and candidate cleanup are deterministic finalization steps, never additional authority changes.

Crash recovery inspects the authenticated prepared transition and current pin. If the prior pin remains current, it restores or retains the inert candidate and removes the uncommitted preparation. If the exact successor pin is current, it retains complete append-only history and consumes only the matching candidate. Any third state, missing authenticated transition material, mismatched hash, competing successor, or ambiguous current pin fails closed for manual quarantine. Repeating the same confirmed subject is idempotent; a competing confirmation cannot overwrite it. Fault injection before and after every boundary plus concurrent confirmation tests are release blockers. Filesystem signatures do not independently prevent rollback by an attacker controlling both storage and controller keys; external anchors remain a separate assurance requirement.

### 11.3 Portable host-trust capsules

The legacy closed capsule in `soma-host-trust-capsule.schema.json` carries every current host pin and every committed ordinary-succession transition as exact canonical JSON bytes, but only while the initial controller key remains active. The controller-history-capable capsule in `soma-host-trust-capsule-v2.schema.json` additionally carries every committed ordinary controller-key rotation from the initial key through the active signing key. Neither version contains a private key, recovery share, bearer credential, consent, question, answer, contribution, or model artifact. Embedded object paths are normalized, unique, sorted, bounded, and paired with exact byte length and SHA-256.

For version 1, transition IDs appear in authenticated predecessor-to-successor order under `somavera:soma-host-trust-history-chain:v1`; host summaries, object manifest cores, capsule identity, and the active-key signature use their corresponding `v1` domains. Version 1 requires an independently supplied expected controller DID and raw active-key hash and cannot represent a controller rotation.

Version 2 uses fresh domains for every capsule-level projection:

    controller_history_root =
      H("somavera:soma-controller-history-chain:v2\n" ||
        JCS(ordered_rotation_ids))

    history_chain_root =
      H("somavera:soma-host-trust-history-chain:v2\n" ||
        JCS(ordered_transition_ids))

    current_set_root =
      H("somavera:soma-host-trust-current-set:v2\n" ||
        JCS(ordered_host_summaries))

The object manifest projection removes only `canonical_json_base64`; path, kind, byte length, and SHA-256 still commit every embedded byte:

    object_set_root =
      H("somavera:soma-host-trust-object-set:v2\n" ||
        JCS(ordered_object_manifest_cores))

The capsule core is every field except `$schema`, `capsule_id`, and `signature`:

    capsule_id =
      H("somavera:soma-host-trust-capsule:v2\n" ||
        JCS(capsule_core))

The active controller key derived from the verified rotation head signs:

    "somavera:soma-host-trust-capsule-signature:v2\n" ||
    HEXDEC(capsule_id)

Version-2 verification requires an independently supplied expected stable controller DID and raw Ed25519 hash of the initial controller key. Copying either from the same candidate capsule provides integrity but no identity assurance. The verifier authenticates the initial key against that expectation, validates every rotation ID, predecessor, sequence, key interval, prior signature, and successor signature in exact order, derives the unique active key, and verifies the capsule signature with that key. It then authenticates every embedded pin and host transition at its historical controller-key interval, reconstructs every complete chain, recomputes every summary, root, and count, and rejects unknown, missing, duplicate, orphaned, forked, reordered, noncanonical, oversized, or substituted objects.

A version-1 trusted capsule may be compared with a version-2 candidate only when the independently expected key is both the v1 signing key and the candidate's initial key, the v2 rotation chain descends from it, and every trusted host transition list remains an exact prefix. Version-2 to version-2 comparison additionally requires the trusted controller rotation list to be an exact prefix of the candidate list. Equal height with a different controller head, active key, host pin, or transition is a fork.

The capsule is an anchor candidate, not an external anchor. Creating it does not prove that any independent medium or party retained it, does not detect rollback by itself, and authorizes no restore, pin change, connection, consent, disclosure, send, or emergency recovery. A separately preserved prior capsule or authenticated hash is required for rollback comparison. A later restore profile must separately specify state installation, conflict handling, quarantine, and controller-key lifecycle.

## 12. Return-encryption descriptor and query authority
A return descriptor is not independently signed. It is a complete object inside the signed inner request payload.

    return_descriptor_core = all return-descriptor fields except:
      $schema
      descriptor_id

    descriptor_id =
      H("somavera:return-encryption-descriptor:v1\n" ||
        JCS(return_descriptor_core))

The core binds network, execution context, request action and nonce, requester, authorized host, destination Soma DID, exact return key ID/public key/role, HPKE suite, allowed response actions, validity, usage, and maximum plaintext bytes. The request action and every allowed response action must appear in the pinned host descriptor, and the action-specific schema conditional permits only its success result(s) plus `private.error`; a query key cannot receive a contribution acknowledgement. It intentionally does **not** contain `request_event_id`: the descriptor is inside that event, so doing so would be circular. The signed event nonce provides the pre-ID request binding; after event derivation, responses bind both descriptor ID and request event ID.

A direct query is authorized only when the signed request actor is the controlling principal under the active identity policy. Otherwise it carries the complete query delegation:

    query_delegation_core = all query-delegation fields except:
      $schema
      delegation_id
      signature

    delegation_id =
      H("somavera:query-delegation:v1\n" || JCS(query_delegation_core))

The controller signs:

    "somavera:query-delegation-signature:v1\n" ||
    HEXDEC(delegation_id)

The request must fall within the delegation's network/context, delegate DID, host audience, return Soma DID, query hashes when enumerated, scope, purpose, source statuses, top-k limit, validity, depth, and revocation state. Child authority is the strict intersection of every ancestor and may never expand it. A DID string, nature label, UI relationship, or claimed parent has no authority without this verified credential.

## 13. Private request stream

### 13.1 HPKE key wrap

The provisional suite label maps to RFC 9180 base mode with X25519/HKDF-SHA256/AES-256-GCM. It wraps one fresh uniformly random 32-byte object DEK. It does not directly encrypt the stream body.

    request_wrap_info_core = {
      schema_version,
      network_lineage_id,
      execution_context_id,
      sender_did,
      destination_host_did,
      recipient_ingestion_key_id,
      inner_event_id,
      consent_grant_id,
      outer_nonce,
      issued_at,
      expires_at
    }

    request_wrap_info =
      "somavera:request-hpke-info:v1\n" || JCS(request_wrap_info_core)

After HPKE setup returns `hpke_enc`, its single `Seal` call uses:

    request_wrap_aad_core = request_wrap_info_core plus {
      hpke_suite,
      hpke_enc,
      chunk_bytes,
      chunk_count,
      plaintext_bytes
    }

    request_wrap_aad =
      "somavera:request-key-wrap-aad:v1\n" || JCS(request_wrap_aad_core)

`wrapped_object_dek` is `Seal(request_wrap_aad, object_dek)`. Exporter-secret use, PSK/auth modes, and sender-static HPKE keys are forbidden in this profile.

### 13.2 Stream AAD and chunks

    request_stream_aad_core = request_wrap_aad_core plus {
      wrapped_object_dek
    }

    aad_hash =
      H("somavera:request-stream-aad:v1\n" || JCS(request_stream_aad_core))

For ordered chunk `i`, whose declared plaintext byte count is `chunk_plaintext_bytes_i`:

    chunk_aad_i =
      "somavera:request-chunk-aad:v1\n" ||
      HEXDEC(aad_hash) ||
      UINT32BE(i) ||
      UINT32BE(chunk_plaintext_bytes_i)

Each chunk uses AES-256-GCM under the object DEK with a fresh random 96-bit nonce that is unique within that DEK. `ciphertext` includes the 16-byte tag.

    ciphertext_hash_i =
      H("somavera:request-chunk-ciphertext:v1\n" ||
        B64DEC(ciphertext_i))

    leaf_i =
      H("somavera:request-ciphertext-leaf:v1\n" ||
        UINT32BE(i) ||
        UINT32BE(chunk_plaintext_bytes_i) ||
        B64DEC(nonce_i) ||
        HEXDEC(ciphertext_hash_i))

Merkle nodes are:

    node = H("somavera:request-ciphertext-node:v1\n" || left || right)

Leaves remain in ascending index order. At every level an unpaired final node is duplicated. `ciphertext_root` is the final 32-byte node encoded lowercase hex. Empty streams are forbidden.

    request_stream_core = {
      every stream_header field except stream_id,
      chunks: ordered [{ index, plaintext_bytes, nonce, ciphertext_hash }]
    }

    stream_id =
      H("somavera:vera-encrypted-stream:v1\n" || JCS(request_stream_core))

The verifier requires indices `0..chunk_count-1` without gaps or duplicates; the array length equals `chunk_count`; the sum of chunk plaintext lengths equals `plaintext_bytes`; all non-final chunks have exactly `chunk_bytes`; the final chunk is nonempty and no larger; all nonces are unique; every ciphertext hash and root recomputes.

### 13.3 Signed outer application envelope

    application_envelope_core = all application-envelope fields except:
      $schema
      envelope_id
      signature

    envelope_id =
      H("somavera:vera-application-envelope:v1\n" ||
        JCS(application_envelope_core))

The Soma/controller signing key signs:

    "somavera:vera-application-envelope-signature:v1\n" ||
    HEXDEC(envelope_id)

Every duplicated binding in the envelope and stream header is exactly equal: network, context, sender, destination host, recipient ingestion key, inner event, grant or null, nonce, issue/expiry, stream ID, ciphertext root, and plaintext length. The signing key is not the recipient ingestion key. After decryption, the inner signed-event ID, network, context, actor, audience, nonce, issue/expiry, grant, recipient key, stream binding, and return descriptor are independently verified. A mismatch fails before authoritative mutation.

## 14. Encrypted private response

Response wrapping and chunking mirror Section 13 with distinct domains. The host uses an ephemeral HPKE sender context to the exact return key and a fresh 32-byte response DEK.

    response_wrap_info_core = {
      schema_version,
      network_lineage_id,
      execution_context_id,
      request_event_id,
      response_event_id,
      response_action,
      host_did,
      destination_soma_did,
      recipient_return_key_id,
      return_descriptor_id,
      return_key_commitment,
      issued_at,
      expires_at
    }

    response_wrap_info =
      "somavera:response-hpke-info:v1\n" || JCS(response_wrap_info_core)

    response_wrap_aad_core = response_wrap_info_core plus {
      hpke_suite,
      hpke_enc,
      chunk_bytes,
      chunk_count,
      plaintext_bytes
    }

    response_wrap_aad =
      "somavera:response-key-wrap-aad:v1\n" ||
      JCS(response_wrap_aad_core)

`wrapped_response_dek` is the sole HPKE `Seal` output over the fresh response DEK. Then:

    response_stream_aad_core = response_wrap_aad_core plus {
      wrapped_response_dek
    }

    aad_hash =
      H("somavera:response-stream-aad:v1\n" ||
        JCS(response_stream_aad_core))

Response chunk AAD, ciphertext hashes, Merkle leaves, and nodes use the Section 13 construction with the distinct domains `somavera:response-chunk-aad:v1`, `somavera:response-chunk-ciphertext:v1`, `somavera:response-ciphertext-leaf:v1`, and `somavera:response-ciphertext-node:v1`.

    response_envelope_core = {
      every encrypted-response field except:
        $schema
        response_envelope_id
        outer_signature
        chunks[].ciphertext,
      chunks remain ordered and include index, plaintext_bytes,
        nonce, and ciphertext_hash
    }

    response_envelope_id =
      H("somavera:vera-encrypted-response:v1\n" ||
        JCS(response_envelope_core))

The valid Vera host-signing key signs:

    "somavera:vera-encrypted-response-signature:v1\n" ||
    HEXDEC(response_envelope_id)

`return_descriptor_id` and `return_key_commitment` are the same recomputed descriptor hash. The destination, return key, host, response action, validity, and size must fall within that descriptor; network/context/request match the decrypted signed request. The outer host-signing key is different from the return encryption key. After decryption, Soma recomputes the inner action-specific object ID and signature and requires it to equal `response_event_id`; no raw plaintext hash is exposed in the outer response.

## 15. Contribution acknowledgement

    contribution_ack_core = all acknowledgement fields except:
      $schema
      acknowledgement_id
      signature

    acknowledgement_id =
      H("somavera:vera-contribution-acknowledgement:v1\n" ||
        JCS(contribution_ack_core))

The host signs:

    "somavera:vera-contribution-acknowledgement-signature:v1\n" ||
    HEXDEC(acknowledgement_id)

`host_signing_key_id` equals `signature.key_id`. Accepted/narrowed decisions require action `contribution.accepted`, authoritative mutation, non-null accepted scope, at least one durable object, host sequence, state/checkpoint reference, and null reason. Rejected decisions require action `contribution.rejected`, no mutation, null accepted scope/sequence/state, no durable objects, and a typed reason. The request, event, grant, ingestion key, return key/descriptor, inbound stream/root, and plaintext payload commitment all match the verified private request. This plaintext commitment exists only inside the encrypted response.

## 16. Answer/source bundle

    answer_bundle_core = all answer/source-bundle fields except:
      $schema
      response_event_id
      signature

    response_event_id =
      H("somavera:vera-answer-source-bundle:v1\n" ||
        JCS(answer_bundle_core))

The host signs:

    "somavera:vera-answer-source-bundle-signature:v1\n" ||
    HEXDEC(response_event_id)

`host_signing_key_id` equals `signature.key_id`. Direct authority requires controller and requester identity equality under verified identity policy and null delegation. Delegated authority requires the named verified delegation and strict attenuation rules in Section 12. Every citation names exactly one included source ID; citation excerpt hashes equal that source's excerpt hash; source, citation, contradiction, event, evidence, receipt, edge, and evaluation IDs are unique where their schemas require sets. An answered bundle has nonempty answer, citation, and source sets and no abstention reason. An abstained bundle has empty answer text and at least one typed reason. Host signatures authenticate bytes and provenance claims, never truth.

## 17. Temporal and recipient validation

In addition to shape and cryptography, every wire object enforces:

- `issued_at <= not_before <= expires_at` where all three exist, otherwise issue precedes expiry;
- request expiry is at most 900 seconds after issue;
- descriptor/key validity covers issue and intended response window;
- the active network and execution context match exactly;
- the exact recipient DID and key ID match the locally pinned or request-bound value;
- key status is evaluated at issue time and again before new encryption;
- nonce/replay state is scoped to network, context, actor, action, audience, and key;
- no redirect, alias, fallback key, added recipient, group key, or stale context is accepted.

Schema-valid but semantically inconsistent objects fail. In particular, duplicated binding fields, counts, sums, ID/signature key IDs, cross-object request/response IDs, return descriptor commitments, source references, and active-key pointers must agree exactly.

## 18. Ratification blockers

Before these draft wire objects become release-usable, ratification must publish:

1. exact schema hashes and one normative media/serialization profile;
2. RFC 9180 KEM/KDF/AEAD numeric identifiers and a reviewed mapping from the suite label;
3. positive HPKE key-wrap, AES-GCM chunk, Merkle, ID, and signature vectors using non-secret test keys;
4. negative vectors for wrong recipient, key-role reuse, stale/revoked keys, context replay, AAD/header mismatch, chunk gaps/duplicates, nonce reuse, root mismatch, truncation, extra fields, and outer/inner mismatch;
5. matching Rust and JavaScript results plus independent security review;
6. lifecycle rules for descriptor overlap, clock error, replay retention, response loss, and permanent return-key loss.

Until then, `profile_status: freeze_blocking_draft` is mandatory wherever present, production credentials and private data are forbidden, and Vera public/private listeners must not claim conformance to this profile.

## 19. Bootstrap and recovery identifier registry

This section completes the recovery projections used by genesis, checkpoints, state packages, death evidence, and the exact-continuity certificate. The schemas are closed with `additionalProperties: false`; `$schema` is transport metadata and is excluded wherever stated. Unless a projection explicitly says otherwise, `schema_version` is authenticated.

### 19.1 Preactivation governance manifest

The manifest has no embedded ID or signature set. Its externally stored hash is:

    preactivation_governance_core =
      all preactivation-governance fields except $schema

    preactivation_governance_manifest_hash =
      H(
        "somavera:preactivation-governance-manifest:v1\n" ||
        JCS(preactivation_governance_core)
      )

The hash commits chamber names, exact thresholds, absolute validity heights, every seat, public key, weight, controller, organization, and active flag. A schema URI never changes authority. The same projection is used by token activation, checkpoint authority snapshots, and recovery certificates.

### 19.2 Recovery authority manifest

The recovery authority manifest likewise has no embedded ID or signature set:

    recovery_authority_core =
      all recovery-authority fields except $schema

    recovery_authority_manifest_hash =
      H(
        "somavera:recovery-authority-manifest:v1\n" ||
        JCS(recovery_authority_core)
      )

This commits the Origin/release, purpose, absolute validity interval, threshold and independence minima, anti-self-extension flags, and every guardian/key/controller/organization/jurisdiction binding. A proposed successor key never contributes to this hash or authorizes its replacement merely by appearing in a successor certificate.

### 19.3 Old-network death policy

    recovery_death_policy_core =
      all recovery-death-policy fields except:
        $schema
        policy_id

    policy_id =
      H(
        "somavera:recovery-death-policy:v1\n" ||
        JCS(recovery_death_policy_core)
      )

The policy ID therefore commits its `schema_version`, Origin/release, context applicability, finality assumptions, every time bound, observer-independence requirement, reset/abort rule, non-evidence disclaimer, and succession-authority rule. Genesis binds this ID; changing any policy value creates a different policy rather than silently altering the bound predicate.

### 19.4 Signed observer reports and death evidence

Each observer report inside death evidence is independently signed. It has no report ID field:

    observer_report_core =
      all observer-report fields except signature

    observer_report_hash =
      H(
        "somavera:recovery-observer-report:v1\n" ||
        JCS(observer_report_core)
      )

    observer signature message =
      "somavera:recovery-observer-report-signature:v1\n" ||
      HEXDEC(observer_report_hash)

The `suite` remains inside the signed core. `observer_id` resolves to the exact independently registered Ed25519 verification key and controller/organization/jurisdiction binding; values carried only by the report cannot self-authorize that key.

The aggregate evidence identifier is:

    recovery_death_evidence_core =
      all top-level recovery-death-evidence fields except:
        $schema
        schema_version
        evidence_id

    evidence_id =
      H(
        "somavera:recovery-death-evidence:v1\n" ||
        JCS(recovery_death_evidence_core)
      )

`schema_version` is excluded here because the version is fixed by the hash domain; this is an explicit exception, not a general rule. The evidence core includes the complete signed observer reports, including their `suite` and `signature`, plus candidate checkpoint/package binding, newest finality, all windows, late/conflicting proofs, evaluation result, and limitations. Thus report signatures do not create a cycle: they sign report cores first; the aggregate ID then commits their completed signed forms.

### 19.5 Checkpoint state package

Fetch evidence is signed before package construction:

    fetch_receipt_core =
      all fetch-receipt fields except signature

    fetch_receipt_hash =
      H(
        "somavera:checkpoint-state-fetch-receipt:v1\n" ||
        JCS(fetch_receipt_core)
      )

    fetch receipt signature message =
      "somavera:checkpoint-state-fetch-receipt-signature:v1\n" ||
      HEXDEC(fetch_receipt_hash)

The `suite` is signed. `fetcher_controller_id` resolves to the verification key through the ratified recovery-verification registry; a controller string in the receipt is not authority by itself. The receipt binds kind/order, location, fetcher controller/organization, observed hash/length, fetch time, transcript, and success.

An independent implementation signs its reproduction result the same way:

    reproduction_result_core =
      all reproduction-result fields except signature

    reproduction_result_hash =
      H(
        "somavera:checkpoint-state-reproduction-result:v1\n" ||
        JCS(reproduction_result_core)
      )

    reproduction result signature message =
      "somavera:checkpoint-state-reproduction-result-signature:v1\n" ||
      HEXDEC(reproduction_result_hash)

This core binds implementation/controller/organization/jurisdiction, implementation release, checkpoint, reproduced height/root/app hash, transcript, and suite. Controller identity again resolves to a separately authenticated verification key.

After all chunks, availability receipts, and reproduction results exist:

    checkpoint_state_package_core =
      all checkpoint-state-package fields except:
        $schema
        schema_version
        package_id
        publisher_signatures

    package_id =
      H(
        "somavera:checkpoint-state-package:v1\n" ||
        JCS(checkpoint_state_package_core)
      )

`schema_version` is excluded because the hash domain fixes it. `publisher_signatures` are excluded to avoid a package-ID/signature cycle. Fetch-receipt and reproduction-result signatures remain inside the package core, so the package ID commits the completed independent availability and reproduction evidence as well as every ordered state/replay chunk and authority snapshot.

Each publisher signs its own role and key metadata with the package ID:

    package_publisher_signature_core = {
      package_id,
      role,
      key_id,
      suite
    }

    package publisher signature message =
      "somavera:checkpoint-state-package-publisher-signature:v1\n" ||
      JCS(package_publisher_signature_core)

`value` is excluded from this core. Binding `role` prevents an archive-operator signature from being relabeled as an independent-auditor signature. The key ID resolves through the applicable publisher/auditor trust registry.

### 19.6 Recovery certificate reconciliation

The Section 8 certificate projection remains:

    certificate_core excludes:
      $schema
      schema_version
      certificate_id
      ratification_signatures

The certificate ID consequently commits `checkpoint_state_package_id`, `death_policy_id`, `death_evidence_id`, and the complete checkpoint-pre-state authority snapshot without incorporating the signatures that authorize the certificate. Each ratification signature then binds the completed certificate ID plus its own role, authority source/hash, key/controller, and suite using the Section 8 signature core.

The dependency order is acyclic:

    governance / recovery authority / death policy
      -> signed fetch receipts and reproduction results
      -> checkpoint state package ID and publisher signatures
      -> signed observer reports and death evidence ID
      -> recovery certificate ID and ratification signatures

A verifier recomputes every identifier and inner signature before following the next arrow. A placeholder hash, schema-valid shape, unsigned controller label, Merkle root without bytes, package without independent fetch/reproduction signatures, or certificate signature over unbound role metadata is invalid.
