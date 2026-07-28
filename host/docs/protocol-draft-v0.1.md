# vera-knowledge Protocol — Draft v0.1

## Overview

vera-knowledge is a provenance-bearing knowledge service that ingests, stores, and
attributes observations to their originating identity. Every observation accepted by
the service is cryptographically bound to the Soma DID that submitted it: the
submitter signs the payload with their Ed25519 private key before sending, and
vera-knowledge verifies that signature against the registered public key before
writing anything to the database. This makes the provenance chain tamper-evident —
an observation cannot be silently reattributed or backdated after the fact. Soma is
the identity layer: each user has a Decentralized Identifier (DID) and an associated
Ed25519 keypair managed by the Soma runtime. vera-knowledge trusts what Soma attests
and records the cryptographic evidence alongside each batch.

---

## Identity

Each participant is identified by a Soma DID (`did:soma:<id>`) paired with an
Ed25519 keypair. vera-knowledge stores only the base64-encoded public key (32 bytes);
the private key never leaves the caller.

**Registration flow:**
1. Caller sends `POST /v1/register` with their DID, public key, and optional display
   name.
2. vera-knowledge checks that the DID is not already registered.
3. On success, a `users` row is created and the caller receives the new user record.

---

## Observation Ingest

**Signed batch flow:**
1. Caller assembles an array of observation items and computes
   `payload = JSON.stringify(observations)` (no extra whitespace).
2. Caller signs the UTF-8–encoded payload with their Ed25519 private key, then
   base64-encodes the 64-byte signature.
3. Caller sends `POST /v1/observations` with DID, source type, signature, and
   observations array.
4. Server verifies the signature against the registered public key. On success, it
   writes one `observation_batches` row and one `observations` row per item.

**Provenance chain:** The server stores the raw `soma_signature` and a SHA-256 hex
digest of the signed payload (`signed_payload_hash`). Together with the registered
public key these three values allow any auditor to re-verify provenance without
trusting the database content.

---

## Endpoints

### GET /health

```json
// Response 200
{ "status": "ok", "service": "vera-knowledge", "version": "0.1.0", "timestamp": "2026-04-28T12:00:00.000Z" }
```

### POST /v1/register

```json
// Request
{ "soma_did": "did:soma:abc123", "public_key": "<base64 Ed25519 pubkey>", "display_name": "Alice" }

// 201 Created
{ "user": { "id": "<uuid>", "soma_did": "did:soma:abc123", "public_key": "<base64>", "display_name": "Alice", "created_at": "<iso8601>" } }

// 409 Already registered
{ "error": "already_registered", "message": "A user with this Soma DID is already registered" }

// 400 Validation error
{ "error": "validation_error", "message": "Request body validation failed", "details": [ /* zod errors */ ] }
```

`display_name` is optional. `soma_did` and `public_key` are required.

### POST /v1/observations

```json
// Request
{
  "soma_did": "did:soma:abc123",
  "source_type": "manual",
  "signature": "<base64 Ed25519 signature>",
  "observations": [
    { "type": "note", "content": { "text": "Learned about provenance." }, "observed_at": "2026-04-28T11:00:00.000Z" }
  ]
}

// 201 Created
{ "batch": { "id": "<uuid>", "user_id": "<uuid>", "source_type": "manual", "observation_count": 1, "created_at": "<iso8601>" } }

// 403 Bad signature
{ "error": "signature_invalid", "message": "Soma signature verification failed" }

// 404 Unknown DID
{ "error": "user_not_found", "message": "No user registered with this Soma DID" }
```

`observations` must contain at least one item.

---

## Signature Scheme

**Caller (signing):**
1. `payload = JSON.stringify(observations)` — raw output, no pretty-print.
2. Sign `TextEncoder().encode(payload)` with Ed25519 private key → 64-byte signature.
3. Base64-encode the signature; send as `signature` field.

**Server (verification):**
1. Re-serialize the observations from the request: `signedPayload = JSON.stringify(observations)`.
2. Decode caller's base64 public key (32 bytes) and base64 signature (64 bytes).
3. `Ed25519.verify(UTF8(signedPayload), signatureBytes, publicKeyBytes)` → 403 on failure.
4. Compute `SHA-256(signedPayload)` → store hex digest as `signed_payload_hash`.

---

## Schema

| Table | Purpose |
|---|---|
| `users` | One row per registered identity. Stores `soma_did` (unique), base64 `public_key`, optional `display_name`, and timestamps. |
| `observation_batches` | One row per accepted POST. Stores `soma_signature`, `signed_payload_hash`, `source_type`, foreign key to `users`. |
| `observations` | One row per item in a batch. Stores `observation_type`, `content` (JSONB), caller-supplied `observed_at`. Foreign key to `observation_batches`. |
| `knowledge_entries` | Future aggregation output. Schema includes 1536-dim embedding vector, confidence score, tags, and `soma_provenance` JSONB. Not populated in week 1. |
| `teaching_entries` | Future user corrections/reinforcements. Schema includes teaching type, content, optional target knowledge ID, and Soma signature. Not populated in week 1. |

---

## What's Next

The following are intentionally out of scope for week 1:

- **Knowledge aggregation** — deriving `knowledge_entries` from raw observations
- **Teaching processing** — accepting and applying `teaching_entries`
- **Embedding generation** — populating the vector column on `knowledge_entries`
- **Query and retrieval** — any read endpoint beyond `/health`
- **Federation** — cross-service or cross-DID provenance linking
- **CLI integration** — a command-line client or Soma-runtime plugin

---

*This document describes only what is implemented in the week 1 foundation. It is not a formal specification.*
