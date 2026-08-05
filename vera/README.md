# vera

Vera is the observation and intelligence half of Somavera. It is one system
with two ends:

| Directory  | What it is                                                        |
|------------|-------------------------------------------------------------------|
| `observer/`| The client an agent runs. Captures work signals, produces signed structured observation records, submits them to a host. |
| `host/`    | The server anyone can run. Receives signed observation batches, verifies the Soma signature, stores the corpus. |

## The dependency direction is one-way, deliberately

Vera depends on Soma. Soma never depends on Vera.

Soma must be fully functional with Vera absent — not degraded, absent. An
agent that declines observation keeps its identity, its credentials, and its
evidence chain. If Soma ever needed Vera to work, declining observation would
mean declining identity, and consent would become a word in a document rather
than a property of the system.

That asymmetry is the reason these live in a different repository from Soma.

## Status

Neither end is production ready.

- `observer/` runs and produces signed batches. It has known privacy gaps: it
  ships author emails, absolute local paths, and source excerpts in plaintext.
  A redaction layer is required before any real deployment.
- `host/` is recovered from the archived `veraAI` v1 TypeScript implementation.

## The signing contract

Batches are signed as a domain-separated, RFC 8785 canonical envelope. See
`SIGNING-SPEC.md` for the reasoning behind each rule, and `TESTING.md` to run it.

```
signed_bytes = "somavera:vera-observation-batch:v1\n" || canonical_json(envelope)
```

The envelope carries exactly six fields — `batch_id`, `observations`,
`schema_version`, `soma_did`, `source_type`, `submitted_at`. An unknown field is
rejected rather than ignored, because ignoring one lets a future version's
meaning past a host that does not understand it.

This replaced a v0 contract that signed `JSON.stringify(observations)`. Each of
its four defects is now closed and pinned by a test in the end-to-end loop:

| v0 defect | Closed by |
|---|---|
| Only the observations array was signed, so `source_type` — provenance, the product — could be relabelled in transit | Metadata inside the envelope |
| `signedPayloadHash` was computed and never enforced unique, so a body could be replayed indefinitely | Client `batch_id` with a uniqueness index, plus a 300s window. A replay returns the original batch rather than an error, because a retry after a timeout is not an attack |
| `JSON.stringify` is not canonical, so a Rust observer would produce different bytes for identical data | RFC 8785 in both ends, proven against shared conformance vectors |
| No domain separation, so a signature made for one purpose could be presented for another | Domain prefix |

Identities are `did:key`, so the identifier **is** the public key. Registration
recomputes the commitment and refuses any mismatch — otherwise anyone could
register their own key against someone else's identifier and sign as them.

## Still missing before real data

- The observer ships author emails, absolute local paths, and source excerpts in
  plaintext. A redaction layer is required first.
- `guardian-auth.ts` signs with the same identity key but carries no domain
  prefix and builds its input with `JSON.stringify`. It binds a timestamp and
  nonce, so replay is handled, but it should come under `SIGNING-SPEC.md`.

Nothing here should be pointed at real user data yet.
