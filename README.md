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

### The signing contract has four defects

Both ends sign and verify `JSON.stringify(observations)`. They agree with each
other; the problems are with the scheme itself.

1. **The signature does not cover the metadata.** Only the observations array is
   signed. `source_type` is stored but never authenticated, so provenance — the
   thing this system exists to establish — can be relabelled in transit.
   `soma_did` is incidentally protected because it selects the verifying key.
2. **Nothing prevents replay.** `signedPayloadHash` is computed and stored but
   never enforced unique. The same signed body can be submitted repeatedly, each
   time creating another batch with another copy of the observations.
3. **`JSON.stringify` is not a canonical form.** Two TypeScript ends agree today,
   but Soma canonicalizes per RFC 8785 and rejects non-canonical input. A Rust
   observer would serialize the same logical data to different bytes — key
   order, escaping, number formatting — and its signatures would not verify.
4. **No domain separation.** Soma applies it across all twelve of its signing
   contexts. Vera signs bare payload bytes with the same identity key, so a
   signature made for one purpose can be presented for another.

Fixing these means a signed envelope: domain-separated, RFC 8785 canonical,
covering the metadata, and carrying a client batch identifier the host enforces
as unique. It must land in shared conformance vectors so that a Rust observer
and a TypeScript host are forced to agree rather than merely expected to.

Nothing here should be pointed at real user data yet.
