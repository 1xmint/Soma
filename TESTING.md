# Testing Vera end to end

Vera has two ends that must agree: the observer an agent runs, and the host
anyone can run. Testing either alone proves very little, so the loop below runs
both against a real database with real signatures.

## Requirements

Node 22 or later, and Docker for Postgres. The host needs `pgvector`.

## Unit suites

```
cd observer && npm ci --ignore-scripts && npm test
cd host     && npm ci --ignore-scripts && npm run test:build
```

The host suite needs a database:

```
cd host
docker compose up -d
export DATABASE_URL=postgres://vera:vera_dev@localhost:5433/vera_knowledge
npm run db:migrate
npm run test:build
```

The host tests deliberately use a real Postgres. Mocking it would test the mock
rather than the receiver — and the receiver is the part that verifies
signatures.

## The loop

Start a host:

```bash
cd host
docker compose up -d
export DATABASE_URL=postgres://vera:vera_dev@localhost:5433/vera_knowledge
npm run db:migrate
npm run build
npm start
```

Then, in another shell:

```bash
cd observer
npm run build
node e2e/loop.mjs http://localhost:3100
```

CI runs exactly this on every change, and `End-to-end` is a required check, so
it gates merges rather than merely reporting.

### What the ten checks establish

| # | Check | Why it matters |
|---|---|---|
| 1 | Host is reachable | — |
| 2 | The identity is its own key | `did:key:z…` — nothing has to be trusted to distribute it |
| 3 | Registration is accepted | — |
| 4 | Registration refuses a key the DID does not commit to | Otherwise anyone could register their own key against your identifier and sign as you |
| 5 | A signed batch is accepted | — |
| 6 | The batch reports what it carried | — |
| 7 | Replay returns the original batch | A retry after a network timeout must not be punished, and must not duplicate |
| 8 | Relabelled provenance is rejected | `source_type` is inside the signature. Provenance is the product |
| 9 | Member order does not affect verification | Canonical bytes are the content, not the wire form |
| 10 | Foreign signatures and stale submissions are refused | — |

## Checking it by hand

```bash
# 1. An identity that is its own key
#    (observer/src/lib/did.ts derives did:key from the public key)

# 2. Register
curl -s localhost:3100/v1/register \
  -H 'content-type: application/json' \
  -d '{"soma_did":"did:key:z...","public_key":"<base64>"}'

# 3. Submit a signed envelope
curl -s localhost:3100/v1/observations \
  -H 'content-type: application/json' \
  -d '{"envelope":{...},"signature":"<base64>"}'
```

The envelope must carry exactly six fields — `batch_id`, `observations`,
`schema_version`, `soma_did`, `source_type`, `submitted_at` — and the signature
covers `"somavera:vera-observation-batch:v1\n"` followed by the RFC 8785
canonical form. An unknown field is rejected rather than ignored: ignoring one
lets a future version's meaning past a host that does not understand it.

See `SIGNING-SPEC.md` for the reasoning behind each rule.

## What passing does not mean

The loop proves an identity can register, sign work, and have a running host
verify it. **It does not prove the observed work happened.** A signature
establishes who said something, never whether it is true.

Counter-signed receipts in Soma address attribution by a second party. Nothing
in Vera does, and nothing here should be read as if it did.

## Known gaps

- The observer ships author emails, absolute local paths, and source excerpts in
  plaintext. A redaction layer is required before this points at anything real.
- `guardian-auth.ts` signs with the same identity key but carries no domain
  prefix and builds its input with `JSON.stringify`. It binds a timestamp and
  nonce, so replay is handled, but it should come under `SIGNING-SPEC.md`.
- Receipts are not revocable, and a subject cannot decline one attached to it.
