# vera-knowledge — AGENTS.md

Knowledge service for the Vera intelligence layer. Receives Soma-signed
observations, stores them with provenance, and will aggregate them into
reusable knowledge entries.

## What This Repo Is

vera-knowledge is the shared knowledge service — a persistent store that
receives observations from developer work, attaches full provenance, and
exposes a query API for the Vera model to consume.

## What This Repo Is NOT

- Not the observer (that lives in Cortex or a dedicated observer agent)
- Not the CLI evaluator (legacy code in src/legacy/)
- Not the Vera model itself
- Not Soma — it uses soma-heart but does not own the protocol

## Dependencies

- `soma-heart` npm package — Soma identity and signature verification
- PostgreSQL with pgvector extension — primary store
- Cortex / observer agents — produce the signed observations ingested here

## Stack

- TypeScript (Node.js, ESM)
- Fastify — HTTP server
- Zod — schema validation
- Drizzle ORM — database access
- PostgreSQL + pgvector — storage and vector search

## Workflow Rules

1. Open implementation. No closed-source service code.
2. Stage, commit, push after medium-to-major changes.
3. Provenance on every stored record — Soma signature must be preserved verbatim.
4. Soma signature verification required on all observation ingest endpoints.
5. Evaluation decisions and knowledge entries must be logged and auditable.
