# vera-observer — AGENTS.md

Local daemon that captures developer work and produces structured observation
records. Part of the Vera Day 0 build. Implements the "observe" step in the
loop: code → observe → learn → improve.

## What This Repo Is

vera-observer runs locally on the developer's machine. It reads raw developer
signals (git commits in Week 1, filesystem and test results later) and stores
structured observation records in a local SQLite database. Raw data stays
local — this is the "secure room." Only extracted patterns will eventually
leave (in a future week, not Week 1).

The loop: developer commits code → vera-observer reads git log → extracts
structured GitCommitObservation records → stores locally in SQLite → (future)
submits signed pattern summaries to vera-knowledge.

## What This Repo Is NOT

- Not vera-knowledge (the hosted shared-layer service at veraAI repo)
- Not the Vera model or evaluator
- Not a real-time file watcher (Week 1 is batch, not daemon)
- Not Soma — it will eventually use soma-heart for signing but does not own
  the identity protocol
- Not responsible for HTTP submission to vera-knowledge (Week 2+)

## Dependencies

- `sql.js` — local observation store (pure-JS SQLite, in-memory + persisted to disk)
- `zod` — schema validation
- `soma-heart` — Soma cryptographic provider (Ed25519 signing for submission)
- `git` CLI — reading commits via child_process (no npm git packages)
- Node.js >= 22.12.0

## Observation Contract

Output types are compatible with vera-knowledge's ObservationItem schema:
- `type`: string tag (e.g. "git_commit")
- `content`: Record<string, unknown> — GitCommitObservation shape
- `observed_at`: ISO 8601 timestamp

See `src/lib/types.ts` for the full type definitions and Zod schemas.

## Stack

- TypeScript (Node.js, ESM)
- Zod — schema validation
- sql.js — local store (pure-JS SQLite, no native compilation)
- soma-heart — Ed25519 signing (Soma crypto provider)
- Node.js built-in test runner

## Week 1 Scope

1. Observation types (GitCommitObservation, ObservationRecord)
2. Git observation module — reads N most recent commits from a local repo
3. Local SQLite store — insert, query by repo, query by time range, dedup

## Workflow Rules

1. Raw observation data never leaves the local machine (no HTTP in Week 1).
2. Dedup on commit hash — never double-insert the same commit.
3. Stage and commit after medium-to-major changes.
4. Do not touch vera-knowledge or Cortex repos directly.
5. Observation types must remain compatible with vera-knowledge's
   ObservationItem schema (type + content + observed_at).

## Future Seams (not Week 1)

- Filesystem observation (Level 2)
- Test result observation (Level 2)
- Claude Code session capture (Level 3)
- HTTP submission to vera-knowledge with Soma signing
- Daemon/watch mode (real-time commit watching)
- vera-cli integration
- `vera init --repo` git history bootstrap
- Journey tracking / session sequencing
- Pattern aggregation across commits
