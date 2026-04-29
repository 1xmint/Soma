# vera-observer

Local daemon that captures developer work and produces structured observation
records. Part of the Vera intelligence layer.

## What it does

vera-observer reads raw developer signals and stores structured observation
records in a local SQLite database. Week 1 captures git commits.

The loop: code → **observe** → learn → improve

## Week 1 capabilities

- Read N most recent commits from any local git repo
- Extract structured `GitCommitObservation` records (hash, author, files
  changed, stats, message)
- Store records in local SQLite with dedup on commit hash
- Query observations by repo path or time range

## Setup

```bash
npm install
npm run build
npm test
```

## Architecture

Raw observation data stays local. Only extracted patterns will eventually
leave the machine (future weeks). See `AGENTS.md` for full architecture
and workflow rules.

## Stack

- TypeScript / Node.js ESM
- better-sqlite3 (local store)
- Zod (schema validation)
- Node.js built-in test runner
