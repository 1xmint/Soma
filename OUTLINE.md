# Soma — Project Outline

> Legend: ✅ Done | ❌ Not Done | ⚠️ Check Later

---

## Table of Contents

| Status | Section | Notes |
|--------|---------|-------|
| ✅ | [Repository Setup](#repository-setup) | |
| ✅ | [Project Structure](#project-structure) | Directories + config files |
| ✅ | [Core Logic](#core-logic) | Genome commitment + encrypted channel |
| ✅ | [Configuration](#configuration) | .env.example, tsconfig, package.json |
| ✅ | [Tests](#tests) | 18 core crypto tests passing |
| ❌ | [Experiment (Phase 0)](#experiment-phase-0) | Phenotype proof |
| ❌ | [Sensorium](#sensorium) | Observation layer |
| ❌ | [Documentation](#documentation) | |
| ❌ | [CI/CD](#cicd) | |

---

## Repository Setup
✅ **Git repo initialized** — Version control set up
✅ **CLAUDE.md created** — Complete project context and design document
✅ **`.gitignore` configured** — Ignores node_modules, dist, .env, results output
✅ **License chosen** — MIT

## Project Structure
✅ **Directory layout created** — `src/core/`, `src/experiment/`, `src/sensorium/`, `tests/`, `results/`
✅ **Package manifest** — `package.json` with pnpm, scripts for test/experiment/analyze
✅ **TypeScript config** — `tsconfig.json` with strict mode, ESNext modules

## Core Logic
✅ **Genome commitment** (`src/core/genome.ts`) — Create, hash, sign, verify, mutate genomes. Ed25519 signing via tweetnacl. SHA-256 hashing. DID:key identifiers.
✅ **Authenticated encrypted channel** (`src/core/channel.ts`) — X25519 key exchange, NaCl secretbox encryption, genome commitment verification during handshake. Forward secrecy via ephemeral keys.

## Configuration
✅ **Environment variables** — `.env.example` with API key slots for Google AI Studio, Groq, Mistral
✅ **TypeScript strict mode** — No `any` types, strict null checks
✅ **Dev tooling** — tsx for execution, vitest for testing

## Tests
✅ **Test framework** — Vitest
✅ **Core crypto tests** (`tests/core.test.ts`) — 18 tests covering:
  - Genome creation, deterministic hashing, epigenetic variant detection
  - Commitment signing, verification, tamper detection (genome, hash, key, DID)
  - Mutation versioning and hash chain
  - Channel establishment, bidirectional encryption/decryption
  - Random nonce uniqueness, tamper rejection, eavesdropper isolation
  - Invalid genome commitment rejection during handshake

## Experiment (Phase 0)
❌ **Agent genome configs** (`src/experiment/configs.ts`) — 9+ agent definitions across providers
❌ **Probe battery** (`src/experiment/probes.ts`) — 100 prompts across 5 categories
❌ **Signal extraction** (`src/experiment/signals.ts`) — Cognitive, structural, temporal, error signals
❌ **Provider clients** (`src/experiment/providers.ts`) — Streaming API clients for Google, Groq, Mistral
❌ **Experiment runner** (`src/experiment/runner.ts`) — Send probes, capture signals
❌ **ML analysis** (`src/experiment/analyze.ts`) — Random forest classifier, accuracy reports

## Sensorium
❌ **Phenotype matcher** (`src/sensorium/matcher.ts`) — GREEN/AMBER/RED/UNCANNY confidence signals

## Documentation
❌ **README** — Public-facing project description and usage

## CI/CD
❌ **Automated tests** — GitHub Actions or similar
