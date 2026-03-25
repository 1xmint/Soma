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
| ✅ | [Tests](#tests) | 60 tests passing (core + experiment) |
| ✅ | [Experiment (Phase 0)](#experiment-phase-0) | All modules built, ready to run |
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
✅ **Experiment tests** (`tests/signals.test.ts`) — 42 tests covering:
  - Cognitive signal extraction (hedging, certainty, disclaimers, empathy, questions)
  - Structural signal extraction (word counts, lists, headers, code blocks, opening/closing patterns)
  - Temporal signal extraction (inter-token intervals, burstiness, median, std)
  - Error signal extraction (refusals, uncertainty, self-corrections, assertive-when-wrong)
  - Full signal pipeline + feature vector generation
  - Probe battery integrity (100 probes, 20 per category, unique IDs)
  - Agent config integrity (10 agents, 2 epigenetic, 1 proxy, unique IDs)

## Experiment (Phase 0)
✅ **Agent genome configs** (`src/experiment/configs.ts`) — 10 agent definitions: 7 base models (Gemini Flash/Pro, Llama 70B/8B, Mixtral, Gemma2, Mistral Small) + 2 epigenetic variants (formal/chaotic Llama 70B) + 1 proxy attack
✅ **Probe battery** (`src/experiment/probes.ts`) — 100 prompts across 5 categories (normal, ambiguity, edge case, failure induction, rapid-fire)
✅ **Signal extraction** (`src/experiment/signals.ts`) — 4 signal channels (cognitive, structural, temporal, error) with 34-feature numeric vector output for ML
✅ **Provider clients** (`src/experiment/providers.ts`) — Streaming clients for Google AI Studio (raw fetch + SSE), Groq & Mistral (OpenAI SDK), plus proxy attack simulation with log-normal latency injection
✅ **Experiment runner** (`src/experiment/runner.ts`) — Sends all probes to all agents, captures streaming traces, extracts signals, saves JSON results with rate limiting
❌ **ML analysis** (`src/experiment/analyze.ts`) — Random forest classifier, accuracy reports

## Sensorium
❌ **Phenotype matcher** (`src/sensorium/matcher.ts`) — GREEN/AMBER/RED/UNCANNY confidence signals

## Documentation
❌ **README** — Public-facing project description and usage

## CI/CD
❌ **Automated tests** — GitHub Actions or similar
