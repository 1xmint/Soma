# Soma — CLAUDE.md

Agent identity verification through computational phenotyping. Two packages: `soma-heart` (agent side) and `soma-sense` (observer side). Identity is inseparable from computation — the heart IS the execution pathway.

## Workflow Rules

1. Always stage, commit, and push after medium-to-major changes.
2. Never assume — always verify. Check the actual code, search the web, or read docs before answering. If unsure, research first, ask second.
3. Keep this file ≤ 100 lines. Detail goes in `docs/`.

## Quick Reference

```bash
pnpm install         # Install dependencies
pnpm test            # Run all 536 tests
pnpm build           # Compile to dist/
```

**Published:** `soma-heart@0.1.1`, `soma-sense@0.1.0` on npm.
**Paper:** [DOI 10.5281/zenodo.19260081](https://doi.org/10.5281/zenodo.19260081)
**On-chain:** ERC-8004 on Base Mainnet — agent 37696.

## Tech Stack

- **TypeScript** strict mode, no `any`
- **pnpm** package manager
- **tweetnacl** — Ed25519 + X25519 (zero-dependency, audited)
- **@modelcontextprotocol/sdk** — official MCP SDK
- **openai** — OpenAI-compatible API client
- **vitest** — testing

## Project Structure

```
src/
├── core/         Crypto foundations (genome, channel, crypto-provider, soma-check)
├── heart/        Execution runtime + multi-agent primitives
├── sensorium/    Model verification (observer side)
├── mcp/          MCP transport wrapper, session management
└── experiment/   Runner, providers, security attacks
tests/            451 tests across 35 files
```

## Two-Package Split (CRITICAL)

- **soma-heart** — agent operator installs. Holds credentials. `generate()`, `callTool()`, `fetchData()`.
- **soma-sense** — observer installs. Passive observation. Verdicts. Receipt verification.

An agent verifying itself is meaningless. The observer MUST do the sensing on their own machine. Heart and sense never run in the same process.

## Security Rules (non-negotiable)

1. **Soma is the heart, not a wrapper** — credentials live inside, no bypassing
2. **Soma never speaks** — no "I am Soma" messages, genome exchanged via MCP metadata
3. **All observation inside encrypted channels** — X25519 + NaCl secretbox
4. **Sensorium runs locally** — observer's process, no central server
5. **Identity is a distribution, not a snapshot** — behavioral landscape over time
6. **Every token is cryptographically authenticated** — per-token HMAC, invalid = RED
7. **Must be crypto-agile** — designed for post-quantum migration

## Key Metrics

| Metric | Result |
|---|---|
| Local classification (5 models) | **100.0%** |
| Cloud classification (11 agents) | **93.2%** |
| Security attacks detected | **8/8** |
| HMAC overhead per token | **3.4–5.4 microseconds** |
| Tests passing | **536** |

## Code Style

- Strict TypeScript: `strict: true`, no `any`
- Biological terminology in names and comments
- Test crypto with both valid and tampered inputs

## Detailed Docs

- `docs/primitives.md` — multi-agent API reference, observability, Soma Check
- `docs/philosophy.md` — The Insight, Three Layers, Generation paradigm
- `docs/security.md` — Full security rules + TEE deployment model
- `docs/build-plan.md` — Phase 2 build plan (historical)
- `docs/roadmap.md` — Phase 3 community network, multi-agent future
- `docs/design/` — design specs for upcoming primitives
- `SOMA-CHECK-SPEC.md` — Soma Check v1.0 protocol spec
