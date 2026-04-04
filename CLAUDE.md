# Soma — CLAUDE.md

Agent identity verification through computational phenotyping. Two packages: `soma-heart` (agent side) and `soma-sense` (observer side). Identity is inseparable from computation — the heart IS the execution pathway.

## Workflow Rules

1. Always stage, commit, and push after medium-to-major changes.
2. Never assume — always verify. Check the actual code, search the web, or read docs before answering. If unsure, research first, ask second.

## Quick Reference

```bash
pnpm install         # Install dependencies
pnpm test            # Run all 377 tests
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
├── core/              Crypto foundations (genome, channel, crypto-provider)
├── heart/             Execution runtime (generate, callTool, fetchData)
│   ├── runtime.ts     Heart runtime — all computation passes through here
│   ├── seed.ts        Dynamic seed generation (HKDF + behavioral space)
│   ├── heartbeat.ts   Tamper-evident hash chain
│   ├── birth-certificate.ts  Data provenance with co-signing
│   └── credential-vault.ts   Encrypted credential storage
├── sensorium/         Model verification (observer side)
│   ├── senses/        3 weighted senses (temporal 5x, topology 2x, vocabulary 1x)
│   ├── atlas.ts       Phenotype atlas — memoryless reference classifier
│   ├── matcher.ts     Verdict engine (GREEN/AMBER/RED/UNCANNY)
│   ├── landscape.ts   Behavioral landscape — drift detection
│   ├── receipt-verifier.ts  Offline ClawNet Soma Receipt verification
│   ├── smart-fetch.ts Soma Check: drop-in fetch() with auto If-Soma-Hash
│   └── stream-capture.ts   Token stream analysis
├── mcp/               MCP transport wrapper, session management
└── experiment/        Runner, providers, 8 security attacks (all detected)
tests/                 377 tests across 27 files
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
| Tests passing | **377** |

## Code Style

- Strict TypeScript: `strict: true`, no `any`
- Biological terminology in names and comments
- Test crypto with both valid and tampered inputs
- Every sense: extract → test → measure → commit

## Soma Check Protocol (soma-check/1.0)

First conditional payment protocol for APIs. Reuses birth-cert `dataHash` as the change-detection key, so there's one primitive for both provenance and payment gating. Backward compatible with x402 / any payment rail.

- **Spec:** `SOMA-CHECK-SPEC.md`
- **Shared helpers:** `src/core/soma-check.ts` — headers, `SomaCheckHashStore`, provider decision helpers
- **Consumer:** `soma-sense` exports `createSmartFetch()` — drop-in `fetch()` that auto-sends `If-Soma-Hash`
- **Provider:** `soma-heart` exports `extractIfSomaHash()`, `shouldRespondUnchanged()`, `buildUnchangedResponse()`, plus `heart.hashContent()` for birth-cert-compatible hashing

## Detailed Docs

For deeper context on specific topics:
- `docs/philosophy.md` — The Insight, Three Layers, Generation paradigm, design decisions
- `docs/security.md` — Full security rules + TEE deployment model
- `docs/build-plan.md` — Phase 2 build plan (historical, all 9 steps)
- `docs/roadmap.md` — Phase 3 community phenotype network, multi-agent future, open problems
- `SOMA-CHECK-SPEC.md` — Soma Check v1.0 protocol spec
