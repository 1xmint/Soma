# Soma - AGENTS.md

Agent identity verification through computational phenotyping. Two publishable packages: `soma-heart` (source of truth) and `soma-sense` (thin re-export of `soma-heart/sense`).

## Workflow Rules

1. Always stage, commit, and push after medium-to-major changes.
2. Releases happen from GitHub Actions, not from local `npm publish`.
   Merge to `master`, then push a tag `soma-heart-v<version>` to trigger `Publish Packages` for both `soma-heart` and `soma-sense`.
3. Never assume - always verify. Check actual code, docs, and runtime behavior before answering.

## Quick Reference

```bash
pnpm install
pnpm test
pnpm build
```

**Branch:** `master`  
**Release tag:** `soma-heart-v<version>`  
**Trusted publishing:** GitHub Actions `Publish Packages` + `npm-release` environment  
**Build-script approval:** `pnpm-workspace.yaml` controls allowed dependency builds (`esbuild`)

## Two-Package Split (CRITICAL)

- `soma-heart` - source of truth. Agent installs this. Includes heart primitives and `soma-heart/sense`.
- `soma-sense` - thin compatibility re-export for observer-only installs.

An agent verifying itself is meaningless. The observer must do the sensing on their own machine.

## Security Rules

1. Soma is the heart, not a wrapper.
2. Soma never speaks as a persona.
3. Observation stays inside encrypted channels.
4. Sensorium runs locally.
5. Identity is a distribution over time, not a snapshot.
6. Every token is cryptographically authenticated.
7. Must stay crypto-agile.

## Detailed Docs

- `docs/secure-release-workflow.md`
- `docs/primitives.md`
- `docs/limits.md`
- `docs/philosophy.md`
- `docs/security.md`
- `docs/roadmap.md`
