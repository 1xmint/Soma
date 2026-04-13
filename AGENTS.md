# Soma - AGENTS.md

Agent identity verification protocol and reference implementation through computational phenotyping. Two publishable packages: `soma-heart` (source of truth) and `soma-sense` (thin re-export of `soma-heart/sense`).

## Workflow Rules

1. Always stage, commit, and push after medium-to-major changes.
2. Releases happen from GitHub Actions, not from local `npm publish`.
   Merge to `master`, then push a tag `soma-heart-v<version>` to trigger `Publish Packages` for both `soma-heart` and `soma-sense`.
3. Never assume - always verify. Check actual code, docs, and runtime behavior before answering.

## Tighter Build Loop

Use this repo flow for important work:

1. Discovery in Discussions, internal proposal notes, or issue drafts
2. Proposal in `docs/proposals/`
3. Boundary check against downstream repos
4. ADR if protocol ownership, semantics, package surfaces, or security posture changes
5. Parent issue -> sub-issues -> small PR slices
6. Release/readiness review before merge and tag

Heuristic:

- brainstorming belongs in proposal/discussion space first
- normative protocol decisions belong in ADRs and specs
- shipped truth belongs in canonical docs and package/spec surfaces

## Repo Truth Rules

- Treat GitHub as the source of truth. Normal code pushes should go to the GitHub remote and land through PRs.
- `docs/` is the canonical repo-truth layer.
- Soma is the protocol home for identity, delegation, verification semantics, and security model.
- Downstream repos should document integration, not redefine Soma semantics.
- If protocol behavior changes, update specs or package reference docs, not just implementation notes.

## Push And Release Discipline

- Before pushing from a local clone or worktree, verify `origin` points at the canonical GitHub repo for Soma and not a stale fork or temporary transfer target.
- Do not bypass the release workflow with local `npm publish` or ad hoc publish steps unless the user explicitly asks for emergency recovery.
- Before starting work, re-check the actual current branch with Git instead of trusting a stale session header or UI summary.

## Merge Conventions

- Default to `Squash and merge`.
- Use `Merge commit` only when preserving branch history is intentionally valuable.
- This public repo can safely use auto-merge when checks are pending and the PR is otherwise ready. Prefer asking whether to enable auto-merge instead of waiting around for manual merge timing.
- Be collaborative: when a PR looks merge-ready, explicitly prompt the user before merging instead of assuming.

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

- `docs/overview.md`
- `docs/architecture/context.md`
- `docs/reference/packages.md`
- `docs/reference/spec-index.md`
- `docs/reference/primitives.md`
- `docs/explanation/vision.md`
- `docs/explanation/security-model.md`
- `docs/limits.md`
- `docs/operations/release.md`
- `docs/decisions/`
- `docs/proposals/PROPOSAL-TEMPLATE.md`
- `SOMA-CHECK-SPEC.md`
- `SOMA-DELEGATION-SPEC.md`
- `SOMA-CAPABILITIES-SPEC.md`
