# Soma Development Workflow

Status: canonical


This document keeps the important project context in repo-owned documentation that works well with any editor or coding assistant.

## Overview

Soma provides agent identity verification through computational phenotyping. It is split into two packages:

- `soma-heart` for the agent-side runtime and credentials
- `soma-sense` for observer-side verification and verdicts

The observer must remain separate from the agent runtime. Heart and sense should not be treated as the same process.

## Core Commands

```bash
pnpm install
pnpm lint
pnpm format:check
pnpm test
```

## Architecture Rules

- Keep `soma-heart` and `soma-sense` conceptually separate.
- Do not design around self-verification.
- Treat identity as a longitudinal behavioral signal, not a single snapshot.
- Keep encrypted-channel and authenticated-token assumptions intact when editing runtime code.

## Code Rules

- Prefer strict TypeScript.
- Avoid `any` where practical, especially in new code.
- Preserve the project's biological terminology when naming new concepts.
- Test cryptographic changes with both valid and tampered inputs.

## Environment And Secrets

- Keep provider keys in local `.env` files only.
- Use [.env.example](C:\Users\Josh\Desktop\GitHub\Soma\.env.example) as the public template.
- Never commit real provider credentials.
- Keep experiment logs, package tarballs, and local secret variants out of git.
- Treat this repo as a package/research workspace, not a long-lived VPS service.

## Related Docs

- [docs/reference/primitives.md](C:\Users\Josh\Desktop\GitHub\Soma\docs\reference\primitives.md)
- [docs/limits.md](C:\Users\Josh\Desktop\GitHub\Soma\docs\limits.md)
- [docs/explanation/security-model.md](C:\Users\Josh\Desktop\GitHub\Soma\docs\explanation\security-model.md)
- [docs/proposals/roadmap.md](C:\Users\Josh\Desktop\GitHub\Soma\docs\proposals\roadmap.md)
- [docs/operations/ops-security.md](C:\Users\Josh\Desktop\GitHub\Soma\docs\operations\ops-security.md)
