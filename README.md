# Soma

Soma is the protocol and reference implementation for cryptographic agent identity, verification, delegation, and related trust primitives.

This repo is the canonical home for Soma's normative specs, security model, reference packages, and protocol-level rationale. It is not the place to define ClawNet product behavior or Pulse product docs.

## Repo Role

- Owns protocol and package truth
- Owns normative specs and security model
- Owns protocol rationale, limits, and future protocol proposals
- Stays separate from downstream product/runtime docs

## Packages

- `soma-heart`: source-of-truth package and execution runtime
- `soma-sense`: thin compatibility re-export for observer-only installs

## Quick Start

```bash
pnpm install
pnpm test
pnpm build
```

## Specs And Docs

- Repo overview: [docs/overview.md](docs/overview.md)
- Vision and rationale: [docs/explanation/vision.md](docs/explanation/vision.md)
- Security model: [docs/explanation/security-model.md](docs/explanation/security-model.md)
- Honest limits: [docs/limits.md](docs/limits.md)
- Package map: [docs/reference/packages.md](docs/reference/packages.md)
- Spec index: [docs/reference/spec-index.md](docs/reference/spec-index.md)
- Primitive reference: [docs/reference/primitives.md](docs/reference/primitives.md)
- Local development: [docs/how-to/local-dev.md](docs/how-to/local-dev.md)
- Release workflow: [docs/operations/release.md](docs/operations/release.md)
- Proposals: [docs/proposals/README.md](docs/proposals/README.md)
- Archive: [docs/archive/README.md](docs/archive/README.md)

## Normative Specs

- [SOMA-CHECK-SPEC.md](SOMA-CHECK-SPEC.md)
- [SOMA-DELEGATION-SPEC.md](SOMA-DELEGATION-SPEC.md)
- [SOMA-CAPABILITIES-SPEC.md](SOMA-CAPABILITIES-SPEC.md)
