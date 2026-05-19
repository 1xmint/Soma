# Soma Architecture Context

Status: canonical

## Role In The System

Soma defines the trust layer.

It specifies how agent identity, execution integrity, delegation, and verification work. Downstream systems may apply Soma, but they should not redefine Soma's normative behavior.

## Context

```text
Soma (this repo)
  -> protocol, specs, packages, security model

ClawNet
  -> production orchestration platform that applies Soma

Pulse
  -> downstream product on ClawNet
```

## Major Internal Surfaces

- `packages/` for publishable packages
- top-level `SOMA-*-SPEC.md` files for normative specs
- `docs/reference/` for package/primitives/spec navigation
- `docs/explanation/` for rationale and security framing
- `docs/proposals/` for future protocol work
