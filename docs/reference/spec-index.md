# Spec Index

Status: canonical

This file is the entry point for Soma's normative specifications.

## Normative Specs

- `SOMA-CHECK-SPEC.md`
  - Conditional payment protocol tied to content-addressed change detection
- `SOMA-DELEGATION-SPEC.md`
  - Scoped, bounded, auditable authority transfer
- `SOMA-CAPABILITIES-SPEC.md`
  - Capability structure, caveats, attenuation, and verification
- `SOMA-ROTATION-SPEC.md`
  - Credential rotation lifecycle, pre-rotation commitment, rollback invariant, and v0.1 single-witness assurance bound (see ADR-0004)
- `SOMA-HEART-CERTIFICATE-SPEC.md`
  - Soma Heart certificate primitive, v0.1 profiles, bounded claim/evidence vocabulary, and verifier-policy trust-chain semantics (draft; see ADR-0005)

## Supporting Reference

- [primitives.md](primitives.md)
- [packages.md](packages.md)
- [../explanation/security-model.md](../explanation/security-model.md)
- [../limits.md](../limits.md)

## Boundary Rule

If a downstream repo explains how it uses Soma, that is integration documentation.

If a document defines Soma's rules, semantics, or guarantees, it belongs here in `Soma`.
