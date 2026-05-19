# ADR-0001: Soma Is The Protocol Home

Status: accepted

## Context

Soma is consumed by downstream repos, but those repos should not redefine the protocol itself.

Without an explicit rule, protocol truth drifts into integrations and product docs.

## Decision

Use `Soma` as the canonical home for:

- protocol semantics
- normative specs
- package surfaces
- security model

## Consequences

- downstream repos should document integration, not protocol ownership
- Soma stays cleaner as the source of normative truth
- cross-repo trust and identity language becomes less ambiguous
