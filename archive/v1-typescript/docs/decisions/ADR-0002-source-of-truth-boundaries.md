# ADR-0002: Cross-Repo Source-Of-Truth Boundaries

Status: accepted

## Context

The system includes `Soma`, `claw-net`, and `pulse`. Contributors need a durable rule for where protocol, runtime, and product truth live.

## Decision

Use the following source-of-truth split:

- `Soma`: protocol semantics, trust primitives, public package/reference truth
- `claw-net`: runtime/deploy/platform truth
- `pulse`: product-specific behavior and X-only product truth

## Consequences

- protocol docs should not be rewritten downstream
- runtime and deploy docs belong outside `Soma`
- cross-repo references should point to the canonical repo instead of copying truth
