# ADR-0003: Public Release And Publish Model

Status: accepted

## Context

Soma is a public protocol/reference repo with npm publishing and public package consumers. Its release model should stay explicit and distinct from private product deploy workflows.

## Decision

Keep `Soma` public and treat package publishing as the canonical release path for the repo's primary artifacts.

## Consequences

- GitHub Actions publish flow is part of the repo's operational truth
- package versioning and specs need stronger release discipline than internal product repos
- protocol credibility benefits from public visibility and explicit release hygiene
