# ADR-001: Modular monolith with a single execution gateway

- Status: Accepted for initial implementation
- Date: 2026-10-02

## Context

The project must demonstrate deterministic, inspectable authorization and complete
mediation while remaining local-first and reproducible. Distributed services would add
failure modes and operational work before the security thesis is proven.

## Decision

Build a typed Python modular monolith. Keep policy evaluation free of tool side effects,
and expose one agent-facing execution gateway as the mandatory route to protected tools.
Keep evaluation code and generated experiment artifacts separate from runtime code.

## Consequences

Tests can exercise the security kernel without an LLM or network, and call paths remain
auditable. Module boundaries must be enforced by API design and tests rather than a
network boundary. A future service or MCP gateway may wrap the same kernel only after
evidence shows a deployment boundary is useful.

