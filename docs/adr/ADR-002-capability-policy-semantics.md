# ADR-002: Explicit capability constraints and ordered fail-closed policy semantics

- Status: Accepted
- Date: 2026-10-02

## Context

Authorization must be deterministic, inspectable, and independent of model behavior.
Ambiguous grants, floating-point limits, permissive parsing, and exceptions that fall
through to execution would weaken those guarantees.

## Decision

Represent security inputs and outputs with frozen typed models. Bind each capability to
one runtime agent identity, reject duplicate grants for the same capability, require
timezone-aware expiry, and use `Decimal` for monetary constraints. Validate arguments
against the registered tool schema before capability checks. Apply checks in a stable
order and return one structured reason code. Unknown tools, malformed requests, missing
or expired grants, scope violations, and internal evaluation errors all return DENY.

An approval threshold or withdrawal rule returns REQUIRE_APPROVAL, never ALLOW. Phase 1
does not consume approvals or execute tools; those transitions belong to later phases.

## Consequences

The kernel is locally testable without an LLM, network, or financial state. One grant per
agent/capability removes conflict resolution ambiguity for the initial system. More
complex composition would require an explicit deny-overrides algorithm and a new ADR.

