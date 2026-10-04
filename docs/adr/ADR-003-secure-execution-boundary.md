# ADR-003: Internal sandbox behind one fail-closed execution gateway

- Status: Accepted
- Date: 2026-10-02

## Context

Correct policy decisions do not protect state if agent-facing code can invoke tools
directly, if raw arguments can change after authorization, or if approval checks fail
open. Phase 2 needs observable state transitions without building a production exchange.

## Decision

Keep the mutable deterministic sandbox internal and expose `ExecutionGateway` as the
only package-level execution API. The gateway uses the Phase 1 engine, executes its
normalized argument snapshot, defaults to denying required approvals, and converts
approval-verifier failures into non-execution. Expected sandbox errors validate before
mutation. Each request emits correlated in-memory lifecycle events.

## Consequences

Integration tests can prove that policy outcomes control actual state and that denied or
unapproved actions do not mutate it. Python cannot make private modules inaccessible to
malicious host code; complete mediation is an application architecture guarantee, not a
host-sandbox guarantee. Durable approvals, audit storage, and replay remain later work.

