# Security invariants

These are required properties of the completed runtime. Phase 0 defines them; later
phases must implement automated evidence. A feature is incomplete if its relevant
invariant lacks a test.

| ID | Invariant | Planned verification |
| --- | --- | --- |
| INV-01 | A DENY decision never results in tool execution or state mutation. | Gateway unit/integration tests and state snapshots |
| INV-02 | An identity without the required capability never executes the action. | Capability boundary and property tests |
| INV-03 | An expired capability never authorizes execution. | Clock-controlled expiry boundary tests |
| INV-04 | REQUIRE_APPROVAL never executes before a valid approval. | Approval state-machine tests |
| INV-05 | Unknown protected tools fail closed. | Registry and gateway tests |
| INV-06 | Arguments are schema-validated before policy evaluation or execution. | Malformed/generated input tests |
| INV-07 | Standard functioning recorders produce correlated pre-execution and terminal events; recorder failure is explicit and pre-execution failure prevents mutation. | Integration and fault-injection tests |
| INV-08 | An approval cannot authorize a changed action, agent, principal, environment, reuse, or post-expiry execution. | Binding, replay, identity, environment, and expiry tests |
| INV-09 | Every agent-facing protected call is completely mediated by the gateway. | Architecture/API checks and integration tests |
| INV-10 | Security-evaluation failure cannot degrade into ALLOW. | Fault-injection tests |
| INV-11 | Capability constraints (symbol, amount, environment, action) cannot be exceeded without the explicitly configured approval path. | Boundary/property tests |
| INV-12 | Untrusted content, tool output, or prompt claims cannot create capabilities or approvals. | Adversarial scenario tests |
| INV-13 | A principal cannot read or mutate another principal's resource without explicit delegated scope. | Multi-principal resource/property tests |
| INV-14 | One approval is consumed at most once across local manager instances and binds principal/environment. | Multi-instance and context-substitution tests |
| INV-15 | Indirect identifiers are authorized against authoritative resource owner, environment, and symbol. | Cancellation regression tests |
| INV-16 | A repeated state-changing idempotency identity produces at most one side effect. | Replay/conflict/concurrency tests |
| INV-17 | Standard audit recorders minimize secrets, isolate event objects, and detect hash-chain modification. | Redaction, mutation, and tamper tests |
| INV-18 | Cumulative operations cannot exceed the configured principal/environment budget. | Sequential/concurrent property tests |
| INV-19 | Asset movement to a destination outside deterministic trusted scope never executes. | Destination/property tests |

Tests will use deterministic clocks and exact decimal values where relevant. Each
security defect discovered later must add a regression case mapped to an invariant or
define a new invariant.

## Phase 1 evidence boundary

Phase 1 automatically verifies the authorization-result portions of INV-01 through
INV-06, plus fail-closed INV-10 and monetary boundary INV-11. Because this phase has no
execution path by design, the “never executes or mutates state” portions of INV-01 and
INV-04 must additionally be proven by gateway/sandbox integration tests in Phase 2.

Phase 2 integration tests now verify those execution and state-mutation portions through
the public gateway, including DENY, REQUIRE_APPROVAL, malformed request, expired grant,
symbol scope, amount limit, approval-backend failure, and sandbox failure paths.

## Phase 5 evidence boundary

Phase 5 state-machine and gateway tests verify INV-04, INV-07, and INV-08: approval is
issued only as pending state, an allowlisted authority must resolve it, its digest binds
the normalized action and agent identity, expiry is enforced, and successful consumption
is single-use. Structured lifecycle events can be persisted, filtered, and replayed.
Authorized mutation is stopped if the mandatory pre-execution audit write fails.

## Phase 6 evidence boundary

Phase 6 adds generated malformed-request and monetary-limit checks, direct gateway fault
injection, and regression tests for non-finite decimals, Unicode confusables, backdated
approval clocks, verifier mutation, concurrent oversubscription, single-use approval
consumption, and parseable concurrent audit writes. In-process locks protect the mutable
sandbox, approval manager, and each audit-recorder instance.

## Phase 9 evidence boundary

Phase 9 verifies INV-13 through INV-19. Resource state is principal/environment
partitioned; indirect cancellation resolves stored attributes; approval consumption is
file-locked and atomically replaced across local manager instances; state-changing calls
have idempotency identities; aggregate budgets and destinations are checked under the
gateway lock; and standard audit recorders deep-copy, redact recursively, and hash-chain
events.

Distributed idempotency/approval, deletion-proof audit retention, and crash consistency
between terminal audit and sandbox mutation remain production-storage concerns.
Deterministic policy still cannot infer malicious semantic intent for a fully authorized
action without a separate trusted mandate.
