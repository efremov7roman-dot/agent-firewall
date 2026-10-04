# Interview guide

## 1. Why can't the LLM authorize itself?

The same untrusted inputs that influence the proposal would influence the decision. Identity, ownership, limits, and approvals must come from trusted deterministic state outside the model.

## 2. What does zero trust mean here?

Every model call is an untrusted proposal. The gateway verifies identity, resource, capability, policy, state, and approval for each protected action. It is a scoped design principle, not a claim that every host component is untrusted.

## 3. What was wrong with the original architecture?

It authorized mostly at tool/call level. Phase 8 showed missing resource ownership, cross-instance approval replay, weak cancellation/context binding, absent idempotency and aggregate/destination scope, and audit gaps.

## 4. Why did Phase 8 ASR jump to 65.4%?

The development set emphasized known per-call checks. The blind set exercised new stateful and resource-level paths. Different datasets make the gap diagnostic, not a paired statistical estimate.

## 5. How did you fix principal/resource isolation?

State is partitioned by principal/environment. Indirect mutations resolve the stored object first and authorize its actual owner and attributes; cross-principal access requires explicit delegated scope.

## 6. How are capabilities represented?

Typed grants bind an operation to an agent and optional constraints such as action, symbol, amount, destination, resource principal, environment, and expiry. Grants narrow authority; model text cannot expand them.

## 7. Why bind approvals to exact context?

An approval for one subject, environment, tool, or normalized argument set must not authorize a changed action. Exact binding turns approval into a narrow capability rather than a reusable yes/no flag.

## 8. How do you prevent approval replay?

Approved records are atomically consumed under a local cross-process file lock. Exact retries are handled through idempotent replay without a second side effect. This assumes a shared local filesystem, not multiple hosts.

## 9. How does idempotency work?

The gateway keys protected requests within principal/environment state and returns the recorded result for an exact repeat. A conflicting reuse does not create another mutation.

## 10. How do aggregate limits work?

The gateway keeps cumulative local state per principal/environment and evaluates a new action against the applicable budget before mutation, preventing a caller from splitting a prohibited total into individually valid calls.

## 11. What does fail closed mean here?

Validation, identity, capability, policy, resource, approval, or mandatory pre-audit errors prevent protected execution and leave state unchanged. Post-execution audit failure is a documented atomicity exception.

## 12. What does the audit hash chain guarantee?

Given a trusted prior chain head, recomputation can detect event content modification or reordering in the retained sequence.

## 13. What does it not guarantee?

It does not encrypt or sign records, prove remote origin, enforce access control, prevent deletion/truncation, or atomically commit the terminal event with sandbox mutation.

## 14. Why isn't 0/40 proof of universal security?

It is one frozen scripted local dataset. Untested attacks, deployments, models, integrations, and trusted-component failures remain possible.

## 15. Why is semantic-intent safety different from authorization safety?

Authorization asks whether a declared capability permits a call. Intent safety asks whether the call advances the user's real mandate. A fully authorized but economically harmful action can pass unless trusted policy encodes that intent.

## 16. What would you change for distributed production?

Move approvals, idempotency, aggregates, and resource state into transactional durable services; use strong identity/workload credentials, distributed locking or serializable transactions, external audit anchoring, recovery semantics, and operational policy management.

## 17. How would you integrate this with MCP?

Treat MCP servers, descriptions, and outputs as untrusted. Wrap each protected MCP tool behind the gateway, derive identity and grants from the trusted host, normalize arguments, and never let MCP content grant authority.

## 18. What would change for a real exchange?

Add exchange-specific asset/order semantics, reconciliation, fees/slippage, rate limits, durable transaction and retry models, key custody, account segregation, incident controls, compliance review, and extensive fault testing. The sandbox result cannot be carried over as certification.

## 19. Why is Phase 9 not independent validation?

The fixes were informed by Phase 8 scenarios, so replay measures regression against known cases. It cannot support a new generalization claim.

## 20. What is the strongest evidence that the architecture generalized?

Phase 10: 40 newly designed frozen adversarial cases and 16 benign workflows, with a recorded dataset digest, production-code freeze, preserved invalid evaluator attempt, and 0/40 attacks in the first technically valid complete run. The claim remains local and scoped.
