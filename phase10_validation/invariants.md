# Independently derived Phase 10 invariants

1. Each protected side effect requires a matching runtime agent identity and a currently valid grant for its exact tool, principal, environment, and applicable resource and argument constraints.
2. A stored resource's authoritative owner, environment and symbol govern indirect actions; caller metadata cannot replace them.
3. The normalized action authorized and approved is the action executed, including amount, destination and resource identity.
4. A required approval authorizes one exact action in one lifecycle and must be valid at the moment of execution.
5. Reordering, retrying or changing a request key cannot create an additional side effect beyond currently authorized risk.
6. Stateful spending controls account for every executed operation they claim to govern, including across operation types and retries, within the stated principal/environment scope.
7. Errors in policy, resource lookup, approval, persistence or pre-execution audit do not permit an unauthorized side effect.
8. Every actual protected mutation has accurate terminal evidence when the standard recorder functions; audit limitations must be represented honestly.
9. Separate principals and environments cannot read or change each other's protected state without explicit delegated scope.
10. Narrowing any grant dimension cannot enlarge authority in another dimension.
11. Legitimate operations at valid boundaries remain usable, including approval, retries, and multi-step workflows.

The host-provided identity, grants, clock, policy configuration and approval authority are trusted inputs. A caller that controls them is outside the intended model-facing threat boundary.
