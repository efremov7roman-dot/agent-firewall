# Phase 10 claims audit

| Claim | Classification | Evidence and required scope |
| --- | --- | --- |
| Model proposals cannot grant themselves authority | SUPPORTED | Identity, missing-grant, wrong-grant, action and environment cases blocked; host construction of context remains trusted. |
| Local principal/environment resource isolation | SUPPORTED | Foreign order cancellation and environment crossover blocked; own/delegated cancellation worked. This does not establish multi-host isolation. |
| Least-privilege capability constraints | SUPPORTED | Symbol, amount, action, environment, expiration, and destination probes blocked; boundary-valid actions worked. |
| Complete mediation of agent-facing tools | PARTIALLY SUPPORTED | All tested calls went through the gateway. Architecture and public API support this local route, but this benchmark cannot prove every possible host integration uses it. |
| Single-use, action-bound approval | SUPPORTED | Exact approved actions worked; changed amount, destination, principal, and failed-action reuse did not execute. Cross-process atomicity was not independently measured here. |
| Idempotency prevents duplicate local effects | SUPPORTED | Same-key changed operations conflicted; exact benign retry replayed. Durability across gateway restart is outside this claim and not measured. |
| Aggregate controls limit cumulative local spend | SUPPORTED | Order, transfer and mixed-operation budget cases blocked overspend; failed operations did not consume budget. This is gateway-local accounting. |
| Destination restriction | SUPPORTED | Explicit and default destination probes blocked while allowed destination executed. |
| Audit integrity | PARTIALLY SUPPORTED | No adverse state change lacked normal gateway events in the examined run, and implementation hashes standard events. This run did not test tampering or recorder failure. Hash chaining does not prevent truncation. |
| Prompt-injection resistance | PARTIALLY SUPPORTED | Deterministic authorization of scripted malicious proposals is supported. Live-model susceptibility and semantic intent were not measured. |
| Fail-closed behavior | PARTIALLY SUPPORTED | Malformed, unknown-resource, missing-grant, wrong-scope, and approval-wait cases failed safely. Fault injection and crash boundaries were not tested in this dataset. |
| Zero-trust runtime security | PARTIALLY SUPPORTED | The model-facing boundary is treated as untrusted in tested paths. Host, identity provider, policy/grant store, approval authority, and software supply chain are explicitly trusted. |

No current README or security-documentation statement must be removed on the basis of an observed Phase 10 failure. Any use of “zero-trust,” “complete mediation,” “prompt-injection resistance,” “audit integrity,” or “fail-closed” without the local trusted-host and tested-boundary qualifiers would overstate this evidence. The current README largely includes those qualifiers. The Phase 9 regression numbers are development evidence, not independent post-hardening validation.
