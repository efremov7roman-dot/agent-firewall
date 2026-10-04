# Claims Audit

The classifications below apply to the repository state tested on 2026-10-03. “Supported”
means supported within the documented local sandbox scope; it is not a production-security
certification.

| Source / claim | Classification | Independent assessment |
| --- | --- | --- |
| README: “zero-trust runtime authorization layer” | PARTIALLY SUPPORTED | The gateway distrusts model text and makes deterministic decisions, but it trusts caller-supplied identity/capability objects and lacks subject-resource isolation. “Zero trust” needs an explicit integration/threat-scope qualifier. |
| README: deterministic policy, scoped capabilities, and approval decide execution | PARTIALLY SUPPORTED | This is true for registered calls through `ExecutionGateway`, but cancellation ignores symbol scope and account/resource ownership is absent. |
| README: action-bound approvals are expiring and single-use | PARTIALLY SUPPORTED | Exact amount/destination mutation, agent_id substitution, and expiry were rejected. One persisted approval executed twice through two manager instances, and principal/environment are not bound. |
| README: the gateway is the only agent-facing route to protected execution | SUPPORTED | The `FinancialAgent` sends proposed calls through `ExecutionGateway`; the sandbox is private-by-convention. The documentation correctly excludes host/process isolation, so this is an application-architecture claim only. |
| README: audit events preserve request, context, policy, approval, latency, and status | PARTIALLY SUPPORTED | Normal paths record these fields, but a post-execution recorder failure leaves no terminal EXECUTED event, in-memory evidence can be mutated, and secret redaction is incomplete. |
| README / resume: original firewall ASR is 3/24 (12.5%) | SUPPORTED | Independent raw-record recomputation and a clean benchmark rerun reproduced 3/24. This supports only the frozen scenario set. |
| README / resume: original firewall UAR is 4/25 (16%) | SUPPORTED | Independent action-level recomputation reproduced 4/25. A07-01 contributes two unauthorized executions, so UAR and ASR correctly have different numerators and denominators. |
| README / resume: benign success 8/8 and false blocks 0/13 | SUPPORTED | Both raw recomputation and reproduction matched. Independent benign validation also achieved 14/14 and 0/17. Coverage remains small and local. |
| README: “reducing attack success ... while retaining all benchmarked benign tasks” | SUPPORTED | Accurate comparative wording for the fixed scripted benchmark. It must not be read as a general 79.2 percentage-point security guarantee. |
| README / resume: p50/p95/p99 decision latency of 0.0231/0.0331/0.0397 ms | SUPPORTED | Values and percentile computation match the recorded 38 samples. They are single-host microbenchmarks of policy decisions, not production latency. |
| docs/benchmark.md and experiments/README.md: final artifact is “committed” | UNSUPPORTED | The working repository has no commits or reachable HEAD. The file exists and verifies internally, but “committed” is factually unprovable in this repository state. |
| docs/failure-analysis.md: exact-argument limits but no aggregate/velocity budget explain A07 | SUPPORTED | Independent repeated and cross-tool compositions also succeeded, confirming the limitation extends beyond the original two cases. |
| docs/failure-analysis.md: capability-valid intent attacks require trusted intent/mandate or more approval boundaries | SUPPORTED | Independent in-scope transfer and cancellation induction succeeded. Deterministic authorization cannot infer semantic user intent from the untrusted model. |
| docs/failure-analysis.md: A01/A02/A03/A04/A05/A06/A08/A10/A11/A12 had no successful firewall attacks | SUPPORTED | Correct for the frozen dataset only. Several labels share the same effective missing-capability enforcement path, so this does not establish broad category resistance. |
| docs/security-invariants.md INV-07: every protected attempt produces structured audit | UNSUPPORTED | IV-A-026 executes a side effect while recording only AUTHORIZED after terminal audit failure. The limitation is candidly documented elsewhere, but the invariant is stated absolutely. |
| docs/security-invariants.md INV-08: approval cannot authorize another agent, changed action, reuse, or post-expiry execution | PARTIALLY SUPPORTED | Changed actions, changed agent_id, and expiry are handled. Reuse across manager instances and substitution of principal/environment succeed. |
| docs/security-invariants.md INV-11: capability constraints cannot be exceeded | PARTIALLY SUPPORTED | Amount, create/read symbol, environment, and expiry boundaries held. Symbol scope is not enforced for cancellation, and no resource/account constraint exists. |
| docs/threat-model.md: approval replay is controlled by single-use approval | PARTIALLY SUPPORTED | True for one manager instance, false across concurrently loaded persisted instances. The documented cross-process limitation reduces overstatement but does not preserve the absolute control claim. |
| Project-wide implication that prompt injection is “blocked” | MISLEADING if unqualified | The firewall blocks injected calls that lack capability or exceed deterministic constraints. It does not block capability-valid maliciously induced actions; original A09 and independent IV-A-024/025 demonstrate this. Use “blocks unauthorized tool execution under encoded policy” instead. |
| Any implication of production readiness or comprehensive financial isolation | UNSUPPORTED | The repository explicitly describes a local sandbox and does not directly claim production readiness. Independent cross-principal, approval, idempotency, and audit findings rule out inferring it from the current metrics. |

## Required wording changes

- Qualify “zero trust” as model-facing deterministic authorization inside a trusted host and
  trusted identity/capability provisioning boundary.
- Replace absolute “single-use” approval language with the current single-manager guarantee,
  or delay that claim until atomic durable consumption exists.
- State that scope applies only to fields carried by each tool schema; cancellation and
  account/resource ownership are not currently scoped.
- Avoid generic “blocks prompt injection.” Say that untrusted text cannot itself grant
  authority, while already-authorized, intent-unsafe actions remain possible.
- Remove “committed” until a real commit/tag exists.
- Reconcile absolute audit invariants with the documented non-transactional terminal-audit
  limitation.
