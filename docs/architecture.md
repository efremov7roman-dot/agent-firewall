# Architecture

## Local LLM orchestration and evaluated boundary

The local `OllamaProvider` uses native `/api/chat` function proposals. A
`LangGraphFinancialAgent` StateGraph has agent, authorization, execution,
recovery, and advance nodes. The graph treats model calls and tool outputs as
untrusted. Its only protected execution path is `ExecutionGateway.execute`,
which resolves stored resources and enforces current host-supplied context,
policy, approval, idempotency, audit, and sandbox execution. The graph has no
side-effecting checkpoint resume; repeat invocations use stable trace/call
ordinals so the same gateway can replay a result without repeating a mutation.

The provider now validates the parsed loopback hostname and rejects redirects.
The graph checks deadlines after model responses as well as before calls. A
blocking model request remains bounded by the provider timeout. The trusted
Python process can still import the internal sandbox, and gateway idempotency
is process-local. See [live adversarial validation](live-v2-validation.md) for
the frozen local-model experiment and those scope limits.

## System and trust boundary

Agent Firewall is a local modular monolith around tool execution. The LLM, prompts, retrieved content, tool output, and every proposed call are untrusted. The host-provided identity, capability/policy configuration, approval authority, gateway process, and local sandbox are trusted within the evaluated boundary.

```text
UNTRUSTED                                  TRUSTED LOCAL BOUNDARY
user/content -> agent -> ToolRequest ----> ExecutionGateway
                                             | validate identity + schema
                                             | resolve stored resource/owner
                                             | evaluate capability + policy
                                             | apply destination/idempotency/aggregate state
                                             | verify or request bound approval
                                             | append mandatory pre-execution audit
                                             v
                                      FinancialSandbox mutation
                                             |
                                             v
                                      terminal audit event
```

No model output is accepted as identity, policy, or approval. Complete mediation is a property of supported integrations that route protected tools through the gateway; a malicious trusted host can bypass the Python boundary and is out of scope.

## Components

| Component | Responsibility | Trust / authority |
| --- | --- | --- |
| Agent/provider adapters | Normalize proposed calls | Untrusted; no authority |
| Host security context | Supply agent, principal, environment, clock, grants | Trusted input |
| Tool registry and schemas | Bind known tools to strict arguments | Trusted configuration |
| Resource resolver | Load actual object ownership and attributes | Trusted gateway step |
| Capability evaluator | Match identity, action, resource, amount, destination, expiry | Deterministic authority check |
| Policy engine | Return `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` | Deterministic policy |
| Stateful controls | Enforce local idempotency and aggregate budgets | Local in-process state |
| Approval manager | Bind and consume exact-context approvals | Trusted local authority |
| Execution gateway | Orchestrate checks and fail closed | Sole supported execution path |
| Audit recorder | Persist redacted decision/execution evidence | Observability; not authority |
| Financial sandbox | Simulate protected financial effects | Local deterministic state; no funds |

## Principal and resource model

`AgentIdentity` binds an agent ID to a principal and environment. Sandbox state is partitioned by principal/environment. For indirect actions such as cancellation, the gateway resolves the stored object before evaluation and authorizes against its actual owner and attributes. Delegation must be explicit through resource-principal scope.

## Capability and policy model

Capabilities name an operation and bind it to an agent. Constraints can narrow symbols, actions, amounts, destinations, principals, environment, resources, and expiry. The evaluator intersects applicable grants; it does not let model text expand them. Policy adds deterministic conditions such as approval thresholds. Unknown tools, malformed values, missing grants, mismatched identity, expired grants, and policy errors deny by default.

## Approval lifecycle

An approval record binds the normalized action to agent, principal, environment, tool, arguments, lifetime, and authority. Pending records do not execute. A permitted human authority may approve or reject them. Execution atomically consumes a matching approved record under a local cross-process file lock; changed context requires a different approval. Exact repeated requests are handled safely through idempotent replay.

This design assumes one shared local filesystem. It is not a distributed consensus or transactional approval service.

## Execution, stateful controls, and audit

The gateway validates, resolves, authorizes, and writes a mandatory pre-execution event before calling the sandbox. Per-principal/environment aggregate accounting and idempotency are updated under local synchronization. Standard audit recorders redact and deep-copy data and add a SHA-256 chain. A pre-execution audit failure denies without mutation; a terminal audit failure after mutation cannot roll back the sandbox.

The chain makes content edits detectable when the trusted chain head is retained. It does not provide encryption, signatures, remote attestation, access control, or deletion/truncation prevention.

## Fail-closed behavior

Schema, identity, capability, resource, destination, amount, approval, policy, and mandatory pre-audit failures all prevent protected execution. An expected sandbox business failure is reported as failed execution rather than authorization success.

## Deployment boundary and limitations

- Aggregate and idempotency state are local; multi-host coordination is absent.
- Approval persistence relies on a shared local filesystem.
- Sandbox mutation and terminal audit append are not one crash-consistent transaction.
- The trusted host constructs important security context.
- Live-model semantic intent, real exchanges/funds, hostile administrators/hosts, compromised identity providers, and external log anchoring are not established.

See [the threat model](threat-model.md), [evaluation guide](evaluation.md), and [Phase 9 hardening design](security-hardening/hardening-design.md).
