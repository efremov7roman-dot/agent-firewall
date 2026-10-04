# Threat model

## Assets

- Authorization integrity: only explicitly permitted protected actions execute.
- Principal-owned balances, positions, orders, and transaction state.
- Capability, policy, approval, idempotency, and aggregate-control integrity.
- Audit confidentiality, integrity, and useful decision/execution evidence.
- Frozen evaluation datasets, fingerprints, and results.

## Trust assumptions

The host correctly supplies identity, principal, environment, time, capabilities, policy, and approval authority. Protected integrations call tools through `ExecutionGateway`. The local process, filesystem permissions, dependencies, and administrator are trusted. The sandbox contains no real credentials or funds.

## Adversaries

An attacker may control user prompts, retrieved documents/webpages, MCP or tool output, and model-generated tool names and arguments. They may induce the model to ignore the user, compose actions, retry requests, alter representations, target another principal, or attempt approval reuse. They do not initially control the trusted host, policy store, identity provider, approval authority, or administrator.

## Attack surfaces

| Boundary | Representative attacks | Deterministic controls |
| --- | --- | --- |
| Content → model | Direct/indirect prompt injection | Content never confers authority |
| Model → gateway | Unknown tool, malformed fields, identity substitution | Registry, strict schemas, host-bound identity |
| Gateway → resource | Caller-described ownership, cross-principal cancellation | Stored-resource resolution and ownership scope |
| Capability/policy | Expiry, amount/symbol/action confusion, fail-open errors | Exact typed constraints, trusted clock, default deny |
| Stateful execution | Duplicate calls, split limits, destination abuse | Idempotency, aggregate budgets, allowlists |
| Approval | Forgery, context substitution, replay | Authority allowlist, exact binding, expiry, atomic consumption |
| Audit | Secret leakage, object mutation, record editing | Redaction, deep copy, mandatory pre-audit, hash chain |

## Security properties

Within the trusted local boundary, the system attempts to guarantee that every supported protected action is mediated; model text cannot create authority; resource authorization uses stored ownership; applicable constraints and approvals bind to the executed action; duplicate/split actions respect local state; failures deny before mutation where possible; and standard audit-record content changes are detectable.

## Semantic intent is different

**Semantic-intent safety is not deterministic authorization safety.** The firewall can show that a capability permits a call. It cannot infer that an otherwise authorized call matches the user's current economic intent unless a trusted mandate expresses that intent as policy or constraints.

## Out of scope

- Live-model susceptibility rates or universal prompt-injection prevention.
- Arbitrary malicious intent that remains inside valid capabilities.
- Malicious trusted host, dependency, administrator, or policy configuration.
- Compromised identity provider or approval authority.
- Multi-host state and distributed approval persistence.
- Production exchange behavior, real-money safety, compliance, or certification.
- External audit anchoring, deletion-proof retention, or remote attestation.

## Known limitations

Aggregate/idempotency state is local. Approval persistence assumes a shared local filesystem. Sandbox mutation and terminal audit append are not one transaction. Hash chaining detects content modification but cannot prevent deletion/truncation. Important security context is constructed by the trusted host. These limits are deployment boundaries, not hidden guarantees.
