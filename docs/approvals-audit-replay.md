# Approvals, audit, and replay

## Approval lifecycle

For a `REQUIRE_APPROVAL` decision, `ApprovalManager.check` creates or finds a pending
record. The record binds the requesting agent, principal, environment, tool, normalized
arguments, policy reason, request time, and expiry through a canonical SHA-256 action digest. Only an explicitly
allowlisted authority may approve or reject it. The next exact request consumes an
approved record before execution; consumed, rejected, changed, cross-agent, and expired
records cannot authorize execution.

The gateway never accepts approval claims from prompts, model output, or tool arguments.
Its safe default is `DenyAllApprovalVerifier`. A file-backed manager rewrites a typed JSON
ledger after each transition so local developer runs can survive process restarts.
An exclusive lock file, authoritative reload, and atomic replacement make consumption
single-use across manager instances sharing that local filesystem.

## Audit lifecycle

Each terminal denial, approval wait, failure, and successful execution produces a typed
event. Allowed execution has two correlated events: `AUTHORIZED` is recorded before the
side effect and `EXECUTED` afterward. If the mandatory pre-execution write fails, the
tool does not run. If the final write fails after a side effect, the result carries
`AUDIT_RECORDING_FAILED`; the earlier authorization event remains available.

Events contain the request and security context required for replay, normalized
arguments, required capability, matched policy, decision/reason, approval state,
decision latency, and execution status. Current tool schemas contain no credentials and
unknown arguments are rejected. Standard recorders deep-copy event values, recursively
redact sensitive key classes, and chain canonical event payloads with SHA-256. Model
chain-of-thought is never recorded.

## Replay and inspection

`DecisionReplay` re-evaluates the recorded request and context with a supplied or current
policy engine, compares the complete typed decision, and reports whether the historical
event represented execution. A mismatch is useful evidence of policy/configuration drift;
replay never re-executes the tool.

The `agent-firewall` CLI offers four read-only commands: `audit`, `denied`, `replay`, and
`approvals`. Output is stable JSON suitable for developer inspection or piping to other
local tools.

## Known limitations

- Approval consumption is coordinated on one local filesystem, not across hosts or
  eventually consistent replicas.
- Audit chain verification detects content modification but cannot prevent deletion or
  truncation. Stores are not encrypted, signed, remotely attested, or access-controlled.
- Audit and sandbox mutation are not one transactional commit.
- The approval is consumed before tool execution, so a failed tool needs a new approval.
- `policies_evaluated` records the decisive policy path exposed by the current engine,
  not an internal step-by-step reasoning trace.
- Retention, access control, external identity proof, and high-availability storage are
  deployment responsibilities outside this local sandbox phase.
