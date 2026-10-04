# Phase 9 Hardening Design

## Authorization model

The trusted execution path now evaluates:

`identity → capability → action → resolved resource → constraints → current state`

Sandbox accounts are partitioned by `(principal, environment)`. Orders and transactions
carry authoritative owner/environment metadata. Portfolio and open-order reads select
only the caller’s partition. `cancel_order` resolves the order before mutation and checks
its stored owner, environment, and symbol; caller arguments cannot assert these values.
An explicit `allowed_resource_principals` grant supports deliberate delegation.

## Capability and local policy constraints

Phase 9 adds runtime constraints for:

- allowed resource principals;
- allowed destinations;
- cumulative financial amount.

These fields are deliberately excluded from serialization of the frozen Phase 4 scenario
models so its SHA-256 remains unchanged. Runtime audit decisions still expose the matched
policy and result. New deployments should set explicit destination and aggregate scopes;
the local sandbox has a small default trusted-destination set for backward-compatible
sample workflows.

If no explicit aggregate value exists, a configured per-action order/transfer maximum is
used as a conservative cumulative budget for the gateway lifetime. The gateway lock
serializes aggregate check, sandbox mutation, and budget commit, preventing check/use
races inside the local process.

## Approval lifecycle

The action digest now includes agent ID, principal, environment, tool, and canonical
normalized arguments. File-backed transitions use an exclusive lock file plus atomic
ledger replacement. Every check reloads authoritative persisted state while holding that
lock, so independently loaded managers cannot both consume one approval.

This is a defensible local-filesystem mechanism, not a distributed consensus protocol.
Networked/multi-host deployment requires a transactional shared store.

## Idempotency

Every state-changing request has a logical idempotency identity scoped by agent,
principal, and environment. `ToolRequest.idempotency_key` is explicit; the agent adapter
uses provider `call_id`. Direct gateway calls fall back to a digest-scoped trace identity.

- exact retry: returns `REPLAYED` with the prior result and performs no side effect;
- same explicit key with different action/arguments: `DENY / IDEMPOTENCY_CONFLICT`;
- different key: treated as a new operation and evaluated normally.

The in-memory store is atomic within one gateway. Production durability requires moving
the same compare/store semantics to the authoritative transaction store.

## Destination and aggregate policy

Transfers and withdrawals resolve their destination field from normalized arguments.
An explicit capability allowlist overrides the local sandbox defaults; any other
destination is denied by P14. P15 checks cumulative order/transfer amount for the current
principal/environment before the side effect and commits usage under the same gateway
lock.

## Audit guarantees

Standard recorders now:

- deep-copy on record and read;
- recursively redact dictionaries, lists, and tuples, including `access_key`;
- chain events with SHA-256 over the previous hash and canonical event payload;
- expose integrity verification;
- record authorization before every permitted side effect and a terminal event on normal
  success/failure paths.

The chain detects modification but does not prevent deletion/truncation by a host
attacker. Files are not encrypted, signed, remotely attested, or access-controlled by
this package. A deliberately failing recorder after sandbox commit can still omit the
terminal event; the returned result reports `AUDIT_RECORDING_FAILED`. This local
non-transactional limitation is stated rather than hidden.

## Complete mediation map

```text
FinancialAgent / direct trusted caller
  → ToolRequest (call_id/idempotency identity)
  → ExecutionGateway lock
  → schema + identity + capability policy
  → authoritative resource resolution and owner/symbol/environment policy
  → destination + idempotency + aggregate-state policy
  → approval check/atomic consume when required
  → pre-execution AUTHORIZED audit
  → principal-partitioned _FinancialSandbox mutation/read
  → aggregate/idempotency commit
  → terminal audit/result
```

`FinancialAgent` has no alternate tool executor. `_FinancialSandbox` remains private and
is used directly only by intentionally unprotected benchmark baselines inside the trusted
evaluation package.

## Invariant mapping

| Finding | Invariant | Generalized defense |
| --- | --- | --- |
| HIGH-01 | INV-13 | Principal/environment partitions and authoritative resource ownership |
| HIGH-02 | INV-14 | File-locked reload/compare/consume and atomic replacement |
| HIGH-03 | INV-17 | Recursive minimization, deep copies, hash chain, precise atomicity claim |
| MEDIUM-01 | INV-15 | Resolve order then check actual owner/environment/symbol |
| MEDIUM-02 | INV-16 | Explicit logical keys, replay result, conflict denial |
| MEDIUM-03 | INV-14 | Principal/environment added to approval record and digest |
| MEDIUM-04 | INV-18/19 | Atomic cumulative budgets and destination allowlists; intent limit documented |
