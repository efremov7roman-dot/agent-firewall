# Phase 6 security hardening and reliability (historical)

## Hardening coverage

Phase 6 concentrates on bypass resistance rather than new product features. The automated
suite now covers:

- generated malformed raw requests and amounts above exact `Decimal` limits;
- zero, negative-zero, NaN, and infinite monetary representations;
- Unicode-confusable symbols that must not match ASCII capability scope;
- unknown tools, duplicate grants, expired capabilities, approval reuse, changed actions,
  backdated/naive approval clocks, and mutation attempts by an approval adapter;
- complete policy-engine failure and mandatory pre-execution audit failure;
- concurrent transfers, balance oversubscription, approval consumption, unique IDs, and
  JSONL writes from threads.

The gateway deep-copies request/context inputs and the objects supplied to approval
adapters. A policy implementation that raises is converted to deterministic `DENY / P10 /
POLICY_EVALUATION_ERROR`. The sandbox, approval manager, and audit recorder use re-entrant
locks to make transitions atomic within one process.

## Development performance profile

Command:

```powershell
.\.venv\Scripts\python.exe -m agent_firewall.hardening `
  --iterations 5000 --warmup 250 `
  --output experiments\hardening_performance.json
```

Observed on Python 3.12.14, Windows 11 build 26200, using one process and an authorized
in-memory `get_portfolio` workload:

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| Direct policy decision | 0.0052 ms | 0.0056 ms | 0.0059 ms |
| Gateway end-to-end | 0.0629 ms | 0.0958 ms | 0.1359 ms |

Measured gateway throughput was 13,409.8 requests/second for the same 5,000-request run.
These values are a local development measurement, not a cross-machine performance claim
or the frozen Phase 7 benchmark. The generated JSON artifact contains exact metadata,
sample count, warm-up count, and unrounded throughput.

## Residual limitations

- The deterministic firewall enforces declared authority, not semantic user intent. An
  unwanted action inside a valid capability may still execute.
- Limits are per request. Aggregate spend, velocity, rate, and rolling-window controls are
  not implemented; this is visible in the A07 benchmark failures.
- In-process locking does not coordinate separate processes or hosts. JSONL and approval
  files are not signed, encrypted, or tamper-evident.
- Sandbox mutation and the final `EXECUTED` audit event are not a transactional commit. A
  post-execution audit failure is reported but cannot roll back the side effect.
- A consumed approval is not restored after tool failure, favoring replay safety over
  retry convenience.
- The performance profile is single-threaded, in-memory, synthetic, and host-specific; it
  does not represent network, durable storage, model, or distributed-system latency.
- There are no real exchange connections, real credentials, or production funds.

These were the Phase 6 limits at the time of measurement. Phase 9 subsequently added
principal-owned resources, local cross-instance approval consumption, idempotency,
aggregate budgets, destination scope, and detectable audit hash chains. Current design
and measurements are in `docs/security-hardening/`; the semantic-intent and terminal
audit atomicity limitations remain.
