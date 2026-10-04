# Portfolio summary

## Problem

Tool-using AI agents turn generated text into side effects. A prompt, retrieved document,
or tool response can influence the model, so the model cannot safely be the authority
that decides whether its own proposed action is permitted. Prompt instructions alone do
not bind identity, resource ownership, amount, destination, approval, or cumulative state.

## Solution

Agent Firewall is a deterministic runtime authorization layer between an AI agent and a
local financial sandbox. The agent may propose a call, but a trusted execution gateway
validates its schema and host-bound identity, resolves stored resource ownership,
evaluates scoped capabilities and policy, applies idempotency and aggregate constraints,
verifies exact-context human approval where required, and records the outcome. The LLM
never becomes the authorization authority.

## Engineering depth

The system is more than an LLM wrapper: it models principals, environments, owned
resources, constrained capabilities, approval lifecycles, destination allowlists,
cumulative budgets, deterministic failure behavior, and hash-chained local audit events.
Tests cover unit, integration, property, concurrency, approval replay, resource isolation,
audit behavior, and evaluation invariants. The core demo and benchmarks are deterministic
and need no paid API.

## Evaluation

The engineering story includes failure. An initial 24-scenario development benchmark
looked promising at 3/24 successful attacks. A separately designed Phase 8 blind review
then broke the architecture: 17/26 attacks succeeded, revealing missing ownership,
cross-instance approval, idempotency, aggregate, destination, and audit controls. Those
results remain public. Phase 9 addressed root causes instead of matching attack strings;
reusing the known Phase 8 set is correctly labeled regression evidence.

Phase 10 froze a second independent dataset before execution. Its first technically valid
complete local run observed 0/40 successful adversarial scenarios, 0/45 unauthorized
executed actions, 16/16 successful benign workflows, and 0/20 false blocks. This is the
strongest evidence that the hardened design generalized within the tested boundary.

## Limitations

The result is not universal security or production certification. Live-model semantic
influence, capability-valid malicious intent, multi-host coordination, distributed
approvals, crash-consistent financial/audit transactions, real exchanges and funds,
malicious trusted hosts or administrators, compromised identity providers, and external
audit anchoring remain outside scope. Local hash chaining detects content modification
but cannot prevent record deletion or truncation.
