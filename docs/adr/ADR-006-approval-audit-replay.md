# ADR-006: action-bound approvals and replayable audit

## Status

Accepted in Phase 5.

## Context

A model-generated assertion that a human approved an action is not trustworthy. Generic
or reusable approval tokens can authorize modified amounts, different tools, another
agent, or replay. Operational diagnosis also requires the exact deterministic inputs and
outcome without storing private model reasoning.

## Decision

Approval records are controlled by an authority allowlist and bind a SHA-256 digest of
agent ID, tool name, and policy-normalized arguments. Records expire and move through
`PENDING`, `APPROVED`, `REJECTED`, `CONSUMED`, or `EXPIRED`; approval is consumed once,
before execution.

The execution gateway emits typed, correlated lifecycle events through a pluggable audit
recorder. A pre-execution `AUTHORIZED` event is mandatory before a side effect. JSONL is
the local persistent implementation. Replay reconstructs only the deterministic policy
decision from the recorded request and security context and never invokes a tool.

## Consequences

Argument changes, agent substitution, expiry, and reuse fail closed. Developers can
inspect historical decisions and detect policy drift without chain-of-thought. Consuming
before execution favors replay safety over retry convenience. Local files do not provide
concurrency control, transactional execution coupling, or tamper evidence; a production
deployment must replace these adapters without changing the gateway contract.
