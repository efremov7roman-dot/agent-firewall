# Phase 9 Root-Cause Analysis

## Evidence basis

Phase 9 is informed by the frozen Phase 8 audit. Phase 8 evidence was not edited and its
dataset was not relabelled. Post-hardening execution of that dataset is a regression run,
not a second independent validation.

## Root causes

### RC-01: authority stopped at the tool boundary

Capabilities selected a tool and checked caller-supplied arguments, but protected state
did not carry an authoritative owner/environment. An order ID was treated as sufficient
input for cancellation, and balances/positions were one shared namespace. Consequently,
the policy could answer “may this agent call cancel_order?” but not “may this principal
cancel this owner’s ETH order in this environment?”

### RC-02: local synchronization was mistaken for global approval consumption

`ApprovalManager` guarded in-memory state with an instance lock. Two instances could load
the same APPROVED record and each transition its private copy to CONSUMED. The action
digest also omitted principal and environment, so the approval subject was incomplete.

### RC-03: financial commands had no logical request identity

`trace_id` and provider `call_id` were correlation data, not enforced idempotency keys.
Retries and cross-turn duplicate calls therefore created new side effects.

### RC-04: limits were stateless and destination-blind

Per-action amounts were exact, but successful actions did not consume an authoritative
per-principal aggregate budget. Transfer authority also lacked a deterministic trusted
destination policy. Individually valid calls could therefore compose into an excessive
or misdirected outcome.

### RC-05: audit objects and redaction were shallow

In-memory recorders retained shared nested objects. Redaction depended on a limited key
fragment list and traversed dictionaries/lists but not tuples. JSONL events had no
detectable linkage. Finally, sandbox mutation and terminal audit append were two separate
operations, so a recorder failure after execution could not be rolled back.

### RC-06: authorization and semantic intent were conflated in claims

Deterministic policy can enforce identity, ownership, scope, amount, destination, expiry,
approval, and stateful limits. It cannot generally determine that a fully authorized
owner action was maliciously induced without a separate trusted mandate. The previous
wording did not always keep that boundary explicit.

## Finding mapping

| Phase 8 finding | Root cause |
| --- | --- |
| HIGH-01 principal/resource isolation | RC-01 |
| HIGH-02 multi-instance approval replay | RC-02 |
| HIGH-03 audit weaknesses | RC-05 |
| MEDIUM-01 cancellation symbol scope | RC-01 |
| MEDIUM-02 idempotency | RC-03 |
| MEDIUM-03 approval context binding | RC-02 |
| MEDIUM-04 aggregate/destination/intent | RC-04 and RC-06 |
