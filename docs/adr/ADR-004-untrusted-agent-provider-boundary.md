# ADR-004: Providers propose actions; trusted runtime identity and gateway authorize them

- Status: Accepted
- Date: 2026-10-02

## Context

An LLM can misunderstand direct instructions, follow malicious external content, emit
malformed arguments, or claim a privileged identity. Provider-specific APIs must not
leak into the security kernel or create alternate execution paths.

## Decision

Use a vendor-neutral session protocol returning typed, explicitly untrusted tool
proposals. `FinancialAgent` obtains identity only from `SecurityContext`, bounds its
tool loop, and sends every proposal to `ExecutionGateway`. Tool results returned to a
provider remain classified as untrusted. Keep deterministic/scripted providers for all
core tests and implement the optional real provider as a Responses API adapter.

## Consequences

The same security kernel protects deterministic and real-model runs. Provider failures
terminate the agent run without granting access. Prompt-injection resistance does not
depend on the system prompt: an influenced model may still propose an attack, but the
gateway enforces identity, schema, capability, scope, limits, and approval independently.

