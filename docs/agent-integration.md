# Agent and model-provider integration

## Authorization boundary

`FinancialAgent` is an orchestration loop, not an authorization authority. It constructs
the runtime `agent_id` from trusted `SecurityContext`; a provider can supply only a tool
name and arguments. Every proposal becomes a `ToolRequest` and crosses
`ExecutionGateway`. Model text, user instructions, external content, and tool output
cannot create capabilities or approvals.

The loop is bounded. If a model emits more calls than the configured limit, the entire
excess turn is rejected before any call in that turn executes. Each call in an allowed
multi-tool turn is evaluated independently.

## Trust classification

| Value | Meaning |
| --- | --- |
| `TRUSTED_SYSTEM` | Application-owned security instruction or configuration |
| `UNTRUSTED_USER` | Direct user task; expresses intent but not authorization |
| `UNTRUSTED_EXTERNAL` | Page/document/retrieved content; data only |
| `UNTRUSTED_MODEL` | Model-proposed tool call |
| `UNTRUSTED_TOOL` | Tool/gateway result returned to the model |

External content is framed separately from the direct user instruction. The
deterministic provider never interprets external content as a command. The real-model
system instruction explicitly says embedded external instructions are data, while the
gateway remains the authoritative defense if the model proposes an unsafe call anyway.

## Providers

- `ScriptedProvider`: exact predefined turns for security and integration tests.
- `DeterministicFinancialProvider`: local parser for price, portfolio, order, cancel,
  withdrawal, and open-order demonstrations.
- `OpenAIResponsesProvider`: optional standard-library adapter for the OpenAI Responses
  API. It declares seven function tools and returns gateway results with
  `function_call_output`. API key and model are always explicit environment inputs.

The real provider follows the official OpenAI function-calling flow documented at
<https://developers.openai.com/api/docs/guides/function-calling>. Network/API tests are
not part of the default suite; the transport is mocked so local verification is free and
deterministic.

MCP is intentionally not added in Phase 3. It would introduce another transport without
strengthening the current authorization proof; a future MCP adapter must terminate at
the same gateway and cannot expose the sandbox directly.

