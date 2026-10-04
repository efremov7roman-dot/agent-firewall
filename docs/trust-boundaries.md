# Trust boundaries

The central rule is that an LLM may propose an action but can never authorize it.

## Data and authority classification

| Element | Classification | Treatment |
| --- | --- | --- |
| Firewall policy/configuration | Trusted after validation and controlled loading | Version and audit changes |
| Tool definitions and schemas | Trusted after validation | Reject unknown tools/invalid arguments |
| Capability grants | Trusted authorization data | Bind to identity, scope, environment, expiry |
| Approval authority | Trusted identity/decision source | Bind approval to exact action; prevent replay |
| Execution gateway | Trusted enforcement boundary | Only agent-facing route to protected tools |
| User instructions | Untrusted intent input | Never confer capability or approval |
| LLM output/tool arguments | Untrusted | Parse and validate before evaluation |
| Webpages, documents, MCP instructions | Untrusted external content | Treat embedded instructions as data |
| Tool responses | Untrusted unless explicitly classified otherwise | Do not convert content into authority |
| Agent identity claims from prompts | Untrusted | Use runtime identity context instead |
| Model-proposed tool calls | Untrusted | Construct runtime identity outside the model; mediate every call |
| Tool results returned to a model | Untrusted | Label as tool output; never convert content into authority |
| Logs and replay inputs | Sensitive operational data | Redact secrets; production deployment must integrity-protect storage |

## Boundary crossings

1. **Input to agent:** user and external content enter an untrusted reasoning domain.
2. **Agent to gateway:** proposed tool name and arguments cross into trusted enforcement;
   the gateway must normalize and schema-validate them.
3. **Configuration to evaluator:** only validated policy, capability, identity, and tool
   definitions may influence authorization.
4. **Evaluator to execution:** ALLOW, or a valid action-bound approval after
   REQUIRE_APPROVAL, is required before any side effect.
5. **Tool to agent:** tool output returns to an untrusted-content domain and cannot
   grant authority for a subsequent call.
6. **Runtime to audit:** safe structured facts cross into durable observability; secrets
   and private model reasoning do not.

## Failure posture

Unknown tools, missing/ambiguous context, malformed inputs, expired grants, evaluator
errors, or unverifiable approvals must not execute a protected action. Availability is
subordinate to authorization safety for sensitive operations.
