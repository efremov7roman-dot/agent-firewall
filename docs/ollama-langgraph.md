# Local Ollama and LangGraph integration

`LangGraphFinancialAgent` uses a compiled `StateGraph` with explicit `agent`,
`authorization`, `execution`, `recovery`, and `advance` nodes. The Ollama adapter
posts native `tools` to `/api/chat` with `stream: false`, `think: false`, a fixed
seed, and temperature zero. The model supplies proposals; the host supplies identity and
capabilities through `context_provider` on every call. The execution node calls
the existing `ExecutionGateway`, which performs authoritative schema validation,
resource resolution, policy, approval checks, audit, and sandbox execution.

The graph does not install a checkpointer. There is no stateful graph resume path
that can replay a side effect. Requests use a trace-scoped idempotency key, and
the gateway handles repeated requests within its current instance. This is a
local-process guarantee; a crash between sandbox mutation and audit completion,
or recreating a gateway after a crash, is not transactionally protected. Do not
use this integration for real assets.

Denied and failed tool calls return typed gateway outcomes to the model. Recovery
is bounded by `max_recoveries`; tool calls are bounded by `max_tool_calls`.
Idempotency keys use the trace ID and the call's ordinal position, so invoking
the same task again against the same gateway cannot repeat a state change even
if the model assigns a different call ID. A changed call at that position is
blocked as a conflict.

Provider calls have a network timeout, and the graph checks its overall deadline
before model and tool execution. A blocking provider call can run until its own
timeout before the graph notices the overall deadline. Traces contain node names,
tool names, statuses, timing, and correlation IDs, without arguments or tool
payloads. The gateway's sanitized audit is the authoritative action record.

## Reproduce

Install Python 3.12+, Ollama, and the local `qwen3:8b` model. From the repository
root:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
ollama pull qwen3:8b
.\.venv\Scripts\python.exe examples\ollama_graph_demo.py
.\.venv\Scripts\python.exe -m agent_firewall.evaluation.live --output experiments\live_ollama.json
```

The live evaluation compares unprotected direct sandbox execution, a static
capability-name rule, and the full gateway. The direct execution path exists only
inside `evaluation.live` as an intentionally unsafe comparator. All three modes
use the same Ollama model, tools, task text, seed, and generation settings. Each
scenario starts with fresh sandbox state. The four-scenario set includes two
benign tasks and two explicit unauthorized requests. Task and attack success are
checked against sandbox state; a block counts as prevention only when the
forbidden state change did not occur. For the read-only task, both requested
gateway reads must execute.

The sample is exploratory: only two benign and two adversarial scenarios per
mode, no order randomization, and no prompt-injection corpus. Wilson intervals
quantify sampling uncertainty but cannot establish broad security. `qwen3:8b`
generation can vary despite fixed options. Token counts are an execution-cost
proxy; the local model has no per-call billed dollar cost. Existing Phase 7–10
scripted benchmarks are historical authorization evaluations, not live-model
results.

The expanded, independently scored evaluation and security audit are documented
in [live adversarial validation](live-v2-validation.md). This page preserves the
first four-scenario integration run as historical context.

The sandbox is an in-process Python object, so trusted code in the same process
can import its internal class and bypass the gateway. The graph and the public
agent path never do this; the deliberately unsafe evaluation comparators do.
Host compromise or untrusted Python code running in the agent process therefore
remains outside the enforcement boundary.

## Measured local run

The saved [live artifact](../experiments/live_ollama.json) contains 12 actual
`qwen3:8b` runs: four scenarios in each of three modes. All four agent runs per
mode completed, and each mode proposed five tool calls. The two benign tasks
succeeded in every mode. Unauthorized sandbox mutations occurred in 2/2
unprotected scenarios, 1/2 basic-rules scenarios, and 0/2 firewall scenarios.
The same counts apply to unauthorized execution per two observed unauthorized
target calls in each mode. There were no false blocks among three benign target
calls per mode. The firewall's 0/2 attack rate has a 95% Wilson interval of
0–65.76%, so it is a narrow experiment rather than a general security estimate.

| Mode | Attack success | Benign success | Tool p95 | End-to-end p95 |
| --- | ---: | ---: | ---: | ---: |
| Unprotected | 2/2 | 2/2 | 0.077 ms | 2681.023 ms |
| Basic rules | 1/2 | 2/2 | 0.070 ms | 2735.837 ms |
| Full firewall | 0/2 | 2/2 | 0.151 ms | 2371.574 ms |

The firewall prevented one additional successful unauthorized scenario compared
with basic rules in this set, while all benign scenarios remained successful.
Its observed tool-call p95 was 0.081 ms higher than basic rules; with only five
tool calls per mode, these latency percentiles are descriptive, not stable
performance estimates. The artifact also includes p50/p99, model request and
token counts, failure rates, per-run statuses, and denominators.
