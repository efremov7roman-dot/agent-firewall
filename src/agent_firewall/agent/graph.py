"""LangGraph orchestration with a single protected execution boundary."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic, perf_counter_ns
from typing import Any, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from agent_firewall.agent.models import (
    AgentRunResult,
    AgentRunStatus,
    AgentTask,
    ModelTurn,
    ProposedToolCall,
    ToolOutcome,
)
from agent_firewall.agent.provider import ModelProvider
from agent_firewall.agent.runner import SYSTEM_INSTRUCTION
from agent_firewall.agent.tools import build_tool_specs
from agent_firewall.domain import INITIAL_TOOL_REGISTRY, SecurityContext, ToolRequest
from agent_firewall.gateway import ExecutionGateway, GatewayResult, GatewayStatus


class GraphState(TypedDict, total=False):
    turn: ModelTurn
    pending: tuple[ProposedToolCall, ...]
    index: int
    outcomes: tuple[ToolOutcome, ...]
    results: tuple[GatewayResult, ...]
    count: int
    recoveries: int
    status: AgentRunStatus
    final_text: str
    error: str | None
    authorized: bool
    trace: tuple[dict[str, Any], ...]


class LangGraphFinancialAgent:
    """One graph invocation per task, without a replayable execution checkpoint."""

    def __init__(
        self,
        *,
        provider: ModelProvider,
        gateway: ExecutionGateway | None = None,
        context_provider: Callable[[], SecurityContext],
        max_tool_calls: int = 8,
        max_recoveries: int = 2,
        timeout_seconds: float = 120,
    ) -> None:
        if max_tool_calls < 1 or max_recoveries < 0 or timeout_seconds <= 0:
            raise ValueError("invalid graph limits")
        self.provider = provider
        self.gateway = gateway or ExecutionGateway()
        self.context_provider = context_provider
        self.max_tool_calls = max_tool_calls
        self.max_recoveries = max_recoveries
        self.timeout_seconds = timeout_seconds
        self.last_trace: tuple[dict[str, Any], ...] = ()

    def run(self, task: AgentTask) -> AgentRunResult:
        self.last_trace = ()
        try:
            session = self.provider.start_session(
                task=task, tools=build_tool_specs(), system_instruction=SYSTEM_INSTRUCTION
            )
        except Exception as error:
            return AgentRunResult(
                trace_id=task.trace_id,
                status=AgentRunStatus.PROVIDER_ERROR,
                provider_error=type(error).__name__,
            )
        deadline = monotonic() + self.timeout_seconds

        def event(state: GraphState, node: str, **fields: Any) -> tuple[dict[str, Any], ...]:
            return (*state.get("trace", ()), {"trace_id": task.trace_id, "node": node, **fields})

        def expired() -> bool:
            return monotonic() >= deadline

        def agent(state: GraphState) -> GraphState:
            if expired():
                return {"status": AgentRunStatus.TIMEOUT, "error": "TIMEOUT"}
            try:
                turn = session.next_turn(state.get("outcomes", ()))
            except Exception as error:
                timed_out = expired()
                return {
                    "status": (
                        AgentRunStatus.TIMEOUT if timed_out else AgentRunStatus.PROVIDER_ERROR
                    ),
                    "error": "TIMEOUT" if timed_out else type(error).__name__,
                    "trace": event(state, "agent", outcome="provider_error"),
                }
            if expired():
                return {
                    "status": AgentRunStatus.TIMEOUT,
                    "error": "TIMEOUT",
                    "trace": event(state, "agent", outcome="late_model_response"),
                }
            if not turn.tool_calls:
                return {
                    "status": AgentRunStatus.COMPLETED,
                    "final_text": turn.text,
                    "trace": event(state, "agent", outcome="final"),
                }
            if state.get("count", 0) + len(turn.tool_calls) > self.max_tool_calls:
                return {
                    "status": AgentRunStatus.TOOL_LIMIT_REACHED,
                    "final_text": "Tool-call limit reached.",
                    "trace": event(state, "agent", outcome="limit"),
                }
            return {
                "pending": turn.tool_calls,
                "index": 0,
                "outcomes": (),
                "count": state.get("count", 0) + len(turn.tool_calls),
                "trace": event(state, "agent", outcome="proposed", calls=len(turn.tool_calls)),
            }

        def after_agent(state: GraphState) -> str:
            return "done" if "status" in state else "authorization"

        def authorization(state: GraphState) -> GraphState:
            call = state["pending"][state["index"]]
            definition = INITIAL_TOOL_REGISTRY.get(call.name)
            valid = False
            if definition is not None:
                try:
                    definition.arguments_model.model_validate(call.arguments)
                    valid = True
                except Exception:
                    pass
            return {
                "authorized": valid,
                "trace": event(state, "authorization", tool=call.name, schema_valid=valid),
            }

        def after_authorization(state: GraphState) -> str:
            # Gateway owns the authoritative schema check and records invalid proposals.
            return "execution"

        def execution(state: GraphState) -> GraphState:
            call = state["pending"][state["index"]]
            if expired():
                return {"status": AgentRunStatus.TIMEOUT, "error": "TIMEOUT"}
            started = perf_counter_ns()
            try:
                # The trusted host supplies current identity and capabilities for every call.
                context = self.context_provider().model_copy(
                    update={"evaluated_at": datetime.now(UTC)}
                )
                result = self.gateway.execute(
                    ToolRequest(
                        trace_id=task.trace_id,
                        agent_id=context.identity.agent_id,
                        tool=call.name,
                        arguments=call.arguments,
                        # Stable ordinal blocks a repeated graph invocation even when
                        # the model supplies a new provider-specific call ID.
                        idempotency_key=(
                            f"{task.trace_id}:"
                            f"{state['count'] - len(state['pending']) + state['index']}"
                        ),
                    ),
                    context,
                )
            except Exception as error:
                return {
                    "status": AgentRunStatus.PROVIDER_ERROR,
                    "error": type(error).__name__,
                    "trace": event(state, "execution", outcome="gateway_error"),
                }
            outcome = ToolOutcome(call_id=call.call_id, output=result.model_dump_json())
            return {
                "results": (*state.get("results", ()), result),
                "outcomes": (*state.get("outcomes", ()), outcome),
                "trace": event(
                    state,
                    "execution",
                    tool=call.name,
                    status=result.status.value,
                    latency_ms=(perf_counter_ns() - started) / 1_000_000,
                ),
            }

        def recovery(state: GraphState) -> GraphState:
            recoveries = state.get("recoveries", 0) + 1
            return {
                "recoveries": recoveries,
                **(
                    {"status": AgentRunStatus.RECOVERY_LIMIT_REACHED}
                    if recoveries > self.max_recoveries
                    else {}
                ),
                "trace": event(state, "recovery", outcome="denied_or_failed"),
            }

        def advance(state: GraphState) -> GraphState:
            return {"index": state["index"] + 1}

        def after_attempt(state: GraphState) -> str:
            if "status" in state or state.get("recoveries", 0) > self.max_recoveries:
                return "done"
            if state["index"] + 1 < len(state["pending"]):
                return "advance"
            return "agent"

        def after_execution(state: GraphState) -> str:
            if "status" in state:
                return "done"
            latest = state["results"][-1]
            return (
                "recovery"
                if latest.status not in (GatewayStatus.EXECUTED, GatewayStatus.REPLAYED)
                else after_attempt(state)
            )

        builder = StateGraph(GraphState)
        builder.add_node("agent", agent)
        builder.add_node("authorization", authorization)
        builder.add_node("execution", execution)
        builder.add_node("recovery", recovery)
        builder.add_node("advance", advance)
        builder.add_edge(START, "agent")
        builder.add_conditional_edges(
            "agent", after_agent, {"done": END, "authorization": "authorization"}
        )
        builder.add_conditional_edges(
            "authorization", after_authorization, {"execution": "execution"}
        )
        builder.add_conditional_edges(
            "execution",
            after_execution,
            {"done": END, "recovery": "recovery", "advance": "advance", "agent": "agent"},
        )
        builder.add_conditional_edges(
            "recovery",
            after_attempt,
            {"done": END, "advance": "advance", "agent": "agent"},
        )
        builder.add_edge("advance", "authorization")
        try:
            final = cast(
                GraphState,
                builder.compile().invoke(
                    {"results": (), "count": 0, "recoveries": 0, "trace": ()},
                    {"recursion_limit": self.max_tool_calls * 5 + 10},
                ),
            )
        except Exception as error:
            return AgentRunResult(
                trace_id=task.trace_id,
                status=AgentRunStatus.PROVIDER_ERROR,
                provider_error=type(error).__name__,
            )
        self.last_trace = final.get("trace", ())
        status = final.get("status", AgentRunStatus.TOOL_LIMIT_REACHED)
        return AgentRunResult(
            trace_id=task.trace_id,
            status=status,
            final_text=final.get("final_text", ""),
            gateway_results=final.get("results", ()),
            provider_error=final.get("error"),
        )
