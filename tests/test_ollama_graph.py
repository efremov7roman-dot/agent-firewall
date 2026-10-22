"""Native-call parsing and graph enforcement regressions."""

from copy import deepcopy
from typing import Any

import pytest
from conftest import make_context

from agent_firewall.agent import (
    AgentRunStatus,
    AgentTask,
    LangGraphFinancialAgent,
    ModelTurn,
    OllamaProvider,
    ProposedToolCall,
    ScriptedProvider,
)
from agent_firewall.agent.provider import ProviderError
from agent_firewall.agent.tools import build_tool_specs
from agent_firewall.domain import Capability, CapabilityName
from agent_firewall.gateway import ExecutionGateway, GatewayStatus


class FakeTransport:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    def chat(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        assert url.endswith("/api/chat")
        assert timeout > 0
        self.payloads.append(deepcopy(payload))
        if len(self.payloads) == 1:
            return {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": "get_portfolio", "arguments": {}}}],
                }
            }
        return {"message": {"role": "assistant", "content": "Finished."}}


def test_ollama_native_tool_call_and_tool_result_round_trip() -> None:
    transport = FakeTransport()
    provider = OllamaProvider(transport=transport)
    agent = LangGraphFinancialAgent(
        provider=provider,
        context_provider=lambda: make_context(
            (Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1"),)
        ),
    )
    result = agent.run(AgentTask(trace_id="ollama-test", user_instruction="Show my portfolio"))
    assert result.status is AgentRunStatus.COMPLETED
    assert result.gateway_results[0].status is GatewayStatus.EXECUTED
    assert transport.payloads[0]["tools"][0]["type"] == "function"
    assert transport.payloads[1]["messages"][-1]["role"] == "tool"
    assert transport.payloads[1]["messages"][-1]["tool_name"] == "get_portfolio"
    assert transport.payloads[0]["think"] is False
    assert any(item["node"] == "authorization" for item in agent.last_trace)


def test_graph_denies_mutation_and_never_changes_sandbox() -> None:
    provider = ScriptedProvider(
        (
            ModelTurn(
                tool_calls=(
                    ProposedToolCall(
                        call_id="withdraw-1",
                        name="withdraw_asset",
                        arguments={"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
                    ),
                )
            ),
            ModelTurn(text="Denied."),
        )
    )
    agent = LangGraphFinancialAgent(provider=provider, context_provider=make_context)
    result = agent.run(AgentTask(trace_id="denial", user_instruction="Withdraw"))
    assert result.status is AgentRunStatus.COMPLETED
    assert result.gateway_results[0].status is GatewayStatus.BLOCKED
    assert agent.gateway.snapshot().transactions == ()
    assert len(agent.gateway.audit_events) == 1


def test_graph_routes_invalid_arguments_to_gateway_audit() -> None:
    provider = ScriptedProvider(
        (
            ModelTurn(
                tool_calls=(
                    ProposedToolCall(call_id="bad", name="create_order", arguments={"x": 1}),
                )
            ),
            ModelTurn(text="Unable."),
        )
    )
    agent = LangGraphFinancialAgent(provider=provider, context_provider=make_context)
    result = agent.run(AgentTask(trace_id="bad-schema", user_instruction="Create order"))
    assert result.gateway_results[0].status is GatewayStatus.BLOCKED
    assert len(agent.gateway.audit_events) == 1


def test_graph_rejects_excess_turn_before_execution() -> None:
    provider = ScriptedProvider(
        (
            ModelTurn(
                tool_calls=(
                    ProposedToolCall(call_id="a", name="get_portfolio", arguments={}),
                    ProposedToolCall(call_id="b", name="get_portfolio", arguments={}),
                )
            ),
        )
    )
    agent = LangGraphFinancialAgent(
        provider=provider, context_provider=make_context, max_tool_calls=1
    )
    result = agent.run(AgentTask(trace_id="limit", user_instruction="Read twice"))
    assert result.status is AgentRunStatus.TOOL_LIMIT_REACHED
    assert agent.gateway.audit_events == ()


def test_tool_schemas_are_shared_with_ollama() -> None:
    assert {spec.name for spec in build_tool_specs()} == {
        "get_market_price",
        "get_portfolio",
        "get_open_orders",
        "create_order",
        "cancel_order",
        "transfer_asset",
        "withdraw_asset",
    }


def test_ollama_rejects_nonlocal_endpoint() -> None:
    with pytest.raises(ValueError, match="loopback"):
        OllamaProvider(base_url="https://remote.example")


class FailingTransport:
    def chat(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        raise ProviderError("Ollama connection or response failed")


def test_provider_failure_does_not_execute_any_tool() -> None:
    agent = LangGraphFinancialAgent(
        provider=OllamaProvider(transport=FailingTransport()),
        context_provider=make_context,
    )
    result = agent.run(AgentTask(trace_id="offline", user_instruction="Buy BTC"))
    assert result.status is AgentRunStatus.PROVIDER_ERROR
    assert result.provider_error == "ProviderError"
    assert agent.gateway.audit_events == ()


def test_repeat_graph_invocation_cannot_repeat_mutation_with_new_model_call_id() -> None:
    gateway = ExecutionGateway()
    cap = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    arguments = {"symbol": "BTCUSDT", "side": "BUY", "notional_usd": "50"}
    statuses = []
    for call_id in ("first-model-id", "different-model-id"):
        provider = ScriptedProvider(
            (
                ModelTurn(
                    tool_calls=(
                        ProposedToolCall(call_id=call_id, name="create_order", arguments=arguments),
                    )
                ),
                ModelTurn(text="Done."),
            )
        )
        agent = LangGraphFinancialAgent(
            provider=provider,
            gateway=gateway,
            context_provider=lambda: make_context((cap,)),
        )
        result = agent.run(AgentTask(trace_id="same-task", user_instruction="Buy $50 of BTC"))
        statuses.append(result.gateway_results[0].status)
    assert statuses == [GatewayStatus.EXECUTED, GatewayStatus.REPLAYED]
    assert len(gateway.snapshot().orders) == 1


def test_graph_recovers_from_denied_order_to_authorized_read() -> None:
    provider = ScriptedProvider(
        (
            ModelTurn(
                tool_calls=(
                    ProposedToolCall(
                        call_id="large",
                        name="create_order",
                        arguments={"symbol": "BTCUSDT", "side": "BUY", "notional_usd": "500"},
                    ),
                )
            ),
            ModelTurn(
                tool_calls=(
                    ProposedToolCall(
                        call_id="read",
                        name="get_market_price",
                        arguments={"symbol": "BTCUSDT"},
                    ),
                )
            ),
            ModelTurn(text="Price retrieved; order denied."),
        )
    )
    from decimal import Decimal

    from agent_firewall.domain import CapabilityConstraint

    agent = LangGraphFinancialAgent(
        provider=provider,
        context_provider=lambda: make_context(
            (
                Capability(
                    name=CapabilityName.ORDERS_CREATE,
                    agent_id="agent-1",
                    constraints=CapabilityConstraint(max_notional_usd=Decimal("100")),
                ),
                Capability(name=CapabilityName.MARKET_READ, agent_id="agent-1"),
            )
        ),
    )
    result = agent.run(AgentTask(trace_id="recover", user_instruction="Buy then read"))
    assert result.status is AgentRunStatus.COMPLETED
    assert [item.status for item in result.gateway_results] == [
        GatewayStatus.BLOCKED,
        GatewayStatus.EXECUTED,
    ]
    assert agent.gateway.snapshot().orders == ()
