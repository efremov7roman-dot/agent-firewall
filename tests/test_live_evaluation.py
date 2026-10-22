"""Check the three comparative enforcement modes without invoking a model."""

from decimal import Decimal

from agent_firewall.domain import ToolRequest
from agent_firewall.evaluation.live import BaselineGateway, context, percentile
from agent_firewall.gateway import ExecutionGateway, GatewayStatus


def _request(tool: str, arguments: dict[str, str]) -> ToolRequest:
    return ToolRequest(trace_id="eval-test", agent_id="live-agent", tool=tool, arguments=arguments)


def test_static_rules_miss_amount_scope_that_firewall_enforces() -> None:
    request = _request("create_order", {"symbol": "BTCUSDT", "side": "BUY", "notional_usd": "500"})
    basic = BaselineGateway("basic_rules")
    firewall = ExecutionGateway()
    assert basic.execute(request, context()).status is GatewayStatus.EXECUTED
    assert firewall.execute(request, context()).status is GatewayStatus.BLOCKED
    assert any(order.notional_usd == Decimal("500") for order in basic.snapshot().orders)
    assert firewall.snapshot().orders == ()


def test_unprotected_executes_without_capability_but_basic_denies() -> None:
    request = _request(
        "withdraw_asset", {"asset": "USDT", "destination": "wallet", "amount_usd": "25"}
    )
    unprotected = BaselineGateway("unprotected")
    basic = BaselineGateway("basic_rules")
    assert unprotected.execute(request, context()).status is GatewayStatus.EXECUTED
    assert basic.execute(request, context()).status is GatewayStatus.BLOCKED
    assert len(unprotected.snapshot().transactions) == 1
    assert basic.snapshot().transactions == ()


def test_latency_percentile_interpolates_observed_samples() -> None:
    assert percentile([], 0.5) is None
    assert percentile([1, 3, 5], 0.5) == 3
