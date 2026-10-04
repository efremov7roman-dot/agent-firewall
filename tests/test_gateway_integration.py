from datetime import timedelta
from decimal import Decimal

from conftest import NOW, make_context, make_request

import agent_firewall
from agent_firewall.domain import (
    Capability,
    CapabilityConstraint,
    CapabilityName,
    Decision,
    DecisionReason,
    PolicyDecision,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.gateway import ApprovalCheck, ExecutionGateway, GatewayStatus
from agent_firewall.sandbox import (
    MarketPrice,
    OpenOrdersView,
    OrderRecord,
    OrderStatus,
    PortfolioView,
    TransactionKind,
    TransactionRecord,
)


class ApproveExactTrace:
    def __init__(self, trace_id: str) -> None:
        self._trace_id = trace_id

    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        del decision, context
        return ApprovalCheck(approved=request.trace_id == self._trace_id)


class ExplodingApprovalVerifier:
    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        del request, decision, context
        raise RuntimeError("approval backend unavailable")


def test_authorized_market_read_executes_without_state_mutation() -> None:
    capability = Capability(name=CapabilityName.MARKET_READ, agent_id="agent-1")
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request("get_market_price", {"symbol": "btcusdt"}),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.EXECUTED
    assert result.decision.decision is Decision.ALLOW
    assert isinstance(result.result, MarketPrice)
    assert result.result.price_usd == Decimal("50000")
    assert gateway.snapshot() == before


def test_authorized_order_mutates_only_order_state() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(
            allowed_symbols=frozenset({"BTCUSDT"}),
            max_notional_usd=Decimal("500"),
        ),
    )
    gateway = ExecutionGateway()

    result = gateway.execute(
        make_request("create_order", _order("500")),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.EXECUTED
    assert isinstance(result.result, OrderRecord)
    assert result.result.order_id == "order-000001"
    assert gateway.snapshot().orders == (result.result,)
    assert gateway.snapshot().transactions == ()


def test_missing_capability_cannot_withdraw_or_mutate_state() -> None:
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
        ),
        make_context(),
    )

    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.MISSING_CAPABILITY
    assert result.result is None
    assert gateway.snapshot() == before


def test_order_over_limit_is_denied_without_state_mutation() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_notional_usd=Decimal("1000")),
    )
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request("create_order", _order("10000")),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.NOTIONAL_LIMIT_EXCEEDED
    assert gateway.snapshot() == before


def test_symbol_scope_denial_does_not_create_order() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(allowed_symbols=frozenset({"BTCUSDT"})),
    )
    gateway = ExecutionGateway()

    result = gateway.execute(
        make_request("create_order", _order("10", symbol="ETHUSDT")),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.SYMBOL_SCOPE_VIOLATION
    assert gateway.snapshot().orders == ()


def test_expired_capability_cannot_execute_or_mutate_state() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        expires_at=NOW - timedelta(microseconds=1),
    )
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request("create_order", _order("10")),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.EXPIRED_CAPABILITY
    assert gateway.snapshot() == before


def test_invalid_arguments_cannot_execute_or_mutate_state() -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request("create_order", {"symbol": "BTCUSDT", "notional_usd": "-1"}),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.MALFORMED_REQUEST
    assert gateway.snapshot() == before


def test_withdrawal_waits_for_approval_by_default() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.AWAITING_APPROVAL
    assert result.approval_verified is False
    assert gateway.snapshot() == before


def test_valid_approval_allows_exact_withdrawal_request() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway(approval_verifier=ApproveExactTrace("trace-1"))

    result = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.EXECUTED
    assert result.approval_verified is True
    assert isinstance(result.result, TransactionRecord)
    assert gateway.snapshot().balances_usd["USDT"] == Decimal("9900")
    assert len(gateway.snapshot().transactions) == 1


def test_approval_verifier_failure_fails_closed() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway(approval_verifier=ExplodingApprovalVerifier())
    before = gateway.snapshot()

    result = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.FAILED
    assert result.error_code == "APPROVAL_VERIFICATION_FAILED"
    assert gateway.snapshot() == before


def test_insufficient_balance_fails_without_partial_mutation() -> None:
    capability = Capability(name=CapabilityName.TRANSFERS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway()
    before = gateway.snapshot()

    result = gateway.execute(
        make_request(
            "transfer_asset",
            {
                "asset": "USDT",
                "destination_account": "savings",
                "amount_usd": "1000000",
            },
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.FAILED
    assert result.error_code == "INSUFFICIENT_BALANCE"
    assert gateway.snapshot() == before


def test_order_can_be_cancelled_through_authorized_gateway_calls() -> None:
    create = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    cancel = Capability(name=CapabilityName.ORDERS_CANCEL, agent_id="agent-1")
    context = make_context((create, cancel))
    gateway = ExecutionGateway()
    created = gateway.execute(make_request("create_order", _order("10")), context)
    assert isinstance(created.result, OrderRecord)

    cancelled = gateway.execute(
        make_request("cancel_order", {"order_id": created.result.order_id}),
        context,
    )

    assert cancelled.status is GatewayStatus.EXECUTED
    assert isinstance(cancelled.result, OrderRecord)
    assert cancelled.result.status is OrderStatus.CANCELLED
    assert gateway.snapshot().orders[0].status is OrderStatus.CANCELLED


def test_portfolio_and_open_order_reads_reflect_current_state() -> None:
    create = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    read_orders = Capability(name=CapabilityName.ORDERS_READ, agent_id="agent-1")
    read_portfolio = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1")
    context = make_context((create, read_orders, read_portfolio))
    gateway = ExecutionGateway()
    gateway.execute(make_request("create_order", _order("10")), context)

    orders = gateway.execute(
        make_request("get_open_orders", {"symbol": "BTCUSDT"}),
        context,
    )
    portfolio = gateway.execute(make_request("get_portfolio", {}), context)

    assert isinstance(orders.result, OpenOrdersView)
    assert len(orders.result.orders) == 1
    assert isinstance(portfolio.result, PortfolioView)
    assert portfolio.result.positions["BTCUSDT"] == Decimal("1")


def test_authorized_transfer_updates_balance_and_history() -> None:
    capability = Capability(
        name=CapabilityName.TRANSFERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_transfer_amount_usd=Decimal("100")),
    )
    gateway = ExecutionGateway()

    result = gateway.execute(
        make_request(
            "transfer_asset",
            {
                "asset": "USDT",
                "destination_account": "savings",
                "amount_usd": "100",
            },
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.EXECUTED
    assert isinstance(result.result, TransactionRecord)
    assert result.result.kind is TransactionKind.TRANSFER
    assert gateway.snapshot().balances_usd["USDT"] == Decimal("9900")


def test_every_request_emits_correlated_audit_event() -> None:
    capability = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1")
    gateway = ExecutionGateway()

    gateway.execute(make_request("get_portfolio", {}), make_context((capability,)))
    gateway.execute(make_request("withdraw_asset", {}), make_context())

    events = gateway.audit_events
    assert [event.status for event in events] == [
        GatewayStatus.AUTHORIZED,
        GatewayStatus.EXECUTED,
        GatewayStatus.BLOCKED,
    ]
    assert all(event.trace_id == "trace-1" for event in events)


def test_mutating_snapshot_cannot_bypass_internal_state() -> None:
    gateway = ExecutionGateway()
    snapshot = gateway.snapshot()

    snapshot.balances_usd["USDT"] = Decimal("999999999")

    assert gateway.snapshot().balances_usd["USDT"] == Decimal("10000")


def test_financial_sandbox_is_not_exported_as_agent_facing_api() -> None:
    assert not hasattr(agent_firewall, "FinancialSandbox")


def _order(amount: str, *, symbol: str = "BTCUSDT") -> dict[str, object]:
    return {
        "symbol": symbol,
        "side": "BUY",
        "notional_usd": amount,
        "order_type": "MARKET",
    }
