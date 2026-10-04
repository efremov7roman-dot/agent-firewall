from datetime import timedelta
from decimal import Decimal

from conftest import NOW, make_context, make_request

from agent_firewall.domain import (
    Capability,
    CapabilityConstraint,
    CapabilityName,
    Decision,
    DecisionReason,
    ToolRequest,
)
from agent_firewall.policy import PolicyEngine


def test_unknown_tool_is_denied_by_default() -> None:
    decision = PolicyEngine().evaluate(
        make_request("admin_backdoor", {}),
        make_context(),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.UNKNOWN_TOOL
    assert decision.matched_policy == "P01"


def test_missing_capability_is_denied() -> None:
    decision = PolicyEngine().evaluate(
        make_request("create_order", _order("10")),
        make_context(),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MISSING_CAPABILITY
    assert decision.required_capability == "orders.create"


def test_expired_capability_is_denied_at_boundary() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        expires_at=NOW,
    )

    decision = PolicyEngine().evaluate(
        make_request("create_order", _order("10")),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.EXPIRED_CAPABILITY


def test_valid_capability_allows_normalized_order() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(
            allowed_symbols=frozenset({"BTCUSDT"}),
            max_notional_usd=Decimal("100"),
            environment="sandbox",
        ),
        expires_at=NOW + timedelta(minutes=1),
    )

    decision = PolicyEngine().evaluate(
        make_request("create_order", _order("100", symbol="btcusdt")),
        make_context((capability,)),
    )

    assert decision.decision is Decision.ALLOW
    assert decision.reason is DecisionReason.ALLOWED
    assert decision.normalized_arguments is not None
    assert decision.normalized_arguments["symbol"] == "BTCUSDT"
    assert decision.normalized_arguments["notional_usd"] == Decimal("100")


def test_out_of_scope_symbol_is_denied() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(allowed_symbols=frozenset({"BTCUSDT"})),
    )

    decision = PolicyEngine().evaluate(
        make_request("create_order", _order("10", symbol="ETHUSDT")),
        make_context((capability,)),
    )

    assert decision.reason is DecisionReason.SYMBOL_SCOPE_VIOLATION


def test_scoped_open_orders_request_cannot_omit_symbol() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_READ,
        agent_id="agent-1",
        constraints=CapabilityConstraint(allowed_symbols=frozenset({"BTCUSDT"})),
    )

    decision = PolicyEngine().evaluate(
        make_request("get_open_orders", {}),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.SYMBOL_SCOPE_VIOLATION


def test_malformed_arguments_are_denied_before_capability_check() -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    malformed = _order("10") | {"unexpected": True}

    decision = PolicyEngine().evaluate(
        make_request("create_order", malformed),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MALFORMED_REQUEST
    assert decision.matched_policy == "P04"


def test_limit_order_without_price_is_malformed() -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    arguments = _order("10") | {"order_type": "LIMIT"}

    decision = PolicyEngine().evaluate(
        make_request("create_order", arguments),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MALFORMED_REQUEST


def test_raw_malformed_request_is_denied() -> None:
    decision = PolicyEngine().evaluate_raw(
        {"trace_id": "trace", "agent_id": "agent-1", "arguments": {}},
        make_context(),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MALFORMED_REQUEST


def test_runtime_identity_claim_cannot_be_spoofed() -> None:
    capability = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1")
    request = ToolRequest(
        trace_id="trace",
        agent_id="agent-2",
        tool="get_portfolio",
        arguments={},
    )

    decision = PolicyEngine().evaluate(request, make_context((capability,)))

    assert decision.reason is DecisionReason.AGENT_IDENTITY_MISMATCH


def test_environment_and_action_scope_are_enforced() -> None:
    wrong_environment = Capability(
        name=CapabilityName.ORDERS_CANCEL,
        agent_id="agent-1",
        constraints=CapabilityConstraint(environment="production"),
    )
    environment_decision = PolicyEngine().evaluate(
        make_request("cancel_order", {"order_id": "order-1"}),
        make_context((wrong_environment,)),
    )
    assert environment_decision.reason is DecisionReason.ENVIRONMENT_MISMATCH

    wrong_action = Capability(
        name=CapabilityName.ORDERS_CANCEL,
        agent_id="agent-1",
        constraints=CapabilityConstraint(allowed_actions=frozenset({"other_action"})),
    )
    action_decision = PolicyEngine().evaluate(
        make_request("cancel_order", {"order_id": "order-1"}),
        make_context((wrong_action,)),
    )
    assert action_decision.reason is DecisionReason.ACTION_SCOPE_VIOLATION


def test_transfer_limit_is_enforced() -> None:
    capability = Capability(
        name=CapabilityName.TRANSFERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_transfer_amount_usd=Decimal("50")),
    )

    decision = PolicyEngine().evaluate(
        make_request(
            "transfer_asset",
            {"asset": "USD", "destination_account": "savings", "amount_usd": "50.01"},
        ),
        make_context((capability,)),
    )

    assert decision.reason is DecisionReason.TRANSFER_LIMIT_EXCEEDED


def test_configured_threshold_requires_approval_only_above_boundary() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(
            max_notional_usd=Decimal("1000"),
            approval_above_usd=Decimal("100"),
        ),
    )
    engine = PolicyEngine()

    at_boundary = engine.evaluate(
        make_request("create_order", _order("100")), make_context((capability,))
    )
    above_boundary = engine.evaluate(
        make_request("create_order", _order("100.01")), make_context((capability,))
    )

    assert at_boundary.decision is Decision.ALLOW
    assert above_boundary.decision is Decision.REQUIRE_APPROVAL
    assert above_boundary.reason is DecisionReason.APPROVAL_REQUIRED
    assert above_boundary.approval_requirement is not None
    assert above_boundary.approval_requirement.binds_to_request is True


def test_withdrawal_always_requires_approval() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")

    decision = PolicyEngine().evaluate(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "sandbox-wallet", "amount_usd": "1"},
        ),
        make_context((capability,)),
    )

    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert decision.reason is DecisionReason.WITHDRAWAL_APPROVAL_REQUIRED
    assert decision.matched_policy == "P08"


def _order(amount: str, *, symbol: str = "BTCUSDT") -> dict[str, object]:
    return {
        "symbol": symbol,
        "side": "BUY",
        "notional_usd": amount,
        "order_type": "MARKET",
    }
