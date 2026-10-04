from datetime import timedelta
from decimal import Decimal

from conftest import NOW, make_context, make_request
from hypothesis import given
from hypothesis import strategies as st

from agent_firewall.capabilities import CapabilityEvaluator
from agent_firewall.domain import (
    Capability,
    CapabilityConstraint,
    CapabilityName,
    Decision,
    DecisionReason,
)
from agent_firewall.policy import PolicyEngine


@given(
    amount=st.decimals(
        min_value=Decimal("100.01"),
        max_value=Decimal("1000000000"),
        places=2,
        allow_nan=False,
        allow_infinity=False,
    )
)
def test_inv_11_amounts_over_capability_limit_never_authorize(amount: Decimal) -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_notional_usd=Decimal("100")),
    )

    decision = PolicyEngine().evaluate(
        make_request(
            "create_order",
            {
                "symbol": "BTCUSDT",
                "side": "BUY",
                "notional_usd": amount,
                "order_type": "MARKET",
            },
        ),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.NOTIONAL_LIMIT_EXCEEDED


def test_inv_02_missing_capability_never_authorizes() -> None:
    decision = PolicyEngine().evaluate(
        make_request("get_portfolio", {}),
        make_context(),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MISSING_CAPABILITY


@given(seconds_expired=st.integers(min_value=0, max_value=10_000_000))
def test_inv_03_expired_capability_never_authorizes(seconds_expired: int) -> None:
    capability = Capability(
        name=CapabilityName.PORTFOLIO_READ,
        agent_id="agent-1",
        expires_at=NOW - timedelta(seconds=seconds_expired),
    )

    decision = PolicyEngine().evaluate(
        make_request("get_portfolio", {}),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.EXPIRED_CAPABILITY


def test_inv_01_deny_is_an_authorization_result_without_execution() -> None:
    decision = PolicyEngine().evaluate(
        make_request("create_order", {"symbol": "BTCUSDT"}),
        make_context(),
    )

    assert decision.decision is Decision.DENY
    assert decision.normalized_arguments is None


def test_inv_04_require_approval_is_not_allow() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")

    decision = PolicyEngine().evaluate(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "1"},
        ),
        make_context((capability,)),
    )

    assert decision.decision is Decision.REQUIRE_APPROVAL


def test_inv_05_unknown_tools_fail_closed() -> None:
    decision = PolicyEngine().evaluate(make_request("unknown", {}), make_context())

    assert decision.decision is Decision.DENY


def test_inv_06_invalid_arguments_never_authorize() -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")

    decision = PolicyEngine().evaluate(
        make_request("create_order", {"symbol": "BTCUSDT", "notional_usd": "-1"}),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.MALFORMED_REQUEST


class ExplodingCapabilityEvaluator(CapabilityEvaluator):
    def evaluate(self, **_: object) -> None:  # type: ignore[override]
        raise RuntimeError("simulated evaluator failure")


def test_inv_10_internal_evaluation_failure_fails_closed() -> None:
    capability = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1")
    engine = PolicyEngine(capability_evaluator=ExplodingCapabilityEvaluator())

    decision = engine.evaluate(
        make_request("get_portfolio", {}),
        make_context((capability,)),
    )

    assert decision.decision is Decision.DENY
    assert decision.reason is DecisionReason.POLICY_EVALUATION_ERROR
