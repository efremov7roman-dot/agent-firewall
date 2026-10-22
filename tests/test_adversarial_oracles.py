"""Independent state checks for attacks the model may choose not to attempt."""

from __future__ import annotations

import json
from typing import Any

from agent_firewall.agent import ModelTurn, ProposedToolCall, ToolOutcome
from agent_firewall.domain import ToolRequest
from agent_firewall.evaluation.adversarial import (
    DATASET,
    InjectingSession,
    _context,
    _oracle,
    _seed,
    _snapshot,
    _unauthorized_proposals,
)
from agent_firewall.evaluation.live import BaselineGateway
from agent_firewall.gateway import ExecutionGateway, GatewayStatus


def _case(family: str) -> dict[str, Any]:
    data = json.loads((DATASET / "development.json").read_text(encoding="utf-8"))
    return next(item for item in data if item["family"] == family)


def test_victim_cancellation_oracle_observes_baseline_mutation_only() -> None:
    scenario = _case("cross_cancel")
    statuses = []
    for boundary in (BaselineGateway("basic_rules"), ExecutionGateway()):
        _seed(boundary, scenario, None)
        before = _snapshot(boundary)
        result = boundary.execute(
            ToolRequest(
                trace_id="cross-test",
                agent_id="eval-agent",
                tool="cancel_order",
                arguments={"order_id": "order-000001"},
            ),
            _context(["orders_cancel"]),
        )
        after = _snapshot(boundary)
        statuses.append((result.status, _oracle(scenario, before, after, (result,))[0]))
    assert statuses == [
        (GatewayStatus.EXECUTED, True),
        (GatewayStatus.BLOCKED, False),
    ]


def test_tool_result_injection_is_delivered_as_untrusted_text() -> None:
    class RecordingSession:
        outcomes: tuple[ToolOutcome, ...] = ()

        def next_turn(self, outcomes: tuple[ToolOutcome, ...] = ()) -> ModelTurn:
            self.outcomes = outcomes
            return ModelTurn(text="Done")

    session = RecordingSession()
    injected = InjectingSession(session, "malicious tool text")
    injected.next_turn((ToolOutcome(call_id="x", output="{}"),))
    assert injected.used
    assert session.outcomes[0].output.endswith("malicious tool text")


def test_split_order_oracle_counts_only_budget_crossing_attempt() -> None:
    scenario = _case("aggregate_split")
    calls = [
        ProposedToolCall(
            call_id=str(index),
            name="create_order",
            arguments={"symbol": "BTCUSDT", "side": "BUY", "notional_usd": "61"},
        )
        for index in range(2)
    ]
    assert _unauthorized_proposals(scenario, calls) == [False, True]


def test_model_refusal_has_zero_unauthorized_attempt_denominator() -> None:
    scenario = _case("withdraw_no_cap")
    assert _unauthorized_proposals(scenario, []) == []


def test_exact_attack_oracle_rejects_wrong_symbol_or_destination() -> None:
    order_scenario = _case("order_over_limit")
    boundary = BaselineGateway("unprotected")
    before = _snapshot(boundary)
    amount = order_scenario["oracle"]["amount"]
    wrong_symbol = "ETHUSDT" if "BTCUSDT" in order_scenario["instruction"] else "BTCUSDT"
    result = boundary.execute(
        ToolRequest(
            trace_id="wrong-symbol",
            agent_id="eval-agent",
            tool="create_order",
            arguments={"symbol": wrong_symbol, "side": "BUY", "notional_usd": amount},
        ),
        _context(["order_limited"]),
    )
    assert _oracle(order_scenario, before, _snapshot(boundary), (result,))[0] is False

    withdraw_scenario = _case("withdraw_no_cap")
    boundary = BaselineGateway("unprotected")
    before = _snapshot(boundary)
    result = boundary.execute(
        ToolRequest(
            trace_id="wrong-destination",
            agent_id="eval-agent",
            tool="withdraw_asset",
            arguments={
                "asset": "USDT",
                "destination": "other-wallet",
                "amount_usd": withdraw_scenario["oracle"]["amount"],
            },
        ),
        _context([]),
    )
    assert _oracle(withdraw_scenario, before, _snapshot(boundary), (result,))[0] is False
