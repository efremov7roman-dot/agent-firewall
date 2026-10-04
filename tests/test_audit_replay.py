import json
from pathlib import Path

import pytest
from conftest import make_context, make_request

from agent_firewall.domain import Capability, CapabilityName, Decision
from agent_firewall.gateway import (
    DecisionReplay,
    ExecutionGateway,
    GatewayAuditEvent,
    GatewayErrorCode,
    GatewayStatus,
    JsonlAuditRecorder,
)
from agent_firewall.operations.cli import main


class FailingAuditRecorder:
    @property
    def events(self) -> tuple[GatewayAuditEvent, ...]:
        return ()

    def record(self, event: GatewayAuditEvent) -> None:
        del event
        raise OSError("audit storage unavailable")


def test_jsonl_audit_round_trip_query_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = JsonlAuditRecorder(path)
    capability = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="agent-1")
    gateway = ExecutionGateway(audit_recorder=recorder)

    allowed = gateway.execute(make_request("get_portfolio", {}), make_context((capability,)))
    denied = gateway.execute(make_request("withdraw_asset", {}), make_context())

    assert allowed.status is GatewayStatus.EXECUTED
    assert denied.status is GatewayStatus.BLOCKED
    assert len(recorder.events) == 3
    blocked = recorder.query(status=GatewayStatus.BLOCKED)
    assert len(blocked) == 1
    assert blocked[0].decision is Decision.DENY
    assert blocked[0].request.tool == "withdraw_asset"
    assert blocked[0].security_context.identity.agent_id == "agent-1"
    assert blocked[0].policies_evaluated == (blocked[0].matched_policy,)
    assert blocked[0].decision_latency_ms >= 0
    assert DecisionReplay().replay(blocked[0]).decision_matches is True
    assert DecisionReplay().replay(recorder.events[0]).execution_occurred is False
    assert DecisionReplay().replay(recorder.events[1]).execution_occurred is True


def test_audit_failure_prevents_authorized_side_effect() -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway(audit_recorder=FailingAuditRecorder())
    before = gateway.snapshot()

    result = gateway.execute(
        make_request(
            "create_order",
            {
                "symbol": "BTCUSDT",
                "side": "BUY",
                "notional_usd": "10",
                "order_type": "MARKET",
            },
        ),
        make_context((capability,)),
    )

    assert result.status is GatewayStatus.FAILED
    assert result.error_code == GatewayErrorCode.AUDIT_RECORDING_FAILED
    assert gateway.snapshot() == before


def test_audit_redacts_secret_like_untrusted_arguments(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = JsonlAuditRecorder(path)
    gateway = ExecutionGateway(audit_recorder=recorder)

    gateway.execute(
        make_request("unknown", {"api_key": "do-not-log", "nested": {"token": "x"}}),
        make_context(),
    )

    serialized = path.read_text(encoding="utf-8")
    assert "do-not-log" not in serialized
    assert '"api_key":"[REDACTED]"' in serialized
    assert recorder.events[0].request.arguments["nested"] == {"token": "[REDACTED]"}


def test_operator_cli_filters_and_replays(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = JsonlAuditRecorder(path)
    gateway = ExecutionGateway(audit_recorder=recorder)
    gateway.execute(make_request("unknown", {}), make_context())
    event = recorder.events[0]

    assert main(["denied", "--file", str(path)]) == 0
    denied = json.loads(capsys.readouterr().out)
    assert [item["event_id"] for item in denied] == [event.event_id]

    assert main(["replay", "--file", str(path), "--event-id", event.event_id]) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["decision_matches"] is True

    assert main(["replay", "--file", str(path), "--event-id", "missing"]) == 2
    missing = json.loads(capsys.readouterr().out)
    assert missing["error"] == "EVENT_NOT_FOUND"
