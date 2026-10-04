from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from conftest import NOW, make_context, make_request
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_firewall.domain import (
    Capability,
    CapabilityConstraint,
    CapabilityName,
    Decision,
    PolicyDecision,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.gateway import (
    ApprovalCheck,
    ApprovalError,
    ApprovalErrorCode,
    ApprovalManager,
    ExecutionGateway,
    GatewayResult,
    GatewayStatus,
    JsonlAuditRecorder,
)
from agent_firewall.hardening import run_performance_profile
from agent_firewall.policy import PolicyEngine


class ExplodingPolicyEngine(PolicyEngine):
    def evaluate(self, request: ToolRequest, context: SecurityContext) -> PolicyDecision:
        del request, context
        raise RuntimeError("policy backend unavailable")


class MutatingApprovalVerifier:
    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        del request, context
        assert decision.normalized_arguments is not None
        decision.normalized_arguments["amount_usd"] = Decimal("9000")
        return ApprovalCheck(approved=True)


def _order(amount: Decimal | float | str) -> dict[str, object]:
    return {
        "symbol": "BTCUSDT",
        "side": "BUY",
        "notional_usd": amount,
        "order_type": "MARKET",
    }


@given(
    payload=st.dictionaries(
        keys=st.text(max_size=20),
        values=st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=30)),
        max_size=12,
    )
)
def test_arbitrary_raw_requests_fail_closed_without_capabilities(
    payload: dict[str, object],
) -> None:
    decision = PolicyEngine().evaluate_raw(payload, make_context())
    assert decision.decision is Decision.DENY


@given(
    amount=st.decimals(
        min_value=Decimal("100.0000000000000000001"),
        max_value=Decimal("1000000000000"),
        allow_nan=False,
        allow_infinity=False,
    )
)
@settings(max_examples=60)
def test_generated_amounts_above_limit_never_mutate_state(amount: Decimal) -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_notional_usd=Decimal("100")),
    )
    gateway = ExecutionGateway()
    before = gateway.snapshot()
    result = gateway.execute(
        make_request("create_order", _order(amount)), make_context((capability,))
    )
    assert result.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before


@given(
    amount=st.floats(
        min_value=100.000001,
        max_value=1_000_000_000,
        allow_nan=False,
        allow_infinity=False,
    )
)
@settings(max_examples=60)
def test_binary_float_above_limit_cannot_bypass_decimal_comparison(amount: float) -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_notional_usd=Decimal("100")),
    )
    result = ExecutionGateway().execute(
        make_request("create_order", _order(amount)), make_context((capability,))
    )
    assert result.status is GatewayStatus.BLOCKED


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-Infinity", "-0", "0"])
def test_non_finite_and_non_positive_money_is_denied(amount: str) -> None:
    capability = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")
    result = ExecutionGateway().execute(
        make_request("create_order", _order(amount)), make_context((capability,))
    )
    assert result.status is GatewayStatus.BLOCKED


def test_unicode_confusable_symbol_does_not_match_ascii_scope() -> None:
    capability = Capability(
        name=CapabilityName.ORDERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(allowed_symbols=frozenset({"BTCUSDT"})),
    )
    result = ExecutionGateway().execute(
        make_request(
            "create_order",
            _order("10") | {"symbol": "\uff22\uff34\uff23\uff35\uff33\uff24\uff34"},
        ),
        make_context((capability,)),
    )
    assert result.status is GatewayStatus.BLOCKED


def test_gateway_contains_replaced_policy_engine_failure() -> None:
    gateway = ExecutionGateway(policy_engine=ExplodingPolicyEngine())
    before = gateway.snapshot()
    result = gateway.execute(make_request("get_portfolio", {}), make_context())
    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason == "POLICY_EVALUATION_ERROR"
    assert gateway.snapshot() == before


def test_approval_verifier_cannot_mutate_executed_arguments() -> None:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway(approval_verifier=MutatingApprovalVerifier())
    result = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
        ),
        make_context((capability,)),
    )
    assert result.status is GatewayStatus.EXECUTED
    assert gateway.snapshot().balances_usd["USDT"] == Decimal("9900")


def test_approval_rejects_naive_or_backdated_authority_time() -> None:
    manager = ApprovalManager(allowed_authorities=frozenset({"human:alice"}))
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    gateway = ExecutionGateway(approval_verifier=manager)
    pending = gateway.execute(
        make_request(
            "withdraw_asset",
            {"asset": "USDT", "destination": "wallet", "amount_usd": "1"},
        ),
        make_context((capability,)),
    )
    assert pending.approval_id is not None
    for invalid_time in (datetime(2026, 10, 2), NOW - timedelta(seconds=1)):
        with pytest.raises(ApprovalError) as error:
            manager.approve(pending.approval_id, authority="human:alice", at=invalid_time)
        assert error.value.code is ApprovalErrorCode.INVALID_APPROVAL_STATE


def test_concurrent_transfers_are_atomic_and_have_unique_ids() -> None:
    capability = Capability(
        name=CapabilityName.TRANSFERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_transfer_amount_usd=Decimal("100")),
    )
    capability = capability.model_copy(
        update={
            "constraints": capability.constraints.model_copy(
                update={
                    "allowed_destinations": frozenset(f"account-{index}" for index in range(20)),
                    "max_aggregate_amount_usd": Decimal("2000"),
                }
            )
        }
    )
    gateway = ExecutionGateway()
    context = make_context((capability,))

    def transfer(index: int) -> GatewayResult:
        return gateway.execute(
            make_request(
                "transfer_asset",
                {
                    "asset": "USDT",
                    "destination_account": f"account-{index}",
                    "amount_usd": "100",
                },
            ),
            context,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(transfer, range(20)))

    assert all(result.status is GatewayStatus.EXECUTED for result in results)
    snapshot = gateway.snapshot()
    assert snapshot.balances_usd["USDT"] == Decimal("8000")
    assert len({item.transaction_id for item in snapshot.transactions}) == 20


def test_concurrent_oversubscription_cannot_make_balance_negative() -> None:
    capability = Capability(
        name=CapabilityName.TRANSFERS_CREATE,
        agent_id="agent-1",
        constraints=CapabilityConstraint(max_transfer_amount_usd=Decimal("6000")),
    )
    capability = capability.model_copy(
        update={
            "constraints": capability.constraints.model_copy(
                update={"max_aggregate_amount_usd": Decimal("12000")}
            )
        }
    )
    gateway = ExecutionGateway()
    request = make_request(
        "transfer_asset",
        {"asset": "USDT", "destination_account": "savings", "amount_usd": "6000"},
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        requests = tuple(
            request.model_copy(update={"idempotency_key": f"oversubscription-{index}"})
            for index in range(2)
        )
        results = tuple(
            pool.map(lambda item: gateway.execute(item, make_context((capability,))), requests)
        )
    assert sorted(result.status.value for result in results) == ["EXECUTED", "FAILED"]
    assert gateway.snapshot().balances_usd["USDT"] == Decimal("4000")


def test_concurrent_approval_consumption_executes_exactly_once() -> None:
    manager = ApprovalManager(allowed_authorities=frozenset({"human:alice"}))
    gateway = ExecutionGateway(approval_verifier=manager)
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    request = make_request(
        "withdraw_asset",
        {"asset": "USDT", "destination": "wallet", "amount_usd": "100"},
    )
    context = make_context((capability,))
    pending = gateway.execute(request, context)
    assert pending.approval_id is not None
    manager.approve(pending.approval_id, authority="human:alice", at=NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(lambda _: gateway.execute(request, context), range(8)))

    assert sum(result.status is GatewayStatus.EXECUTED for result in results) == 1
    assert sum(result.status is GatewayStatus.REPLAYED for result in results) == 7
    assert len(gateway.snapshot().transactions) == 1


def test_concurrent_jsonl_audit_writes_remain_parseable(tmp_path: Path) -> None:
    recorder = JsonlAuditRecorder(tmp_path / "audit.jsonl")
    gateway = ExecutionGateway(audit_recorder=recorder)
    with ThreadPoolExecutor(max_workers=8) as pool:
        tuple(
            pool.map(
                lambda index: gateway.execute(make_request(f"unknown-{index}", {}), make_context()),
                range(40),
            )
        )
    assert len(recorder.events) == 40
    assert all(event.status is GatewayStatus.BLOCKED for event in recorder.events)


def test_performance_profile_records_percentiles_and_throughput() -> None:
    artifact = run_performance_profile(iterations=20, warmup_iterations=2)
    assert artifact.policy_decision_latency.sample_count == 20
    assert artifact.gateway_end_to_end_latency.sample_count == 20
    assert artifact.policy_decision_latency.p50_ms <= artifact.policy_decision_latency.p99_ms
    assert artifact.gateway_end_to_end_latency.p50_ms <= artifact.gateway_end_to_end_latency.p99_ms
    assert artifact.gateway_throughput_requests_per_second > 0
