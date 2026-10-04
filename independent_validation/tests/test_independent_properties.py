"""Property tests authored independently for the Phase 8 validation."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given, settings
from hypothesis import strategies as st

from agent_firewall.domain import CapabilityName
from agent_firewall.gateway import ApprovalManager, ExecutionGateway, GatewayStatus
from independent_validation.runner import (
    ADVERSARIAL_HANDLERS,
    BENIGN_HANDLERS,
    NOW,
    SCENARIO_ROOT,
    _cap,
    _context,
    _load_definitions,
    _order,
    _request,
    _transfer,
    _withdraw,
)


@given(
    amount=st.decimals(
        min_value=Decimal("100.000000000000000001"),
        max_value=Decimal("1000000000000"),
        allow_nan=False,
        allow_infinity=False,
    )
)
@settings(max_examples=80)
def test_amounts_above_maximum_never_execute_or_mutate(amount: Decimal) -> None:
    gateway = ExecutionGateway()
    capability = _cap(CapabilityName.ORDERS_CREATE, "agent", max_notional="100")
    before = gateway.snapshot()
    result = gateway.execute(
        _request("property-over-limit", "agent", "create_order", _order(str(amount))),
        _context("agent", "principal", (capability,)),
    )
    assert result.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before


@given(age_microseconds=st.integers(min_value=0, max_value=10**12))
@settings(max_examples=60)
def test_expired_capabilities_never_execute(age_microseconds: int) -> None:
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.TRANSFERS_CREATE,
        "agent",
        max_transfer="100",
        expires_at=NOW - timedelta(microseconds=age_microseconds),
    )
    before = gateway.snapshot()
    result = gateway.execute(
        _request("property-expiry", "agent", "transfer_asset", _transfer("1")),
        _context("agent", "principal", (capability,)),
    )
    assert result.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before


@given(
    amount=st.decimals(
        min_value=Decimal("0.000000000000000001"),
        max_value=Decimal("10000"),
        allow_nan=False,
        allow_infinity=False,
    )
)
@settings(max_examples=60)
def test_denied_requests_leave_state_unchanged(amount: Decimal) -> None:
    gateway = ExecutionGateway()
    before = gateway.snapshot()
    result = gateway.execute(
        _request("property-deny", "agent", "transfer_asset", _transfer(str(amount))),
        _context("agent", "principal"),
    )
    assert result.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before


@given(
    mutation=st.one_of(
        st.tuples(
            st.just("amount_usd"),
            st.decimals(min_value=Decimal("100.01"), max_value=Decimal("9999")),
        ),
        st.tuples(
            st.just("destination"),
            st.text(
                alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=20
            ).filter(lambda value: value != "approved-wallet"),
        ),
    )
)
@settings(max_examples=60)
def test_approval_mutations_never_execute(
    mutation: tuple[str, object],
) -> None:
    with TemporaryDirectory() as temporary_directory:
        manager = ApprovalManager(
            allowed_authorities=frozenset({"human:reviewer"}),
            storage_path=Path(temporary_directory) / "approvals.json",
        )
        capability = _cap(CapabilityName.WITHDRAWALS_CREATE, "agent")
        context = _context("agent", "principal", (capability,))
        original = _request(
            "property-approval",
            "agent",
            "withdraw_asset",
            _withdraw("100", "approved-wallet"),
        )
        gateway = ExecutionGateway(approval_verifier=manager)
        pending = gateway.execute(original, context)
        assert pending.approval_id is not None
        manager.approve(pending.approval_id, authority="human:reviewer", at=NOW)

        arguments = _withdraw("100", "approved-wallet")
        field, value = mutation
        arguments[field] = str(value)
        before = gateway.snapshot()
        result = gateway.execute(
            _request("property-approval", "agent", "withdraw_asset", arguments),
            context.model_copy(update={"evaluated_at": NOW + timedelta(seconds=1)}),
        )
        assert result.status is GatewayStatus.AWAITING_APPROVAL
        assert gateway.snapshot() == before


def test_frozen_scenario_definitions_have_exact_handler_coverage() -> None:
    assert SCENARIO_ROOT.is_dir()
    adversarial, benign = _load_definitions()
    assert {case["case"] for case in adversarial} == set(ADVERSARIAL_HANDLERS)
    assert {case["case"] for case in benign} == set(BENIGN_HANDLERS)
    assert len(adversarial) == 26
    assert len(benign) == 14
