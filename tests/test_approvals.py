from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from conftest import NOW, make_context, make_request

from agent_firewall.domain import Capability, CapabilityName, SecurityContext, ToolRequest
from agent_firewall.gateway import (
    ApprovalError,
    ApprovalErrorCode,
    ApprovalManager,
    ApprovalStatus,
    ExecutionGateway,
    GatewayStatus,
)


def _withdrawal(amount: str = "100") -> ToolRequest:
    return make_request(
        "withdraw_asset",
        {"asset": "USDT", "destination": "wallet", "amount_usd": amount},
    )


def _context(*, at: datetime = NOW) -> SecurityContext:
    capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-1")
    return make_context((capability,), evaluated_at=at)


def test_exact_approval_executes_once_and_cannot_be_replayed() -> None:
    manager = ApprovalManager(allowed_authorities=frozenset({"human:alice"}))
    gateway = ExecutionGateway(approval_verifier=manager)
    before = gateway.snapshot()

    pending = gateway.execute(_withdrawal(), _context())
    assert pending.status is GatewayStatus.AWAITING_APPROVAL
    assert pending.approval_status is ApprovalStatus.PENDING
    assert pending.approval_id is not None
    assert gateway.snapshot() == before

    manager.approve(pending.approval_id, authority="human:alice", at=NOW)
    executed = gateway.execute(_withdrawal(), _context(at=NOW + timedelta(seconds=1)))
    assert executed.status is GatewayStatus.EXECUTED
    assert executed.approval_verified is True
    assert executed.approval_status is ApprovalStatus.CONSUMED
    assert gateway.snapshot().balances_usd["USDT"] == Decimal("9900")

    replay = gateway.execute(_withdrawal(), _context(at=NOW + timedelta(seconds=2)))
    assert replay.status is GatewayStatus.REPLAYED
    assert replay.approval_id == pending.approval_id
    assert len(gateway.snapshot().transactions) == 1


def test_approval_is_bound_to_arguments_and_agent_identity() -> None:
    manager = ApprovalManager(allowed_authorities=frozenset({"human:alice"}))
    gateway = ExecutionGateway(approval_verifier=manager)
    pending = gateway.execute(_withdrawal("100"), _context())
    assert pending.approval_id is not None
    manager.approve(pending.approval_id, authority="human:alice", at=NOW)

    changed = gateway.execute(_withdrawal("101"), _context(at=NOW + timedelta(seconds=1)))
    assert changed.status is GatewayStatus.AWAITING_APPROVAL
    assert changed.approval_id != pending.approval_id

    other_request = _withdrawal("100").model_copy(update={"agent_id": "agent-2"})
    other_capability = Capability(name=CapabilityName.WITHDRAWALS_CREATE, agent_id="agent-2")
    other_context = _context(at=NOW + timedelta(seconds=2)).model_copy(
        update={
            "identity": _context().identity.model_copy(update={"agent_id": "agent-2"}),
            "capabilities": (other_capability,),
        }
    )
    other = gateway.execute(other_request, other_context)
    assert other.status is GatewayStatus.AWAITING_APPROVAL
    assert other.approval_id not in {pending.approval_id, changed.approval_id}


def test_expired_rejected_and_unauthorized_approvals_fail_closed() -> None:
    manager = ApprovalManager(
        allowed_authorities=frozenset({"human:alice"}),
        default_ttl=timedelta(seconds=2),
    )
    gateway = ExecutionGateway(approval_verifier=manager)
    pending = gateway.execute(_withdrawal(), _context())
    assert pending.approval_id is not None

    with pytest.raises(ApprovalError) as unauthorized:
        manager.approve(pending.approval_id, authority="model", at=NOW)
    assert unauthorized.value.code is ApprovalErrorCode.UNAUTHORIZED_APPROVER

    with pytest.raises(ApprovalError) as expired:
        manager.approve(
            pending.approval_id,
            authority="human:alice",
            at=NOW + timedelta(seconds=2),
        )
    assert expired.value.code is ApprovalErrorCode.APPROVAL_EXPIRED
    assert manager.get(pending.approval_id).status is ApprovalStatus.EXPIRED

    new_pending = gateway.execute(_withdrawal(), _context(at=NOW + timedelta(seconds=3)))
    assert new_pending.approval_id is not None
    manager.reject(
        new_pending.approval_id,
        authority="human:alice",
        at=NOW + timedelta(seconds=3),
    )
    retry = gateway.execute(_withdrawal(), _context(at=NOW + timedelta(seconds=4)))
    assert retry.status is GatewayStatus.AWAITING_APPROVAL
    assert retry.approval_id != new_pending.approval_id
    assert gateway.snapshot().transactions == ()


def test_approval_ledger_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "approvals.json"
    manager = ApprovalManager(allowed_authorities=frozenset({"human:alice"}), storage_path=path)
    gateway = ExecutionGateway(approval_verifier=manager)
    pending = gateway.execute(_withdrawal(), _context())
    assert pending.approval_id is not None
    manager.approve(pending.approval_id, authority="human:alice", at=NOW)

    loaded = ApprovalManager.from_file(path)
    assert loaded.get(pending.approval_id).status is ApprovalStatus.APPROVED
    assert loaded.get(pending.approval_id).authority == "human:alice"
