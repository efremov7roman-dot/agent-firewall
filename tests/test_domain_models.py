from datetime import datetime
from decimal import Decimal

import pytest
from conftest import NOW
from pydantic import ValidationError

from agent_firewall.domain import (
    AgentIdentity,
    ApprovalKind,
    ApprovalRequirement,
    Capability,
    CapabilityConstraint,
    CapabilityName,
    SecurityContext,
)


def test_capability_constraints_normalize_symbols_and_preserve_decimal() -> None:
    constraints = CapabilityConstraint(
        allowed_symbols=frozenset({" btcusdt ", "ETHUSDT"}),
        max_notional_usd=Decimal("1000.00"),
    )

    assert constraints.allowed_symbols == frozenset({"BTCUSDT", "ETHUSDT"})
    assert constraints.max_notional_usd == Decimal("1000.00")


def test_naive_expiration_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Capability(
            name=CapabilityName.ORDERS_CREATE,
            agent_id="agent-1",
            expires_at=datetime(2026, 10, 2),
        )


def test_duplicate_capability_grants_are_rejected() -> None:
    grant = Capability(name=CapabilityName.ORDERS_CREATE, agent_id="agent-1")

    with pytest.raises(ValidationError, match="duplicate capabilities"):
        SecurityContext(
            identity=AgentIdentity(agent_id="agent-1", principal="demo", environment="sandbox"),
            capabilities=(grant, grant),
            evaluated_at=NOW,
        )


def test_approval_requirement_enforces_kind_shape() -> None:
    with pytest.raises(ValidationError, match="requires threshold"):
        ApprovalRequirement(kind=ApprovalKind.ABOVE_AMOUNT, policy_id="P07")
