from __future__ import annotations

import json
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from conftest import NOW
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_firewall.domain import (
    AgentIdentity,
    Capability,
    CapabilityConstraint,
    CapabilityName,
    DecisionReason,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.gateway import (
    ApprovalManager,
    ExecutionGateway,
    GatewayAuditEvent,
    GatewayStatus,
    InMemoryAuditRecorder,
    JsonlAuditRecorder,
)
from agent_firewall.sandbox import OpenOrdersView, OrderRecord, PortfolioView


class _FailSecondAuditRecorder:
    def __init__(self) -> None:
        self._events: list[GatewayAuditEvent] = []

    @property
    def events(self) -> tuple[GatewayAuditEvent, ...]:
        return tuple(self._events)

    def record(self, event: GatewayAuditEvent) -> None:
        if len(self._events) == 1:
            raise OSError("terminal audit unavailable")
        self._events.append(event)


def _context(
    agent_id: str,
    principal: str,
    capabilities: tuple[Capability, ...],
    *,
    environment: str = "sandbox",
    at: datetime = NOW,
) -> SecurityContext:
    return SecurityContext(
        identity=AgentIdentity(
            agent_id=agent_id,
            principal=principal,
            environment=environment,
        ),
        capabilities=capabilities,
        evaluated_at=at,
    )


def _cap(
    name: CapabilityName,
    agent_id: str,
    *,
    allowed_symbols: frozenset[str] | None = None,
    max_notional_usd: Decimal | None = None,
    max_transfer_amount_usd: Decimal | None = None,
    allowed_resource_principals: frozenset[str] | None = None,
    allowed_destinations: frozenset[str] | None = None,
    max_aggregate_amount_usd: Decimal | None = None,
) -> Capability:
    return Capability(
        name=name,
        agent_id=agent_id,
        constraints=CapabilityConstraint(
            allowed_symbols=allowed_symbols,
            max_notional_usd=max_notional_usd,
            max_transfer_amount_usd=max_transfer_amount_usd,
            allowed_resource_principals=allowed_resource_principals,
            allowed_destinations=allowed_destinations,
            max_aggregate_amount_usd=max_aggregate_amount_usd,
        ),
    )


def _request(
    agent_id: str,
    tool: str,
    arguments: dict[str, object],
    *,
    trace_id: str = "phase9",
    idempotency_key: str | None = None,
) -> ToolRequest:
    return ToolRequest(
        trace_id=trace_id,
        agent_id=agent_id,
        tool=tool,
        arguments=arguments,
        idempotency_key=idempotency_key,
    )


def _order(amount: str = "10", symbol: str = "BTCUSDT") -> dict[str, object]:
    return {
        "symbol": symbol,
        "side": "BUY",
        "notional_usd": amount,
        "order_type": "MARKET",
    }


def _transfer(amount: str, destination: str = "savings") -> dict[str, object]:
    return {
        "asset": "USDT",
        "destination_account": destination,
        "amount_usd": amount,
    }


def _withdraw(amount: str = "100") -> dict[str, object]:
    return {"asset": "USDT", "destination": "wallet", "amount_usd": amount}


def test_principal_accounts_and_portfolios_are_isolated() -> None:
    gateway = ExecutionGateway()
    transfer = _cap(
        CapabilityName.TRANSFERS_CREATE,
        "agent-a",
        max_transfer_amount_usd=Decimal("100"),
    )
    context_a = _context("agent-a", "principal-a", (transfer,))
    moved = gateway.execute(_request("agent-a", "transfer_asset", _transfer("100")), context_a)
    assert moved.status is GatewayStatus.EXECUTED

    read = _cap(CapabilityName.PORTFOLIO_READ, "agent-b")
    context_b = _context("agent-b", "principal-b", (read,))
    portfolio = gateway.execute(_request("agent-b", "get_portfolio", {}), context_b)
    assert isinstance(portfolio.result, PortfolioView)
    assert portfolio.result.owner_principal == "principal-b"
    assert portfolio.result.balances_usd["USDT"] == Decimal("10000")
    assert gateway.snapshot(principal="principal-a").balances_usd["USDT"] == Decimal("9900")


def test_open_orders_are_filtered_by_authoritative_owner() -> None:
    gateway = ExecutionGateway()
    owner = _context(
        "agent-a",
        "principal-a",
        (_cap(CapabilityName.ORDERS_CREATE, "agent-a"),),
    )
    gateway.execute(_request("agent-a", "create_order", _order()), owner)
    reader = _context(
        "agent-b",
        "principal-b",
        (_cap(CapabilityName.ORDERS_READ, "agent-b"),),
    )
    result = gateway.execute(_request("agent-b", "get_open_orders", {}), reader)
    assert isinstance(result.result, OpenOrdersView)
    assert result.result.orders == ()


def test_cross_principal_cancellation_is_blocked() -> None:
    gateway = ExecutionGateway()
    owner = _context(
        "agent-a",
        "principal-a",
        (_cap(CapabilityName.ORDERS_CREATE, "agent-a"),),
    )
    created = gateway.execute(_request("agent-a", "create_order", _order()), owner)
    assert isinstance(created.result, OrderRecord)
    attacker = _context(
        "agent-b",
        "principal-b",
        (_cap(CapabilityName.ORDERS_CANCEL, "agent-b"),),
    )
    result = gateway.execute(
        _request("agent-b", "cancel_order", {"order_id": created.result.order_id}),
        attacker,
    )
    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.RESOURCE_SCOPE_VIOLATION


def test_explicit_cross_principal_scope_can_delegate_cancellation() -> None:
    gateway = ExecutionGateway()
    owner = _context(
        "agent-a",
        "principal-a",
        (_cap(CapabilityName.ORDERS_CREATE, "agent-a"),),
    )
    created = gateway.execute(_request("agent-a", "create_order", _order()), owner)
    assert isinstance(created.result, OrderRecord)
    delegated = _context(
        "agent-b",
        "principal-b",
        (
            _cap(
                CapabilityName.ORDERS_CANCEL,
                "agent-b",
                allowed_resource_principals=frozenset({"principal-a"}),
            ),
        ),
    )
    result = gateway.execute(
        _request("agent-b", "cancel_order", {"order_id": created.result.order_id}),
        delegated,
    )
    assert result.status is GatewayStatus.EXECUTED


def test_cancellation_uses_resolved_order_symbol() -> None:
    gateway = ExecutionGateway()
    creator = _context(
        "agent",
        "principal",
        (_cap(CapabilityName.ORDERS_CREATE, "agent"),),
    )
    created = gateway.execute(_request("agent", "create_order", _order(symbol="ETHUSDT")), creator)
    assert isinstance(created.result, OrderRecord)
    cancel = _context(
        "agent",
        "principal",
        (
            _cap(
                CapabilityName.ORDERS_CANCEL,
                "agent",
                allowed_symbols=frozenset({"BTCUSDT"}),
            ),
        ),
    )
    result = gateway.execute(
        _request("agent", "cancel_order", {"order_id": created.result.order_id}), cancel
    )
    assert result.status is GatewayStatus.BLOCKED
    assert result.decision.reason is DecisionReason.SYMBOL_SCOPE_VIOLATION


def test_approval_is_bound_to_principal_and_environment() -> None:
    manager = ApprovalManager(allowed_authorities=frozenset({"human:reviewer"}))
    gateway = ExecutionGateway(approval_verifier=manager)
    capability = _cap(CapabilityName.WITHDRAWALS_CREATE, "agent")
    original = _context("agent", "principal-a", (capability,))
    request = _request("agent", "withdraw_asset", _withdraw())
    pending = gateway.execute(request, original)
    assert pending.approval_id is not None
    manager.approve(pending.approval_id, authority="human:reviewer", at=NOW)

    other_principal = gateway.execute(
        request,
        _context(
            "agent",
            "principal-b",
            (capability,),
            at=NOW + timedelta(seconds=1),
        ),
    )
    other_environment = gateway.execute(
        request,
        _context(
            "agent",
            "principal-a",
            (capability,),
            environment="production",
            at=NOW + timedelta(seconds=1),
        ),
    )
    assert other_principal.status is GatewayStatus.AWAITING_APPROVAL
    assert other_environment.status is GatewayStatus.AWAITING_APPROVAL


def test_persisted_approval_is_atomic_across_manager_instances(tmp_path: Path) -> None:
    ledger = tmp_path / "approvals.json"
    manager = ApprovalManager(
        allowed_authorities=frozenset({"human:reviewer"}), storage_path=ledger
    )
    capability = _cap(CapabilityName.WITHDRAWALS_CREATE, "agent")
    context = _context("agent", "principal", (capability,))
    request = _request("agent", "withdraw_asset", _withdraw())
    pending = ExecutionGateway(approval_verifier=manager).execute(request, context)
    assert pending.approval_id is not None
    manager.approve(pending.approval_id, authority="human:reviewer", at=NOW)
    first_manager = ApprovalManager.from_file(ledger)
    second_manager = ApprovalManager.from_file(ledger)

    first = ExecutionGateway(approval_verifier=first_manager).execute(request, context)
    second = ExecutionGateway(approval_verifier=second_manager).execute(request, context)
    assert first.status is GatewayStatus.EXECUTED
    assert second.status is GatewayStatus.AWAITING_APPROVAL


def test_same_idempotency_identity_executes_once_and_conflicts_fail_closed() -> None:
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.TRANSFERS_CREATE,
        "agent",
        max_transfer_amount_usd=Decimal("100"),
    )
    context = _context("agent", "principal", (capability,))
    request = _request(
        "agent",
        "transfer_asset",
        _transfer("50"),
        idempotency_key="logical-payment-1",
    )
    first = gateway.execute(request, context)
    replay = gateway.execute(request, context)
    conflict = gateway.execute(request.model_copy(update={"arguments": _transfer("51")}), context)
    assert first.status is GatewayStatus.EXECUTED
    assert replay.status is GatewayStatus.REPLAYED
    assert conflict.status is GatewayStatus.BLOCKED
    assert conflict.decision.reason is DecisionReason.IDEMPOTENCY_CONFLICT
    assert len(gateway.snapshot().transactions) == 1


def test_aggregate_limit_is_checked_atomically_with_state_mutation() -> None:
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.ORDERS_CREATE,
        "agent",
        max_notional_usd=Decimal("250"),
        max_aggregate_amount_usd=Decimal("250"),
    )
    context = _context("agent", "principal", (capability,))
    first = gateway.execute(
        _request("agent", "create_order", _order("150"), idempotency_key="order-1"),
        context,
    )
    second = gateway.execute(
        _request("agent", "create_order", _order("101"), idempotency_key="order-2"),
        context,
    )
    assert first.status is GatewayStatus.EXECUTED
    assert second.status is GatewayStatus.BLOCKED
    assert second.decision.reason is DecisionReason.AGGREGATE_LIMIT_EXCEEDED
    assert len(gateway.snapshot().orders) == 1


def test_destination_allowlist_blocks_asset_movement() -> None:
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.TRANSFERS_CREATE,
        "agent",
        max_transfer_amount_usd=Decimal("100"),
        allowed_destinations=frozenset({"treasury"}),
    )
    context = _context("agent", "principal", (capability,))
    before = gateway.snapshot()
    denied = gateway.execute(
        _request("agent", "transfer_asset", _transfer("50", "attacker")), context
    )
    allowed = gateway.execute(
        _request(
            "agent",
            "transfer_asset",
            _transfer("50", "treasury"),
            idempotency_key="treasury-payment",
        ),
        context,
    )
    assert denied.status is GatewayStatus.BLOCKED
    assert denied.decision.reason is DecisionReason.DESTINATION_SCOPE_VIOLATION
    assert allowed.status is GatewayStatus.EXECUTED
    assert before.balances_usd["USDT"] - gateway.snapshot().balances_usd["USDT"] == 50


def test_audit_redaction_immutability_completeness_and_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = JsonlAuditRecorder(path)
    gateway = ExecutionGateway(audit_recorder=recorder)
    capability = _cap(CapabilityName.ORDERS_CREATE, "agent")
    context = _context("agent", "principal", (capability,))
    result = gateway.execute(
        _request("agent", "create_order", _order()),
        context,
    )
    assert result.status is GatewayStatus.EXECUTED
    assert [event.status for event in recorder.events] == [
        GatewayStatus.AUTHORIZED,
        GatewayStatus.EXECUTED,
    ]
    assert recorder.verify_integrity()

    assert result.decision.normalized_arguments is not None
    result.decision.normalized_arguments["notional_usd"] = Decimal("999")
    assert recorder.events[-1].normalized_arguments is not None
    assert recorder.events[-1].normalized_arguments["notional_usd"] == "10"

    blocked = gateway.execute(
        _request(
            "agent",
            "unknown_tool",
            {"access_key": "top-secret", "nested": ({"api_key": "nested-secret"},)},
        ),
        _context("agent", "principal", ()),
    )
    assert blocked.status is GatewayStatus.BLOCKED
    serialized = path.read_text(encoding="utf-8")
    assert "top-secret" not in serialized
    assert "nested-secret" not in serialized
    assert recorder.verify_integrity()

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["tool"] = "tampered"
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not recorder.verify_integrity()


def test_in_memory_audit_recorder_returns_deep_copies() -> None:
    recorder = InMemoryAuditRecorder()
    gateway = ExecutionGateway(audit_recorder=recorder)
    capability = _cap(CapabilityName.ORDERS_CREATE, "agent")
    result = gateway.execute(
        _request("agent", "create_order", _order()),
        _context("agent", "principal", (capability,)),
    )
    assert result.decision.normalized_arguments is not None
    result.decision.normalized_arguments["notional_usd"] = Decimal("900")
    assert recorder.events[-1].normalized_arguments is not None
    assert recorder.events[-1].normalized_arguments["notional_usd"] == Decimal("10")
    assert recorder.verify_integrity()


def test_post_execution_audit_failure_is_explicit_but_not_atomic() -> None:
    recorder = _FailSecondAuditRecorder()
    gateway = ExecutionGateway(audit_recorder=recorder)
    capability = _cap(CapabilityName.ORDERS_CREATE, "agent")
    result = gateway.execute(
        _request("agent", "create_order", _order()),
        _context("agent", "principal", (capability,)),
    )
    assert result.status is GatewayStatus.EXECUTED
    assert result.error_code == "AUDIT_RECORDING_FAILED"
    assert [event.status for event in recorder.events] == [GatewayStatus.AUTHORIZED]
    assert len(gateway.snapshot().orders) == 1


@given(
    owner=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
    attacker=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
)
@settings(max_examples=50)
def test_property_foreign_principals_cannot_cancel(owner: str, attacker: str) -> None:
    if owner == attacker:
        return
    gateway = ExecutionGateway()
    owner_context = _context(
        "owner-agent",
        owner,
        (_cap(CapabilityName.ORDERS_CREATE, "owner-agent"),),
    )
    created = gateway.execute(_request("owner-agent", "create_order", _order()), owner_context)
    assert isinstance(created.result, OrderRecord)
    attacker_context = _context(
        "attacker-agent",
        attacker,
        (_cap(CapabilityName.ORDERS_CANCEL, "attacker-agent"),),
    )
    denied = gateway.execute(
        _request("attacker-agent", "cancel_order", {"order_id": created.result.order_id}),
        attacker_context,
    )
    assert denied.status is GatewayStatus.BLOCKED


@given(
    first=st.decimals(min_value=Decimal("0.01"), max_value=Decimal("99.99"), places=2),
    excess=st.decimals(min_value=Decimal("0.01"), max_value=Decimal("100"), places=2),
)
@settings(max_examples=60)
def test_property_aggregate_overage_never_mutates(first: Decimal, excess: Decimal) -> None:
    limit = first + excess - Decimal("0.01")
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.ORDERS_CREATE,
        "agent",
        max_notional_usd=Decimal("200"),
        max_aggregate_amount_usd=limit,
    )
    context = _context("agent", "principal", (capability,))
    gateway.execute(
        _request("agent", "create_order", _order(str(first)), idempotency_key="first"),
        context,
    )
    before = gateway.snapshot()
    denied = gateway.execute(
        _request("agent", "create_order", _order(str(excess)), idempotency_key="excess"),
        context,
    )
    assert denied.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before


@given(
    destination=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=20).filter(
        lambda value: value != "trusted"
    )
)
@settings(max_examples=50)
def test_property_unauthorized_destinations_never_move_assets(destination: str) -> None:
    gateway = ExecutionGateway()
    capability = _cap(
        CapabilityName.TRANSFERS_CREATE,
        "agent",
        max_transfer_amount_usd=Decimal("100"),
        allowed_destinations=frozenset({"trusted"}),
    )
    context = _context("agent", "principal", (capability,))
    before = gateway.snapshot()
    denied = gateway.execute(
        _request("agent", "transfer_asset", _transfer("1", destination)), context
    )
    assert denied.status is GatewayStatus.BLOCKED
    assert gateway.snapshot() == before
