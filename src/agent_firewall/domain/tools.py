"""Typed tool definitions and the deterministic initial registry."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from agent_firewall.domain.models import ApprovalKind, ApprovalRequirement, CapabilityName
from agent_firewall.domain.schemas import (
    CancelOrderArguments,
    CreateOrderArguments,
    EmptyArguments,
    OpenOrdersArguments,
    SymbolArguments,
    TransferAssetArguments,
    WithdrawAssetArguments,
)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    required_capability: CapabilityName
    arguments_model: type[BaseModel]
    symbol_field: str | None = None
    amount_field: str | None = None
    approval_requirement: ApprovalRequirement | None = None
    destination_field: str | None = None
    state_changing: bool = False
    resolves_resource: bool = False


class ToolRegistry:
    """Immutable-by-convention registry used by the security kernel."""

    def __init__(self, definitions: tuple[ToolDefinition, ...]) -> None:
        self._definitions = {definition.name: definition for definition in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("tool names must be unique")

    def get(self, name: str) -> ToolDefinition | None:
        return self._definitions.get(name)

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions.values())


INITIAL_TOOL_REGISTRY = ToolRegistry(
    (
        ToolDefinition(
            "get_market_price",
            CapabilityName.MARKET_READ,
            SymbolArguments,
            symbol_field="symbol",
        ),
        ToolDefinition("get_portfolio", CapabilityName.PORTFOLIO_READ, EmptyArguments),
        ToolDefinition(
            "get_open_orders",
            CapabilityName.ORDERS_READ,
            OpenOrdersArguments,
            symbol_field="symbol",
        ),
        ToolDefinition(
            "create_order",
            CapabilityName.ORDERS_CREATE,
            CreateOrderArguments,
            symbol_field="symbol",
            amount_field="notional_usd",
            state_changing=True,
        ),
        ToolDefinition(
            "cancel_order",
            CapabilityName.ORDERS_CANCEL,
            CancelOrderArguments,
            state_changing=True,
            resolves_resource=True,
        ),
        ToolDefinition(
            "transfer_asset",
            CapabilityName.TRANSFERS_CREATE,
            TransferAssetArguments,
            symbol_field="asset",
            amount_field="amount_usd",
            destination_field="destination_account",
            state_changing=True,
        ),
        ToolDefinition(
            "withdraw_asset",
            CapabilityName.WITHDRAWALS_CREATE,
            WithdrawAssetArguments,
            symbol_field="asset",
            amount_field="amount_usd",
            destination_field="destination",
            state_changing=True,
            approval_requirement=ApprovalRequirement(
                kind=ApprovalKind.ALWAYS,
                policy_id="P08",
            ),
        ),
    )
)
