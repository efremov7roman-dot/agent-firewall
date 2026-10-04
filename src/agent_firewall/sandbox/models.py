"""Immutable models returned by the deterministic financial sandbox."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.domain.schemas import OrderSide, OrderType


class SandboxModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OrderStatus(StrEnum):
    OPEN = "OPEN"
    CANCELLED = "CANCELLED"


class TransactionKind(StrEnum):
    TRANSFER = "TRANSFER"
    WITHDRAWAL = "WITHDRAWAL"


class MarketPrice(SandboxModel):
    symbol: str
    price_usd: Decimal = Field(gt=0)


class OrderRecord(SandboxModel):
    order_id: str
    symbol: str
    side: OrderSide
    notional_usd: Decimal = Field(gt=0)
    order_type: OrderType
    price: Decimal | None = Field(default=None, gt=0)
    status: OrderStatus
    owner_principal: str
    environment: str


class TransactionRecord(SandboxModel):
    transaction_id: str
    kind: TransactionKind
    asset: str
    destination: str
    amount_usd: Decimal = Field(gt=0)
    owner_principal: str
    environment: str


class PortfolioView(SandboxModel):
    owner_principal: str
    environment: str
    balances_usd: dict[str, Decimal]
    positions: dict[str, Decimal]


class OpenOrdersView(SandboxModel):
    owner_principal: str
    environment: str
    orders: tuple[OrderRecord, ...]


class SandboxSnapshot(SandboxModel):
    balances_usd: dict[str, Decimal]
    positions: dict[str, Decimal]
    orders: tuple[OrderRecord, ...]
    transactions: tuple[TransactionRecord, ...]


ToolResult = MarketPrice | PortfolioView | OpenOrdersView | OrderRecord | TransactionRecord
