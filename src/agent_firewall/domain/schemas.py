"""Strict argument schemas for the initial protected tool registry."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EmptyArguments(ToolArguments):
    pass


class SymbolArguments(ToolArguments):
    symbol: str = Field(min_length=1)

    @field_validator("symbol", mode="after")
    @classmethod
    def normalize_symbol(cls, value: str) -> str:
        return value.upper()


class OpenOrdersArguments(ToolArguments):
    symbol: str | None = None

    @field_validator("symbol", mode="after")
    @classmethod
    def normalize_symbol(cls, value: str | None) -> str | None:
        return value.upper() if value is not None else None


class OrderSide(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


class OrderType(StrEnum):
    MARKET = "MARKET"
    LIMIT = "LIMIT"


class CreateOrderArguments(ToolArguments):
    symbol: str = Field(min_length=1)
    side: OrderSide
    notional_usd: Decimal = Field(gt=0)
    order_type: OrderType = OrderType.MARKET
    price: Decimal | None = Field(default=None, gt=0)

    @field_validator("symbol", mode="after")
    @classmethod
    def normalize_symbol(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def validate_price_for_order_type(self) -> CreateOrderArguments:
        if self.order_type is OrderType.LIMIT and self.price is None:
            raise ValueError("LIMIT orders require price")
        if self.order_type is OrderType.MARKET and self.price is not None:
            raise ValueError("MARKET orders cannot define price")
        return self


class CancelOrderArguments(ToolArguments):
    order_id: str = Field(min_length=1)


class TransferAssetArguments(ToolArguments):
    asset: str = Field(min_length=1)
    destination_account: str = Field(min_length=1)
    amount_usd: Decimal = Field(gt=0)

    @field_validator("asset", mode="after")
    @classmethod
    def normalize_asset(cls, value: str) -> str:
        return value.upper()


class WithdrawAssetArguments(ToolArguments):
    asset: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    amount_usd: Decimal = Field(gt=0)

    @field_validator("asset", mode="after")
    @classmethod
    def normalize_asset(cls, value: str) -> str:
        return value.upper()
