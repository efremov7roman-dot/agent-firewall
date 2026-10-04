"""Internal deterministic financial sandbox; agent code must use the gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from threading import RLock
from typing import Any

from agent_firewall.domain import ProtectedResource
from agent_firewall.domain.schemas import OrderSide, OrderType
from agent_firewall.sandbox.models import (
    MarketPrice,
    OpenOrdersView,
    OrderRecord,
    OrderStatus,
    PortfolioView,
    SandboxSnapshot,
    ToolResult,
    TransactionKind,
    TransactionRecord,
)


class SandboxErrorCode(StrEnum):
    UNSUPPORTED_SYMBOL = "UNSUPPORTED_SYMBOL"
    UNKNOWN_ORDER = "UNKNOWN_ORDER"
    ORDER_NOT_OPEN = "ORDER_NOT_OPEN"
    INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
    UNSUPPORTED_TOOL = "UNSUPPORTED_TOOL"


class SandboxExecutionError(RuntimeError):
    def __init__(self, code: SandboxErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def _initial_balances() -> dict[str, Decimal]:
    return {
        "USD": Decimal("100000"),
        "USDT": Decimal("10000"),
        "BTC": Decimal("50000"),
        "ETH": Decimal("25000"),
    }


def _initial_positions() -> dict[str, Decimal]:
    return {"BTCUSDT": Decimal("1"), "ETHUSDT": Decimal("10")}


@dataclass
class _AccountState:
    balances_usd: dict[str, Decimal] = field(default_factory=_initial_balances)
    positions: dict[str, Decimal] = field(default_factory=_initial_positions)
    transactions: list[TransactionRecord] = field(default_factory=list)


class _FinancialSandbox:
    """Mutable state hidden behind ExecutionGateway."""

    def __init__(self) -> None:
        self._prices: dict[str, Decimal] = {
            "BTCUSDT": Decimal("50000"),
            "ETHUSDT": Decimal("2500"),
            "USDTUSD": Decimal("1"),
        }
        self._accounts: dict[tuple[str, str], _AccountState] = {}
        self._orders: dict[str, OrderRecord] = {}
        self._next_order = 1
        self._next_transaction = 1
        self._last_account: tuple[str, str] | None = None
        self._lock = RLock()

    def execute(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        principal: str,
        environment: str,
        authorized_resource: ProtectedResource | None = None,
    ) -> ToolResult:
        with self._lock:
            self._last_account = (principal, environment)
            if tool == "get_market_price":
                return self._get_market_price(arguments)
            if tool == "get_portfolio":
                return self._get_portfolio(principal, environment)
            if tool == "get_open_orders":
                return self._get_open_orders(arguments, principal, environment)
            if tool == "create_order":
                return self._create_order(arguments, principal, environment)
            if tool == "cancel_order":
                return self._cancel_order(
                    arguments, principal, environment, authorized_resource=authorized_resource
                )
            if tool == "transfer_asset":
                return self._transfer_asset(arguments, principal, environment)
            if tool == "withdraw_asset":
                return self._withdraw_asset(arguments, principal, environment)
            raise SandboxExecutionError(SandboxErrorCode.UNSUPPORTED_TOOL)

    def resolve_resource(self, tool: str, arguments: dict[str, Any]) -> ProtectedResource | None:
        with self._lock:
            if tool != "cancel_order":
                return None
            order = self._orders.get(self._string(arguments, "order_id"))
            if order is None:
                raise SandboxExecutionError(SandboxErrorCode.UNKNOWN_ORDER)
            return ProtectedResource(
                resource_id=order.order_id,
                owner_principal=order.owner_principal,
                environment=order.environment,
                symbol=order.symbol,
            )

    def snapshot(
        self,
        *,
        principal: str | None = None,
        environment: str = "sandbox",
    ) -> SandboxSnapshot:
        with self._lock:
            key = (principal, environment) if principal is not None else self._last_account
            account = self._accounts.get(key) if key is not None else None
            balances = account.balances_usd if account is not None else _initial_balances()
            positions = account.positions if account is not None else _initial_positions()
            transactions = account.transactions if account is not None else []
            orders = tuple(
                order
                for order in self._orders.values()
                if key is not None and (order.owner_principal, order.environment) == key
            )
            return SandboxSnapshot(
                balances_usd=dict(balances),
                positions=dict(positions),
                orders=orders,
                transactions=tuple(transactions),
            )

    def _get_market_price(self, arguments: dict[str, Any]) -> MarketPrice:
        symbol = self._string(arguments, "symbol")
        price = self._prices.get(symbol)
        if price is None:
            raise SandboxExecutionError(SandboxErrorCode.UNSUPPORTED_SYMBOL)
        return MarketPrice(symbol=symbol, price_usd=price)

    def _get_portfolio(self, principal: str, environment: str) -> PortfolioView:
        account = self._account(principal, environment)
        return PortfolioView(
            owner_principal=principal,
            environment=environment,
            balances_usd=dict(account.balances_usd),
            positions=dict(account.positions),
        )

    def _get_open_orders(
        self, arguments: dict[str, Any], principal: str, environment: str
    ) -> OpenOrdersView:
        symbol = arguments.get("symbol")
        orders = tuple(
            order
            for order in self._orders.values()
            if order.status is OrderStatus.OPEN
            and order.owner_principal == principal
            and order.environment == environment
            and (symbol is None or order.symbol == symbol)
        )
        return OpenOrdersView(
            owner_principal=principal,
            environment=environment,
            orders=orders,
        )

    def _create_order(
        self, arguments: dict[str, Any], principal: str, environment: str
    ) -> OrderRecord:
        symbol = self._string(arguments, "symbol")
        if symbol not in self._prices:
            raise SandboxExecutionError(SandboxErrorCode.UNSUPPORTED_SYMBOL)
        order_id = f"order-{self._next_order:06d}"
        order = OrderRecord(
            order_id=order_id,
            symbol=symbol,
            side=OrderSide(arguments["side"]),
            notional_usd=self._decimal(arguments, "notional_usd"),
            order_type=OrderType(arguments["order_type"]),
            price=self._optional_decimal(arguments, "price"),
            status=OrderStatus.OPEN,
            owner_principal=principal,
            environment=environment,
        )
        self._orders[order_id] = order
        self._next_order += 1
        return order

    def _cancel_order(
        self,
        arguments: dict[str, Any],
        principal: str,
        environment: str,
        *,
        authorized_resource: ProtectedResource | None,
    ) -> OrderRecord:
        order_id = self._string(arguments, "order_id")
        order = self._orders.get(order_id)
        if order is None:
            raise SandboxExecutionError(SandboxErrorCode.UNKNOWN_ORDER)
        authorized_owner = (
            authorized_resource.owner_principal
            if authorized_resource is not None and authorized_resource.resource_id == order.order_id
            else principal
        )
        if order.owner_principal != authorized_owner or order.environment != environment:
            raise SandboxExecutionError(SandboxErrorCode.UNKNOWN_ORDER)
        if order.status is not OrderStatus.OPEN:
            raise SandboxExecutionError(SandboxErrorCode.ORDER_NOT_OPEN)
        cancelled = order.model_copy(update={"status": OrderStatus.CANCELLED})
        self._orders[order_id] = cancelled
        return cancelled

    def _transfer_asset(
        self, arguments: dict[str, Any], principal: str, environment: str
    ) -> TransactionRecord:
        return self._move_asset(
            arguments, TransactionKind.TRANSFER, "destination_account", principal, environment
        )

    def _withdraw_asset(
        self, arguments: dict[str, Any], principal: str, environment: str
    ) -> TransactionRecord:
        return self._move_asset(
            arguments, TransactionKind.WITHDRAWAL, "destination", principal, environment
        )

    def _move_asset(
        self,
        arguments: dict[str, Any],
        kind: TransactionKind,
        destination_field: str,
        principal: str,
        environment: str,
    ) -> TransactionRecord:
        account = self._account(principal, environment)
        asset = self._string(arguments, "asset")
        amount = self._decimal(arguments, "amount_usd")
        balance = account.balances_usd.get(asset, Decimal("0"))
        if amount > balance:
            raise SandboxExecutionError(SandboxErrorCode.INSUFFICIENT_BALANCE)
        transaction_id = f"transaction-{self._next_transaction:06d}"
        transaction = TransactionRecord(
            transaction_id=transaction_id,
            kind=kind,
            asset=asset,
            destination=self._string(arguments, destination_field),
            amount_usd=amount,
            owner_principal=principal,
            environment=environment,
        )
        account.balances_usd[asset] = balance - amount
        account.transactions.append(transaction)
        self._next_transaction += 1
        return transaction

    def _account(self, principal: str, environment: str) -> _AccountState:
        return self._accounts.setdefault((principal, environment), _AccountState())

    @staticmethod
    def _string(arguments: dict[str, Any], field: str) -> str:
        value = arguments[field]
        if not isinstance(value, str):
            raise TypeError(f"normalized {field} must be a string")
        return value

    @staticmethod
    def _decimal(arguments: dict[str, Any], field: str) -> Decimal:
        value = arguments[field]
        if not isinstance(value, Decimal):
            raise TypeError(f"normalized {field} must be Decimal")
        return value

    @staticmethod
    def _optional_decimal(arguments: dict[str, Any], field: str) -> Decimal | None:
        value = arguments.get(field)
        if value is not None and not isinstance(value, Decimal):
            raise TypeError(f"normalized {field} must be Decimal or None")
        return value
