"""Deterministic and scripted providers for local runs and tests."""

from __future__ import annotations

import re
from collections import deque

from agent_firewall.agent.models import (
    AgentTask,
    ModelTurn,
    ProposedToolCall,
    ToolOutcome,
    ToolSpec,
)
from agent_firewall.agent.provider import ModelSession


class ScriptedProvider:
    """Return predefined model turns without network or paid APIs."""

    def __init__(self, turns: tuple[ModelTurn, ...]) -> None:
        self._turns = turns

    def start_session(
        self,
        *,
        task: AgentTask,
        tools: tuple[ToolSpec, ...],
        system_instruction: str,
    ) -> ModelSession:
        del task, tools, system_instruction
        return _ScriptedSession(self._turns)


class _ScriptedSession:
    def __init__(self, turns: tuple[ModelTurn, ...]) -> None:
        self._turns = deque(turns)

    def next_turn(self, outcomes: tuple[ToolOutcome, ...] = ()) -> ModelTurn:
        del outcomes
        if not self._turns:
            return ModelTurn(text="Script completed.")
        return self._turns.popleft()


class DeterministicFinancialProvider:
    """Parse a small documented command set for deterministic demonstrations."""

    def start_session(
        self,
        *,
        task: AgentTask,
        tools: tuple[ToolSpec, ...],
        system_instruction: str,
    ) -> ModelSession:
        del tools, system_instruction
        return _DeterministicSession(task)


class _DeterministicSession:
    def __init__(self, task: AgentTask) -> None:
        self._task = task
        self._planned = False

    def next_turn(self, outcomes: tuple[ToolOutcome, ...] = ()) -> ModelTurn:
        if outcomes:
            return ModelTurn(text=f"Processed {len(outcomes)} protected tool result(s).")
        if self._planned:
            return ModelTurn(text="No additional action required.")
        self._planned = True
        proposal = self._plan(self._task.user_instruction)
        if proposal is None:
            return ModelTurn(text="No supported financial action was requested.")
        return ModelTurn(tool_calls=(proposal,))

    @staticmethod
    def _plan(instruction: str) -> ProposedToolCall | None:
        lowered = instruction.lower()
        if "portfolio" in lowered:
            return _call("get_portfolio", {})
        if "open order" in lowered:
            symbol = _symbol(lowered)
            return _call("get_open_orders", {"symbol": symbol} if symbol else {})
        if "price" in lowered:
            symbol = _symbol(lowered) or "BTCUSDT"
            return _call("get_market_price", {"symbol": symbol})

        cancel = re.search(r"cancel\s+(order-[0-9]+)", lowered)
        if cancel:
            return _call("cancel_order", {"order_id": cancel.group(1)})

        order = re.search(r"\b(buy|sell)\b.*?\$?([0-9]+(?:\.[0-9]+)?)", lowered)
        if order:
            return _call(
                "create_order",
                {
                    "symbol": _symbol(lowered) or "BTCUSDT",
                    "side": order.group(1).upper(),
                    "notional_usd": order.group(2),
                    "order_type": "MARKET",
                },
            )

        withdrawal = re.search(r"withdraw.*?\$?([0-9]+(?:\.[0-9]+)?)", lowered)
        if withdrawal:
            return _call(
                "withdraw_asset",
                {
                    "asset": "USDT",
                    "destination": "requested-wallet",
                    "amount_usd": withdrawal.group(1),
                },
            )
        return None


def _call(name: str, arguments: dict[str, object]) -> ProposedToolCall:
    return ProposedToolCall(call_id="deterministic-call-1", name=name, arguments=arguments)


def _symbol(text: str) -> str | None:
    if "eth" in text:
        return "ETHUSDT"
    if "btc" in text or "bitcoin" in text:
        return "BTCUSDT"
    return None
