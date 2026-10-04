"""Provider abstraction independent of any model vendor."""

from __future__ import annotations

from typing import Protocol

from agent_firewall.agent.models import AgentTask, ModelTurn, ToolOutcome, ToolSpec


class ModelSession(Protocol):
    def next_turn(self, outcomes: tuple[ToolOutcome, ...] = ()) -> ModelTurn: ...


class ModelProvider(Protocol):
    def start_session(
        self,
        *,
        task: AgentTask,
        tools: tuple[ToolSpec, ...],
        system_instruction: str,
    ) -> ModelSession: ...


class ProviderError(RuntimeError):
    """Safe provider failure without secret-bearing response bodies."""
