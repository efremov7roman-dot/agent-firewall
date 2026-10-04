"""Deterministic replay of recorded policy decisions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from agent_firewall.domain import PolicyDecision
from agent_firewall.gateway.models import GatewayAuditEvent, GatewayStatus
from agent_firewall.policy import PolicyEngine


class ReplayResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    original_decision: PolicyDecision
    replayed_decision: PolicyDecision
    decision_matches: bool
    execution_occurred: bool


class DecisionReplay:
    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self._policy_engine = policy_engine or PolicyEngine()

    def replay(self, event: GatewayAuditEvent) -> ReplayResult:
        replayed = self._policy_engine.evaluate(event.request, event.security_context)
        return ReplayResult(
            event_id=event.event_id,
            original_decision=event.policy_decision,
            replayed_decision=replayed,
            decision_matches=event.policy_decision == replayed,
            execution_occurred=event.status is GatewayStatus.EXECUTED,
        )
