"""Execution and audit result models for the secure gateway."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.domain import (
    CapabilityName,
    Decision,
    DecisionReason,
    PolicyDecision,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.gateway.approval import ApprovalStatus
from agent_firewall.sandbox import ToolResult


class GatewayStatus(StrEnum):
    BLOCKED = "BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    REPLAYED = "REPLAYED"


class GatewayErrorCode(StrEnum):
    APPROVAL_VERIFICATION_FAILED = "APPROVAL_VERIFICATION_FAILED"
    AUDIT_RECORDING_FAILED = "AUDIT_RECORDING_FAILED"
    MISSING_NORMALIZED_ARGUMENTS = "MISSING_NORMALIZED_ARGUMENTS"
    INTERNAL_EXECUTION_ERROR = "INTERNAL_EXECUTION_ERROR"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"


class GatewayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayAuditEvent(GatewayModel):
    event_id: str
    trace_id: str
    run_id: str
    agent_id: str
    tool: str
    timestamp: datetime
    request: ToolRequest
    security_context: SecurityContext
    runtime_constraints: tuple[dict[str, Any], ...] = ()
    normalized_arguments: dict[str, Any] | None = None
    required_capability: CapabilityName | None = None
    policies_evaluated: tuple[str, ...]
    matched_policy: str
    policy_decision: PolicyDecision
    decision: Decision
    reason: DecisionReason
    status: GatewayStatus
    approval_verified: bool
    approval_id: str | None = None
    approval_status: ApprovalStatus | None = None
    decision_latency_ms: float = Field(ge=0)
    error_code: str | None = None
    previous_event_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    event_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class GatewayResult(GatewayModel):
    decision: PolicyDecision
    status: GatewayStatus
    approval_verified: bool = False
    approval_id: str | None = None
    approval_status: ApprovalStatus | None = None
    result: ToolResult | None = None
    error_code: str | None = None
    decision_latency_ms: float = Field(default=0, ge=0)
