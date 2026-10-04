"""Typed domain models for deterministic authorization decisions."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FrozenModel(BaseModel):
    """Base model for immutable security inputs and outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DecisionReason(StrEnum):
    ALLOWED = "ALLOWED"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    AGENT_IDENTITY_MISMATCH = "AGENT_IDENTITY_MISMATCH"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"
    EXPIRED_CAPABILITY = "EXPIRED_CAPABILITY"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    ACTION_SCOPE_VIOLATION = "ACTION_SCOPE_VIOLATION"
    SYMBOL_SCOPE_VIOLATION = "SYMBOL_SCOPE_VIOLATION"
    NOTIONAL_LIMIT_EXCEEDED = "NOTIONAL_LIMIT_EXCEEDED"
    TRANSFER_LIMIT_EXCEEDED = "TRANSFER_LIMIT_EXCEEDED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    WITHDRAWAL_APPROVAL_REQUIRED = "WITHDRAWAL_APPROVAL_REQUIRED"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"
    RESOURCE_SCOPE_VIOLATION = "RESOURCE_SCOPE_VIOLATION"
    DESTINATION_SCOPE_VIOLATION = "DESTINATION_SCOPE_VIOLATION"
    AGGREGATE_LIMIT_EXCEEDED = "AGGREGATE_LIMIT_EXCEEDED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"


class CapabilityName(StrEnum):
    MARKET_READ = "market.read"
    PORTFOLIO_READ = "portfolio.read"
    ORDERS_READ = "orders.read"
    ORDERS_CREATE = "orders.create"
    ORDERS_CANCEL = "orders.cancel"
    TRANSFERS_CREATE = "transfers.create"
    WITHDRAWALS_CREATE = "withdrawals.create"


class ApprovalKind(StrEnum):
    ALWAYS = "ALWAYS"
    ABOVE_AMOUNT = "ABOVE_AMOUNT"


class AgentIdentity(FrozenModel):
    agent_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    environment: str = Field(min_length=1)


class ToolRequest(FrozenModel):
    trace_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=1)


class CapabilityConstraint(FrozenModel):
    allowed_symbols: frozenset[str] | None = None
    max_notional_usd: Decimal | None = Field(default=None, gt=0)
    max_transfer_amount_usd: Decimal | None = Field(default=None, gt=0)
    approval_above_usd: Decimal | None = Field(default=None, ge=0)
    environment: str | None = None
    allowed_actions: frozenset[str] | None = None
    # Phase 9 constraints are excluded from legacy dataset serialization so the frozen
    # Phase 4 fingerprint remains stable. They remain available to runtime enforcement.
    allowed_resource_principals: frozenset[str] | None = Field(default=None, exclude=True)
    allowed_destinations: frozenset[str] | None = Field(default=None, exclude=True)
    max_aggregate_amount_usd: Decimal | None = Field(default=None, gt=0, exclude=True)

    @field_validator("allowed_symbols", mode="after")
    @classmethod
    def normalize_symbols(cls, value: frozenset[str] | None) -> frozenset[str] | None:
        if value is None:
            return None
        normalized = frozenset(symbol.strip().upper() for symbol in value if symbol.strip())
        if not normalized:
            raise ValueError("allowed_symbols cannot be empty")
        return normalized

    @field_validator("allowed_actions", mode="after")
    @classmethod
    def reject_empty_actions(cls, value: frozenset[str] | None) -> frozenset[str] | None:
        if value is not None and not value:
            raise ValueError("allowed_actions cannot be empty")
        return value

    @field_validator("allowed_resource_principals", "allowed_destinations", mode="after")
    @classmethod
    def reject_empty_scopes(cls, value: frozenset[str] | None) -> frozenset[str] | None:
        if value is None:
            return None
        normalized = frozenset(item.strip() for item in value if item.strip())
        if not normalized:
            raise ValueError("explicit security scopes cannot be empty")
        return normalized


class Capability(FrozenModel):
    name: CapabilityName
    agent_id: str = Field(min_length=1)
    constraints: CapabilityConstraint = Field(default_factory=CapabilityConstraint)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value


class Policy(FrozenModel):
    policy_id: str = Field(pattern=r"^P[0-9]{2}$")
    description: str = Field(min_length=1)
    priority: int = Field(ge=0)


class ApprovalRequirement(FrozenModel):
    kind: ApprovalKind
    policy_id: str = Field(pattern=r"^P[0-9]{2}$")
    threshold_usd: Decimal | None = Field(default=None, ge=0)
    binds_to_request: bool = True

    @model_validator(mode="after")
    def validate_threshold(self) -> ApprovalRequirement:
        if self.kind is ApprovalKind.ABOVE_AMOUNT and self.threshold_usd is None:
            raise ValueError("ABOVE_AMOUNT requires threshold_usd")
        if self.kind is ApprovalKind.ALWAYS and self.threshold_usd is not None:
            raise ValueError("ALWAYS cannot define threshold_usd")
        return self


class SecurityContext(FrozenModel):
    identity: AgentIdentity
    capabilities: tuple[Capability, ...] = ()
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def reject_ambiguous_grants(self) -> SecurityContext:
        keys = [(capability.agent_id, capability.name) for capability in self.capabilities]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate capabilities for an agent are ambiguous")
        return self


class PolicyDecision(FrozenModel):
    decision: Decision
    reason: DecisionReason
    matched_policy: str = Field(pattern=r"^P[0-9]{2}$")
    required_capability: CapabilityName | None = None
    normalized_arguments: dict[str, Any] | None = None
    approval_requirement: ApprovalRequirement | None = None


class ProtectedResource(FrozenModel):
    """Authoritative resource attributes resolved by the trusted execution boundary."""

    resource_id: str
    owner_principal: str
    environment: str
    symbol: str | None = None
