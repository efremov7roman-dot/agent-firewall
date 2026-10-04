"""Deterministic least-privilege capability evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from agent_firewall.domain.models import (
    Capability,
    CapabilityName,
    DecisionReason,
    ProtectedResource,
    SecurityContext,
)
from agent_firewall.domain.tools import ToolDefinition


@dataclass(frozen=True, slots=True)
class CapabilityCheck:
    authorized: bool
    reason: DecisionReason
    matched_policy: str
    capability: Capability | None = None
    approval_threshold_usd: Decimal | None = None


class CapabilityEvaluator:
    """Evaluate a request against one unambiguous capability grant."""

    def evaluate(
        self,
        *,
        request_agent_id: str,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        context: SecurityContext,
    ) -> CapabilityCheck:
        if request_agent_id != context.identity.agent_id:
            return CapabilityCheck(False, DecisionReason.AGENT_IDENTITY_MISMATCH, "P11")

        capability = next(
            (
                grant
                for grant in context.capabilities
                if grant.agent_id == context.identity.agent_id
                and grant.name == tool.required_capability
            ),
            None,
        )
        if capability is None:
            return CapabilityCheck(False, DecisionReason.MISSING_CAPABILITY, "P02")
        if capability.expires_at is not None and capability.expires_at <= context.evaluated_at:
            return CapabilityCheck(False, DecisionReason.EXPIRED_CAPABILITY, "P03", capability)

        constraints = capability.constraints
        if constraints.environment is not None and (
            constraints.environment != context.identity.environment
        ):
            return CapabilityCheck(False, DecisionReason.ENVIRONMENT_MISMATCH, "P12", capability)
        if constraints.allowed_actions is not None and tool.name not in constraints.allowed_actions:
            return CapabilityCheck(False, DecisionReason.ACTION_SCOPE_VIOLATION, "P12", capability)

        if tool.symbol_field is not None and constraints.allowed_symbols is not None:
            symbol = arguments.get(tool.symbol_field)
            if symbol not in constraints.allowed_symbols:
                return CapabilityCheck(
                    False, DecisionReason.SYMBOL_SCOPE_VIOLATION, "P05", capability
                )

        amount = self._amount(arguments, tool.amount_field)
        if (
            tool.required_capability is CapabilityName.ORDERS_CREATE
            and constraints.max_notional_usd is not None
            and amount is not None
            and amount > constraints.max_notional_usd
        ):
            return CapabilityCheck(False, DecisionReason.NOTIONAL_LIMIT_EXCEEDED, "P06", capability)
        if (
            tool.required_capability is CapabilityName.TRANSFERS_CREATE
            and constraints.max_transfer_amount_usd is not None
            and amount is not None
            and amount > constraints.max_transfer_amount_usd
        ):
            return CapabilityCheck(False, DecisionReason.TRANSFER_LIMIT_EXCEEDED, "P12", capability)

        return CapabilityCheck(
            True,
            DecisionReason.ALLOWED,
            "P00",
            capability,
            constraints.approval_above_usd,
        )

    def evaluate_resource(
        self,
        *,
        request_agent_id: str,
        tool: ToolDefinition,
        resource: ProtectedResource,
        context: SecurityContext,
    ) -> CapabilityCheck:
        """Authorize using trusted attributes resolved from the target resource."""

        capability = self._matching_capability(request_agent_id, tool, context)
        if capability is None:
            return CapabilityCheck(False, DecisionReason.MISSING_CAPABILITY, "P02")
        allowed_principals = capability.constraints.allowed_resource_principals
        if resource.owner_principal != context.identity.principal and (
            allowed_principals is None or resource.owner_principal not in allowed_principals
        ):
            return CapabilityCheck(
                False, DecisionReason.RESOURCE_SCOPE_VIOLATION, "P13", capability
            )
        if resource.environment != context.identity.environment:
            return CapabilityCheck(
                False, DecisionReason.RESOURCE_SCOPE_VIOLATION, "P13", capability
            )
        allowed_symbols = capability.constraints.allowed_symbols
        if (
            resource.symbol is not None
            and allowed_symbols is not None
            and resource.symbol not in allowed_symbols
        ):
            return CapabilityCheck(False, DecisionReason.SYMBOL_SCOPE_VIOLATION, "P05", capability)
        return CapabilityCheck(True, DecisionReason.ALLOWED, "P00", capability)

    @staticmethod
    def _matching_capability(
        request_agent_id: str,
        tool: ToolDefinition,
        context: SecurityContext,
    ) -> Capability | None:
        if request_agent_id != context.identity.agent_id:
            return None
        return next(
            (
                grant
                for grant in context.capabilities
                if grant.agent_id == context.identity.agent_id
                and grant.name == tool.required_capability
            ),
            None,
        )

    @staticmethod
    def _amount(arguments: dict[str, Any], field: str | None) -> Decimal | None:
        value = arguments.get(field) if field is not None else None
        return value if isinstance(value, Decimal) else None
