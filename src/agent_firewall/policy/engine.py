"""Fail-closed deterministic policy engine."""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from pydantic import ValidationError

from agent_firewall.capabilities import CapabilityEvaluator
from agent_firewall.domain.models import (
    ApprovalKind,
    ApprovalRequirement,
    CapabilityName,
    Decision,
    DecisionReason,
    Policy,
    PolicyDecision,
    ProtectedResource,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.domain.tools import INITIAL_TOOL_REGISTRY, ToolDefinition, ToolRegistry

DEFAULT_POLICIES = (
    Policy(policy_id="P01", description="Unknown tools are denied", priority=10),
    Policy(policy_id="P02", description="Missing capabilities are denied", priority=20),
    Policy(policy_id="P03", description="Expired capabilities are denied", priority=30),
    Policy(policy_id="P04", description="Tool arguments must satisfy the schema", priority=40),
    Policy(policy_id="P05", description="Symbol scope is enforced", priority=50),
    Policy(policy_id="P06", description="Order notional limits are enforced", priority=60),
    Policy(
        policy_id="P07", description="Configured sensitive actions require approval", priority=70
    ),
    Policy(policy_id="P08", description="Withdrawals require explicit approval", priority=80),
    Policy(policy_id="P09", description="Denied actions cannot execute", priority=90),
    Policy(policy_id="P10", description="Evaluation failures fail closed", priority=100),
    Policy(policy_id="P11", description="Runtime identity must match the request", priority=15),
    Policy(policy_id="P12", description="Capability scope is enforced", priority=55),
    Policy(policy_id="P13", description="Resource ownership is enforced", priority=56),
    Policy(policy_id="P14", description="Destination scope is enforced", priority=57),
    Policy(policy_id="P15", description="Aggregate limits are enforced", priority=58),
    Policy(policy_id="P16", description="Idempotency is enforced", priority=59),
    Policy(policy_id="P00", description="All required checks passed", priority=999),
)


class PolicyEngine:
    """Evaluate authorization without executing tools or mutating state."""

    def __init__(
        self,
        registry: ToolRegistry = INITIAL_TOOL_REGISTRY,
        capability_evaluator: CapabilityEvaluator | None = None,
    ) -> None:
        self._registry = registry
        self._capabilities = capability_evaluator or CapabilityEvaluator()
        self.policies = DEFAULT_POLICIES

    def evaluate_raw(self, request: Mapping[str, Any], context: SecurityContext) -> PolicyDecision:
        """Validate an untrusted request and evaluate it, denying malformed input."""

        try:
            typed_request = ToolRequest.model_validate(request)
        except (ValidationError, TypeError, ValueError):
            return self._deny(DecisionReason.MALFORMED_REQUEST, "P04")
        return self.evaluate(typed_request, context)

    def tool_definition(self, name: str) -> ToolDefinition | None:
        """Return trusted registry metadata used by the execution boundary."""

        return self._registry.get(name)

    def evaluate(self, request: ToolRequest, context: SecurityContext) -> PolicyDecision:
        """Return a deterministic decision and convert internal failures into DENY."""

        try:
            return self._evaluate(request, context)
        except Exception:
            return self._deny(DecisionReason.POLICY_EVALUATION_ERROR, "P10")

    def evaluate_resource(
        self,
        request: ToolRequest,
        context: SecurityContext,
        decision: PolicyDecision,
        resource: ProtectedResource,
    ) -> PolicyDecision:
        """Apply trusted resource attributes after normal request authorization."""

        if decision.decision is Decision.DENY:
            return decision
        tool = self._registry.get(request.tool)
        if tool is None:
            return self._deny(DecisionReason.UNKNOWN_TOOL, "P01")
        try:
            check = self._capabilities.evaluate_resource(
                request_agent_id=request.agent_id,
                tool=tool,
                resource=resource,
                context=context,
            )
        except Exception:
            return self._deny(DecisionReason.POLICY_EVALUATION_ERROR, "P10")
        if check.authorized:
            return decision
        return self._deny(
            check.reason,
            check.matched_policy,
            required_capability=tool.required_capability,
            normalized_arguments=decision.normalized_arguments,
        )

    def _evaluate(self, request: ToolRequest, context: SecurityContext) -> PolicyDecision:
        tool = self._registry.get(request.tool)
        if tool is None:
            return self._deny(DecisionReason.UNKNOWN_TOOL, "P01")

        arguments = self._validate_arguments(tool, request.arguments)
        if arguments is None:
            return self._deny(
                DecisionReason.MALFORMED_REQUEST,
                "P04",
                required_capability=tool.required_capability,
            )

        capability = self._capabilities.evaluate(
            request_agent_id=request.agent_id,
            tool=tool,
            arguments=arguments,
            context=context,
        )
        if not capability.authorized:
            return self._deny(
                capability.reason,
                capability.matched_policy,
                required_capability=tool.required_capability,
                normalized_arguments=arguments,
            )

        if tool.approval_requirement is not None:
            reason = (
                DecisionReason.WITHDRAWAL_APPROVAL_REQUIRED
                if tool.name == "withdraw_asset"
                else DecisionReason.APPROVAL_REQUIRED
            )
            return self._approval(tool, arguments, tool.approval_requirement, reason)

        amount = self._amount(arguments, tool.amount_field)
        if (
            capability.approval_threshold_usd is not None
            and amount is not None
            and amount > capability.approval_threshold_usd
        ):
            requirement = ApprovalRequirement(
                kind=ApprovalKind.ABOVE_AMOUNT,
                policy_id="P07",
                threshold_usd=capability.approval_threshold_usd,
            )
            return self._approval(tool, arguments, requirement, DecisionReason.APPROVAL_REQUIRED)

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=DecisionReason.ALLOWED,
            matched_policy="P00",
            required_capability=tool.required_capability,
            normalized_arguments=arguments,
        )

    @staticmethod
    def _validate_arguments(
        tool: ToolDefinition, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        try:
            parsed = tool.arguments_model.model_validate(arguments)
        except (ValidationError, TypeError, ValueError):
            return None
        return parsed.model_dump(mode="python")

    @staticmethod
    def _amount(arguments: dict[str, Any], field: str | None) -> Decimal | None:
        value = arguments.get(field) if field is not None else None
        return value if isinstance(value, Decimal) else None

    @staticmethod
    def _deny(
        reason: DecisionReason,
        policy_id: str,
        *,
        required_capability: CapabilityName | None = None,
        normalized_arguments: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            matched_policy=policy_id,
            required_capability=required_capability,
            normalized_arguments=normalized_arguments,
        )

    @staticmethod
    def _approval(
        tool: ToolDefinition,
        arguments: dict[str, Any],
        requirement: ApprovalRequirement,
        reason: DecisionReason,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason=reason,
            matched_policy=requirement.policy_id,
            required_capability=tool.required_capability,
            normalized_arguments=arguments,
            approval_requirement=requirement,
        )
