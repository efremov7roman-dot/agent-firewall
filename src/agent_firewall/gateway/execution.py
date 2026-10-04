"""The sole agent-facing path to protected financial sandbox tools."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from threading import RLock
from time import perf_counter_ns
from typing import Any
from uuid import uuid4

from agent_firewall.domain import (
    Decision,
    DecisionReason,
    PolicyDecision,
    SecurityContext,
    ToolDefinition,
    ToolRequest,
)
from agent_firewall.gateway.approval import (
    ApprovalStatus,
    ApprovalVerifier,
    DenyAllApprovalVerifier,
)
from agent_firewall.gateway.audit import AuditRecorder, InMemoryAuditRecorder
from agent_firewall.gateway.models import (
    GatewayAuditEvent,
    GatewayErrorCode,
    GatewayResult,
    GatewayStatus,
)
from agent_firewall.policy import PolicyEngine
from agent_firewall.sandbox import SandboxSnapshot
from agent_firewall.sandbox.runtime import SandboxExecutionError, _FinancialSandbox

_SENSITIVE_ARGUMENT_FRAGMENTS = (
    "api_key",
    "access_key",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


@dataclass(frozen=True, slots=True)
class GatewaySecurityPolicy:
    """Small deterministic local policy for destination and aggregate enforcement."""

    trusted_transfer_destinations: frozenset[str] = frozenset(
        {"savings", "savings-a", "savings-b", "payroll", "external"}
    )
    trusted_withdrawal_destinations: frozenset[str] = frozenset(
        {"wallet", "approved-wallet", "sandbox-wallet"}
    )
    derive_aggregate_limit_from_per_action_limit: bool = True


class ExecutionGateway:
    """Mediate authorization, approval, execution, and minimal audit correlation."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        audit_recorder: AuditRecorder | None = None,
        security_policy: GatewaySecurityPolicy | None = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._approval_verifier = approval_verifier or DenyAllApprovalVerifier()
        self._audit_recorder = audit_recorder or InMemoryAuditRecorder()
        self._security_policy = security_policy or GatewaySecurityPolicy()
        self._sandbox = _FinancialSandbox()
        self._lock = RLock()
        self._idempotency_results: dict[str, tuple[str, GatewayResult]] = {}
        self._aggregate_spent: dict[tuple[str, str], Decimal] = {}

    @property
    def audit_events(self) -> tuple[GatewayAuditEvent, ...]:
        return self._audit_recorder.events

    def snapshot(
        self,
        *,
        principal: str | None = None,
        environment: str = "sandbox",
    ) -> SandboxSnapshot:
        """Return an immutable copy suitable for assertions and inspection."""

        return self._sandbox.snapshot(principal=principal, environment=environment)

    def execute(self, request: ToolRequest, context: SecurityContext) -> GatewayResult:
        with self._lock:
            return self._execute_locked(request, context)

    def _execute_locked(self, request: ToolRequest, context: SecurityContext) -> GatewayResult:
        request = request.model_copy(deep=True)
        context = context.model_copy(deep=True)
        decision_started = perf_counter_ns()
        try:
            decision = self._policy_engine.evaluate(request, context).model_copy(deep=True)
        except Exception:
            decision = PolicyDecision(
                decision=Decision.DENY,
                reason=DecisionReason.POLICY_EVALUATION_ERROR,
                matched_policy="P10",
            )
        decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000
        if decision.decision is Decision.DENY:
            return self._terminal_result(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.BLOCKED,
                decision_latency_ms=decision_latency_ms,
            )

        arguments = decision.normalized_arguments
        if arguments is None:
            return self._terminal_result(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.FAILED,
                decision_latency_ms=decision_latency_ms,
                error_code=GatewayErrorCode.MISSING_NORMALIZED_ARGUMENTS,
            )

        tool = self._policy_engine.tool_definition(request.tool)
        if tool is None:
            return self._terminal_result(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.BLOCKED,
                decision_latency_ms=decision_latency_ms,
            )

        resource = None
        if tool.resolves_resource:
            try:
                resource = self._sandbox.resolve_resource(request.tool, arguments)
            except SandboxExecutionError as error:
                return self._terminal_result(
                    request=request,
                    context=context,
                    decision=decision,
                    status=GatewayStatus.FAILED,
                    decision_latency_ms=decision_latency_ms,
                    error_code=error.code,
                )
            if resource is not None:
                decision = self._policy_engine.evaluate_resource(
                    request, context, decision, resource
                )
                if decision.decision is Decision.DENY:
                    decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000
                    return self._terminal_result(
                        request=request,
                        context=context,
                        decision=decision,
                        status=GatewayStatus.BLOCKED,
                        decision_latency_ms=decision_latency_ms,
                    )

        destination_denial = self._destination_denial(tool, arguments, context)
        if destination_denial is not None:
            decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000
            return self._terminal_result(
                request=request,
                context=context,
                decision=destination_denial,
                status=GatewayStatus.BLOCKED,
                decision_latency_ms=decision_latency_ms,
            )

        idempotency_key = None
        request_digest = None
        if tool.state_changing:
            idempotency_key, request_digest = self._idempotency_identity(
                request, context, arguments
            )
            previous = self._idempotency_results.get(idempotency_key)
            if previous is not None:
                previous_digest, previous_result = previous
                if previous_digest != request_digest:
                    conflict = self._deny_decision(
                        decision, DecisionReason.IDEMPOTENCY_CONFLICT, "P16"
                    )
                    decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000
                    return self._terminal_result(
                        request=request,
                        context=context,
                        decision=conflict,
                        status=GatewayStatus.BLOCKED,
                        decision_latency_ms=decision_latency_ms,
                        error_code=GatewayErrorCode.IDEMPOTENCY_CONFLICT,
                    )
                replayed = previous_result.model_copy(
                    deep=True,
                    update={
                        "status": GatewayStatus.REPLAYED,
                        "decision_latency_ms": (perf_counter_ns() - decision_started) / 1_000_000,
                    },
                )
                self._record_result(
                    request=request,
                    context=context,
                    result=replayed,
                    decision_latency_ms=replayed.decision_latency_ms,
                )
                return replayed

        aggregate_denial = self._aggregate_denial(tool, arguments, context, decision)
        if aggregate_denial is not None:
            decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000
            return self._terminal_result(
                request=request,
                context=context,
                decision=aggregate_denial,
                status=GatewayStatus.BLOCKED,
                decision_latency_ms=decision_latency_ms,
            )

        decision_latency_ms = (perf_counter_ns() - decision_started) / 1_000_000

        approval_verified = False
        approval_id = None
        approval_status = None
        if decision.decision is Decision.REQUIRE_APPROVAL:
            try:
                approval = self._approval_verifier.check(
                    request=request.model_copy(deep=True),
                    decision=decision.model_copy(deep=True),
                    context=context.model_copy(deep=True),
                )
                approval_verified = approval.approved
                approval_id = approval.approval_id
                approval_status = approval.status
            except Exception:
                return self._terminal_result(
                    request=request,
                    context=context,
                    decision=decision,
                    status=GatewayStatus.FAILED,
                    decision_latency_ms=decision_latency_ms,
                    error_code=GatewayErrorCode.APPROVAL_VERIFICATION_FAILED,
                )
            if not approval_verified:
                return self._terminal_result(
                    request=request,
                    context=context,
                    decision=decision,
                    status=GatewayStatus.AWAITING_APPROVAL,
                    decision_latency_ms=decision_latency_ms,
                    approval_id=approval_id,
                    approval_status=approval_status,
                )

        try:
            self._record(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.AUTHORIZED,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
            )
        except Exception:
            return GatewayResult(
                decision=decision,
                status=GatewayStatus.FAILED,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                error_code=GatewayErrorCode.AUDIT_RECORDING_FAILED,
                decision_latency_ms=decision_latency_ms,
            )
        try:
            tool_result = self._sandbox.execute(
                request.tool,
                arguments,
                principal=context.identity.principal,
                environment=context.identity.environment,
                authorized_resource=resource,
            )
        except SandboxExecutionError as error:
            return self._terminal_result(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.FAILED,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
                error_code=error.code,
            )
        except Exception:
            return self._terminal_result(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.FAILED,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
                error_code=GatewayErrorCode.INTERNAL_EXECUTION_ERROR,
            )

        result = GatewayResult(
            decision=decision,
            status=GatewayStatus.EXECUTED,
            approval_verified=approval_verified,
            approval_id=approval_id,
            approval_status=approval_status,
            result=tool_result,
            decision_latency_ms=decision_latency_ms,
        )
        self._commit_aggregate(tool, arguments, context)
        if idempotency_key is not None and request_digest is not None:
            self._idempotency_results[idempotency_key] = (
                request_digest,
                result.model_copy(deep=True),
            )
        try:
            self._record(
                request=request,
                context=context,
                decision=decision,
                status=GatewayStatus.EXECUTED,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
            )
        except Exception:
            return result.model_copy(update={"error_code": GatewayErrorCode.AUDIT_RECORDING_FAILED})
        return result

    def _destination_denial(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        context: SecurityContext,
    ) -> PolicyDecision | None:
        if tool.destination_field is None:
            return None
        destination = arguments.get(tool.destination_field)
        if not isinstance(destination, str):
            return self._deny_decision_from_tool(
                tool, arguments, DecisionReason.DESTINATION_SCOPE_VIOLATION, "P14"
            )
        capability = self._matching_capability(tool, context)
        if capability is None:
            return self._deny_decision_from_tool(
                tool, arguments, DecisionReason.MISSING_CAPABILITY, "P02"
            )
        allowed = capability.constraints.allowed_destinations
        if allowed is None:
            allowed = (
                self._security_policy.trusted_transfer_destinations
                if tool.name == "transfer_asset"
                else self._security_policy.trusted_withdrawal_destinations
            )
        if destination not in allowed:
            return self._deny_decision_from_tool(
                tool, arguments, DecisionReason.DESTINATION_SCOPE_VIOLATION, "P14"
            )
        return None

    def _aggregate_denial(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        context: SecurityContext,
        decision: PolicyDecision,
    ) -> PolicyDecision | None:
        amount = self._amount(arguments, tool.amount_field)
        if amount is None or tool.name == "withdraw_asset":
            return None
        capability = self._matching_capability(tool, context)
        if capability is None:
            return self._deny_decision(decision, DecisionReason.MISSING_CAPABILITY, "P02")
        limit = capability.constraints.max_aggregate_amount_usd
        if limit is None and self._security_policy.derive_aggregate_limit_from_per_action_limit:
            limit = (
                capability.constraints.max_notional_usd
                if tool.name == "create_order"
                else capability.constraints.max_transfer_amount_usd
            )
        if limit is None:
            return None
        key = (context.identity.principal, context.identity.environment)
        if self._aggregate_spent.get(key, Decimal("0")) + amount > limit:
            return self._deny_decision(decision, DecisionReason.AGGREGATE_LIMIT_EXCEEDED, "P15")
        return None

    def _commit_aggregate(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        context: SecurityContext,
    ) -> None:
        amount = self._amount(arguments, tool.amount_field)
        if amount is None or tool.name == "withdraw_asset":
            return
        key = (context.identity.principal, context.identity.environment)
        self._aggregate_spent[key] = self._aggregate_spent.get(key, Decimal("0")) + amount

    def _idempotency_identity(
        self,
        request: ToolRequest,
        context: SecurityContext,
        arguments: dict[str, Any],
    ) -> tuple[str, str]:
        request_payload = {
            "agent_id": request.agent_id,
            "principal": context.identity.principal,
            "environment": context.identity.environment,
            "tool": request.tool,
            "arguments": _canonical_json_value(arguments),
        }
        request_digest = _sha256_json(request_payload)
        logical_key = request.idempotency_key or f"{request.trace_id}:{request_digest}"
        identity = _sha256_json(
            {
                "agent_id": request.agent_id,
                "principal": context.identity.principal,
                "environment": context.identity.environment,
                "idempotency_key": logical_key,
            }
        )
        return identity, request_digest

    def _record_result(
        self,
        *,
        request: ToolRequest,
        context: SecurityContext,
        result: GatewayResult,
        decision_latency_ms: float,
    ) -> None:
        try:
            self._record(
                request=request,
                context=context,
                decision=result.decision,
                status=result.status,
                approval_verified=result.approval_verified,
                approval_id=result.approval_id,
                approval_status=result.approval_status,
                decision_latency_ms=decision_latency_ms,
                error_code=result.error_code,
            )
        except Exception:
            return

    @staticmethod
    def _matching_capability(tool: ToolDefinition, context: SecurityContext) -> Any:
        return next(
            (
                capability
                for capability in context.capabilities
                if capability.agent_id == context.identity.agent_id
                and capability.name == tool.required_capability
            ),
            None,
        )

    @staticmethod
    def _amount(arguments: dict[str, Any], field: str | None) -> Decimal | None:
        value = arguments.get(field) if field is not None else None
        return value if isinstance(value, Decimal) else None

    @staticmethod
    def _deny_decision(
        decision: PolicyDecision,
        reason: DecisionReason,
        policy_id: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            matched_policy=policy_id,
            required_capability=decision.required_capability,
            normalized_arguments=decision.normalized_arguments,
        )

    @staticmethod
    def _deny_decision_from_tool(
        tool: ToolDefinition,
        arguments: dict[str, Any],
        reason: DecisionReason,
        policy_id: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            matched_policy=policy_id,
            required_capability=tool.required_capability,
            normalized_arguments=arguments,
        )

    def _terminal_result(
        self,
        *,
        request: ToolRequest,
        context: SecurityContext,
        decision: PolicyDecision,
        status: GatewayStatus,
        approval_verified: bool = False,
        approval_id: str | None = None,
        approval_status: ApprovalStatus | None = None,
        decision_latency_ms: float,
        error_code: str | None = None,
    ) -> GatewayResult:
        result = GatewayResult(
            decision=decision,
            status=status,
            approval_verified=approval_verified,
            approval_id=approval_id,
            approval_status=approval_status,
            error_code=error_code,
            decision_latency_ms=decision_latency_ms,
        )
        try:
            self._record(
                request=request,
                context=context,
                decision=decision,
                status=status,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
                error_code=error_code,
            )
        except Exception:
            return result.model_copy(update={"error_code": GatewayErrorCode.AUDIT_RECORDING_FAILED})
        return result

    def _record(
        self,
        *,
        request: ToolRequest,
        context: SecurityContext,
        decision: PolicyDecision,
        status: GatewayStatus,
        approval_verified: bool,
        approval_id: str | None,
        approval_status: ApprovalStatus | None,
        decision_latency_ms: float,
        error_code: str | None = None,
    ) -> None:
        self._audit_recorder.record(
            GatewayAuditEvent(
                event_id=uuid4().hex,
                trace_id=request.trace_id,
                run_id=request.trace_id,
                agent_id=context.identity.agent_id,
                tool=request.tool,
                timestamp=context.evaluated_at,
                request=_safe_request(request),
                security_context=context,
                runtime_constraints=_runtime_constraints(context),
                normalized_arguments=decision.normalized_arguments,
                required_capability=decision.required_capability,
                policies_evaluated=(decision.matched_policy,),
                matched_policy=decision.matched_policy,
                policy_decision=decision,
                decision=decision.decision,
                reason=decision.reason,
                status=status,
                approval_verified=approval_verified,
                approval_id=approval_id,
                approval_status=approval_status,
                decision_latency_ms=decision_latency_ms,
                error_code=error_code,
            )
        )


def _safe_request(request: ToolRequest) -> ToolRequest:
    return request.model_copy(update={"arguments": _redact_mapping(request.arguments)})


def _redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        normalized_key = key.casefold()
        if any(fragment in normalized_key for fragment in _SENSITIVE_ARGUMENT_FRAGMENTS):
            redacted[key] = "[REDACTED]"
        elif isinstance(item, dict):
            redacted[key] = _redact_mapping(item)
        elif isinstance(item, (list, tuple)):
            redacted[key] = [_redact_value(nested) for nested in item]
        else:
            redacted[key] = item
    return redacted


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonical_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    if isinstance(value, Decimal):
        return str(value)
    if hasattr(value, "value"):
        return _canonical_json_value(value.value)
    return value


def _sha256_json(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _runtime_constraints(context: SecurityContext) -> tuple[dict[str, Any], ...]:
    captured: list[dict[str, Any]] = []
    for capability in context.capabilities:
        constraints = capability.constraints
        if (
            constraints.allowed_resource_principals is None
            and constraints.allowed_destinations is None
            and constraints.max_aggregate_amount_usd is None
        ):
            continue
        captured.append(
            {
                "capability": capability.name.value,
                "allowed_resource_principals": sorted(
                    constraints.allowed_resource_principals or ()
                ),
                "allowed_destinations": sorted(constraints.allowed_destinations or ()),
                "max_aggregate_amount_usd": constraints.max_aggregate_amount_usd,
            }
        )
    return tuple(captured)
