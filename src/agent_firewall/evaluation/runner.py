"""Deterministic runners for unprotected, basic-rule, and firewall configurations."""

from __future__ import annotations

import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter_ns

from pydantic import ValidationError

from agent_firewall.agent import (
    AgentTask,
    FinancialAgent,
    ModelTurn,
    ProposedToolCall,
    ScriptedProvider,
)
from agent_firewall.domain import (
    INITIAL_TOOL_REGISTRY,
    PolicyDecision,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.evaluation.dataset import DATASET_VERSION, EVALUATED_AT, load_scenarios
from agent_firewall.evaluation.metrics import compute_metrics
from agent_firewall.evaluation.models import (
    ActionObservation,
    BenchmarkArtifact,
    BenchmarkConfiguration,
    BenchmarkMetadata,
    EvaluationScenario,
    ScenarioKind,
    ScenarioResult,
    ScenarioToolCall,
)
from agent_firewall.gateway import (
    ApprovalCheck,
    ApprovalStatus,
    ApprovalVerifier,
    ExecutionGateway,
    GatewayStatus,
)
from agent_firewall.policy import PolicyEngine
from agent_firewall.sandbox.runtime import SandboxExecutionError, _FinancialSandbox

BENCHMARK_VERSION = "phase4-runtime-authorization-v1"
DEFAULT_SEED = 42


class _RecordingPolicyEngine(PolicyEngine):
    def __init__(self) -> None:
        super().__init__()
        self.latencies_ms: list[float] = []

    def evaluate(self, request: ToolRequest, context: SecurityContext) -> PolicyDecision:
        started = perf_counter_ns()
        decision = super().evaluate(request, context)
        self.latencies_ms.append(_elapsed_ms(started))
        return decision


class _ScenarioApprovalVerifier:
    def __init__(self, approved: bool) -> None:
        self._approved = approved

    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        del request, decision, context
        return ApprovalCheck(
            approved=self._approved,
            status=ApprovalStatus.CONSUMED if self._approved else None,
        )


def run_benchmark(
    configuration: BenchmarkConfiguration,
    scenarios: tuple[EvaluationScenario, ...] | None = None,
    *,
    seed: int = DEFAULT_SEED,
) -> BenchmarkArtifact:
    selected = scenarios or load_scenarios()
    results = tuple(_run_scenario(configuration, scenario) for scenario in selected)
    return BenchmarkArtifact(
        metadata=BenchmarkMetadata(
            benchmark_version=BENCHMARK_VERSION,
            dataset_version=DATASET_VERSION,
            configuration=configuration,
            seed=seed,
            generated_at=datetime.now(UTC),
            python_version=sys.version.split()[0],
            platform=platform.platform(),
            agent_provider="scripted-v1",
        ),
        scenario_definitions=selected,
        metrics=compute_metrics(results),
        scenarios=results,
    )


def run_all(output_directory: Path, *, seed: int = DEFAULT_SEED) -> tuple[Path, ...]:
    output_directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for configuration in BenchmarkConfiguration:
        artifact = run_benchmark(configuration, seed=seed)
        path = output_directory / f"{configuration.value}.json"
        path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
        written.append(path)
    return tuple(written)


def _run_scenario(
    configuration: BenchmarkConfiguration,
    scenario: EvaluationScenario,
) -> ScenarioResult:
    started = perf_counter_ns()
    if configuration is BenchmarkConfiguration.UNPROTECTED:
        actions = _run_unprotected(scenario)
    elif configuration is BenchmarkConfiguration.BASIC_RULES:
        actions = _run_basic_rules(scenario)
    else:
        actions = _run_firewall(scenario)
    action_by_id = {action.call_id: action for action in actions}
    attack_success = (
        any(action_by_id[call_id].executed for call_id in scenario.attack_success_call_ids)
        if scenario.kind is ScenarioKind.ADVERSARIAL
        else None
    )
    required = tuple(call for call in scenario.tool_calls if call.required_for_benign_success)
    benign_success = (
        all(action_by_id[call.call_id].executed for call in required)
        if scenario.kind is ScenarioKind.BENIGN
        else None
    )
    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        kind=scenario.kind,
        category=scenario.category,
        actions=actions,
        attack_success=attack_success,
        benign_success=benign_success,
        end_to_end_latency_ms=_elapsed_ms(started),
    )


def _run_unprotected(scenario: EvaluationScenario) -> tuple[ActionObservation, ...]:
    sandbox = _FinancialSandbox()
    observations: list[ActionObservation] = []
    for call in scenario.tool_calls:
        definition = INITIAL_TOOL_REGISTRY.get(call.tool)
        if definition is None:
            observations.append(_observation(call, False, "BLOCKED", "UNKNOWN_TOOL"))
            continue
        try:
            normalized = definition.arguments_model.model_validate(call.arguments).model_dump(
                mode="python"
            )
        except ValidationError:
            observations.append(_observation(call, False, "BLOCKED", "MALFORMED_REQUEST"))
            continue
        try:
            sandbox.execute(
                call.tool,
                normalized,
                principal=scenario.identity.principal,
                environment=scenario.identity.environment,
            )
        except SandboxExecutionError as error:
            observations.append(_observation(call, False, "FAILED", error.code.value))
        else:
            observations.append(_observation(call, True, "EXECUTED"))
    return tuple(observations)


def _run_basic_rules(scenario: EvaluationScenario) -> tuple[ActionObservation, ...]:
    sandbox = _FinancialSandbox()
    observations: list[ActionObservation] = []
    for call in scenario.tool_calls:
        started = perf_counter_ns()
        definition = INITIAL_TOOL_REGISTRY.get(call.tool)
        if definition is None:
            observations.append(
                _observation(
                    call,
                    False,
                    "BLOCKED",
                    "UNKNOWN_TOOL",
                    security_latency_ms=_elapsed_ms(started),
                )
            )
            continue
        grant_exists = any(
            capability.agent_id == scenario.identity.agent_id
            and capability.name is definition.required_capability
            for capability in scenario.capabilities
        )
        if not grant_exists:
            observations.append(
                _observation(
                    call,
                    False,
                    "BLOCKED",
                    "STATIC_RULE_DENY",
                    security_latency_ms=_elapsed_ms(started),
                )
            )
            continue
        try:
            normalized = definition.arguments_model.model_validate(call.arguments).model_dump(
                mode="python"
            )
        except ValidationError:
            observations.append(
                _observation(
                    call,
                    False,
                    "BLOCKED",
                    "MALFORMED_REQUEST",
                    security_latency_ms=_elapsed_ms(started),
                )
            )
            continue
        decision_latency = _elapsed_ms(started)
        try:
            sandbox.execute(
                call.tool,
                normalized,
                principal=scenario.identity.principal,
                environment=scenario.identity.environment,
            )
        except SandboxExecutionError as error:
            observations.append(
                _observation(
                    call,
                    False,
                    "FAILED",
                    error.code.value,
                    security_latency_ms=decision_latency,
                )
            )
        else:
            observations.append(
                _observation(
                    call,
                    True,
                    "EXECUTED",
                    security_latency_ms=decision_latency,
                )
            )
    return tuple(observations)


def _run_firewall(scenario: EvaluationScenario) -> tuple[ActionObservation, ...]:
    engine = _RecordingPolicyEngine()
    verifier: ApprovalVerifier = _ScenarioApprovalVerifier(scenario.approval_granted)
    gateway = ExecutionGateway(policy_engine=engine, approval_verifier=verifier)
    provider = ScriptedProvider(
        (
            ModelTurn(
                tool_calls=tuple(
                    ProposedToolCall(
                        call_id=call.call_id,
                        name=call.tool,
                        arguments=call.arguments,
                    )
                    for call in scenario.tool_calls
                )
            ),
            ModelTurn(text="Scenario complete."),
        )
    )
    agent = FinancialAgent(
        provider=provider,
        gateway=gateway,
        max_tool_calls=max(8, len(scenario.tool_calls)),
    )
    context = SecurityContext(
        identity=scenario.identity,
        capabilities=scenario.capabilities,
        evaluated_at=EVALUATED_AT,
    )
    run = agent.run(
        AgentTask(
            trace_id=scenario.scenario_id,
            user_instruction=scenario.user_task,
            external_content=scenario.external_content,
        ),
        context,
    )
    observations: list[ActionObservation] = []
    for call, result in zip(
        scenario.tool_calls,
        run.gateway_results,
        strict=True,
    ):
        observations.append(
            _observation(
                call,
                result.status is GatewayStatus.EXECUTED,
                result.status.value,
                result.decision.reason.value,
                security_latency_ms=result.decision_latency_ms,
            )
        )
    return tuple(observations)


def _observation(
    call: ScenarioToolCall,
    executed: bool,
    status: str,
    reason: str | None = None,
    *,
    security_latency_ms: float | None = None,
) -> ActionObservation:
    return ActionObservation(
        call_id=call.call_id,
        tool=call.tool,
        authorized_by_oracle=call.authorized_by_oracle,
        required_for_benign_success=call.required_for_benign_success,
        executed=executed,
        status=status,
        reason=reason,
        security_decision_latency_ms=security_latency_ms,
    )


def _elapsed_ms(started_ns: int) -> float:
    return (perf_counter_ns() - started_ns) / 1_000_000
