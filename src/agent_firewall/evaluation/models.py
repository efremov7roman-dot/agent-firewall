"""Versioned adversarial benchmark schemas and result artifacts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_firewall.agent import ExternalContent
from agent_firewall.domain import AgentIdentity, Capability


class EvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScenarioKind(StrEnum):
    BENIGN = "BENIGN"
    ADVERSARIAL = "ADVERSARIAL"


class AttackCategory(StrEnum):
    A01_DIRECT_INSTRUCTION = "A01"
    A02_INDIRECT_PROMPT_INJECTION = "A02"
    A03_UNAUTHORIZED_TOOL = "A03"
    A04_PRIVILEGE_ESCALATION = "A04"
    A05_ARGUMENT_MANIPULATION = "A05"
    A06_APPROVAL_BYPASS = "A06"
    A07_EXCESSIVE_ACTION = "A07"
    A08_UNAUTHORIZED_CHAINING = "A08"
    A09_UNTRUSTED_CONTENT_INFLUENCE = "A09"
    A10_STALE_CAPABILITY = "A10"
    A11_MALFORMED_REQUEST = "A11"
    A12_CAPABILITY_SCOPE = "A12"


class BenchmarkConfiguration(StrEnum):
    UNPROTECTED = "baseline_unprotected"
    BASIC_RULES = "baseline_rules"
    FIREWALL = "firewall"


class ScenarioEnvironment(EvaluationModel):
    fixture_id: str = "financial-sandbox-default-v1"
    description: str = "Deterministic default balances, positions, prices, and empty history"


class ScenarioToolCall(EvaluationModel):
    call_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    arguments: dict[str, Any]
    authorized_by_oracle: bool
    required_for_benign_success: bool = False


class EvaluationScenario(EvaluationModel):
    scenario_id: str = Field(pattern=r"^(BEN|A[0-9]{2})-[0-9]{2}$")
    kind: ScenarioKind
    category: AttackCategory | None = None
    description: str
    user_task: str
    identity: AgentIdentity
    capabilities: tuple[Capability, ...] = ()
    environment: ScenarioEnvironment = Field(default_factory=ScenarioEnvironment)
    external_content: tuple[ExternalContent, ...] = ()
    expected_authorization_constraints: tuple[str, ...]
    attack_goal: str | None = None
    tool_calls: tuple[ScenarioToolCall, ...]
    attack_success_call_ids: frozenset[str] = frozenset()
    approval_granted: bool = False

    @model_validator(mode="after")
    def validate_scenario_oracle(self) -> EvaluationScenario:
        call_ids = [call.call_id for call in self.tool_calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("scenario tool call IDs must be unique")
        if not self.attack_success_call_ids.issubset(call_ids):
            raise ValueError("attack success IDs must reference declared tool calls")
        if self.kind is ScenarioKind.ADVERSARIAL:
            if self.category is None or not self.attack_goal or not self.attack_success_call_ids:
                raise ValueError("adversarial scenarios require category, goal, and success calls")
        elif self.category is not None or self.attack_goal is not None:
            raise ValueError("benign scenarios cannot define attack metadata")
        return self


class ActionObservation(EvaluationModel):
    call_id: str
    tool: str
    authorized_by_oracle: bool
    required_for_benign_success: bool
    executed: bool
    status: str
    reason: str | None = None
    security_decision_latency_ms: float | None = Field(default=None, ge=0)


class ScenarioResult(EvaluationModel):
    scenario_id: str
    kind: ScenarioKind
    category: AttackCategory | None
    actions: tuple[ActionObservation, ...]
    attack_success: bool | None
    benign_success: bool | None
    end_to_end_latency_ms: float = Field(ge=0)


class RatioMetric(EvaluationModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None = Field(default=None, ge=0, le=1)


class LatencyMetric(EvaluationModel):
    sample_count: int = Field(ge=0)
    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    p99_ms: float | None = Field(default=None, ge=0)


class BenchmarkMetrics(EvaluationModel):
    total_scenarios: int
    benign_scenarios: int
    adversarial_scenarios: int
    attack_success_rate: RatioMetric
    unauthorized_action_rate: RatioMetric
    benign_task_success_rate: RatioMetric
    false_block_rate: RatioMetric
    security_decision_latency: LatencyMetric
    end_to_end_latency: LatencyMetric
    attack_success_by_category: dict[AttackCategory, RatioMetric]


class BenchmarkMetadata(EvaluationModel):
    benchmark_version: str
    dataset_version: str
    configuration: BenchmarkConfiguration
    seed: int
    generated_at: datetime
    python_version: str
    platform: str
    agent_provider: str


class BenchmarkArtifact(EvaluationModel):
    metadata: BenchmarkMetadata
    scenario_definitions: tuple[EvaluationScenario, ...]
    metrics: BenchmarkMetrics
    scenarios: tuple[ScenarioResult, ...]
