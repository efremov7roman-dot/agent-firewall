"""Frozen Phase 7 benchmark contract and consolidated artifact generation."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from agent_firewall.domain import INITIAL_TOOL_REGISTRY
from agent_firewall.evaluation.dataset import DATASET_VERSION, load_scenarios
from agent_firewall.evaluation.models import (
    BenchmarkArtifact,
    BenchmarkConfiguration,
    EvaluationModel,
    EvaluationScenario,
)
from agent_firewall.evaluation.runner import BENCHMARK_VERSION, DEFAULT_SEED, run_benchmark
from agent_firewall.policy import PolicyEngine

FINAL_BENCHMARK_VERSION = "phase7-final-v1"
METRIC_DEFINITION_VERSION = "evaluation-metrics-v1"
FROZEN_DATASET_SHA256 = "bcf06e8803328c9c9c6ef201dee73a2ce56145e8678359db363a4903501d058e"
FROZEN_SEED = DEFAULT_SEED


class FrozenConfiguration(EvaluationModel):
    configuration: BenchmarkConfiguration
    description: str


class FinalBenchmarkMetadata(EvaluationModel):
    final_benchmark_version: str
    runner_version: str
    dataset_version: str
    dataset_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    metric_definition_version: str
    seed: int
    generated_at: datetime
    python_version: str
    platform: str
    scenario_count: int
    configurations: tuple[FrozenConfiguration, ...]
    policy_ids: tuple[str, ...]
    protected_tools: tuple[str, ...]


class FinalBenchmarkArtifact(EvaluationModel):
    metadata: FinalBenchmarkMetadata
    runs: tuple[BenchmarkArtifact, ...]

    @model_validator(mode="after")
    def validate_frozen_contract(self) -> FinalBenchmarkArtifact:
        expected = tuple(BenchmarkConfiguration)
        actual = tuple(run.metadata.configuration for run in self.runs)
        if actual != expected:
            raise ValueError("final artifact must contain each frozen configuration in order")
        if any(run.metadata.seed != self.metadata.seed for run in self.runs):
            raise ValueError("all final runs must use the frozen seed")
        if any(
            dataset_digest(run.scenario_definitions) != FROZEN_DATASET_SHA256 for run in self.runs
        ):
            raise ValueError("final runs do not contain the frozen dataset")
        return self


FROZEN_CONFIGURATIONS = (
    FrozenConfiguration(
        configuration=BenchmarkConfiguration.UNPROTECTED,
        description="Schema validation and sandbox execution without authorization",
    ),
    FrozenConfiguration(
        configuration=BenchmarkConfiguration.BASIC_RULES,
        description="Static capability-to-tool presence checks without scopes or approvals",
    ),
    FrozenConfiguration(
        configuration=BenchmarkConfiguration.FIREWALL,
        description="Typed capability, policy, approval, gateway, and audit enforcement",
    ),
)


def dataset_digest(scenarios: tuple[EvaluationScenario, ...]) -> str:
    payload = _canonical_value(scenarios)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, frozenset):
        normalized = [_canonical_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        )
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    return value


def run_final_benchmark(output_path: Path, *, seed: int = DEFAULT_SEED) -> FinalBenchmarkArtifact:
    if seed != FROZEN_SEED:
        raise ValueError(f"final benchmark seed is frozen at {FROZEN_SEED}")
    scenarios = load_scenarios()
    digest = dataset_digest(scenarios)
    if digest != FROZEN_DATASET_SHA256:
        raise RuntimeError(
            f"frozen dataset digest mismatch: expected {FROZEN_DATASET_SHA256}, got {digest}"
        )
    runs = tuple(
        run_benchmark(configuration, scenarios, seed=seed)
        for configuration in BenchmarkConfiguration
    )
    artifact = FinalBenchmarkArtifact(
        metadata=FinalBenchmarkMetadata(
            final_benchmark_version=FINAL_BENCHMARK_VERSION,
            runner_version=BENCHMARK_VERSION,
            dataset_version=DATASET_VERSION,
            dataset_sha256=digest,
            metric_definition_version=METRIC_DEFINITION_VERSION,
            seed=seed,
            generated_at=datetime.now(UTC),
            python_version=sys.version.split()[0],
            platform=platform.platform(),
            scenario_count=len(scenarios),
            configurations=FROZEN_CONFIGURATIONS,
            policy_ids=tuple(policy.policy_id for policy in PolicyEngine().policies),
            protected_tools=tuple(
                definition.name for definition in INITIAL_TOOL_REGISTRY.definitions
            ),
        ),
        runs=runs,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(output_path)
    return artifact
