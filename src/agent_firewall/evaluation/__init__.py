"""Adversarial evaluation framework."""

from agent_firewall.evaluation.dataset import DATASET_VERSION, load_scenarios
from agent_firewall.evaluation.final import (
    FINAL_BENCHMARK_VERSION,
    FROZEN_DATASET_SHA256,
    FROZEN_SEED,
    FinalBenchmarkArtifact,
    dataset_digest,
    run_final_benchmark,
)
from agent_firewall.evaluation.metrics import compute_metrics
from agent_firewall.evaluation.models import (
    AttackCategory,
    BenchmarkArtifact,
    BenchmarkConfiguration,
    BenchmarkMetrics,
    EvaluationScenario,
)
from agent_firewall.evaluation.runner import BENCHMARK_VERSION, run_all, run_benchmark

__all__ = [
    "BENCHMARK_VERSION",
    "DATASET_VERSION",
    "FINAL_BENCHMARK_VERSION",
    "FROZEN_DATASET_SHA256",
    "FROZEN_SEED",
    "AttackCategory",
    "BenchmarkArtifact",
    "BenchmarkConfiguration",
    "BenchmarkMetrics",
    "EvaluationScenario",
    "FinalBenchmarkArtifact",
    "compute_metrics",
    "dataset_digest",
    "load_scenarios",
    "run_all",
    "run_benchmark",
    "run_final_benchmark",
]
