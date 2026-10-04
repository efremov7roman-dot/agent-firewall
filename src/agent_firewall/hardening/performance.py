"""Reproducible single-process latency and throughput measurement."""

from __future__ import annotations

import math
import platform
import sys
from datetime import UTC, datetime
from time import perf_counter_ns

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.domain import (
    AgentIdentity,
    Capability,
    CapabilityName,
    SecurityContext,
    ToolRequest,
)
from agent_firewall.gateway import ExecutionGateway
from agent_firewall.policy import PolicyEngine


class PerformanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LatencySummary(PerformanceModel):
    sample_count: int = Field(ge=1)
    p50_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)
    p99_ms: float = Field(ge=0)


class PerformanceArtifact(PerformanceModel):
    profile: str
    iterations: int = Field(ge=1)
    warmup_iterations: int = Field(ge=0)
    generated_at: datetime
    python_version: str
    platform: str
    policy_decision_latency: LatencySummary
    gateway_end_to_end_latency: LatencySummary
    gateway_throughput_requests_per_second: float = Field(gt=0)


def run_performance_profile(
    *, iterations: int = 5000, warmup_iterations: int = 250
) -> PerformanceArtifact:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if warmup_iterations < 0:
        raise ValueError("warmup_iterations cannot be negative")

    capability = Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="perf-agent")
    context = SecurityContext(
        identity=AgentIdentity(
            agent_id="perf-agent", principal="phase6-profile", environment="sandbox"
        ),
        capabilities=(capability,),
        evaluated_at=datetime(2026, 10, 2, 12, 0, tzinfo=UTC),
    )
    request = ToolRequest(
        trace_id="phase6-performance",
        agent_id="perf-agent",
        tool="get_portfolio",
        arguments={},
    )
    engine = PolicyEngine()
    gateway = ExecutionGateway()
    for _ in range(warmup_iterations):
        engine.evaluate(request, context)
        gateway.execute(request, context)

    decision_samples = _measure(iterations, lambda: engine.evaluate(request, context))
    gateway_samples = _measure(iterations, lambda: gateway.execute(request, context))
    gateway_seconds = sum(gateway_samples) / 1_000_000_000
    return PerformanceArtifact(
        profile="phase6-authorized-portfolio-read-v1",
        iterations=iterations,
        warmup_iterations=warmup_iterations,
        generated_at=datetime.now(UTC),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        policy_decision_latency=_summary(decision_samples),
        gateway_end_to_end_latency=_summary(gateway_samples),
        gateway_throughput_requests_per_second=iterations / gateway_seconds,
    )


def _measure(iterations: int, operation: object) -> list[int]:
    if not callable(operation):
        raise TypeError("operation must be callable")
    samples: list[int] = []
    for _ in range(iterations):
        started = perf_counter_ns()
        operation()
        samples.append(perf_counter_ns() - started)
    return samples


def _summary(samples_ns: list[int]) -> LatencySummary:
    ordered = sorted(samples_ns)
    return LatencySummary(
        sample_count=len(ordered),
        p50_ms=_percentile(ordered, 0.50) / 1_000_000,
        p95_ms=_percentile(ordered, 0.95) / 1_000_000,
        p99_ms=_percentile(ordered, 0.99) / 1_000_000,
    )


def _percentile(ordered: list[int], percentile: float) -> int:
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]
