"""Frozen live dataset and state-oracle contract checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import agent_firewall.evaluation.adversarial as evaluator
from agent_firewall.evaluation.adversarial import DATASET, _oracle, _seed, _snapshot
from agent_firewall.evaluation.live import BaselineGateway
from agent_firewall.gateway import ExecutionGateway


def test_frozen_splits_have_required_counts_and_distinct_cases() -> None:
    manifest = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
    combined = []
    for split in ("development", "final"):
        raw = (DATASET / f"{split}.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == manifest["splits"][split]["sha256"]
        scenarios = json.loads(raw)
        assert (
            sum(not item["benign"] for item in scenarios)
            == manifest["splits"][split]["adversarial"]
        )
        assert sum(item["benign"] for item in scenarios) == manifest["splits"][split]["benign"]
        combined.extend(scenarios)
    assert len(combined) == 90
    assert sum(not item["benign"] for item in combined) == 60
    assert sum(item["benign"] for item in combined) == 30
    assert len({item["id"] for item in combined}) == 90
    signatures = {
        json.dumps(
            {
                key: item[key]
                for key in (
                    "instruction",
                    "external_content",
                    "tool_response_injection",
                    "oracle",
                    "seed",
                )
            },
            sort_keys=True,
        )
        for item in combined
    }
    assert len(signatures) == 90


def test_cross_principal_oracle_uses_victim_state() -> None:
    scenarios = json.loads((DATASET / "development.json").read_text(encoding="utf-8"))
    scenario = next(item for item in scenarios if item["family"] == "cross_cancel")
    baseline = BaselineGateway("unprotected")
    firewall = ExecutionGateway()
    for boundary in (baseline, firewall):
        _seed(boundary, scenario, None)
        before = _snapshot(boundary)
        assert _oracle(scenario, before, before, ()) == (False, 0)
        assert before["victim"]["orders"][0]["status"] == "OPEN"


def test_frozen_final_file_is_separate_from_invalid_draft() -> None:
    assert (DATASET / "final_invalid_v0.json").exists()
    assert (DATASET / "final.json").exists()
    assert (DATASET / "final_invalid_v0.json").read_bytes() != (DATASET / "final.json").read_bytes()


def test_interrupted_benchmark_resumes_only_same_dataset_and_implementation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    scenarios = [{"id": "case-1", "benign": True}]
    raw = json.dumps(scenarios).encode()
    (dataset / "development.json").write_bytes(raw)
    (dataset / "manifest.json").write_text(
        json.dumps({"splits": {"development": {"sha256": hashlib.sha256(raw).hexdigest()}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(evaluator, "DATASET", dataset)
    monkeypatch.setattr(evaluator, "MODES", ("unprotected", "firewall"))
    monkeypatch.setattr(evaluator, "_model_digest", lambda model: "a" * 64)
    monkeypatch.setattr(evaluator, "_implementation_digest", lambda: "b" * 64)
    monkeypatch.setattr(evaluator, "summarize", lambda runs: {"count": len(runs)})
    calls = 0

    def flaky_run(
        scenario: dict[str, object], mode: str, model: str, timeout: float
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("interrupted")
        return {
            "scenario_id": scenario["id"],
            "mode": mode,
            "run_status": "COMPLETED",
            "target_attempts": 0,
            "task_success": True,
            "attack_success": None,
        }

    monkeypatch.setattr(evaluator, "run_one", flaky_run)
    output = tmp_path / "result.json"
    with pytest.raises(RuntimeError, match="interrupted"):
        evaluator.run_split("development", output)
    partial = output.with_suffix(".partial.jsonl")
    assert partial.exists()
    with pytest.raises(FileExistsError):
        evaluator.run_split("development", output)
    artifact = evaluator.run_split("development", output, resume=True)
    assert len(artifact["runs"]) == 2
    assert not partial.exists()
