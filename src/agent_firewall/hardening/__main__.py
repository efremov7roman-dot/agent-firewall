"""Generate a local hardening performance artifact."""

from __future__ import annotations

import argparse
from pathlib import Path

from agent_firewall.hardening.performance import run_performance_profile


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_firewall.hardening")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--warmup", type=int, default=250)
    parser.add_argument(
        "--output", type=Path, default=Path("experiments/hardening_performance.json")
    )
    args = parser.parse_args()
    artifact = run_performance_profile(
        iterations=args.iterations,
        warmup_iterations=args.warmup,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    print(args.output)
    return 0


raise SystemExit(main())
