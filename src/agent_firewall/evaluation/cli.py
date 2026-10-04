"""CLI for generating Phase 4 machine-readable benchmark artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from agent_firewall.evaluation.final import run_final_benchmark
from agent_firewall.evaluation.runner import DEFAULT_SEED, run_all


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the deterministic Agent Firewall benchmark")
    parser.add_argument("--output-dir", type=Path, default=Path("experiments"))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--final", action="store_true", help="write the frozen Phase 7 artifact")
    args = parser.parse_args()
    if args.final:
        path = args.output_dir / "final_benchmark.json"
        run_final_benchmark(path, seed=args.seed)
        print(path)
        return
    paths = run_all(args.output_dir, seed=args.seed)
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
