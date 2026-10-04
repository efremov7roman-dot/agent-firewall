# Implementation roadmap

Work proceeds sequentially. Each phase ends with tests, Ruff, mypy, documentation of
unresolved issues, and an explicit stop before the next phase.

| Phase | Outcome | Exit summary |
| --- | --- | --- |
| 0 | Foundation, threat model, evaluation design | Installable project; quality gates; trust boundaries, threats, invariants, formulas, roadmap documented |
| 1 | Deterministic security kernel | Typed identity/request/capability/policy decisions; default deny; invariant tests |
| 2 | Financial sandbox and secure gateway | Typed deterministic tools; complete mediation; denied actions cannot mutate state |
| 3 | Tool-using agent integration | Mock plus optional provider; all calls cross gateway; explicit untrusted content |
| 4 | Adversarial evaluation framework | Versioned benign/adversarial scenarios; three configurations; generated metrics/artifacts |
| 5 | Approval, audit, observability, replay | Action-bound approvals; correlated safe audit; inspection/replay CLI |
| 6 | Security hardening and reliability | Fault/property/regression tests; edge cases and measured performance |
| 7 | Frozen benchmark and portfolio release | Frozen reproducible artifacts, honest failure analysis, README/demo, evidence-backed claims |

## Key assumptions

- Python 3.12+ remains available and sufficient for local-first execution.
- The initial financial environment is deterministic and never connects to real funds.
- Trusted configuration and runtime identity are supplied outside prompt/model content.
- Optional real-model evaluation will not be required for core tests or deterministic runs.

## Major delivery risks

- Incomplete mediation could make policy correctness irrelevant.
- Scenario oracles could accidentally mirror implementation logic and bias results.
- Approval binding, exact monetary arithmetic, clocks, or aggregate limits can create
  boundary vulnerabilities.
- Semantic prompt-injection defenses cannot be guaranteed by authorization alone.
- Benchmark tuning after observing final results would undermine credibility.

Mitigations are narrow APIs, independent outcome predicates, exact/controlled test
fixtures, explicit residual-risk reporting, versioned artifacts, and a frozen final run.

## Current status

Phase 7 is complete. Dataset `phase4-v1` is frozen under a canonical SHA-256, and the
`phase7-final-v1` artifact embeds all three configurations, raw scenario/action outcomes,
derived metrics, policy/tool sets, seed, and environment metadata. The final README,
network-free demo, honest failure analysis, and artifact-backed resume metrics are
complete. The recorded failures remain 2/2 A07 excessive-action scenarios and 1/2 A09
semantic-intent scenarios; no post-freeze tuning was performed.
