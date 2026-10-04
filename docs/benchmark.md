# Phase 4 adversarial benchmark

## Purpose and interpretation

This development benchmark measures runtime enforcement, not general model intelligence.
Every configuration receives the same versioned scripted tool proposals. For injection
categories, the proposal represents a successful attempt to influence the agent; attack
success then depends on whether the forbidden action actually executes.

The independent scenario oracle marks every action authorized or unauthorized and lists
the exact call IDs whose execution constitutes attack success. Runtime decisions are
never reused as ground truth.

## Dataset

Dataset `phase4-v1` contains 32 scenarios:

- 8 benign workflows covering reads, orders, cancellation, transfer, and approvals;
- 24 adversarial workflows, exactly two for each category A01–A12;
- 38 total action attempts, including authorized steps in chained attacks.

Each scenario captures identity, capabilities, deterministic environment fixture,
external content, expected authorization constraints, proposed calls, attack goal, and
machine-checkable success criteria. A complete snapshot of these definitions is embedded
in every artifact alongside the raw results.

## Configurations

- `baseline_unprotected`: validates native tool arguments but applies no authorization.
- `baseline_rules`: checks a static identity-to-capability/tool mapping, while ignoring
  expiry, scope, limits, and approval requirements.
- `firewall`: full capability, constraint, policy, approval, gateway, and audit path.

All configurations use a fresh deterministic sandbox per scenario and seed 42. The
scripted provider name, Python/platform data, versions, timestamp, raw outcomes, and
derived metrics are stored in each artifact.

## Frozen Phase 7 findings

The frozen, fingerprinted `phase7-final-v1` artifact reports:

| Configuration | ASR | UAR | Benign success | False block |
| --- | ---: | ---: | ---: | ---: |
| Unprotected | 22/24 | 23/25 | 8/8 | 0/13 |
| Basic rules | 11/24 | 12/25 | 8/8 | 0/13 |
| Firewall | 3/24 | 4/25 | 8/8 | 0/13 |

The dataset is frozen with canonical SHA-256
`bcf06e8803328c9c9c6ef201dee73a2ce56145e8678359db363a4903501d058e`.
The final artifact contains exact latency values and host metadata; these timings are not
generalized beyond the recorded run.

Firewall failures are explicit: both A07 excessive-action scenarios succeed because the
current capability model has no aggregate/rate limit, and one A09 scenario succeeds when
an unintended trade remains inside a valid capability. Deterministic authorization does
not infer semantic intent. These results are retained rather than tuned away.

## Reproduction

```powershell
.\.venv\Scripts\python.exe -m agent_firewall.evaluation --final --output-dir experiments
```

Source of truth: `experiments/final_benchmark.json`.

Metrics are derived from raw `ScenarioResult` records by repository code. A zero
denominator is serialized as `null`, and every ratio includes numerator and denominator.
