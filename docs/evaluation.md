# Evaluation and reproducibility

The project intentionally preserves four different kinds of evidence. Their datasets and purposes differ and must not be collapsed into one efficacy estimate.

| Stage | Purpose | Result | Primary machine-readable evidence |
| --- | --- | --- | --- |
| Phase 7 | Development benchmark | ASR 3/24; UAR 4/25; benign 8/8 | `experiments/final_benchmark.json` |
| Phase 8 | First blind independent validation | ASR 17/26; UAR 15/24; benign 14/14 | `independent_validation/results.json` |
| Phase 9 | Regression after informed hardening | ASR 3/26; UAR 2/24; benign 14/14 | `experiments/phase9_regression.json` |
| Phase 10 | Second blind independent validation | ASR 0/40; UAR 0/45; benign 16/16 | `phase10_validation/results.json` |

## Phase 7 — development evidence

The frozen scripted dataset contains 24 adversarial and 8 benign scenarios. It was built with the original system and is not independent evidence. The artifact records raw outcomes, denominators, latency, environment metadata, and dataset digest `bcf06e8803328c9c9c6ef201dee73a2ce56145e8678359db363a4903501d058e`.

## Phase 8 — first independent evidence

The separately frozen dataset contains 26 adversarial and 14 benign scenarios. Its first valid run found 17 successful attacks and exposed principal/resource, approval, audit, idempotency, aggregate, destination, and semantic-intent boundaries. The negative result is preserved in full under `independent_validation/`.

## Phase 9 — regression evidence

Hardening was informed by Phase 8, so replaying that same dataset cannot demonstrate independent generalization. It shows that known root causes were addressed: 3/26 scenario oracles still counted as success and 2/24 unauthorized attempts executed, with important qualifications recorded in `docs/security-hardening/regression-results.md`.

## Phase 10 — second blind independent evidence

Forty new adversarial scenarios and 16 benign workflows were frozen at SHA-256 `05af25ba7a7fe34122fa36ffbb3867de10032ace49b03b7c685ae1fb775ff841` before execution. The first technically valid complete run recorded 0/40 attacks, 0/45 unauthorized executions, 16/16 benign success, and 0/20 false blocks. The split was 0/21 black-box and 0/19 gray-box. An earlier technically invalid evaluator run is retained rather than hidden. **0/40 is evidence for this local dataset, not proof of universal security.**

## Claim-to-artifact map

| Public claim | Artifact | Field/path |
| --- | --- | --- |
| Phase 7 ASR/UAR/benign | `experiments/final_benchmark.json` | firewall configuration metrics |
| Phase 8 ASR/UAR/benign | `independent_validation/results.json` | `independent_metrics` |
| Phase 9 regression | `experiments/phase9_regression.json` | regression summary |
| Phase 9 performance | `experiments/phase9_original/final_benchmark.json`, `experiments/phase9_performance.json` | latency/throughput metrics |
| Phase 10 dataset digest | `phase10_validation/dataset_manifest.json` | `sha256`, counts |
| Phase 10 results | `phase10_validation/results.json` | `metrics` |

## Reproduction commands

```powershell
.\.venv\Scripts\python.exe -m agent_firewall.evaluation --final --output-dir experiments\reproduction --seed 42
.\.venv\Scripts\python.exe -m independent_validation.runner --fingerprint
```

The historical Phase 8 property tests are preserved with their original outcome oracle.
One destination-mutation case now receives the stricter hardened result `BLOCKED` rather
than the pre-hardening oracle's `AWAITING_APPROVAL`; the protected action still does not
execute or mutate state. The current release suite is the configured 110-test suite.

The Phase 10 result is a preserved first-run artifact; `phase10_validation/run.py` refuses to overwrite it. Dataset integrity can be checked against its manifest and scenario files without replacing the result.
