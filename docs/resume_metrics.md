# Evidence-backed resume metrics

## Short version

- Built a deterministic zero-trust execution gateway for tool-using financial agents, enforcing principal/resource isolation, scoped capabilities, context-bound approvals, idempotency, aggregate limits, destination controls, and tamper-detectable local audit records around seven sandbox tools.
- Used evaluation-first hardening: a first blind review exposed 17/26 successful attacks; after root-cause redesign, a second independently designed frozen local evaluation observed 0/40 successful attacks, 0/45 unauthorized executions, and 16/16 benign workflows in the tested scope.

## Extended version

- Designed a model-independent authorization boundary that treats LLM calls as untrusted proposals and returns deterministic `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` decisions.
- Preserved a failed first blind validation (17/26 ASR, 15/24 UAR) and converted its root causes into ownership-aware resource checks, atomic approval use, idempotency, aggregate budgets, destination scope, and hardened audit behavior.
- Passed a second frozen blind local set with 0/40 successful adversarial scenarios, 0/45 unauthorized executed actions, 16/16 benign workflows, and 0/20 false blocks; the result is scoped evidence, not a universal-security claim.
- Measured hardened local decision latency at 0.0385/0.0804/0.1082 ms p50/p95/p99 and a separate 5,000-iteration gateway profile at 0.2392/0.3035/0.4995 ms with 3,769.5 requests/second on the recorded host.

## Evidence

- Phase 8: `independent_validation/results.json`
- Phase 9: `experiments/phase9_regression.json` and `experiments/phase9_performance.json`
- Phase 10: `phase10_validation/results.json` and `phase10_validation/dataset_manifest.json`

All claims describe a deterministic local sandbox. They do not claim production-ready, enterprise-grade, live-model, real-money, or universal security.
