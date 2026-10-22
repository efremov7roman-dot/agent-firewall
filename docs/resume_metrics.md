# Evidence-backed resume metrics

## Short version

- Built a deterministic zero-trust execution gateway for tool-using financial agents, enforcing principal/resource isolation, scoped capabilities, context-bound approvals, idempotency, aggregate limits, destination controls, and tamper-detectable local audit records around seven sandbox tools.
- Used evaluation-first hardening: a first blind review exposed 17/26 successful attacks; after root-cause redesign, a second independently designed frozen local evaluation observed 0/40 successful attacks, 0/45 unauthorized executions, and 16/16 benign workflows in the tested scope.
- Integrated a local qwen3:8b LangGraph tool-calling agent and built a frozen 90-scenario live-model benchmark. In the unseen final split, Full Firewall observed 0/24 successful attacks, blocked 12/12 model-proposed forbidden calls, and completed 12/12 legitimate tasks; 12/24 attack scenarios never elicited a target call and are not credited as gateway prevention.

## Extended version

- Designed a model-independent authorization boundary that treats LLM calls as untrusted proposals and returns deterministic `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` decisions.
- Preserved a failed first blind validation (17/26 ASR, 15/24 UAR) and converted its root causes into ownership-aware resource checks, atomic approval use, idempotency, aggregate budgets, destination scope, and hardened audit behavior.
- Passed a second frozen blind local set with 0/40 successful adversarial scenarios, 0/45 unauthorized executed actions, 16/16 benign workflows, and 0/20 false blocks; the result is scoped evidence, not a universal-security claim.
- Measured hardened local decision latency at 0.0385/0.0804/0.1082 ms p50/p95/p99 and a separate 5,000-iteration gateway profile at 0.2392/0.3035/0.4995 ms with 3,769.5 requests/second on the recorded host.
- In the frozen live-model final run, Full Firewall tool-call latency was 0.872/1.683/1.699 ms p50/p95/p99 across 32 calls; task latency was 1327.397/2422.262/2638.858 ms across 36 runs. All 36 completed without timeout or execution failure. Fixed-seed first-turn outputs agreed across modes in 7/36 scenarios, so model variation remains material.

## Evidence

- Phase 8: `independent_validation/results.json`
- Phase 9: `experiments/phase9_regression.json` and `experiments/phase9_performance.json`
- Phase 10: `phase10_validation/results.json` and `phase10_validation/dataset_manifest.json`
- Live model: `evals/live_v2/manifest.json`, `evals/live_v2/implementation_freeze.json`, `experiments/live_v2_final.json`, and `docs/live-v2-validation.md`

The earlier deterministic evaluations and the new local-model evaluation are separate evidence. All operations use a sandbox. These results do not claim production readiness, real-money safety, or universal security.
