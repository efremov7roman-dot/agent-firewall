# Phase 10 — Second Blind Independent Validation

## Executive Summary

The first technically valid run of a newly frozen 40-adversarial, 16-benign local dataset found 0 successful attacks, 0 unauthorized executed actions across 45 unauthorized attempts, and 16/16 benign task success. The result supports the hardened local authorization boundary within the tested scope. It does not establish live-model, cross-host, crash-consistency, or production-money guarantees.

## System Version Tested

This repository had no Git `HEAD`; `git status` showed the source and documents as untracked. `dataset_manifest.json` records SHA-256 hashes of production `src/` and `docs/` files before execution. Production code was not changed during Phase 10.

## Independence / Blindness Controls

Scenarios were derived from current production code, public interfaces, trust boundaries and documentation. Phase 8 scenario bodies and Phase 9 regression tests were not opened. The frozen dataset digest was checked by the evaluator before the valid run. Phase 8 high-level aggregate numbers came from the README and metrics document only.

## Attack Surface

See `attack-surface.md`. The critical path is proposal → gateway → policy/capability checks → resource and destination checks → idempotency/aggregate state → approval → pre-execution audit → sandbox → terminal audit.

## Security Invariants

See `invariants.md`. The tests focus on exact authority and action binding, stored-resource ownership, approval lifecycle, retry/state accounting, fail-closed rejection, and legitimate utility.

## Methodology

Each scenario used a fresh gateway and sandbox; multi-step scenarios shared that gateway. Inputs were typed at the public gateway boundary. Cases were classified before execution as black-box or gray-box. `methodology.md` defines ASR, UAR, FBR, invalid cases and the first-run rule.

## Frozen Dataset

40 adversarial and 16 benign scenarios. SHA-256: `05af25ba7a7fe34122fa36ffbb3867de10032ace49b03b7c685ae1fb775ff841`. The complete descriptions and expected outcomes are in `scenarios/`. The manifest includes version hashes.

## First Full Run

An initial attempted run was technically invalid because the evaluator assumed every grant fixture had a `constraints` key. Two scenarios raised `KeyError` before reaching the gateway. It is preserved as `first-invalid-run.json`. The evaluator default was repaired without changing the frozen dataset. `results.json` is the first technically valid complete run: 0 invalid scenarios, 0 evaluator errors, and 4 expected sandbox execution errors (unknown order, insufficient balance twice, unsupported symbol).

## Adversarial Results

0/40 successful attacks. Domain counts (success/total): approval 0/5; audit 0/1; authority 0/5; composition 0/2; destination 0/4; environment 0/2; idempotency 0/4; lifetime 0/1; representation 0/4; resource 0/5; scope 0/3; state 0/4.

## Benign Results

16/16 workflows succeeded. They include reads, order creation/cancellation, boundary amounts, transfers, retries, approval-required operations, another environment, another principal and delegated cancellation. There were 0 false blocks among 20 expected executions.

## ASR / UAR

ASR 0/40 = 0%; UAR 0/45 = 0%. These denominators apply only to this frozen scripted dataset.

## Black-Box vs Gray-Box Results

Black-box: 0/21 successful attacks. Gray-box: 0/19 successful attacks.

## Findings by Severity

Critical 0; High 0; Medium 0; Low 0; Informational 0. No successful attack required severity assessment. `findings.json` records coverage limits separately.

## Root-Cause Analysis

No new architectural root cause was observed. A coverage limit is not evidence that an untested boundary is secure.

## Semantic-Intent Results

No live-model semantic-intent scenario was run. Authorization failures 0; documented semantic limitations observed 0; ambiguous cases 0. The deterministic policy cannot infer malicious intent from an otherwise fully authorized action, as current documentation says.

## Utility Analysis

Benign success 100% (16/16); FBR 0% (0/20 expected executions). Approved withdrawal and threshold order both completed; exact retry replayed without another side effect.

## Claims Audit

See `claims-audit.md`. Local resource isolation, least-privilege constraints, action-bound approval, idempotency and aggregate controls are supported by this run. Complete mediation, audit integrity, fail-closed behavior and prompt-injection resistance have narrower evidence and must retain current scope qualifiers.

## Comparison With Phase 8

The initial Phase 7 development benchmark reported firewall ASR 3/24 and UAR 4/25. Phase 8's first blind validation reported ASR 17/26 and UAR 15/24. Phase 9's replay of Phase 8 cases was regression evidence, not independent validation. Phase 10's second blind dataset reports ASR 0/40 and UAR 0/45. The datasets differ, so the numbers show improved evidence of generalization within the local boundary, not a paired efficacy estimate.

## Remaining Limitations

The trusted host constructs identity, grants, clock and approval authority. This run did not test live-model semantic influence, multi-host state, recorder faults, audit tampering/truncation, crash consistency, or real funds. Gateway aggregate and idempotency state are local in memory; approval persistence uses a local filesystem. These limits remain material when describing a production deployment.

## Final Verdict

**FLAGSHIP-READY** for a scoped, local sandbox portfolio release. The central deterministic authorization claims passed this second blind set and benign utility stayed strong. Release language must keep the trusted-host and local-state limitations explicit. Recommended next action: **PORTFOLIO RELEASE**.
