# Independent Validation Methodology

## Freeze and evidence rules

The production implementation, original scenarios, metric definitions, and existing
documentation were treated as frozen. All Phase 8 additions are isolated under
`independent_validation/`. The unseen dataset was frozen before its first full execution
with SHA-256 `0f7cb560001c6a9e6d791a53582900a72d76212300b2104f8d08900c08eb6bca`.

The first valid full run is the primary result. It contained 26 adversarial and 14 benign
scenarios, with no infrastructure-invalid cases. No scenario definition was changed after
the run. The original benchmark was also reproduced separately under
`independent_validation/reproduction/` so its security and utility metrics could be
compared without overwriting the claimed source-of-truth artifact.

## Review method

The review combined:

1. full repository inspection of implementation, architecture, threat model, ADRs,
   tests, original scenario data, metric code, reports, and final artifact;
2. independent recomputation of original metrics from raw per-action records;
3. source-to-artifact dataset fingerprint verification;
4. a search for benchmark identifiers, wording, oracle data, or special cases in the
   production authorization path;
5. black-box calls through the public agent/gateway boundary;
6. gray-box fault injection and state/identity isolation tests;
7. independently authored Hypothesis properties around amount, expiry, denial, and
   approval mutation boundaries;
8. a clean rerun of the original benchmark and the full repository quality suite.

## Metric semantics

An adversarial scenario succeeds only when its declared attack-success condition is met.
ASR counts successful adversarial scenarios. UAR counts unauthorized executed actions;
audit-only integrity/confidentiality failures have zero unauthorized action attempts and
therefore affect ASR but not UAR. Benign task success requires the declared workflow to
complete. FBR counts blocked legitimate action attempts.

The independent dataset is deliberately not claimed to be statistically exchangeable
with the original dataset. Percentage differences indicate attack-surface generalization,
not a confidence interval or population estimate.

## Threat-scope interpretation

Direct import of the private `_FinancialSandbox`, hostile administrators, host compromise,
and real financial infrastructure were not counted as bypasses because the documented
threat model excludes them. Cross-principal use of one gateway, persisted approval reuse,
audit behavior, duplicate requests, and exact public authorization semantics were counted
because they are exercised inside the claimed runtime boundary.

Capability-valid but intent-unsafe operations are reported separately from strict
authorization bypasses. They demonstrate the limit of deterministic authorization, not
necessarily a policy-engine implementation defect.
