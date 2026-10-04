# Phase 9 Regression Results

## Interpretation

The Phase 7 benchmark remains frozen evidence of the pre-hardening release. The Phase 8
dataset remains frozen evidence of the blind audit. Results below are new regression
measurements after Phase 9; they are not independent evidence of generalization.

## Original benchmark after hardening

Dataset SHA-256 remained
`bcf06e8803328c9c9c6ef201dee73a2ce56145e8678359db363a4903501d058e`.

| Configuration | ASR | UAR | Benign success | False blocks |
| --- | ---: | ---: | ---: | ---: |
| Unprotected | 22/24 (91.7%) | 23/25 (92.0%) | 8/8 | 0/13 |
| Basic rules | 11/24 (45.8%) | 12/25 (48.0%) | 8/8 | 0/13 |
| Hardened firewall | 1/24 (4.2%) | 1/25 (4.0%) | 8/8 | 0/13 |

The remaining original success is the capability-valid A09 semantic-intent scenario.
A07 is now blocked by idempotency/aggregate enforcement.

## Phase 8 dataset as regression

| Measure | Phase 8 first blind run | Phase 9 regression |
| --- | ---: | ---: |
| ASR | 17/26 (65.4%) | 3/26 (11.5%) |
| UAR | 15/24 (62.5%) | 2/24 (8.3%) |
| Benign success | 14/14 | 14/14 |
| False blocks | 0/17 | 0/17 |
| Invalid scenarios | 0 | 0 |

The three remaining scenario-oracle successes require qualification:

- IV-A-003 executes `get_portfolio`, but now returns principal-b’s isolated account. The
  frozen oracle treats any execution as a cross-principal leak, so this is a stale-oracle
  false positive after the ownership model changed.
- IV-A-025 remains an actual semantic-intent limitation: the owner holds valid create and
  cancel capabilities, and no trusted mandate says the induced cancellation is forbidden.
- IV-A-026 confirms the documented local atomicity limit: a recorder that fails after
  mutation can omit the terminal event, although the result reports the audit error.

Approval attacks were 0/6, fail-closed attacks 0/2, and composition attacks 0/2.

## Performance

The hardened original benchmark measured full gateway security-decision time at p50
0.0385 ms, p95 0.0804 ms, and p99 0.1082 ms across 38 decisions. Pre-hardening values were
0.0231/0.0331/0.0397 ms. The increase reflects resource resolution, destination,
idempotency, and aggregate-state checks now included in the measured boundary.

The separate 5,000-iteration profile measured:

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| Direct policy | 0.0052 ms | 0.0056 ms | 0.0059 ms |
| Gateway end-to-end | 0.2392 ms | 0.3035 ms | 0.4995 ms |

Throughput was 3,769.5 requests/second on the recorded host. Hash-chained deep-copy audit
events account for much of the higher gateway cost. These are local synthetic figures.

## Verification

- pytest: 110 passed;
- Phase 9 security/property module: 16 passed;
- Ruff check and format: passed;
- mypy project and independent-validation code: passed;
- pip check: no broken requirements;
- original Phase 7 artifact SHA-256 unchanged;
- all Phase 8 non-cache file hashes unchanged.

Machine-readable summary: `experiments/phase9_regression.json`.
