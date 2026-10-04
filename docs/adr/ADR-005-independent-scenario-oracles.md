# ADR-005: Scripted proposals with independent scenario oracles

- Status: Accepted for Phase 4 development benchmark
- Date: 2026-10-02

## Context

Using a live model would mix authorization effectiveness with nondeterministic model
behavior, provider availability, and cost. Deriving expected outcomes from firewall
decisions would make the benchmark circular.

## Decision

Feed identical, versioned scripted tool proposals to all three configurations. Treat an
injection proposal as evidence that the agent was influenced, then measure whether the
forbidden action executes. Define authorization and success independently in each
scenario oracle. Run each scenario from a fresh deterministic sandbox fixture.

## Consequences

The benchmark isolates the runtime-security thesis and runs locally without APIs. It does
not measure how often a real model follows an injection; optional model-dependent
experiments may be added as a separately reported profile. Scenario-oracle review remains
critical because incorrect labels would bias every configuration equally.

