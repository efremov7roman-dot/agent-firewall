# Generated experiment artifacts

Run the frozen final benchmark with:

```powershell
.\.venv\Scripts\python.exe -m agent_firewall.evaluation --final --output-dir experiments
```

`final_benchmark.json` is the fingerprinted Phase 7 source of truth. It contains frozen
metadata, all three complete runs, scenario definitions, action outcomes, derived metrics,
and latency summaries. Development artifacts remain ignored and may be regenerated.

Phase 9 evidence is separate:

- `phase9_regression.json` is the compact machine-readable hardening summary;
- `phase9_original/final_benchmark.json` is the raw original-dataset rerun;
- `phase9_independent_regression.json` is the raw frozen Phase 8 dataset regression;
- `phase9_performance.json` is the post-hardening local performance profile.

These files do not replace or rewrite the Phase 7 or Phase 8 evidence.
