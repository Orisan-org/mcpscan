# Decisions

## 2026-06-12 - Slice 10 Toy Metrics

Slice 10 toy corpus metrics use founder-supplied hand-computed expected values,
not values derived from the implementation under test. The exact test asserts
TP=1, FP=2, FN=1, one unmapped finding, precision=1/3, recall=0.5, F1=0.4,
provisional status, finalize rejection while unmapped findings remain,
`by_design_downgrade_rate=1.0`, and `real_threat_retention_rate=1.0`.

## 2026-06-11 - Corpus Scoring Units, Threshold, and Finalization

Corpus scoring applies a severity threshold before precision/recall: only
findings with adjusted severity `low` or above are scored. For `mcpscan`, the
adjusted severity is used when present, so `expected_by_purpose` downgrades to
`info` drop out of precision/recall. True positives are unique scored findings
mapped to `real_threat` properties. False negatives are `real_threat` properties
with no scored finding mapped to them. False positives are scored findings that
map to `by_design`, `benign`, or no labeled property. Findings mapped to no
labeled property are written to `corpus/results/unmapped.md`; low-or-above
unmapped findings count as false positives in provisional output.

Scores stay `provisional` by default. `--finalize` only produces `final` status
when the unmapped queue is empty; if the queue is non-empty the CLI exits 2 so a
benchmark cannot be finalized with unreviewed findings.

`real_threat_retention_rate` uses real-threat properties with at least one
mapped finding as its denominator. Missed real-threat properties are already
counted by recall and are intentionally not double-counted in the retention
rate.

## 2026-06-11 - Localhost Pytest Sandbox Escalation

Running `pytest` inside the managed filesystem sandbox failed on the existing
remote integration tests because `socket.bind(("127.0.0.1", 0))` raised
`PermissionError: [Errno 1] Operation not permitted`. The same test suite passed
when rerun with escalation that allowed localhost socket binding. Future CI or
container migrations should preserve localhost bind permission for Streamable
HTTP integration tests.

## 2026-06-11 - MCP-030 SQL Execution Capability Mapping

Slice 2 requires MCP-030 findings to map to either `SHELL_EXEC` or `CODE_EVAL`.
For SQL/database execution surfaces, `mcpscan` maps the finding to `CODE_EVAL`.
This keeps MCP-030 within the requested two-capability output shape while
preserving the evidence text that the sink is SQL/database query execution.
