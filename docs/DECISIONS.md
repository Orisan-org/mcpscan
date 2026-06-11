# Decisions

## 2026-06-11 - MCP-030 SQL Execution Capability Mapping

Slice 2 requires MCP-030 findings to map to either `SHELL_EXEC` or `CODE_EVAL`.
For SQL/database execution surfaces, `mcpscan` maps the finding to `CODE_EVAL`.
This keeps MCP-030 within the requested two-capability output shape while
preserving the evidence text that the sink is SQL/database query execution.
