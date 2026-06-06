# Validation Results

This file tracks sanitized field-validation notes for real MCP servers. It is for repeatable product validation, not for storing raw MCP responses, prompt payloads, source code, credentials, or private target data.

Do not commit raw scan responses. Summarize findings with check IDs, redacted evidence, and reviewer judgment only.

## Results Table

| Target name | Target type | Install command or source | Scan command | Scan date | Result grade | Finding IDs | True positives | Suspected false positives | Suspected false negatives | Confusing output | Crash/error behavior | README/docs improvement | Raw payload stored? | `payload_stored=false` verified? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _Template_ | stdio / Streamable HTTP / SSE | Redacted install/source note | Redacted command with no secrets | YYYY-MM-DD | A-F | MCP-001, MCP-010 | Brief sanitized note | Brief sanitized note | Brief sanitized note | Brief sanitized note | None / summarized error | Brief improvement | No | Yes |

## Entry Template

Copy this block for longer notes when a table row is too small.

```md
### Target: <name>

- Target type: stdio / Streamable HTTP / SSE
- Install command or source: <redacted, no secrets>
- Scan command: <redacted, no secrets>
- Scan date: YYYY-MM-DD
- Result grade: A / B / C / D / F
- Finding IDs: MCP-...
- True positives:
  - <sanitized finding judgment>
- Suspected false positives:
  - <sanitized reason>
- Suspected false negatives:
  - <sanitized missing-risk note>
- Confusing output:
  - <what was unclear>
- Crash/error behavior:
  - <none, or sanitized error summary>
- README/docs improvement:
  - <one improvement suggested by this run>
- Raw payload stored: No
- payload_stored=false verified: Yes / No
- Sanitization notes:
  - <confirm no raw MCP responses, prompt payloads, source code, credentials, or secrets were committed>
```

## Sanitization Rules

- Do not paste raw tool descriptions, prompt content, resource bodies, source code, server responses, headers, tokens, credentials, or customer data.
- Keep scan commands free of real secrets. Replace sensitive values with `<redacted>`.
- Prefer finding IDs and short reviewer judgment over long evidence excerpts.
- Confirm every committed result says raw payload stored: `No`.
- Confirm every committed JSON-derived note was checked for `payload_stored=false`.
