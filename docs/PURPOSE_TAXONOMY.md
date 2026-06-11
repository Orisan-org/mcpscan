# Purpose taxonomy

`mcpscan` uses a small, deterministic purpose taxonomy to describe what an MCP
server claims to be. This is reporting metadata only in the current build; it
does not change findings or severities until contextual adjudication is added.

The taxonomy lives in:

```text
src/mcpscan/data/purpose_categories.yaml
```

Each category defines:

- `keywords`: lowercase substrings matched against declared purpose text.
- `expected_capabilities`: capability enum values considered inherent to that
  purpose.

Current categories:

- `filesystem`
- `database`
- `shell_execution`
- `code_execution`
- `browser_automation`
- `api_wrapper`
- `web_search`
- `communication`
- `dev_tools`
- `memory_store`
- `unknown`

## How inference works

`mcpscan` counts keyword hits per category and picks the category with the most
hits. A tie or zero hits resolves to `unknown`. Explicit CLI flags take
precedence over server metadata.

## Proposing changes

Keep taxonomy changes conservative:

- Prefer precise keywords over broad words.
- Do not add vendor names unless the purpose is clear from that name.
- Keep `unknown` acceptable rather than forcing weak matches.
- Add or update tests when changing expected capabilities.
- Use existing `Capability` enum values only.

The taxonomy is static and local. It is not registry monitoring, and it does not
claim complete MCP ecosystem coverage.
