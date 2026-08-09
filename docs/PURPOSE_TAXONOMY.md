# Purpose taxonomy

`mcpscan` uses a small, deterministic purpose taxonomy to describe what an MCP
server claims to be. The contextual adjudicator uses this profile to label
findings and adjust severity where a capability is inherent to the declared
purpose. Findings are never suppressed.

The taxonomy lives in:

```text
src/mcpscan/data/purpose_categories.yaml
```

Each category defines:

- `keywords`: lowercase substrings matched against declared purpose text.
- `expected_capabilities`: capability enum values considered inherent to that
  purpose.

The file also defines `capability_keywords`, which let the adjudicator tell the
difference between an unexpected capability that was at least declared in text
and a capability that was not declared at all.

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
hits. A tie or zero hits resolves to `unknown`.

Purpose is resolved from the first of these that yields a category, and the
source is reported alongside it:

| Source | Where it comes from | May escalate? | May downgrade? |
| --- | --- | --- | --- |
| `flag` | `--purpose` / `--purpose-category` | Yes | Yes |
| `invocation` | the stdio command line or remote URL typed at the CLI | Yes | Yes |
| `config` | the same, but read from an MCP client config file | Yes | **No** |
| `server_info` | the server's own `name` / `instructions` | Yes | **No** |
| `unknown` | nothing matched | n/a | n/a |

The governing invariant: **any purpose source may escalate a severity; only an
operator-supplied purpose may downgrade one.** Escalation needs no trust,
because the worst a hostile source achieves by escalating is over-reporting its
own findings. A downgrade asserts that a dangerous capability is fine, so it may
only come from outside the system under test.

`config` and `invocation` can be the identical string. The difference is
provenance, not wording: install snippets are routinely copy-pasted from
server-authored documentation, so a config command line may have been written by
the server it is about. `server_info` is the server describing itself outright —
a malicious server can name itself `filesystem-helper` to make its own
file-write capability look routine.

An unconfirmed purpose therefore earns exactly one thing: `mcpscan` stops
escalating a capability it has already called expected, because a header that
says `filesystem` next to a verdict column that says `undeclared` is a
self-contradiction. It never lowers anything. Confirm the purpose with
`--purpose-category` if you want the downgrade.

Only the command line and URL feed `invocation`; they are never used for the
capability-mention check that separates `unexpected` from `undeclared`. An
interpreter path such as `python server.py` would otherwise read as a mention of
code execution.

## Proposing changes

Keep taxonomy changes conservative:

- Prefer precise keywords over broad words.
- Do not add vendor names unless the purpose is clear from that name.
- Keep `unknown` acceptable rather than forcing weak matches.
- Add or update tests when changing expected capabilities.
- Use existing `Capability` enum values only.

The taxonomy is static and local. It is not registry monitoring, and it does not
claim complete MCP ecosystem coverage.
