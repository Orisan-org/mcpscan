# mcpscan 0.1.1 — build brief

Four defects, all isolated to specific causes by direct observation on 2026-08-04
against a clean PyPI install of `orisan-mcpscan` 0.1.0 and the official
`@modelcontextprotocol/server-filesystem`. Roughly one day of work.

Tier per the Orisan agent operating model. Bugs 1 and 2 touch the force-flag list
(`adjudicate.py`, `scoring.py`) or security-adjacent env handling: **Tier C, human
reads the diff before merge, never auto-merged.**

---

## Bug 1 — inferred purpose never reaches the adjudicator · Tier C · ACCURACY-CRITICAL

The header prints the inferred purpose. The verdict column contradicts it on the same
output. Same server, same scan, one flag apart:

```
mcpscan scan --command "mcp-server-filesystem /tmp/safe-root"
  Purpose: filesystem (server_info)
  Grade: F
  CRITICAL (was HIGH)  undeclared  MCP-010  write_file
  CRITICAL (was HIGH)  undeclared  MCP-010  edit_file
  HIGH  unexpected  MCP-010  read_file
  exit 1

mcpscan scan --command "..." --purpose-category filesystem
  Grade: B
  INFO (was HIGH)  expected_by_purpose  MCP-010  write_file
  exit 0
```

**Cause:** the purpose resolved from `server_info` is used for display but not passed
into adjudication, so the adjudicator sees no declared purpose and treats every
capability as `undeclared`, escalating file write to CRITICAL on a server whose
declared identity is a filesystem server.

**Impact:** the default invocation — the one every new user runs — grades the most
widely deployed MCP server in the ecosystem an F with two criticals. This is the
single most damaging possible failure for the accuracy claim the company rests on.

**Fix:** thread the resolved purpose (whatever its source: flag, `--purpose`, or
`server_info`) into the adjudication call. One value, one path.

**Test that must exist afterwards:** scan a fixture whose `server_info.name` implies
a category, with and without the explicit flag, and assert the two runs produce
**identical** verdicts, adjusted severities and grade. That equivalence is the
invariant; anything less lets the two paths drift apart again.

---

## Bug 2 — `scan-config` does not inherit the parent environment · Tier C

The README's own example config fails:

```
Servers: 1 total, 0 scanned, 1 failed, 0 skipped
Worst grade: A
Failures: filesystem: Failed to enumerate stdio MCP server: MCPError: Connection closed
```

**Cause:** the child process receives only the config's `env` dict. With no `env`
block, `npx` launches with no `PATH` and no `HOME` and dies immediately. Isolated by
adding explicit `PATH`/`HOME` to the config `env`, which makes the identical config
scan cleanly. `scan --command "npx ..."` works, so the bug is specific to the
scan-config launch path.

**Impact:** every Claude Desktop, Claude Code, Cursor and Windsurf config in the wild
uses `npx` or `uvx` with no `env` block. The flagship one-liner
`uvx orisan-mcpscan scan-config ./mcp.json --yes` fails for essentially every user.

**Fix:** inherit `os.environ` and overlay the config's `env` on top (config wins on
conflict). **Preserve the redaction invariant**: env values must stay out of all
output. Inherited values must be redacted on the same path as config-supplied ones —
do not let the fix open a leak.

**Test:** an integration test that launches a stdio server through a command
requiring `PATH` resolution, from a config with no `env` block.

---

## Bug 2b — a grade is reported when nothing was scanned · Tier B

`Worst grade: A` printed with `0 scanned, 1 failed`. A grade when nothing was
assessed is a false clean bill of health, and under the honest-finish bar it is a
claim that is not true.

**Fix:** when zero servers were successfully scanned, report no grade and exit
non-zero. **Test:** assert no grade string appears when the scanned count is zero.

---

## Bug 3 — remote scanning is dead on every fresh install · Tier A (packaging)

```
mcpscan scan https://<host>/mcp --transport http
Enumeration error: Streamable HTTP transport is not available in the installed mcp SDK.
```

**Cause:** the wheel declares `mcp[cli]>=1.0.0` with no upper bound. PyPI now resolves
that to mcp 2.0.0, which renamed `streamablehttp_client` to `streamable_http_client`.
The import fails and the code silently degrades to "transport not available" instead
of erroring loudly.

**Impact:** the README states Streamable HTTP is "the primary tested remote transport
in this release." From a clean install today that claim is false. CI is green because
it resolves an older pinned SDK — this is a defect class the current CI structurally
cannot catch.

**Fix:** pin `mcp[cli]>=1.0.0,<2` for 0.1.1, then adapt to the 2.0 name in a follow-up.
Do not silently degrade: if the transport cannot be imported, fail loudly at startup.

**Test, and this is the important one:** install the **built wheel** into a clean
virtualenv and exercise the HTTP transport there. Testing the repo tree instead of the
artifact is why this shipped.

---

## Bug 4 — PyPI metadata points at a repository nobody can open · Tier A

The `Repository` link in 0.1.0's metadata 404s anonymously. Anyone who follows it from
PyPI concludes the project is vapour. Fix the URL in 0.1.1's metadata, or make the
repo public — decide which, then make the metadata true.

---

## Slices

**Slice A — the wheel test harness.** Tier A. Build the wheel, install into a clean
venv, run the headline commands against real fixtures. This is the gate that would
have caught bug 3, and it must exist before the fixes so it can demonstrate the
failure first. Acceptance: the new test **fails** on current main for bug 3, with the
output pasted in the PR.

**Slice B — bug 1, adjudication.** Tier C. Fix, add the equivalence test, human reads
the diff. Acceptance: default scan of the reference filesystem server grades B, not F,
and the inferred and explicit paths are byte-identical in verdict.

**Slice C — bugs 2 and 2b, scan-config.** Tier C. Acceptance: the README's own example
config scans cleanly with no `env` block, redaction still holds under a test that
plants a secret in the inherited environment, and zero-scanned reports no grade.

**Slice D — bugs 3 and 4, packaging and metadata.** Tier A. Acceptance: slice A's test
passes, and the repository URL resolves anonymously.

**Slice E — release.** Bump to 0.1.1, re-verify every README claim against the built
wheel rather than the repo, publish, then **re-run the full reproduction from this
brief against the published package** before announcing anything.

---

## Standing rules for this work

- Detection and adjudication code is security-adjacent: a human reads every diff on
  the force-flag list before merge, regardless of green tests.
- The five mcpscan invariants are re-checked before release: deterministic, no
  findings suppressed, no LLM in scanner logic, `payload_stored=false`, no telemetry.
- Every README claim is re-verified against the **built wheel in a clean environment**,
  not the repo tree. That distinction is the entire lesson of bug 3.
- Do not announce until the reproduction in this brief runs clean against the
  published artifact.
