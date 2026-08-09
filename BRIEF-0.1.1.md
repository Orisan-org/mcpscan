# mcpscan 0.1.1 — build brief

Four defects, all isolated to specific causes by direct observation on 2026-08-04
against a clean PyPI install of `orisan-mcpscan` 0.1.0 and the official
`@modelcontextprotocol/server-filesystem`. Roughly one day of work.

Tier per the Orisan agent operating model. Bugs 1 and 2 touch the force-flag list
(`adjudicate.py`, `scoring.py`) or security-adjacent env handling: **Tier C, human
reads the diff before merge, never auto-merged.**

---

## Bug 1 — the header displays a purpose the adjudicator rejected · Tier C · ACCURACY-CRITICAL

> **CORRECTED 2026-08-09, after implementation.** The original write-up of this bug is
> preserved at the bottom of this section. Its stated cause was wrong and its acceptance
> criterion would have deleted a security control. Read the correction before touching
> `adjudicate.py`. **Do not re-attempt the original fix.**

The header prints the inferred purpose. The verdict column contradicts it on the same
output. Same server, same scan, one flag apart:

```
mcpscan scan --command "npx -y @modelcontextprotocol/server-filesystem /tmp/safe-root"
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

**Actual cause.** The resolved purpose *is* passed into adjudication —
`scanner.scan_context` hands `purpose_profile` straight to `adjudicate_findings`. The F
came from an explicit source gate in `adjudicate.py`: a capability could only take the
expected-by-purpose branch when `category_source == PurposeSource.FLAG`. A purpose from
any other source fell through to the undeclared branch and was escalated.

That gate was added deliberately in `d00f8f7` to close a real hole, and is guarded by
`tests/test_adjudicate_self_declaration.py`. The defect was never that the adjudicator
ignored the purpose. **The defect was that the header displayed a purpose the
adjudicator had deliberately rejected**, so the tool contradicted itself on one screen
and the user could not tell which half to believe.

**Impact.** The default invocation — the one every new user runs — graded the most
widely deployed MCP server in the ecosystem an F with two criticals.

**Fix as shipped.** The operator's own command line is a purpose signal a server cannot
forge, so `PurposeSource.INVOCATION` ranks with `FLAG` and the reference server reaches
`B` on the bare default invocation. `SERVER_INFO` and `CONFIG` still may not downgrade;
they only stop mcpscan escalating a capability it has itself just called expected, which
is the self-contradiction above. Governed by the trust invariant now stated at the top
of `adjudicate.py`:

> **Any purpose source may ESCALATE a severity. Only an operator-supplied purpose may
> DOWNGRADE one.**

`OPERATOR_PURPOSE_SOURCES` and the source gate are on the force-flag list. Every future
change to either is Tier C.

**Test that must exist afterwards:** the equivalence between the two *operator-supplied*
paths — invocation-inferred and explicitly flagged — asserted on verdicts, adjusted
severities and grade. Plus its opposite: the deliberate non-equivalence of an
unconfirmed purpose, asserted rather than left implicit, so no future session collapses
it. Both live in `tests/test_purpose_adjudication_equivalence.py`.

---

### Superseded original write-up, and why it was wrong

The original entry read:

> **Cause:** the purpose resolved from `server_info` is used for display but not passed
> into adjudication, so the adjudicator sees no declared purpose and treats every
> capability as `undeclared`.
>
> **Fix:** thread the resolved purpose (whatever its source: flag, `--purpose`, or
> `server_info`) into the adjudication call. One value, one path.
>
> **Acceptance:** the inferred and explicit paths are byte-identical in verdict.

Two errors, recorded so they are not repeated:

1. **The stated cause was not the cause.** The purpose was already threaded through. An
   implementer taking the brief at its word would have gone looking for a missing
   argument, not found one, and either declared the bug unreproducible or forced the
   equivalence some other way.
2. **The acceptance criterion would have deleted a security control.** "Byte-identical
   regardless of source" means adjudication trusts `server_info` exactly as much as the
   operator. A malicious server would then declare itself a filesystem server and
   downgrade its own file-write finding to `INFO` — precisely the lying-server hole
   `d00f8f7` closed, reopened by a criterion written to fix an accuracy complaint.

The general lesson: **an acceptance criterion phrased as "make these two outputs
identical" is dangerous when the two inputs differ in trust.** Sameness of output is
only a valid goal where the provenance is the same. Where it differs, the difference in
output *is* the control, and a test asserting sameness is a test asserting the control
is gone.

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
and the two **operator-supplied** paths — invocation-inferred and explicitly flagged —
are byte-identical in verdict. Unconfirmed sources are deliberately *not* identical to
those; see the corrected bug 1 above before changing this line.

**Slice C — bugs 2 and 2b, scan-config.** Tier C. Acceptance: the README's own example
config scans cleanly with no `env` block, redaction still holds under a test that
plants a secret in the inherited environment, and zero-scanned reports no grade.

**Slice D — bugs 3 and 4, packaging and metadata.** Tier A. Pin `mcp[cli]>=1.0.0,<2`
and stop there; do not attempt the 2.0 API. Acceptance: slice A's test passes, the 14
pre-existing failures on a fresh dev install clear (any that survive the pin are a
separate defect and get named, not absorbed), and the repository URL resolves
anonymously.

**Slice E — release.** Bump to 0.1.1, re-verify every README claim against the built
wheel rather than the repo, publish, then **re-run the full reproduction from this
brief against the published package** before announcing anything.

**Slice F — adapt to the mcp 2.0 API.** Tier B. Slice D's `<2` pin buys time; it does
not resolve anything. The 2.0 surface is a real port with its own test surface, not a
rename to chase:

- `streamablehttp_client` became `streamable_http_client`.
- **`mcp.server.fastmcp` was removed entirely**, replaced by `mcp.server.mcpserver`.
  There is no alias for either. All of `tests/fixtures/*.py` build their servers on
  `FastMCP`, so the fixture corpus is part of this port, not a downstream consequence
  of it.
- mcp 2.0 pulls a different dependency set (`httpx2`, `mcp-types`, `opentelemetry-api`),
  so the port is an install-surface change as well as an API change.

The work is a compatibility shim over both SDK generations, or a hard move to 2.0 with
the floor raised — decide which, and say why. Either way the acceptance is the same:
**slice A's wheel harness passes on both an mcp 1.x and an mcp 2.x resolution**, which
means the harness gains a second wheel environment rather than trusting one. Do not
widen the pin in `pyproject.toml` or the bounds in `src/mcpscan/sdk_compat.py` until
that harness is green on both.

---

## Candidate checks for a later slice

Not scheduled. Logged so they are not rediscovered from scratch. Both are governed by
the trust invariant: they raise suspicion, they never lower a floor.

**Purpose disagreement between sources.** When the operator's invocation infers one
category and the server's `server_info` infers another, the operator's currently wins
silently. A server whose command line says `server-filesystem` while it describes itself
as a shell execution tool — or the reverse — is worth surfacing on its own. It is weak
evidence of a mislabelled or repurposed package. Under the invariant this can only ever
*add* a finding or escalate one; it must never be allowed to resolve a disagreement in
the direction that lowers a severity. Surfaced during slice B, deliberately not built
there.

**Filesystem scope is not assessed.** `examples/sample-mcp.json` hands
`@modelcontextprotocol/server-filesystem` the path `/`, and nothing in the report says
so. The tools it exposes are the same whether it is scoped to `/tmp/safe` or the whole
disk, so every capability check reads identically while the actual blast radius differs
enormously. The scope lives in the invocation arguments, which mcpscan already parses
for purpose inference. Escalation-only, per the invariant.

## Standing rules for this work

- Detection and adjudication code is security-adjacent: a human reads every diff on
  the force-flag list before merge, regardless of green tests.
- The five mcpscan invariants are re-checked before release: deterministic, no
  findings suppressed, no LLM in scanner logic, `payload_stored=false`, no telemetry.
- Every README claim is re-verified against the **built wheel in a clean environment**,
  not the repo tree. That distinction is the entire lesson of bug 3.
- Do not announce until the reproduction in this brief runs clean against the
  published artifact.
