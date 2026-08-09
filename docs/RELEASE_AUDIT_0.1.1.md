# Release audit — 0.1.1

Slice E of `BRIEF-0.1.1.md`. **Not published.** This records what was verified, how, and
what is left.

Two things are audited: the code, and **the brief itself**. The brief was an input to
this release in the same way the source was, and it turned out to be the less reliable
of the two.

---

## Method

Every claim below was checked against **the built wheel installed into a clean
virtualenv**, not against the repo tree. That distinction is the entire lesson of bug 3.

```
uv build                    -> dist/orisan_mcpscan-0.1.1-py3-none-any.whl
uv venv v && uv pip install v <wheel>     # unconstrained resolution
```

Fixture MCP servers run in a **separate** venv pinned to `mcp[cli]<2`; the server's SDK
is not part of mcpscan's artifact.

Each claim is tagged with its kind, per the standing rule on unpinned inputs:

- **[A] artifact-scoped** — true of this artifact permanently.
- **[R] re-verified** — depends on inputs that move; named job re-checks it.

---

## Claim ledger

| # | Claim | Kind | Verdict | Evidence |
|---|---|---|---|---|
| 1 | Distribution is `orisan-mcpscan`, command is `mcpscan` | A | ✅ | wheel `Name: orisan-mcpscan`; `v/bin/mcpscan` and `v/bin/orisan-mcpscan` both present |
| 2 | Version is 0.1.1 | A | ✅ | `mcpscan version` → `0.1.1`; metadata `Version: 0.1.1`; `test_version_consistency` |
| 3 | Repository URL resolves | R | ✅ | anonymous `GET` → `200` (was `404` before the visibility flip) |
| 4 | Streamable HTTP is the primary tested remote transport | R | ✅ | `pytest -m wheel` → 6 passed, incl. live HTTP scan from the installed wheel |
| 5 | Benign fixture grades `A` with no findings | A | ✅ | wheel run → `grade A, findings 0` |
| 6 | SARIF output is 2.1.0 | A | ✅ | `version: 2.1.0`, `$schema` present, 8 results |
| 7 | Exit codes 0/1/2/3/4 as documented | A | ✅ | clean→0, findings→1, nothing-scanned→2, enum error→3, incompatible SDK→4 |
| 8 | `payload_stored=false` on every finding | A | ✅ | 8/8 findings; fixture secret `ghp_…` absent from the report |
| 9 | Deterministic — identical apart from the run timestamp | A | ✅ | two runs, byte-identical after removing `scan.timestamp_utc` |
| 10 | No LLM in the verdict path | A | ✅ | `grep -rniE "openai\|anthropic\|\bllm\b" src/` → no matches |
| 11 | No telemetry; `--push-envelope` is the only outbound path | A | ✅ | single `httpx.post` in `src/`, in `_push_envelope` |
| 12 | Ten-second sample output in the README | A | ✅ | regenerated from a real wheel run: `Worst grade: D`, `expected_unconfirmed` |
| 13 | Supports Python 3.11–3.14 | R | ✅ | `ci.yml` `test` job runs the full 3.11/3.12/3.13/3.14 matrix across ubuntu, macos and windows |

### One narrower claim than it first appears

**Claim 13 is clean**, and I nearly recorded it as a blocker. The `wheel-harness` job
pins `python-version: "3.13"`, and reading only that job suggests the 3.11–3.14 support
claim is untested. The `test` job above it runs the full matrix — 3.11, 3.12, 3.13, 3.14
across ubuntu, macos and windows. Checking before writing is the only reason this table
does not contain a false entry, which is a small live demonstration of the brief's own
lesson.

What remains true, and is worth naming rather than leaving implicit: the **wheel harness
itself** runs on 3.13 only. The artifact is a pure-Python `py3-none-any` wheel and the
matrix job exercises every supported version against the same code, so this is a
defensible gap rather than an untested claim. It does mean a packaging fault that only
manifests on 3.11 or 3.14 — an entry point, a `tomllib` difference, a metadata edge —
would not be caught by the harness. Candidate for slice F, when the harness gains a
second wheel environment anyway.

---

## Audit of the brief

Six entries. Recorded because the brief's own reliability is a finding.

| Entry | Observation | Stated cause | Prescribed fix | Outcome |
|---|---|---|---|---|
| Bug 1 | ✅ real | ❌ wrong | ❌ would have deleted a control | Fixed by a different mechanism |
| Bug 2 | ⚠️ transient | ❌ false | ❌ would have leaked operator credentials | **Withdrawn** |
| Bug 2b | ✅ real | ✅ correct | ✅ correct | Fixed as specified |
| Bug 3 | ✅ real | ✅ correct | ✅ correct | Fixed as specified; scope understated |
| Bug 4 | ✅ real | ✅ correct | ✅ correct | Closed by the visibility flip |
| Slice A | ✅ | n/a | ✅ correct | Built; failed on main as required |

**Observations were 5/6 reliable. Stated causes were 4/6. Prescribed fixes were 3/6, and
the two that were wrong were both wrong in the direction of removing a security
control.**

That asymmetry is the point, and it is now written into the brief as a standing rule:
black-box observation yields symptoms, never causes; where an entry names a cause, treat
it as a hypothesis to falsify first.

Three specific failure modes, each with a worked example in the brief:

1. **A cause inferred from a symptom without reading the code path it names** (bugs 1
   and 2). Both stated causes described code that did not exist.
2. **An isolation step that did not isolate** (bug 2). "Adding `PATH`/`HOME` made it
   work" does not distinguish a missing `PATH` from a retry that succeeded because a
   download had finished.
3. **A fix specified as a mechanism rather than an outcome** (bugs 1 and 2). Both
   smuggled in a security decision that would not have survived being stated as one.

Bug 3's understated scope is worth its own note: the brief recorded the
`streamablehttp_client` rename but not that mcp 2.0 removed `mcp.server.fastmcp`
entirely. That difference is why slice A needed two virtualenvs rather than one, and why
adapting to 2.0 became slice F rather than a follow-up line.

---

## What was built that the brief did not ask for

- `wheel-canary.yml` — weekly re-verification of the install-time claims. Bug 3 was
  invisible for roughly six weeks because nothing in the repo changed.
- `mcp2-readiness-canary.yml` — the same harness against an mcp 2.x resolution,
  advisory and expected to fail. It answers the question the wheel canary structurally
  cannot: when does the pinned-out major become viable? Guarded by
  `tests/test_readiness_canary_is_not_pinned.py`, because an advisory job quietly
  constrained into the green is worse than no job.
- `sdk_compat.py` — refuses to scan on an out-of-range SDK rather than degrading.
- Slice G — connector failures name their stage. Bug 2's misdiagnosis was caused by
  `Connection closed` meaning three different things.
- The trust invariant, stated in `adjudicate.py`, the README, the taxonomy doc and the
  force-flag config; `purpose.py` added to the force-flag list.

---

## Release status: NOT PUBLISHED

Remaining before publish, in order:

1. **Merge the open stack.** #28 (slice B, Tier C) → #29 (slice C, Tier C) → #30
   (slice G) → this. All draft; all need a human on the diff.
2. **Slice F is not done.** The `<2` pin buys time; mcpscan does not speak the mcp 2.0
   API. The readiness canary now watches for the day it becomes viable; it currently
   fails 3 of 6, all at mcpscan's own SDK guard, which is the correct "not ready".
4. **Publish, then re-run the brief's reproduction against the published artifact**
   before announcing — including the bug 2 reproduction, which must be run in the
   environment where it was originally seen and is expected to pass.

The five invariants re-checked against the built wheel: deterministic ✅, no findings
suppressed ✅ (escalate or annotate, never drop), no LLM in scanner logic ✅,
`payload_stored=false` ✅, no telemetry ✅.
