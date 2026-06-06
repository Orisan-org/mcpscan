# Validation Protocol

Use this protocol when testing `mcpscan` against real-world MCP servers after the v0.1 alpha release. The goal is to learn where the scanner is useful, noisy, confusing, or fragile without expanding product scope.

## Target Selection

Choose a small, diverse set of MCP servers:

- official or reference-style servers that are easy to run locally
- popular stdio servers with simple setup
- at least one tested Streamable HTTP target when available
- targets with low operational risk and no real credentials
- targets that can be run in disposable directories

Do not scan public servers from CI. Do not add runtime registry lookups, registry monitoring, SaaS upload, LLM verdicts, or enforcement behavior as part of validation.

## Safe Environment

- Run each target in a disposable temporary directory.
- Prefer fresh virtual environments, containers, or short-lived working directories.
- Never scan with real credentials, production tokens, customer data, or private source trees.
- Use fake credentials only when you intentionally want to validate redaction behavior.
- Do not point broad filesystem MCP servers at a real home directory.
- Keep target install commands and environment setup reproducible but sanitized.

## Troubleshooting Stale Installs

Always run validation from a fresh virtual environment and verify the binary before trusting scan output:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e /path/to/mcpscan
which mcpscan
mcpscan --help
```

Use `python -m venv .venv` instead if your system exposes Python 3 as `python`.

Expected commands are only:

- `version`
- `list-checks`
- `scan`

If `baseline` or `diff` appears in help output, the shell is resolving a stale global install. Reinstall into the active virtual environment and rerun `which mcpscan`.

To avoid `PATH` confusion during validation, prefer:

```bash
python -m mcpscan --help
python -m mcpscan scan --command "<redacted command>"
```

If editable install fails while fetching build dependencies such as `hatchling`, fix network/dependency installation first. Do not trust scan output from a shell that fell back to a global `mcpscan` binary after install failure.

## Running A Validation Scan

1. Record the target name, target type, install source, and scan date.
2. Run `mcpscan list-checks` so the active/deferred catalogue is clear.
3. Run the scan with terminal output first.
4. Run a JSON report to a temporary path for structured review:

   ```bash
   mcpscan scan --command "<redacted command>" --output json --out /tmp/mcpscan-target.json || test $? -eq 1
   ```

5. Treat exit code `1` as expected when findings meet the severity threshold.
6. Treat exit codes `2`, `3`, and `4` as usability or reliability data to record under crash/error behavior.
7. Do not commit the raw JSON report unless it has been reviewed and sanitized.

## JSON Safety Checks

Before recording validation notes, verify the report preserves the evidence contract:

```bash
python - <<'PY'
import json
from pathlib import Path

path = Path("/tmp/mcpscan-target.json")
payload = json.loads(path.read_text())
findings = payload.get("findings", [])
print("summary_grade", payload.get("summary", {}).get("grade"))
print("finding_count", len(findings))
print("payload_stored_false", all(f.get("payload_stored") is False for f in findings))
PY
```

Also search for obvious synthetic or accidental secrets before committing notes:

```bash
rg -n "sk-|ghp_|xox[baprs]-|AKIA|BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|password=|api_key=" /tmp/mcpscan-target.json
```

If that search returns anything sensitive, do not commit the report. Record only a sanitized summary in `docs/VALIDATION_RESULTS.md`.

## Recording Findings

For each target, classify findings as:

- true positive: the finding describes a real exposed risk or risky default
- suspected false positive: the finding is technically matched but not useful in context
- suspected false negative: manual review found a risk that `mcpscan` missed
- unclear: the output was ambiguous enough that the reviewer could not judge quickly

Record finding IDs, not raw payloads. Use short sanitized descriptions such as:

- `MCP-010 correctly flagged broad file read tool`
- `MCP-050 looked noisy for internal tool name`
- `Possible false negative: tool accepts path-like input but schema was too generic`

## Handling Non-Zero Exit Codes

`mcpscan` returns `1` when a scan completes and at least one finding meets the severity threshold. That is expected for risky targets.

Use this pattern for validation commands that are expected to find issues:

```bash
mcpscan scan --command "<redacted command>" --severity-threshold high || test $? -eq 1
```

Investigate and record exit codes:

- `2`: input or CLI usage error
- `3`: connection or enumeration error
- `4`: internal scanner error

## Before Committing Validation Notes

- Confirm no raw MCP responses are included.
- Confirm no full prompt payloads are included.
- Confirm no source code from the target is included.
- Confirm no real credentials, tokens, headers, or secrets are included.
- Confirm all committed notes say raw payload stored: `No`.
- Confirm `payload_stored=false` was verified for JSON-derived findings.
- Prefer one concrete README/docs improvement per target.
