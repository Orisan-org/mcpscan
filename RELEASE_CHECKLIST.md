# Release Checklist

Use this checklist before tagging an alpha release.

## Local Verification

```bash
ruff format --check .
ruff check .
pytest
python -m mcpscan --help
python -m mcpscan list-checks
mcpscan --help
```

## Fixture Scans

```bash
python -m mcpscan scan --command ".venv/bin/python tests/fixtures/benign_server.py"
python -m mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --severity-threshold high || test $? -eq 1
python -m mcpscan scan --command ".venv/bin/python tests/fixtures/malicious_server.py" --output json --out /tmp/mcpscan-smoke.json || test $? -eq 1
```

Start the local Streamable HTTP fixture in one terminal:

```bash
.venv/bin/python tests/fixtures/remote_streamable_server.py --port 8000
```

Scan it from another terminal:

```bash
python -m mcpscan scan http://127.0.0.1:8000/mcp --transport http || test $? -eq 1
```

## Release Hygiene

- README examples match actual CLI behavior.
- `python -m mcpscan --help` shows no placeholder commands.
- `python -m mcpscan list-checks` keeps MCP-002 marked `deferred`.
- JSON smoke output keeps every finding at `payload_stored=false`.
- Findings do not store raw secrets, full prompt payloads, source code, or full raw MCP responses.
- No `codex/`, build-prompt, scratch, or internal planning artifacts are committed.
- CI is green on the release commit.
- Version in `pyproject.toml` and `src/mcpscan/__init__.py` matches the intended tag.

## Tag

Recommended first alpha tag:

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```
