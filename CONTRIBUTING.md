# Contributing

`mcpscan` is an alpha local-first MCP security scanner. Contributions should keep the scanner deterministic, offline by default, and honest about unsupported scope.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality Gates

```bash
ruff format --check .
ruff check .
pytest
python -m mcpscan --help
python -m mcpscan list-checks
```

## Contribution Rules

- Do not add cloud upload behavior.
- Do not add LLM verdicts.
- Do not add registry monitoring without a separate design discussion.
- Do not store raw secrets, full prompt payloads, source code, or full raw MCP responses in findings.
- Keep every finding at `payload_stored=false`.
- Add focused tests for every user-visible command or check behavior.
