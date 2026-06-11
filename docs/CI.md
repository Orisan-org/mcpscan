# CI usage

`mcpscan` can emit SARIF for GitHub code scanning upload. This is a reporting
format only; it does not make `mcpscan` a GitHub Action package.

Minimal example:

```yaml
name: mcpscan
on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install mcpscan from source
        run: |
          python -m pip install --upgrade pip
          pip install git+https://github.com/Orisan-org/mcpscan.git
      - name: Scan MCP server
        run: |
          mcpscan scan \
            --command '<your MCP server command>' \
            --output sarif \
            --out mcpscan.sarif || test $? -eq 1
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcpscan.sarif
```

Do not run untrusted stdio MCP server commands in CI without isolating the job.
