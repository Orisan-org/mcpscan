# Corpus harness

The corpus harness runs `mcpscan` against pinned real-world MCP server
checkouts and records per-server results.

This is validation tooling, not product scanning behavior.

## Safety

Corpus runs execute third-party code from public repositories. Run the harness
inside a disposable container or VM.

Do not run it on a daily-use workstation with access to real credentials.

The harness requires `--i-understand`, but that acknowledgement is not a
substitute for isolation.

## Manifest

The manifest lives at:

```text
corpus/manifest.yaml
```

Each entry has:

- `id`: stable server id
- `name`: human-readable name
- `repo_url`: source repository
- `git_sha`: pinned commit SHA
- `stratum`: `reference`, `popular`, `risky`, or `dual_nature`
- `category`: purpose category passed to `mcpscan`
- `transport`: currently `stdio`
- `install`: shell commands run from the cloned repo
- `launch_command`: MCP server command; supports `{repo_dir}`, `{work_dir}`,
  and `{results_dir}` placeholders
- `env`: environment values for launch; supports the same placeholders
- `dummy_credentials`: whether dummy credentials were used
- `notes`: short operational note

## Running

Use a container or VM, then run:

```bash
python scripts/run_corpus.py --i-understand
```

To run one server:

```bash
python scripts/run_corpus.py --i-understand --only reference_filesystem
```

Outputs:

- `.corpus-cache/`: cloned repos and per-server work directories
- `corpus/results/<server_id>/mcpscan-0.1.0.json`: report when scan succeeds
- `corpus/results/<server_id>/run.log`: sanitized operational log
- `corpus/results/<server_id>/error.txt`: install, launch, or enumeration failure

Per-server failures are data. The harness continues after failures.

## Adding A Server

Before adding a server, read
[CORPUS_PREREGISTRATION.md](CORPUS_PREREGISTRATION.md).

Only add candidates that satisfy the preregistered inclusion criteria, or
record why the criteria changed.

For servers that require environment variables, prefer dummy values if MCP
enumeration succeeds without valid credentials. Record that in
`dummy_credentials` and `notes`.

Do not invoke tools that call upstream services during corpus enumeration.
