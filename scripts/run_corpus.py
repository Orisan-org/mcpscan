#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import yaml

from mcpscan import __version__

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "corpus" / "manifest.yaml"
DEFAULT_CACHE = ROOT / ".corpus-cache"
DEFAULT_RESULTS = ROOT / "corpus" / "results"


@dataclass(frozen=True)
class CorpusEntry:
    id: str
    name: str
    repo_url: str
    git_sha: str
    stratum: str
    category: str
    transport: str
    install: list[str]
    launch_command: str
    env: dict[str, str]
    dummy_credentials: bool
    notes: str


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the mcpscan corpus harness.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--only", action="append", default=[], help="Server id to run.")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--i-understand",
        action="store_true",
        help="Required. Acknowledge that corpus servers execute locally.",
    )
    args = parser.parse_args()

    if not args.i_understand:
        print(_safety_banner(), file=sys.stderr)
        print("Refusing to run without --i-understand.", file=sys.stderr)
        return 2

    print(_safety_banner())
    if not _looks_isolated():
        print(
            "WARNING: This process does not look like it is running in a container. "
            "Use a disposable VM/container for real corpus runs.",
            file=sys.stderr,
        )

    entries = load_manifest(args.manifest)
    only = set(args.only)
    if only:
        entries = [entry for entry in entries if entry.id in only]

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str, str]] = []
    for entry in sorted(entries, key=lambda item: item.id):
        status, detail = run_entry(
            entry,
            cache_dir=args.cache_dir,
            results_dir=args.results_dir,
            timeout=args.timeout,
        )
        rows.append((entry.id, status, detail))

    print("")
    print("Corpus run summary")
    for server_id, status, detail in rows:
        print(f"- {server_id}: {status} ({detail})")
    return 0


def load_manifest(path: Path) -> list[CorpusEntry]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw_entries = payload.get("entries", []) if isinstance(payload, dict) else []
    entries: list[CorpusEntry] = []
    for raw in raw_entries:
        entries.append(
            CorpusEntry(
                id=raw["id"],
                name=raw["name"],
                repo_url=raw["repo_url"],
                git_sha=raw["git_sha"],
                stratum=raw["stratum"],
                category=raw["category"],
                transport=raw["transport"],
                install=list(raw.get("install", [])),
                launch_command=raw["launch_command"],
                env=dict(raw.get("env", {})),
                dummy_credentials=bool(raw.get("dummy_credentials", False)),
                notes=raw.get("notes", ""),
            )
        )
    return entries


def run_entry(
    entry: CorpusEntry,
    *,
    cache_dir: Path,
    results_dir: Path,
    timeout: float,
) -> tuple[str, str]:
    entry_cache = cache_dir / entry.id
    repo_dir = entry_cache / "repo"
    work_dir = entry_cache / "work"
    result_dir = results_dir / entry.id
    result_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path = result_dir / "run.log"
    error_path = result_dir / "error.txt"
    report_path = result_dir / f"mcpscan-{__version__}.json"
    _remove_if_exists(error_path)

    with log_path.open("w", encoding="utf-8") as log:
        try:
            checkout_repo(entry, repo_dir, log)
            for step in entry.install:
                run_shell(step, cwd=repo_dir, log=log, env=os.environ.copy())
            launch_command = _render_template(
                entry.launch_command,
                repo_dir=repo_dir,
                work_dir=work_dir,
                results_dir=result_dir,
            )
            env = os.environ.copy()
            for name, value in entry.env.items():
                env[name] = _render_template(
                    value, repo_dir=repo_dir, work_dir=work_dir, results_dir=result_dir
                )
            command = [
                sys.executable,
                "-m",
                "mcpscan",
                "scan",
                "--command",
                launch_command,
                "--purpose-category",
                entry.category,
                "--timeout",
                str(timeout),
                "--output",
                "json",
                "--out",
                str(report_path),
            ]
            completed = run_command(
                command,
                cwd=ROOT,
                log=log,
                env=env,
                allowed_returncodes={0, 1},
            )
            _validate_report(report_path)
            return ("ok", f"exit {completed.returncode}")
        except Exception as exc:
            error_path.write_text(str(exc), encoding="utf-8")
            return ("failed", str(exc))


def checkout_repo(entry: CorpusEntry, repo_dir: Path, log) -> None:
    if not repo_dir.exists():
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        run_command(["git", "clone", entry.repo_url, str(repo_dir)], cwd=ROOT, log=log)
    run_command(["git", "fetch", "origin", entry.git_sha, "--depth", "1"], cwd=repo_dir, log=log)
    run_command(["git", "checkout", "--force", entry.git_sha], cwd=repo_dir, log=log)


def run_shell(command: str, *, cwd: Path, log, env: dict[str, str]) -> subprocess.CompletedProcess:
    return run_command(command, cwd=cwd, log=log, env=env, shell=True)


def run_command(
    command: list[str] | str,
    *,
    cwd: Path,
    log,
    env: dict[str, str] | None = None,
    shell: bool = False,
    allowed_returncodes: set[int] | None = None,
) -> subprocess.CompletedProcess:
    log.write(f"$ {command if isinstance(command, str) else ' '.join(command)}\n")
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        shell=shell,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log.write(completed.stdout)
    log.write(f"\n[exit {completed.returncode}]\n")
    log.flush()
    allowed = allowed_returncodes or {0}
    if completed.returncode not in allowed:
        raise RuntimeError(f"command failed with exit {completed.returncode}")
    return completed


def _validate_report(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = payload.get("findings", [])
    if any(finding.get("payload_stored") is not False for finding in findings):
        raise RuntimeError("report contains finding without payload_stored=false")


def _render_template(value: str, *, repo_dir: Path, work_dir: Path, results_dir: Path) -> str:
    return value.format(
        repo_dir=repo_dir,
        work_dir=work_dir,
        results_dir=results_dir,
    )


def _remove_if_exists(path: Path) -> None:
    with suppress(FileNotFoundError):
        path.unlink()


def _safety_banner() -> str:
    return (
        "Corpus harness safety: this executes third-party MCP server code. "
        "Run only inside a disposable container or VM with no real credentials."
    )


def _looks_isolated() -> bool:
    if Path("/.dockerenv").exists():
        return True
    if os.environ.get("CI"):
        return True
    return os.environ.get("MCPSCAN_CORPUS_ISOLATED") == "1"


if __name__ == "__main__":
    raise SystemExit(main())
