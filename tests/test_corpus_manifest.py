from __future__ import annotations

import re
from pathlib import Path

import yaml

from mcpscan.models import PurposeCategory, Transport

ALLOWED_STRATA = {"reference", "popular", "risky", "dual_nature"}


def test_corpus_manifest_schema() -> None:
    payload = yaml.safe_load(Path("corpus/manifest.yaml").read_text())
    entries = payload["entries"]

    assert entries
    ids = [entry["id"] for entry in entries]
    assert len(ids) == len(set(ids))
    for entry in entries:
        assert entry["stratum"] in ALLOWED_STRATA
        assert PurposeCategory(entry["category"])
        assert Transport(entry["transport"])
        assert re.fullmatch(r"[0-9a-f]{40}", entry["git_sha"])
        assert entry["repo_url"].startswith("https://")
        assert isinstance(entry["install"], list)
        assert all(isinstance(step, str) and step for step in entry["install"])
        assert isinstance(entry["launch_command"], str) and entry["launch_command"]
        assert isinstance(entry.get("env", {}), dict)
        assert isinstance(entry.get("dummy_credentials", False), bool)
