"""Every production ScanTarget must state its provenance.

`ScanTarget.origin` decides whether a purpose inferred from the target may downgrade a
severity (see the trust invariant in adjudicate.py). The model default is the *less*
trusted value, so a forgotten stamp fails safe — but failing safe silently is still a
bug, and a new code path that means "the operator typed this" and forgets to say so
loses a real feature without anyone noticing.

This asserts both directions: the default is the untrusted one, and every construction
site in src/ is explicit.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpscan.adjudicate import OPERATOR_PURPOSE_SOURCES
from mcpscan.models import PurposeSource, ScanTarget, TargetKind, TargetOrigin, Transport

SRC = Path(__file__).resolve().parents[1] / "src" / "mcpscan"


def test_the_default_origin_is_the_untrusted_one() -> None:
    """Fail-open on a trust boundary is the failure mode this guards."""
    target = ScanTarget(kind=TargetKind.COMMAND, transport=Transport.STDIO, command=["x"])

    assert target.origin == TargetOrigin.CONFIG
    assert PurposeSource.CONFIG not in OPERATOR_PURPOSE_SOURCES


def test_every_scan_target_construction_in_src_states_its_origin() -> None:
    sites: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "models.py":
            continue  # defines ScanTarget; has no call sites
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"ScanTarget\(", text):
            call = text[match.start() : match.start() + 600]
            depth, end = 0, len(call)
            for index, char in enumerate(call):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        end = index
                        break
            if "origin=" not in call[:end]:
                line = text[: match.start()].count("\n") + 1
                sites.append(f"{path.relative_to(SRC.parent.parent)}:{line}")

    assert not sites, (
        "ScanTarget built without an explicit origin=: "
        + ", ".join(sites)
        + ". Provenance decides downgrade authority; state it."
    )
