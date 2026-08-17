"""No claim about how any other scanner performs, anywhere we ship text.

Naming another tool factually is fine and sometimes necessary: that it emits
SARIF, or needs an account token, are checkable statements about features.
Rating one is not. We have run no controlled comparison, so a sentence
comparing detection quality would be a claim we cannot support, in a project
whose entire pitch is not making claims it cannot support.

(This docstring deliberately does not spell out an example of a forbidden
sentence. Writing one here would put a competitor name beside a comparative
term in a scanned file, and the guard would correctly flag itself. That is not
a hypothetical — the first run of this test did exactly that.)

It is also the claim most likely to age badly. The other tool ships a fix, our
sentence stays in the README, and a reader who checks discovers we were wrong.

THE COMPARATIVE TERMS BELOW ARE ASSEMBLED FROM FRAGMENTS. The competitor names
are literal, because a guard you cannot read is a guard nobody maintains — but
if the terms were literal too, this file would contain a name and a term within
the proximity window and would flag itself. Assembling them means the scan
covers EVERY tracked text file with no exemptions, including this one. An
allowlisted file is a hole, and the first thing through it would be exactly the
sentence this test is looking for.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Characters either side of a competitor mention that count as "near". Roughly
# two or three lines of prose, so a name in one sentence and a verdict in the
# next is still caught.
WINDOW = 240

TEXT_SUFFIXES = {".md", ".py", ".txt", ".toml", ".yml", ".yaml", ".cfg", ".rst"}


def _terms() -> list[str]:
    """Comparative-performance vocabulary, assembled so no literal appears here."""
    parts: list[tuple[str, ...]] = [
        ("false", " ", "positive"),
        ("false", " ", "negative"),
        ("more", " ", "accurate"),
        ("less", " ", "accurate"),
        ("better", " ", "than"),
        ("worse", " ", "than"),
        ("catches", " ", "more"),
        ("misses", " ", "more"),
        ("fails", " to ", "detect"),
        ("failed", " to ", "detect"),
        ("cannot", " ", "detect"),
        ("out", "perform"),
        ("infer", "ior"),
        ("super", "ior"),
        ("un", "reliable"),
        ("in", "accurate"),
    ]
    return ["".join(p) for p in parts]


#: Other scanners in this space. Factual mention allowed; rating not.
COMPETITOR_NAMES: list[str] = [
    "mcp-scan",
    "agent-scan",
    "mcp-scanner",
    "mcp-shield",
    "mcpsafetyscanner",
    "ramparts",
    "invariant labs",
    "invariantlabs",
    "snyk",
    "esentire",
    "cisco",
    "lasso",
]


def _tracked_text_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    files = []
    for rel in out.split("\0"):
        if not rel:
            continue
        path = ROOT / rel
        if path.suffix.lower() in TEXT_SUFFIXES and path.is_file():
            files.append(path)
    return files


def _violations(text: str, source: str) -> list[str]:
    lowered = text.lower()
    terms = _terms()
    found: list[str] = []
    for name in COMPETITOR_NAMES:
        for match in re.finditer(rf"(?<![\w-]){re.escape(name)}(?![\w-])", lowered):
            start = max(0, match.start() - WINDOW)
            end = min(len(lowered), match.end() + WINDOW)
            window = lowered[start:end]
            for term in terms:
                if term in window:
                    line = text[: match.start()].count("\n") + 1
                    excerpt = " ".join(text[start:end].split())[:220]
                    found.append(f'{source}:{line}: "{name}" within {WINDOW} chars of "{term}" — …{excerpt}…')
                    break
    return found


def test_no_shipped_text_rates_a_competitor() -> None:
    files = _tracked_text_files()
    assert len(files) > 20, "file discovery is broken; the guard would pass vacuously"

    violations: list[str] = []
    for path in files:
        violations.extend(_violations(path.read_text(encoding="utf-8", errors="replace"), str(path.relative_to(ROOT))))

    assert not violations, (
        "Shipped text rates another scanner's performance. We have run no controlled "
        "comparison, so this is a claim we cannot support.\n\n" + "\n".join(violations)
    )


def test_this_guard_scans_itself() -> None:
    """No exemptions, including for this file."""
    assert Path(__file__).resolve() in {p.resolve() for p in _tracked_text_files()}


def test_a_rating_sentence_is_caught() -> None:
    bad = "We benchmarked against " + COMPETITOR_NAMES[0] + ", which has a high " + _terms()[0] + " rate."
    assert _violations(bad, "synthetic")


def test_caught_across_a_sentence_boundary() -> None:
    bad = "Ramparts is written in Rust. In our testing it " + _terms()[8] + " tool poisoning."
    assert _violations(bad, "synthetic")


def test_a_factual_mention_is_allowed() -> None:
    good = "Ramparts emits SARIF 2.1.0. Snyk Agent Scan requires an account token."
    assert not _violations(good, "synthetic")


def test_our_own_accuracy_language_is_allowed() -> None:
    # Describing our OWN behaviour must stay sayable; the rule is about others.
    ours = "mcpscan reports a check that could not run as not run, never as passed. " + _terms()[0] + "s are triaged."
    assert not _violations(ours, "synthetic")


def test_the_term_list_cannot_be_quietly_emptied() -> None:
    assert len(_terms()) >= 12
    assert len(COMPETITOR_NAMES) >= 8
    # And no literal term leaks into this file's own source, or the guard would
    # exempt itself by tripping and being "fixed" with an allowlist.
    # Raw source, unnormalised. The fragments are stored as separate string
    # literals, so the assembled term never appears as a contiguous run of
    # characters here — which is the property that lets the guard scan itself.
    source = Path(__file__).read_text(encoding="utf-8").lower()
    leaked = [t for t in _terms() if t in source]
    assert not leaked, f"a comparative term appears literally in the guard's own source: {leaked}"
