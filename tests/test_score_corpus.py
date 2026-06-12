from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.score_corpus import (
    CorpusValidationError,
    load_labels,
    score_corpus,
)

TOY = Path("tests/fixtures/corpus_toy")


def test_label_schema_accepts_toy_labels() -> None:
    labels = load_labels(TOY / "labels")

    assert sorted(labels) == ["toy_alpha", "toy_beta"]
    assert labels["toy_alpha"][0].property_id == "toy_alpha-P01"


def test_malformed_label_file_is_rejected_with_clear_error(tmp_path: Path) -> None:
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "bad.yaml").write_text(
        """
server_id: bad
corpus_sha: not-a-sha
labeler: tester
label_date: 2026-06-11
properties: []
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(CorpusValidationError, match="corpus_sha must be a 40-character git SHA"):
        load_labels(labels_dir)


def test_score_corpus_writes_provisional_outputs_and_unmapped_queue(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    _copy_tree(TOY / "results", results_dir)

    scores, unmapped = score_corpus(
        labels_dir=TOY / "labels",
        mapping_dir=TOY / "mapping",
        results_dir=results_dir,
        manifest_path=TOY / "manifest.yaml",
    )

    assert scores["status"] == "provisional"
    assert scores["summary"]["unmapped_findings"] == 1
    assert [finding.target for finding in unmapped] == ["env_reader"]
    assert (results_dir / "scores.json").exists()
    assert (results_dir / "scores.md").exists()
    unmapped_text = (results_dir / "unmapped.md").read_text(encoding="utf-8")
    assert "toy_alpha" in unmapped_text
    assert "env_reader" in unmapped_text


def test_score_corpus_finalize_requires_empty_unmapped_queue(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    _copy_tree(TOY / "results", results_dir)

    scores, unmapped = score_corpus(
        labels_dir=TOY / "labels",
        mapping_dir=TOY / "mapping",
        results_dir=results_dir,
        manifest_path=TOY / "manifest.yaml",
        finalize=True,
    )

    assert scores["status"] == "provisional"
    assert unmapped


def test_score_corpus_finalizes_when_unmapped_queue_is_empty(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    _copy_tree(TOY / "results", results_dir)
    report_path = results_dir / "toy_alpha" / "mcpscan-0.1.0.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"] = [
        finding for finding in report["findings"] if finding["target"] != "env_reader"
    ]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    scores, unmapped = score_corpus(
        labels_dir=TOY / "labels",
        mapping_dir=TOY / "mapping",
        results_dir=results_dir,
        manifest_path=TOY / "manifest.yaml",
        finalize=True,
    )

    assert scores["status"] == "final"
    assert unmapped == []


def test_score_corpus_cli_rejects_finalize_with_unmapped_queue(tmp_path: Path) -> None:
    # The pure function returns provisional output for inspection. The CLI is
    # stricter so an accidental release cannot mark scores final with an
    # unreviewed unmapped queue.
    from scripts.score_corpus import main

    results_dir = tmp_path / "results"
    _copy_tree(TOY / "results", results_dir)
    argv = [
        "score_corpus.py",
        "--labels-dir",
        str(TOY / "labels"),
        "--mapping-dir",
        str(TOY / "mapping"),
        "--results-dir",
        str(results_dir),
        "--manifest",
        str(TOY / "manifest.yaml"),
        "--finalize",
    ]

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("sys.argv", argv)
        assert main() == 2


def test_toy_metrics_match_hand_computed_expected_values(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    _copy_tree(TOY / "results", results_dir)

    scores, unmapped = score_corpus(
        labels_dir=TOY / "labels",
        mapping_dir=TOY / "mapping",
        results_dir=results_dir,
        manifest_path=TOY / "manifest.yaml",
    )

    mcpscan = scores["scanners"]["mcpscan"]
    assert scores["status"] == "provisional"
    assert scores["summary"]["unmapped_findings"] == 1
    assert len(unmapped) == 1
    assert mcpscan["true_positive"] == 1
    assert mcpscan["false_positive"] == 2
    assert mcpscan["false_negative"] == 1
    assert mcpscan["precision"] == pytest.approx(1 / 3)
    assert mcpscan["recall"] == pytest.approx(0.5)
    assert mcpscan["f1"] == pytest.approx(0.4)
    assert mcpscan["verdict_accuracy"]["by_design_downgrade_rate"] == pytest.approx(1.0)
    assert mcpscan["verdict_accuracy"]["real_threat_retention_rate"] == pytest.approx(1.0)


def _copy_tree(source: Path, target: Path) -> None:
    for path in source.rglob("*"):
        if path.is_dir():
            continue
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
