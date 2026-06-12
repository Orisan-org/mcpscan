#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcpscan.capabilities import Capability

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LABELS_DIR = ROOT / "corpus" / "labels"
DEFAULT_MAPPING_DIR = ROOT / "corpus" / "mapping"
DEFAULT_RESULTS_DIR = ROOT / "corpus" / "results"

PROPERTY_LABELS = {"real_threat", "by_design", "benign"}
SCORED_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class CorpusValidationError(ValueError):
    pass


@dataclass(frozen=True)
class LabeledProperty:
    server_id: str
    corpus_sha: str
    property_id: str
    capability: str
    tool: str | None
    label: str
    evidence: str
    external_refs: list[str]


@dataclass(frozen=True)
class FindingRecord:
    scanner: str
    server_id: str
    finding_id: str
    capability: str
    target: str
    severity: str
    contextual_verdict: str | None
    source_path: Path


@dataclass
class ScannerScore:
    scanner: str
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    by_design_matched: int = 0
    benign_matched: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    by_design_expected_by_purpose: int = 0
    by_design_total: int = 0
    real_threat_high_or_critical: int = 0
    real_threat_total: int = 0
    by_design_detected_properties: set[str] = field(default_factory=set)
    by_design_downgraded_properties: set[str] = field(default_factory=set)
    real_threat_detected_properties: set[str] = field(default_factory=set)
    real_threat_retained_properties: set[str] = field(default_factory=set)
    strata: dict[str, dict[str, int | float]] = field(default_factory=dict)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score corpus scanner results against labels.")
    parser.add_argument("--labels-dir", type=Path, default=DEFAULT_LABELS_DIR)
    parser.add_argument("--mapping-dir", type=Path, default=DEFAULT_MAPPING_DIR)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--manifest", type=Path, default=ROOT / "corpus" / "manifest.yaml")
    parser.add_argument(
        "--finalize",
        action="store_true",
        help="Mark scores final only if the unmapped review queue is empty.",
    )
    args = parser.parse_args()

    try:
        scores, unmapped = score_corpus(
            labels_dir=args.labels_dir,
            mapping_dir=args.mapping_dir,
            results_dir=args.results_dir,
            manifest_path=args.manifest,
            finalize=args.finalize,
        )
    except CorpusValidationError as exc:
        print(f"Corpus scoring error: {exc}", file=sys.stderr)
        return 2

    if args.finalize and unmapped:
        print(
            "Corpus scoring error: --finalize requires an empty unmapped queue. "
            "Review unmapped findings, update labels or mappings, then rerun.",
            file=sys.stderr,
        )
        return 2
    return 0


def score_corpus(
    *,
    labels_dir: Path,
    mapping_dir: Path,
    results_dir: Path,
    manifest_path: Path,
    finalize: bool = False,
) -> tuple[dict[str, Any], list[FindingRecord]]:
    labels = load_labels(labels_dir)
    _load_mapping_files(mapping_dir)
    manifest = _load_manifest(manifest_path)
    findings = load_findings(results_dir)
    scores, unmapped = compute_scores(labels, findings, manifest)
    status = "final" if finalize and not unmapped else "provisional"
    payload = {
        "status": status,
        "summary": {
            "unmapped_findings": len(unmapped),
            "scanners": sorted(scores),
        },
        "scanners": {scanner: _score_to_json(score) for scanner, score in sorted(scores.items())},
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "scores.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (results_dir / "scores.md").write_text(render_scores_markdown(payload), encoding="utf-8")
    (results_dir / "unmapped.md").write_text(render_unmapped_markdown(unmapped), encoding="utf-8")
    return payload, unmapped


def load_labels(labels_dir: Path) -> dict[str, list[LabeledProperty]]:
    if not labels_dir.exists():
        raise CorpusValidationError(f"labels directory does not exist: {labels_dir}")
    labels: dict[str, list[LabeledProperty]] = {}
    for path in sorted(labels_dir.glob("*.yaml")):
        payload = _load_yaml(path)
        server_id = _require_str(payload, "server_id", path)
        corpus_sha = _require_sha(payload, "corpus_sha", path)
        _require_str(payload, "labeler", path)
        _require_date(payload, "label_date", path)
        raw_properties = payload.get("properties")
        if not isinstance(raw_properties, list) or not raw_properties:
            raise CorpusValidationError(f"{path}: properties must be a non-empty list")
        properties: list[LabeledProperty] = []
        property_ids: set[str] = set()
        for raw in raw_properties:
            if not isinstance(raw, dict):
                raise CorpusValidationError(f"{path}: each property must be a mapping")
            property_id = _require_str(raw, "property_id", path)
            if property_id in property_ids:
                raise CorpusValidationError(f"{path}: duplicate property_id {property_id}")
            property_ids.add(property_id)
            capability = _require_capability(raw, "capability", path)
            tool = raw.get("tool")
            if tool is not None and not isinstance(tool, str):
                raise CorpusValidationError(
                    f"{path}: property {property_id} tool must be string/null"
                )
            label = _require_str(raw, "label", path)
            if label not in PROPERTY_LABELS:
                raise CorpusValidationError(
                    f"{path}: property {property_id} label must be one of "
                    f"{', '.join(sorted(PROPERTY_LABELS))}"
                )
            evidence = _require_str(raw, "evidence", path)
            external_refs = raw.get("external_refs")
            if not isinstance(external_refs, list) or not all(
                isinstance(ref, str) for ref in external_refs
            ):
                raise CorpusValidationError(
                    f"{path}: property {property_id} external_refs must be a list of strings"
                )
            properties.append(
                LabeledProperty(
                    server_id=server_id,
                    corpus_sha=corpus_sha,
                    property_id=property_id,
                    capability=capability,
                    tool=tool,
                    label=label,
                    evidence=evidence,
                    external_refs=external_refs,
                )
            )
        labels[server_id] = properties
    if not labels:
        raise CorpusValidationError(f"no label files found in {labels_dir}")
    return labels


def load_findings(results_dir: Path) -> list[FindingRecord]:
    if not results_dir.exists():
        raise CorpusValidationError(f"results directory does not exist: {results_dir}")
    findings: list[FindingRecord] = []
    for path in sorted(results_dir.glob("*/*.json")):
        if path.name in {"scores.json"}:
            continue
        server_id = path.parent.name
        findings.extend(_load_mcpscan_findings(path, server_id))
    return findings


def compute_scores(
    labels: dict[str, list[LabeledProperty]],
    findings: list[FindingRecord],
    manifest: dict[str, str],
) -> tuple[dict[str, ScannerScore], list[FindingRecord]]:
    properties_by_server = labels
    real_properties_by_server = {
        server_id: {prop.property_id for prop in props if prop.label == "real_threat"}
        for server_id, props in labels.items()
    }
    scores: dict[str, ScannerScore] = {}
    unmapped: list[FindingRecord] = []
    matched_real: dict[tuple[str, str], set[str]] = defaultdict(set)
    by_design_matches: dict[tuple[str, str], set[str]] = defaultdict(set)

    for finding in findings:
        score = scores.setdefault(finding.scanner, ScannerScore(scanner=finding.scanner))
        matches = _matching_properties(properties_by_server.get(finding.server_id, []), finding)
        labels_for_match = {match.label for match in matches}
        if finding.scanner == "mcpscan":
            if "by_design" in labels_for_match:
                by_design_match = next(match for match in matches if match.label == "by_design")
                property_key = _property_key(by_design_match)
                score.by_design_detected_properties.add(property_key)
                by_design_matches[(finding.scanner, finding.server_id)].add(
                    by_design_match.property_id
                )
                if finding.contextual_verdict == "expected_by_purpose":
                    score.by_design_downgraded_properties.add(property_key)
            if "real_threat" in labels_for_match:
                real_threat_match = next(match for match in matches if match.label == "real_threat")
                property_key = _property_key(real_threat_match)
                score.real_threat_detected_properties.add(property_key)
                if finding.severity in {"high", "critical"}:
                    score.real_threat_retained_properties.add(property_key)
        if not matches:
            unmapped.append(finding)
        if not _is_scored_finding(finding):
            continue
        if not matches:
            score.false_positive += 1
            _add_stratum_count(
                score, manifest.get(finding.server_id, "unknown"), "false_positive", 1
            )
            continue
        if "real_threat" in labels_for_match:
            real_match = next(match for match in matches if match.label == "real_threat")
            key = (finding.scanner, finding.server_id)
            if real_match.property_id not in matched_real[key]:
                score.true_positive += 1
                _add_stratum_count(
                    score, manifest.get(finding.server_id, "unknown"), "true_positive", 1
                )
            matched_real[key].add(real_match.property_id)
            continue
        if "by_design" in labels_for_match:
            score.false_positive += 1
            _add_stratum_count(
                score, manifest.get(finding.server_id, "unknown"), "false_positive", 1
            )
            continue
        score.false_positive += 1
        score.benign_matched += 1
        _add_stratum_count(score, manifest.get(finding.server_id, "unknown"), "false_positive", 1)

    scanner_names = set(scores)
    if not scanner_names:
        scanner_names.add("mcpscan")
    for scanner in sorted(scanner_names):
        score = scores.setdefault(scanner, ScannerScore(scanner=scanner))
        for server_id, property_ids in real_properties_by_server.items():
            missing = property_ids - matched_real.get((scanner, server_id), set())
            if missing:
                score.false_negative += len(missing)
                _add_stratum_count(
                    score, manifest.get(server_id, "unknown"), "false_negative", len(missing)
                )
        _finish_score(score)
    return scores, sorted(
        unmapped, key=lambda item: (item.server_id, item.scanner, item.finding_id)
    )


def render_scores_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Corpus scores",
        "",
        f"Status: {payload['status']}",
        "",
        "| Scanner | TP | FP | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for scanner, score in payload["scanners"].items():
        lines.append(
            "| {scanner} | {tp} | {fp} | {fn} | {precision:.3f} | {recall:.3f} | {f1:.3f} |".format(
                scanner=scanner,
                tp=score["true_positive"],
                fp=score["false_positive"],
                fn=score["false_negative"],
                precision=score["precision"],
                recall=score["recall"],
                f1=score["f1"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def render_unmapped_markdown(unmapped: list[FindingRecord]) -> str:
    lines = [
        "# Unmapped findings review queue",
        "",
        "Every finding listed here mapped to no labeled property. Review these before finalizing scores.",
        "",
    ]
    if not unmapped:
        lines.append("No unmapped findings.")
        lines.append("")
        return "\n".join(lines)
    grouped: dict[str, dict[str, list[FindingRecord]]] = defaultdict(lambda: defaultdict(list))
    for finding in unmapped:
        grouped[finding.server_id][finding.scanner].append(finding)
    for server_id in sorted(grouped):
        lines.append(f"## {server_id}")
        lines.append("")
        for scanner in sorted(grouped[server_id]):
            lines.append(f"### {scanner}")
            lines.append("")
            for finding in grouped[server_id][scanner]:
                lines.append(
                    f"- `{finding.finding_id}` `{finding.capability}` `{finding.target}` "
                    f"severity=`{finding.severity}` source=`{finding.source_path}`"
                )
            lines.append("")
    return "\n".join(lines)


def _load_mapping_files(mapping_dir: Path) -> None:
    if not mapping_dir.exists():
        raise CorpusValidationError(f"mapping directory does not exist: {mapping_dir}")
    paths = sorted(mapping_dir.glob("*.yaml"))
    if not paths:
        raise CorpusValidationError(f"no mapping files found in {mapping_dir}")
    for path in paths:
        payload = _load_yaml(path)
        scanner = _require_str(payload, "scanner", path)
        raw_rules = payload.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise CorpusValidationError(f"{path}: rules must be a non-empty list")
        for raw in raw_rules:
            if not isinstance(raw, dict):
                raise CorpusValidationError(f"{path}: each rule must be a mapping")
            _require_str(raw, "finding_id", path)
            mode = _require_str(raw, "match", path)
            if mode != "capability_and_tool":
                raise CorpusValidationError(
                    f"{path}: scanner {scanner} uses unsupported mapping mode {mode!r}"
                )


def _load_mcpscan_findings(path: Path, server_id: str) -> list[FindingRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if "findings" not in payload:
        return []
    findings: list[FindingRecord] = []
    for raw in payload.get("findings", []):
        if not isinstance(raw, dict):
            continue
        if raw.get("payload_stored") is not False:
            raise CorpusValidationError(f"{path}: finding does not preserve payload_stored=false")
        capability = raw.get("capability", "other")
        findings.append(
            FindingRecord(
                scanner="mcpscan",
                server_id=server_id,
                finding_id=str(raw.get("id", "")),
                capability=str(capability),
                target=str(raw.get("target", "")),
                severity=str(raw.get("adjusted_severity") or raw.get("severity") or ""),
                contextual_verdict=raw.get("contextual_verdict"),
                source_path=path,
            )
        )
    return findings


def _matching_properties(
    properties: list[LabeledProperty], finding: FindingRecord
) -> list[LabeledProperty]:
    matches: list[LabeledProperty] = []
    finding_target = _normalize_tool(finding.target)
    for prop in properties:
        if prop.capability != finding.capability:
            continue
        if prop.tool is None or _normalize_tool(prop.tool) == finding_target:
            matches.append(prop)
    return matches


def _finish_score(score: ScannerScore) -> None:
    score.by_design_matched = len(score.by_design_detected_properties)
    score.by_design_total = len(score.by_design_detected_properties)
    score.by_design_expected_by_purpose = len(score.by_design_downgraded_properties)
    score.real_threat_total = len(score.real_threat_detected_properties)
    score.real_threat_high_or_critical = len(score.real_threat_retained_properties)
    score.precision = _ratio(score.true_positive, score.true_positive + score.false_positive)
    score.recall = _ratio(score.true_positive, score.true_positive + score.false_negative)
    score.f1 = _ratio(2 * score.precision * score.recall, score.precision + score.recall)
    for metrics in score.strata.values():
        tp = int(metrics.get("true_positive", 0))
        fp = int(metrics.get("false_positive", 0))
        fn = int(metrics.get("false_negative", 0))
        metrics["precision"] = _ratio(tp, tp + fp)
        metrics["recall"] = _ratio(tp, tp + fn)
        metrics["f1"] = _ratio(
            2 * metrics["precision"] * metrics["recall"], metrics["precision"] + metrics["recall"]
        )  # type: ignore[operator]


def _score_to_json(score: ScannerScore) -> dict[str, Any]:
    payload = {
        "true_positive": score.true_positive,
        "false_positive": score.false_positive,
        "false_negative": score.false_negative,
        "precision": score.precision,
        "recall": score.recall,
        "f1": score.f1,
        "by_design_matched": score.by_design_matched,
        "benign_matched": score.benign_matched,
        "strata": score.strata,
    }
    if score.scanner == "mcpscan":
        payload["verdict_accuracy"] = {
            "by_design_downgrade_rate": _ratio(
                score.by_design_expected_by_purpose, score.by_design_total
            ),
            "real_threat_retention_rate": _ratio(
                score.real_threat_high_or_critical, score.real_threat_total
            ),
        }
    return payload


def _add_stratum_count(score: ScannerScore, stratum: str, key: str, value: int) -> None:
    metrics = score.strata.setdefault(
        stratum,
        {"true_positive": 0, "false_positive": 0, "false_negative": 0},
    )
    metrics[key] = int(metrics.get(key, 0)) + value


def _load_manifest(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = _load_yaml(path)
    entries = payload.get("entries", []) if isinstance(payload, dict) else []
    return {
        str(entry["id"]): str(entry["stratum"])
        for entry in entries
        if isinstance(entry, dict) and "id" in entry and "stratum" in entry
    }


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CorpusValidationError(f"{path}: expected YAML mapping")
    return payload


def _require_str(payload: dict[str, Any], key: str, path: Path) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CorpusValidationError(f"{path}: {key} must be a non-empty string")
    return value


def _require_sha(payload: dict[str, Any], key: str, path: Path) -> str:
    value = _require_str(payload, key, path)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise CorpusValidationError(f"{path}: {key} must be a 40-character git SHA")
    return value


def _require_date(payload: dict[str, Any], key: str, path: Path) -> str:
    value = _require_str(payload, key, path)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise CorpusValidationError(f"{path}: {key} must use YYYY-MM-DD")
    return value


def _require_capability(payload: dict[str, Any], key: str, path: Path) -> str:
    value = _require_str(payload, key, path)
    try:
        Capability(value)
    except ValueError as exc:
        raise CorpusValidationError(f"{path}: invalid capability {value!r}") from exc
    return value


def _normalize_tool(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _property_key(prop: LabeledProperty) -> str:
    return f"{prop.server_id}:{prop.property_id}"


def _is_scored_finding(finding: FindingRecord) -> bool:
    return SCORED_SEVERITY_ORDER.get(finding.severity, 0) >= SCORED_SEVERITY_ORDER["low"]


def _ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


if __name__ == "__main__":
    raise SystemExit(main())
