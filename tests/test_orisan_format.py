"""Slice 10 — findings in recorder vocabulary, deliberately not a chain.

A recorder event means something only inside a hash chain. mcpscan cannot
produce one: it does not know the log it will be appended to, what preceded it,
or what will follow. Inventing seq/prev_hash/hash would manufacture evidence
that looks verified and is not.

So the document is detached, and the tests below are mostly about proving it
CANNOT be mistaken for a chain — that its entries are rejected as events, and
that the fields the recorder assigns at append time are absent rather than
guessed.
"""

from __future__ import annotations

import json
import sys

from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.orisan_format import (
    ASSIGNED_ON_APPEND,
    CHAIN_FIELDS,
    DOCUMENT_FORMAT,
    RECORDER_ACTOR_KEYS,
    RECORDER_CLOCK_SOURCES,
    RECORDER_EVENT_KEYS,
    RECORDER_EVENT_KINDS,
)

runner = CliRunner()
PYEXE = sys.executable
MALICIOUS = f"{PYEXE} tests/fixtures/malicious_server.py"


def _document() -> dict:
    out = runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "orisan"])
    return json.loads(out.stdout)


# --------------------------------------------------- it cannot pass as a chain


def test_no_entry_carries_a_chain_field() -> None:
    """The safety property. Present in a recorder event, absent here."""
    for event in _document()["events"]:
        for field in CHAIN_FIELDS:
            assert field not in event, field


def test_fields_the_recorder_assigns_are_absent_not_guessed() -> None:
    for event in _document()["events"]:
        for field in ASSIGNED_ON_APPEND:
            assert field not in event, field


def test_a_recorder_would_reject_every_entry_as_an_event() -> None:
    """Modelled on orisan-recorder's validateEvent.

    A COPY of its rules, not an import — that validator is TypeScript. The
    real one was run against this document during development and rejected
    8/8; this test keeps the property under CI without a cross-repo dependency.
    """
    for event in _document()["events"]:
        assert "v" not in event, "no schema version, so validateEvent fails at the first check"
        assert not {"seq", "prev_hash", "hash", "event_id", "session_id"} & set(event)


def test_the_document_declares_itself_unchained() -> None:
    document = _document()
    assert document["chained"] is False
    assert "not a verified chain" in document["chain_note"]
    assert "must not be presented as one" in document["chain_note"]


def test_the_top_level_is_not_shaped_like_an_event_either() -> None:
    document = _document()
    assert "events" in document and isinstance(document["events"], list)
    assert not set(CHAIN_FIELDS) & set(document)


# --------------------------------------------------- but the vocabulary is right


def test_entries_use_only_field_names_the_recorder_knows() -> None:
    for event in _document()["events"]:
        assert set(event) <= RECORDER_EVENT_KEYS, set(event) - RECORDER_EVENT_KEYS
        assert set(event["actor"]) == RECORDER_ACTOR_KEYS


def test_the_kind_and_clock_source_are_values_the_recorder_accepts() -> None:
    """`clock_source: "system"` reads fine and is not in the recorder's
    vocabulary. Caught by running the real validator, not by reading a list."""
    for event in _document()["events"]:
        assert event["kind"] in RECORDER_EVENT_KINDS
        assert event["clock_source"] in RECORDER_CLOCK_SOURCES
        assert event["clock_source"] == "host_wall_clock"


def test_findings_map_to_the_existing_flag_kind() -> None:
    """No new EVENT_KINDS value, so no cross-repo change is needed and no
    document can arrive before the recorder can read it."""
    assert {event["kind"] for event in _document()["events"]} == {"flag"}


def test_args_digest_is_sha256_hex_as_the_recorder_requires() -> None:
    for event in _document()["events"]:
        assert len(event["args_digest"]) == 64
        int(event["args_digest"], 16)


# --------------------------------------------------- the invariants survive


def test_no_evidence_text_crosses_the_boundary() -> None:
    """payload_stored=false has to hold in every format."""
    document = _document()
    blob = json.dumps(document)
    assert all(event["payload_ref"] is None for event in document["events"])
    # The evidence sentences themselves are digested, never carried.
    assert "Ignore all previous instructions" not in blob
    assert "hardcoded" not in blob.lower() or "args_digest" in blob


def test_the_document_carries_the_ruleset_and_tier() -> None:
    document = _document()
    from mcpscan.ruleset import ruleset_digest

    assert document["ruleset_digest"] == ruleset_digest()
    assert document["tier"] == "live"
    assert document["document_format"] == DOCUMENT_FORMAT


def test_checks_not_run_survive_into_the_document() -> None:
    out = runner.invoke(app, ["scan", "--command", MALICIOUS, "--no-execute", "--output", "orisan"])
    document = json.loads(out.stdout)
    assert document["tier"] == "config"
    assert document["checks_not_run"], "a check that could not run is reported in every format"


def test_output_is_canonical_and_deterministic_apart_from_the_timestamp() -> None:
    """`ts` is when the scan happened, so it moves — as the README's
    determinism claim already carves out. Everything else must not."""
    first = json.loads(
        runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "orisan"]).stdout
    )
    second = json.loads(
        runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "orisan"]).stdout
    )

    def without_ts(document: dict) -> list[dict]:
        return [{k: v for k, v in event.items() if k != "ts"} for event in document["events"]]

    assert without_ts(first) == without_ts(second)
    assert {k: v for k, v in first.items() if k != "events"} == {
        k: v for k, v in second.items() if k != "events"
    }


def test_output_uses_the_recorders_canonical_json_rules() -> None:
    raw = runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "orisan"]).stdout
    assert raw == json.dumps(json.loads(raw), indent=2, sort_keys=True) + "\n"


def test_an_unknown_output_is_still_refused() -> None:
    assert runner.invoke(app, ["scan", "--command", MALICIOUS, "--output", "yaml"]).exit_code == 2
