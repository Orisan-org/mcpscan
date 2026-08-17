"""Slice 6 — optional witness submission.

A signature proves who said something, not when, and not that an inconvenient
result was never deleted. A witness outside the operator's control closes both.

The constraint that shapes everything here: it is optional. No witness, an
unreachable witness, a throttled witness — none of them may block a scan or
turn a clean run into a failure.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.signing import generate_key, load_private_key, public_key_pem
from mcpscan.witness import (
    RETRYABLE_STATUS,
    WitnessKeyMismatch,
    read_config,
    register,
    retry_delay,
    submission_payload,
    submit,
    write_config,
)

runner = CliRunner()
PYEXE = sys.executable
MALICIOUS = f"{PYEXE} tests/fixtures/malicious_server.py"
PUBKEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


@pytest.fixture()
def key(tmp_path: Path):
    path = tmp_path / "k.pem"
    generate_key(path)
    return load_private_key(path)


def _transport(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://witness.test")


def _registered(tmp_path: Path, log_id: str = "log-1") -> Path:
    state = tmp_path / "state"
    write_config(
        state,
        {
            "v": 1,
            "url": "http://witness.test",
            "log_id": log_id,
            "witness_pubkey_pem": PUBKEY,
            "registered_at": "2026-01-01T00:00:00+00:00",
            "next_index": 0,
        },
    )
    return state


# ------------------------------------------------------ what crosses the wire


def test_the_payload_contains_only_the_digest_and_nothing_about_the_target() -> None:
    """Built from an allowlist, so adding a field to the record cannot leak it.

    If the witness received findings or target strings, an opt-in integrity
    feature would have become the telemetry this project promises not to have.
    """
    payload = submission_payload("log-1", 3, "a" * 64)
    assert set(payload) == {"log_id", "index", "seq_from", "seq_to", "merkle_root"}
    assert payload["merkle_root"] == "a" * 64


def test_the_submitted_body_carries_no_finding_or_target_data(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"log_id": "log-1", "index": 0, "witnessed_at": "t"})

    with _transport(handler) as client:
        assert submit(state, "b" * 64, key.sign, client=client).ok

    assert set(seen) == {"log_id", "index", "seq_from", "seq_to", "merkle_root", "signature"}
    blob = json.dumps(seen)
    for leak in ("MCP-", "githab", "run_command", "/Users/", "malicious"):
        assert leak not in blob


def test_the_signature_is_base64_not_raw_bytes(tmp_path: Path, key) -> None:
    """Raw bytes fail JSON serialisation, and the witness decodes base64.

    Found against the live service, not here — this test exists so it cannot
    come back.
    """
    state = _registered(tmp_path)
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"log_id": "log-1", "index": 0})

    with _transport(handler) as client:
        submit(state, "c" * 64, key.sign, client=client)

    assert isinstance(seen["signature"], str)
    assert len(base64.b64decode(seen["signature"])) == 64


# ------------------------------------------------------ never blocking


def test_no_witness_registered_is_not_an_error(tmp_path: Path, key) -> None:
    outcome = submit(tmp_path / "empty", "a" * 64, key.sign)
    assert outcome.ok is False
    assert "no witness registered" in outcome.error


def test_an_unreachable_witness_does_not_raise(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    with _transport(handler) as client:
        outcome = submit(state, "a" * 64, key.sign, client=client)
    assert outcome.ok is False
    assert "unreachable" in outcome.error


def test_a_scan_with_witness_but_no_witness_registered_still_succeeds(tmp_path: Path) -> None:
    key_path = tmp_path / "k.pem"
    generate_key(key_path)
    out = tmp_path / "r.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            MALICIOUS,
            "--sign-result",
            str(out),
            "--signing-key",
            str(key_path),
            "--witness",
            "--state-dir",
            str(tmp_path / "none"),
        ],
    )
    assert result.exit_code in {0, 1}
    record = json.loads(out.read_text(encoding="utf-8"))
    assert record["signed"] is True
    assert record["witness"]["submitted"] is False
    assert "no witness registered" in record["witness"]["reason"]


def test_a_scan_without_the_flag_contacts_nothing(tmp_path: Path, monkeypatch) -> None:
    key_path = tmp_path / "k.pem"
    generate_key(key_path)

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("no outbound request without --witness")

    monkeypatch.setattr(httpx.Client, "post", explode)
    monkeypatch.setattr(httpx.Client, "get", explode)
    out = tmp_path / "r.json"
    result = runner.invoke(
        app,
        ["scan", "--command", MALICIOUS, "--sign-result", str(out), "--signing-key", str(key_path)],
    )
    assert result.exit_code in {0, 1}
    assert "witness" not in json.loads(out.read_text(encoding="utf-8"))


# ------------------------------------------------------ transient handling


def test_retryable_statuses_are_deferred_not_refused(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)
    for status in sorted(RETRYABLE_STATUS):
        calls = {"n": 0}

        def handler(
            request: httpx.Request, status: int = status, calls: dict = calls
        ) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(status, json={"error": "busy"})

        with _transport(handler) as client:
            outcome = submit(state, "a" * 64, key.sign, client=client, sleep=lambda _: None)
        assert outcome.transient is True, status
        assert "not witnessed" in outcome.error
        assert "refused" not in outcome.error
        assert calls["n"] > 1


def test_a_real_refusal_is_not_retried(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(409, json={"error": "fork"})

    with _transport(handler) as client:
        outcome = submit(state, "a" * 64, key.sign, client=client, sleep=lambda _: None)
    assert calls["n"] == 1
    assert outcome.transient is False
    assert "refused" in outcome.error


def test_retry_after_is_honoured_and_capped() -> None:
    assert retry_delay(0, "2") == 2.0
    assert retry_delay(0, "86400") == 8.0
    assert retry_delay(0, "nonsense", jitter=1.0) == 0.4


def test_it_recovers_after_a_transient_failure(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(503, headers={"retry-after": "1"})
        return httpx.Response(200, json={"log_id": "log-1", "index": 0, "witnessed_at": "t"})

    with _transport(handler) as client:
        outcome = submit(state, "a" * 64, key.sign, client=client, sleep=lambda _: None)
    assert outcome.ok is True
    assert calls["n"] == 3


# ------------------------------------------------------ pinning and state


def test_a_receipt_for_another_log_is_an_attack(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"log_id": "someone-elses-log", "index": 0})

    with _transport(handler) as client, pytest.raises(WitnessKeyMismatch):
        submit(state, "a" * 64, key.sign, client=client)


def test_registration_pins_the_key_and_uses_a_random_log_id(tmp_path: Path, key) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/pubkey":
            return httpx.Response(200, json={"public_key_pem": PUBKEY})
        return httpx.Response(200, json={"log_id": "x"})

    state = tmp_path / "state"
    with _transport(handler) as client:
        config = register(state, "http://witness.test", public_key_pem(key), client=client)

    assert config["witness_pubkey_pem"] == PUBKEY
    # The id must not encode the target: the witness is outside this machine's
    # trust boundary and learns only what it is sent.
    assert "malicious" not in config["log_id"]
    assert len(config["log_id"]) == 36


def test_the_index_advances_so_results_chain(tmp_path: Path, key) -> None:
    state = _registered(tmp_path)
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["index"])
        return httpx.Response(200, json={"log_id": "log-1", "index": body["index"]})

    with _transport(handler) as client:
        submit(state, "a" * 64, key.sign, client=client)
        submit(state, "b" * 64, key.sign, client=client)

    assert seen == [0, 1]
    assert read_config(state)["next_index"] == 2
    assert len(list((state / "receipts").iterdir())) == 2
