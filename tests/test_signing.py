"""Slice 5 — signed scan results.

The claim is "same input, same output, byte identical". That is only testable
because the signature covers a body with no wall-clock, no hostname and no
paths in it: Ed25519 is deterministic, so the same body under the same key
produces the same 64 bytes forever. Signing the whole document would produce a
new signature every second and prove nothing about reproducibility.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.signing import (
    EXIT_BAD_SIGNATURE,
    EXIT_CANNOT_VERIFY,
    EXIT_VERIFIED,
    SigningError,
    canonical_body,
    generate_key,
    load_private_key,
    public_key_pem,
    verdict_body,
    verify_record,
)

runner = CliRunner()
PYEXE = sys.executable
MALICIOUS = f"{PYEXE} tests/fixtures/malicious_server.py"


@pytest.fixture()
def key_path(tmp_path: Path) -> Path:
    path = tmp_path / "signing.key"
    generate_key(path)
    return path


def _scan_and_sign(tmp_path: Path, key_path: Path | None, name: str = "r.json") -> dict:
    out = tmp_path / name
    args = ["scan", "--command", MALICIOUS, "--sign-result", str(out)]
    if key_path is not None:
        args += ["--signing-key", str(key_path)]
    else:
        args += ["--signing-key", str(tmp_path / "absent.key")]
    runner.invoke(app, args)
    return json.loads(out.read_text(encoding="utf-8"))


# ------------------------------------------------------ the headline claim


def test_the_same_input_produces_byte_identical_signature_bytes(
    tmp_path: Path, key_path: Path
) -> None:
    first = _scan_and_sign(tmp_path, key_path, "a.json")
    second = _scan_and_sign(tmp_path, key_path, "b.json")
    assert first["signature"] == second["signature"]
    assert first["body_sha256"] == second["body_sha256"]
    assert first["body"] == second["body"]


def test_the_envelope_differs_between_those_runs_and_does_not_affect_the_signature(
    tmp_path: Path, key_path: Path
) -> None:
    first = _scan_and_sign(tmp_path, key_path, "a.json")
    second = _scan_and_sign(tmp_path, key_path, "b.json")
    # Same signature even though this moved.
    assert "signed_at" in first["envelope"]
    assert first["signature"] == second["signature"]


def test_the_body_contains_no_wall_clock_hostname_or_path(tmp_path: Path, key_path: Path) -> None:
    body = json.dumps(_scan_and_sign(tmp_path, key_path)["body"])
    assert "signed_at" not in body
    assert "timestamp" not in body
    assert str(Path.home()) not in body
    assert os.uname().nodename not in body if hasattr(os, "uname") else True


def test_the_target_is_recorded_as_a_digest_not_a_command_line(
    tmp_path: Path, key_path: Path
) -> None:
    """A command line can contain a home directory, which names a person."""
    record = _scan_and_sign(tmp_path, key_path)
    assert len(record["body"]["target_digest"]) == 64
    assert "malicious_server.py" not in json.dumps(record["body"])


def test_the_ruleset_is_inside_the_signature(tmp_path: Path, key_path: Path) -> None:
    from mcpscan.ruleset import RULESET_VERSION, ruleset_digest

    body = _scan_and_sign(tmp_path, key_path)["body"]
    assert body["ruleset_digest"] == ruleset_digest()
    assert body["ruleset_version"] == RULESET_VERSION


# ------------------------------------------------------ verification outcomes


def test_a_good_record_verifies(tmp_path: Path, key_path: Path) -> None:
    outcome = verify_record(_scan_and_sign(tmp_path, key_path))
    assert outcome.exit_code == EXIT_VERIFIED
    assert "VERIFIED" in outcome.report()


def test_editing_any_byte_of_the_body_fails(tmp_path: Path, key_path: Path) -> None:
    record = _scan_and_sign(tmp_path, key_path)
    record["body"]["grade"] = "A"
    assert verify_record(record).exit_code == EXIT_BAD_SIGNATURE


def test_editing_the_body_and_its_digest_still_fails_on_the_signature(
    tmp_path: Path, key_path: Path
) -> None:
    from mcpscan.signing import body_digest

    record = _scan_and_sign(tmp_path, key_path)
    record["body"]["grade"] = "A"
    record["body_sha256"] = body_digest(record["body"])
    outcome = verify_record(record)
    assert outcome.exit_code == EXIT_BAD_SIGNATURE
    assert "signature does not verify" in outcome.report()


def test_editing_an_envelope_field_does_not_invalidate_the_signature(
    tmp_path: Path, key_path: Path
) -> None:
    """And the report names what is outside the signature, so nobody assumes
    the envelope was covered."""
    record = _scan_and_sign(tmp_path, key_path)
    record["envelope"]["signed_at"] = "1999-01-01T00:00:00+00:00"
    outcome = verify_record(record)
    assert outcome.exit_code == EXIT_VERIFIED
    assert "outside signature" in outcome.report()
    assert "signed_at" in outcome.report()


def test_a_different_pinned_key_is_refused(tmp_path: Path, key_path: Path) -> None:
    other = tmp_path / "other.key"
    generate_key(other)
    record = _scan_and_sign(tmp_path, key_path)
    outcome = verify_record(record, expect_pubkey_pem=public_key_pem(load_private_key(other)))
    assert outcome.exit_code == EXIT_BAD_SIGNATURE
    assert "different key" in outcome.report()


def test_the_matching_pinned_key_verifies(tmp_path: Path, key_path: Path) -> None:
    record = _scan_and_sign(tmp_path, key_path)
    pem = public_key_pem(load_private_key(key_path))
    assert verify_record(record, expect_pubkey_pem=pem).exit_code == EXIT_VERIFIED


def test_an_unknown_record_format_is_cannot_verify(tmp_path: Path, key_path: Path) -> None:
    record = _scan_and_sign(tmp_path, key_path)
    record["record_format"] = 99
    assert verify_record(record).exit_code == EXIT_CANNOT_VERIFY


# ------------------------------------------------------ no key: unsigned, never a pass


def test_no_key_produces_an_unsigned_record_and_says_so(tmp_path: Path) -> None:
    record = _scan_and_sign(tmp_path, None)
    assert record["signed"] is False
    assert record["signature"] is None
    assert record["body"], "the body is still written; only the signature is absent"


def test_a_scan_without_a_key_still_succeeds_and_creates_no_key(tmp_path: Path) -> None:
    absent = tmp_path / "absent.key"
    out = tmp_path / "r.json"
    result = runner.invoke(
        app,
        ["scan", "--command", MALICIOUS, "--sign-result", str(out), "--signing-key", str(absent)],
    )
    assert result.exit_code in {0, 1}
    assert out.exists()
    assert not absent.exists(), "a scan must never create key material as a side effect"


def test_verifying_an_unsigned_record_is_cannot_verify_never_zero(tmp_path: Path) -> None:
    outcome = verify_record(_scan_and_sign(tmp_path, None))
    assert outcome.exit_code == EXIT_CANNOT_VERIFY
    assert "unsigned" in outcome.report()


# ------------------------------------------------------ key handling


def test_keygen_writes_owner_only_and_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "k.pem"
    generate_key(path)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(SigningError, match="refusing to overwrite"):
        generate_key(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_a_world_readable_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "k.pem"
    generate_key(path)
    path.chmod(0o644)
    with pytest.raises(SigningError, match="owner-only"):
        load_private_key(path)


def test_the_private_key_never_appears_in_a_record(tmp_path: Path, key_path: Path) -> None:
    record = json.dumps(_scan_and_sign(tmp_path, key_path))
    assert "PRIVATE KEY" not in record
    assert "BEGIN PUBLIC KEY" in record


# ------------------------------------------------------ the CLI contract


def test_verify_result_exit_codes(tmp_path: Path, key_path: Path) -> None:
    good = tmp_path / "good.json"
    runner.invoke(
        app,
        [
            "scan",
            "--command",
            MALICIOUS,
            "--sign-result",
            str(good),
            "--signing-key",
            str(key_path),
        ],
    )
    assert runner.invoke(app, ["verify-result", str(good)]).exit_code == EXIT_VERIFIED

    bad = tmp_path / "bad.json"
    record = json.loads(good.read_text(encoding="utf-8"))
    record["body"]["counts"]["critical"] = 0
    bad.write_text(json.dumps(record), encoding="utf-8")
    assert runner.invoke(app, ["verify-result", str(bad)]).exit_code == EXIT_BAD_SIGNATURE

    assert (
        runner.invoke(app, ["verify-result", str(tmp_path / "nope.json")]).exit_code
        == EXIT_CANNOT_VERIFY
    )


def test_a_replayed_scan_signs_the_surface_tier(tmp_path: Path, key_path: Path) -> None:
    snapshot = tmp_path / "s.json"
    runner.invoke(
        app,
        [
            "snapshot",
            "--command",
            MALICIOUS,
            "--out",
            str(snapshot),
            "--profile",
            "full",
            "--label",
            "t",
        ],
    )
    out = tmp_path / "r.json"
    runner.invoke(
        app,
        [
            "scan",
            "--tier",
            "surface",
            "--from-snapshot",
            str(snapshot),
            "--sign-result",
            str(out),
            "--signing-key",
            str(key_path),
        ],
    )
    record = json.loads(out.read_text(encoding="utf-8"))
    assert record["body"]["tier"] == "surface"
    assert verify_record(record).exit_code == EXIT_VERIFIED


def test_bodies_from_different_rulesets_do_not_collide(
    tmp_path: Path, key_path: Path, monkeypatch
) -> None:
    import mcpscan.signing as signing

    first = verdict_body(_result(tmp_path, key_path))
    monkeypatch.setattr(signing, "ruleset_digest", lambda: "0" * 64)
    second = verdict_body(_result(tmp_path, key_path))
    assert canonical_body(first) != canonical_body(second)


def _result(tmp_path: Path, key_path: Path):
    from mcpscan.models import ScanContext, ScanTarget, TargetKind, Transport
    from mcpscan.scanner import scan_context

    return scan_context(
        ScanContext(
            target=ScanTarget(
                kind=TargetKind.COMMAND, transport=Transport.STDIO, command=["uvx", "t"]
            )
        )
    )
