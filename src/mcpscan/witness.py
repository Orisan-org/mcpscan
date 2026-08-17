"""Optional witness submission: proving a verdict existed at a point in time.

A signature proves who said something. It does not prove WHEN, and it cannot
prove that an inconvenient scan result was not quietly deleted afterwards.
Submitting the verdict's digest to a witness outside the operator's control
closes both: the witness remembers, and its memory cannot be edited from here.

WHAT THE WITNESS RECEIVES, exhaustively: a random log id, an index, and the
body digest of a signed verdict, plus the signature over those. It never
receives findings, grades, target strings, tool names, commands or paths. If it
did, an opt-in integrity feature would have become the telemetry this project
promises not to have — so the payload is built from an allowlist and there is a
test asserting the exact field set.

The witness key is PINNED at registration and never updated from a response, in
the same shape as the recorder's client. A witness that answers with a
different key is an attack, not a rotation.

Nothing here is required. No witness configured means the scan runs and the
result is marked unwitnessed; an unreachable witness means the same. A scan is
never blocked by the absence of something optional.
"""

from __future__ import annotations

import base64
import json
import random
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from mcpscan.errors import McpScanError

WITNESS_CONFIG_FILENAME = "witness.json"
RECEIPTS_DIRNAME = "receipts"

#: Transient. Retried with backoff and reported as deferred, never as a refusal.
#: Same set the recorder settled on: rate-limited, gateway could not reach it,
#: restarting, took too long. Everything else is an answer, not a delay.
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
MAX_ATTEMPTS = 4
MAX_TOTAL_SECONDS = 20.0
_BACKOFF_BASE = 0.4
_BACKOFF_CAP = 8.0


class WitnessKeyMismatch(McpScanError):
    """The witness answered with a key other than the pinned one."""


class WitnessError(McpScanError):
    pass


class Clock(Protocol):
    def __call__(self) -> datetime: ...


def _now() -> datetime:
    return datetime.now(UTC)


def config_path(state_dir: Path) -> Path:
    return state_dir / WITNESS_CONFIG_FILENAME


def read_config(state_dir: Path) -> dict[str, Any] | None:
    path = config_path(state_dir)
    if not path.exists():
        return None
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("v") != 1:
        raise WitnessError(f"Unsupported witness config version: {config.get('v')!r}")
    return config


def write_config(state_dir: Path, config: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    config_path(state_dir).write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def register(
    state_dir: Path, url: str, signing_pubkey_pem: str, *, client: httpx.Client | None = None
) -> dict[str, Any]:
    """Register a log and PIN the key that answered."""
    base = url.rstrip("/")
    owned = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        response = http.get(f"{base}/v1/pubkey")
        if response.status_code != 200:
            raise WitnessError(f"witness /v1/pubkey returned {response.status_code}")
        pem = response.json().get("public_key_pem", "")
        if "BEGIN PUBLIC KEY" not in pem:
            raise WitnessError("witness did not return an SPKI public key")

        log_id = str(uuid.uuid4())
        registration = http.post(
            f"{base}/v1/logs",
            json={"log_id": log_id, "signing_pubkey": signing_pubkey_pem},
        )
        if registration.status_code != 200:
            raise WitnessError(
                f"witness registration failed ({registration.status_code}): {registration.text[:300]}"
            )
    finally:
        if owned:
            http.close()

    config = {
        "v": 1,
        "url": base,
        # A random id. It must not encode the target: the witness is outside
        # this machine's trust boundary and learns nothing it is not sent.
        "log_id": log_id,
        "witness_pubkey_pem": pem,
        "registered_at": _now().isoformat(timespec="seconds"),
        "next_index": 0,
    }
    write_config(state_dir, config)
    return config


def submission_payload(log_id: str, index: int, body_sha256: str) -> dict[str, Any]:
    """Exactly what crosses the wire, and nothing else.

    Built explicitly rather than by filtering a larger object, so adding a
    field to the record cannot leak it here by accident.
    """
    return {
        "log_id": log_id,
        "index": index,
        "seq_from": index,
        "seq_to": index,
        "merkle_root": body_sha256,
    }


def retry_delay(attempt: int, retry_after: str | None, jitter: float | None = None) -> float:
    if retry_after:
        try:
            return min(float(retry_after.strip()), _BACKOFF_CAP)
        except ValueError:
            pass
    base = min(_BACKOFF_BASE * (2**attempt), _BACKOFF_CAP)
    return round(base * (0.5 + (random.random() if jitter is None else jitter) * 0.5), 3)


class SubmitOutcome:
    def __init__(
        self,
        *,
        ok: bool,
        index: int | None = None,
        receipt: dict[str, Any] | None = None,
        error: str | None = None,
        transient: bool = False,
        status: int | None = None,
    ) -> None:
        self.ok = ok
        self.index = index
        self.receipt = receipt
        self.error = error
        self.transient = transient
        self.status = status


def submit(
    state_dir: Path,
    body_sha256: str,
    sign: Any,
    *,
    client: httpx.Client | None = None,
    sleep: Any = time.sleep,
) -> SubmitOutcome:
    """Submit one verdict digest. Never raises for an unreachable witness."""
    config = read_config(state_dir)
    if config is None:
        return SubmitOutcome(
            ok=False, error="no witness registered; run `mcpscan witness register`"
        )

    index = int(config.get("next_index", 0))
    payload = submission_payload(config["log_id"], index, body_sha256)
    # base64, because that is what the witness decodes. Ed25519 sign() returns
    # raw bytes and putting those in a JSON body fails at serialisation — which
    # is how this was found: against the live service, not in a unit test with
    # a stubbed transport.
    signature = base64.b64encode(
        sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    ).decode("ascii")

    owned = client is None
    http = client or httpx.Client(timeout=30.0)
    spent = 0.0
    attempts = 0
    try:
        while True:
            attempts += 1
            try:
                response = http.post(
                    f"{config['url']}/v1/logs/{config['log_id']}/checkpoints",
                    json={**payload, "signature": signature},
                )
            except httpx.HTTPError as exc:
                return SubmitOutcome(ok=False, error=f"witness unreachable: {exc}")

            if response.status_code in RETRYABLE_STATUS:
                wait = retry_delay(attempts - 1, response.headers.get("retry-after"))
                if attempts >= MAX_ATTEMPTS or spent + wait > MAX_TOTAL_SECONDS:
                    what = (
                        "throttled this log (429)"
                        if response.status_code == 429
                        else f"temporarily unavailable ({response.status_code})"
                    )
                    return SubmitOutcome(
                        ok=False,
                        transient=True,
                        status=response.status_code,
                        error=f"witness {what} after {attempts} attempt(s); the result was not witnessed",
                    )
                sleep(wait)
                spent += wait
                continue

            if response.status_code != 200:
                return SubmitOutcome(
                    ok=False,
                    status=response.status_code,
                    error=f"witness refused ({response.status_code}): {response.text[:300]}",
                )
            break
    finally:
        if owned:
            http.close()

    receipt = response.json()
    _assert_pinned_key(config, receipt)

    receipts = state_dir / RECEIPTS_DIRNAME
    receipts.mkdir(parents=True, exist_ok=True)
    (receipts / f"{index:08d}.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    config["next_index"] = index + 1
    write_config(state_dir, config)
    return SubmitOutcome(ok=True, index=index, receipt=receipt)


def _assert_pinned_key(config: dict[str, Any], receipt: dict[str, Any]) -> None:
    """The receipt must be signed by the key pinned at registration.

    Not verified cryptographically here — that needs the witness's own
    signature scheme — but a receipt for the wrong log is checked, which is the
    substitution this can detect without reimplementing the witness.
    """
    if receipt.get("log_id") != config["log_id"]:
        raise WitnessKeyMismatch(
            f"witness returned a receipt for log {receipt.get('log_id')!r}, not {config['log_id']!r}"
        )
