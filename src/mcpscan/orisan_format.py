"""Findings in orisan-recorder vocabulary, deliberately NOT a chain.

A recorder event is only meaningful inside a hash chain: it carries a `seq`, a
`prev_hash` and a `hash` continuous with the events either side of it. mcpscan
cannot produce those. It does not know the log it will be appended to, what
came before, or what will come after, and inventing them would manufacture
evidence that looks verified and is not.

So this emits a DETACHED document. Same field names, same canonical JSON, same
digest rules — and no chain fields at all, plus `chained: false` at the top.
The recorder assigns chain position at append time, which is the only place it
can be assigned correctly.

The alternative considered and rejected was appending straight into a live log
directory. It sounds tighter and is worse: it puts a scanner inside the trust
boundary of the evidence log, and requires the recorder's writer lock from a
Python process. A scanner should not be able to mutate the record of what an
agent did.

Findings map to the `flag` kind, which already exists in the recorder's
EVENT_KINDS. No change to that repo is needed, which also means no version of
this document can arrive before the recorder can read it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcpscan import __version__
from mcpscan.models import ScanResult
from mcpscan.ruleset import RULESET_VERSION, ruleset_digest
from mcpscan.scoring import effective_severity

DOCUMENT_FORMAT = 1

#: Chain fields. Present in a recorder event, absent here by construction, and
#: asserted absent by a test — their absence is the whole safety property.
CHAIN_FIELDS = ("seq", "prev_hash", "hash")

#: Also assigned by the recorder at append time, not guessable here.
ASSIGNED_ON_APPEND = ("v", "event_id", "session_id")

#: Copied from orisan-recorder's schema.ts ALLOWED_EVENT_KEYS. A copy, not an
#: import: this is Python and that is TypeScript. The test that uses it says so.
RECORDER_EVENT_KEYS = frozenset(
    {
        "v",
        "seq",
        "event_id",
        "session_id",
        "ts",
        "clock_source",
        "actor",
        "kind",
        "target",
        "args_digest",
        "payload_ref",
        "outcome",
        "duration_ms",
        "prev_hash",
        "hash",
    }
)
RECORDER_ACTOR_KEYS = frozenset({"human", "agent_id", "tool"})
RECORDER_EVENT_KINDS = frozenset(
    {"model_call", "tool_call", "config_change", "flag", "redaction", "prune"}
)
RECORDER_CLOCK_SOURCES = frozenset({"host_wall_clock"})

_CHAIN_NOTE = (
    "Detached: these entries carry no seq, prev_hash or hash, so they are not a verified "
    "chain and must not be presented as one. Ingest them with orisan-recorder, which assigns "
    "chain position at append time; that is the only place it can be assigned correctly."
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def finding_events(result: ScanResult) -> list[dict[str, Any]]:
    return [
        {
            # Recorder vocabulary, exactly.
            "actor": {"human": None, "agent_id": "mcpscan", "tool": f"mcpscan/{__version__}"},
            "kind": "flag",
            "target": finding.target,
            # The evidence itself is never carried: payload_stored is false on
            # every finding and that has to survive the format boundary.
            "args_digest": _sha256(finding.evidence),
            "payload_ref": None,
            "outcome": f"{effective_severity(finding).value}: {finding.id} {finding.title}",
            "duration_ms": None,
            "ts": result.scan.timestamp_utc,
            # 'host_wall_clock' is the recorder's only CLOCK_SOURCES value.
            # The first version wrote "system", which reads fine and is not in
            # its vocabulary — caught by running the real validator, not by
            # reading the field list.
            "clock_source": "host_wall_clock",
        }
        for finding in result.findings
    ]


def build_document(result: ScanResult) -> dict[str, Any]:
    return {
        "document_format": DOCUMENT_FORMAT,
        "producer": f"mcpscan/{__version__}",
        # First key a reader meets, and the one a consumer must branch on.
        "chained": False,
        "chain_note": _CHAIN_NOTE,
        "ruleset_version": RULESET_VERSION,
        "ruleset_digest": ruleset_digest(),
        "tier": result.tier.value,
        "checks_not_run": result.checks_not_run,
        "events": finding_events(result),
    }


def render_document(result: ScanResult) -> str:
    """Canonical JSON rules matching the recorder's: sorted keys, no padding."""
    return json.dumps(build_document(result), indent=2, sort_keys=True) + "\n"
