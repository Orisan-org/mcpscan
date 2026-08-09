"""The readiness canary must stay able to fail.

An advisory job that has been quietly constrained into the green is worse than no job:
it looks like coverage and reports nothing. These assertions are the enforcement the
workflow's own comment box promises.

If the canary is genuinely wrong, delete it and delete this file, and say so in the PR.
Do not narrow it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / ".github" / "workflows" / "mcp2-readiness-canary.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(CANARY.read_text(encoding="utf-8"))


def _probe_step(workflow: dict) -> dict:
    steps = workflow["jobs"]["mcp2-readiness"]["steps"]
    probe = [step for step in steps if step.get("id") == "probe"]
    assert len(probe) == 1, "the probe step is what this file guards; it must exist"
    return probe[0]


def test_the_probe_targets_mcp_2_or_later_with_no_upper_bound(workflow: dict) -> None:
    """A bound here would silently retarget the canary at a version we already support."""
    spec = _probe_step(workflow)["env"]["MCPSCAN_WHEEL_MCP_SPEC"]

    assert spec == "mcp[cli]>=2", (
        f"readiness canary spec is {spec!r}. It must be an unbounded >=2: the point is "
        "to learn about whatever 2.x resolves to today."
    )


def test_the_probe_runs_the_whole_wheel_harness(workflow: dict) -> None:
    """Narrowing to a subset is the other way to pin it green."""
    assert _probe_step(workflow)["run"].strip() == "pytest -m wheel -v"


def test_the_probe_is_allowed_to_fail_without_failing_the_job(workflow: dict) -> None:
    assert _probe_step(workflow)["continue-on-error"] is True


def test_the_canary_never_gates_a_merge(workflow: dict) -> None:
    """It must not be push- or pull_request-triggered, and must not live in ci.yml."""
    triggers = set((workflow.get("on") or workflow.get(True)).keys())

    assert triggers == {"schedule", "workflow_dispatch"}
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert "mcp2-readiness" not in ci["jobs"]


def test_the_do_not_pin_warning_survives(workflow: dict) -> None:
    """The comment box is the first thing a future editor reads. Keep it."""
    text = CANARY.read_text(encoding="utf-8")

    assert 'DO NOT "FIX" THIS JOB BY MAKING IT GREEN' in text
    assert "Do not pin it into the green" in text
