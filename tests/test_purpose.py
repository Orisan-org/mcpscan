from __future__ import annotations

import json

from mcpscan.capabilities import Capability
from mcpscan.models import PurposeCategory, PurposeSource, ServerInfo
from mcpscan.purpose import build_purpose_profile, infer_purpose_category, load_purpose_taxonomy
from mcpscan.reporters.json_reporter import render_json
from mcpscan.reporters.markdown import render_markdown
from mcpscan.reporters.terminal import render_terminal
from mcpscan.scanner import scan_context
from tests.helpers import benign_context


def test_purpose_taxonomy_loads_with_valid_capabilities() -> None:
    taxonomy = load_purpose_taxonomy()

    assert set(taxonomy) == set(PurposeCategory)
    for entry in taxonomy.values():
        assert all(
            isinstance(capability, Capability) for capability in entry["expected_capabilities"]
        )


def test_purpose_flag_overrides_server_info() -> None:
    ctx = benign_context()
    ctx.server = ServerInfo(
        name="postgres-server",
        instructions="Database server for running SQL queries.",
    )

    profile = build_purpose_profile(ctx, purpose_category=PurposeCategory.FILESYSTEM)

    assert profile.category == PurposeCategory.FILESYSTEM
    assert profile.category_source == PurposeSource.FLAG
    assert profile.expected_capabilities == [
        Capability.FILE_READ,
        Capability.FILE_WRITE,
        Capability.DATA_EXPOSURE,
    ]


def test_server_info_infers_filesystem_purpose() -> None:
    ctx = benign_context()
    ctx.server = ServerInfo(
        name="safe-filesystem",
        instructions="Filesystem server for reading and writing files.",
    )

    profile = build_purpose_profile(ctx)

    assert profile.category == PurposeCategory.FILESYSTEM
    assert profile.category_source == PurposeSource.SERVER_INFO


def test_garbage_empty_and_tie_infer_unknown() -> None:
    assert infer_purpose_category("") == PurposeCategory.UNKNOWN
    assert infer_purpose_category("not a meaningful mcp purpose") == PurposeCategory.UNKNOWN
    assert infer_purpose_category("folder database") == PurposeCategory.UNKNOWN


def test_purpose_profile_appears_in_all_output_formats() -> None:
    result = scan_context(benign_context(), purpose_category=PurposeCategory.FILESYSTEM)

    json_payload = json.loads(render_json(result))
    markdown = render_markdown(result)
    terminal = render_terminal(result, no_color=True)

    assert json_payload["purpose_profile"]["category"] == "filesystem"
    assert json_payload["purpose_profile"]["category_source"] == "flag"
    assert "file_read" in json_payload["purpose_profile"]["expected_capabilities"]
    assert "- Purpose: filesystem" in markdown
    assert "Purpose: filesystem (flag)" in terminal
