from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml

from mcpscan.capabilities import Capability
from mcpscan.models import (
    PurposeCategory,
    PurposeProfile,
    PurposeSource,
    ScanContext,
)


@lru_cache(maxsize=1)
def load_purpose_taxonomy() -> dict[PurposeCategory, dict[str, Any]]:
    path = files("mcpscan.data").joinpath("purpose_categories.yaml")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("purpose taxonomy must be a mapping")

    taxonomy: dict[PurposeCategory, dict[str, Any]] = {}
    for category in PurposeCategory:
        raw_entry = payload.get(category.value)
        if not isinstance(raw_entry, dict):
            raise ValueError(f"purpose taxonomy missing category: {category.value}")
        keywords = raw_entry.get("keywords", [])
        expected = raw_entry.get("expected_capabilities", [])
        if not isinstance(keywords, list) or not all(isinstance(item, str) for item in keywords):
            raise ValueError(f"purpose taxonomy keywords must be strings: {category.value}")
        if not isinstance(expected, list):
            raise ValueError(
                f"purpose taxonomy expected_capabilities must be a list: {category.value}"
            )
        taxonomy[category] = {
            "keywords": [keyword.lower() for keyword in keywords],
            "expected_capabilities": [Capability(item) for item in expected],
        }

    extra = (
        set(payload) - {category.value for category in PurposeCategory} - {"capability_keywords"}
    )
    if extra:
        raise ValueError(f"purpose taxonomy has unknown categories: {sorted(extra)}")
    return taxonomy


@lru_cache(maxsize=1)
def load_capability_keywords() -> dict[Capability, list[str]]:
    path = files("mcpscan.data").joinpath("purpose_categories.yaml")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw_keywords = payload.get("capability_keywords") if isinstance(payload, dict) else None
    if not isinstance(raw_keywords, dict):
        raise ValueError("purpose taxonomy missing capability_keywords")

    keywords: dict[Capability, list[str]] = {}
    for capability in Capability:
        raw_values = raw_keywords.get(capability.value, [])
        if not isinstance(raw_values, list) or not all(
            isinstance(item, str) for item in raw_values
        ):
            raise ValueError(f"capability keywords must be strings: {capability.value}")
        keywords[capability] = [item.lower() for item in raw_values]

    extra = set(raw_keywords) - {capability.value for capability in Capability}
    if extra:
        raise ValueError(f"purpose taxonomy has unknown capabilities: {sorted(extra)}")
    return keywords


def build_purpose_profile(
    ctx: ScanContext,
    *,
    purpose_category: PurposeCategory | None = None,
    purpose_text: str | None = None,
) -> PurposeProfile:
    flag_text = (purpose_text or "").strip()
    invocation_text = _invocation_text(ctx)
    server_text = _server_declared_text(ctx)
    declared_text = "\n".join(piece for piece in (flag_text, server_text) if piece)

    if purpose_category is not None:
        category = purpose_category
        source = PurposeSource.FLAG
    elif flag_text:
        category = infer_purpose_category(flag_text)
        source = PurposeSource.FLAG
    elif (invocation_category := infer_purpose_category(invocation_text)) != (
        PurposeCategory.UNKNOWN
    ):
        # The operator typed this target. A server cannot forge the command line or URL
        # it was launched from, so this ranks with --purpose, above the server's own
        # account of itself.
        category = invocation_category
        source = PurposeSource.INVOCATION
    elif server_text:
        category = infer_purpose_category(server_text)
        source = (
            PurposeSource.SERVER_INFO
            if category != PurposeCategory.UNKNOWN
            else PurposeSource.UNKNOWN
        )
    else:
        category = PurposeCategory.UNKNOWN
        source = PurposeSource.UNKNOWN

    taxonomy = load_purpose_taxonomy()
    return PurposeProfile(
        category=category,
        category_source=source,
        declared_text=declared_text,
        expected_capabilities=taxonomy[category]["expected_capabilities"],
    )


def infer_purpose_category(text: str) -> PurposeCategory:
    normalized = text.lower()
    if not normalized.strip():
        return PurposeCategory.UNKNOWN

    taxonomy = load_purpose_taxonomy()
    scores: dict[PurposeCategory, int] = {}
    for category, entry in taxonomy.items():
        if category == PurposeCategory.UNKNOWN:
            continue
        scores[category] = sum(
            1 for keyword in entry["keywords"] if keyword and keyword in normalized
        )

    best_score = max(scores.values(), default=0)
    if best_score == 0:
        return PurposeCategory.UNKNOWN
    winners = [category for category, score in scores.items() if score == best_score]
    return winners[0] if len(winners) == 1 else PurposeCategory.UNKNOWN


def _server_declared_text(ctx: ScanContext) -> str:
    return "\n".join(
        piece for piece in (ctx.server.name or "", ctx.server.instructions or "") if piece.strip()
    )


def _invocation_text(ctx: ScanContext) -> str:
    """The target as the operator wrote it: the stdio command line, or the remote URL.

    Deliberately kept out of ``declared_text``. This text is only ever used to infer a
    category. Feeding it to the capability-mention check as well would mean an
    interpreter path like ``python server.py`` reads as a mention of code execution and
    silently stops MCP-030 escalating on every stdio scan.
    """
    pieces = []
    if ctx.target.command:
        pieces.append(" ".join(ctx.target.command))
    if ctx.target.url:
        pieces.append(ctx.target.url)
    return "\n".join(piece for piece in pieces if piece.strip())
