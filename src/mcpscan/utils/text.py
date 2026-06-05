from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if value is None:
        return
    if isinstance(value, str):
        yield path or "$", value
        return
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from iter_strings(item, child)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            child = f"{path}[{index}]" if path else f"[{index}]"
            yield from iter_strings(item, child)
