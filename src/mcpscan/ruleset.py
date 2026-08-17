"""What the checks were, expressed as something you can compare.

A verdict is only reproducible if you know which rules produced it. "mcpscan
0.1.1 said B" is not a reproducible claim — the version pins the code, not the
patterns, and a pattern change is exactly the thing that moves a verdict.

This lands before signing on purpose. Signing a verdict whose ruleset is
unidentified signs an unreproducible claim: the signature would prove only that
this machine said it, not that the same inputs would say it again.

HOW THE DIGEST IS DERIVED. Every module-level constant in a check's defining
module is collected and canonicalised, along with the check's own metadata. So
adding a pattern changes the digest whether or not anyone remembers to declare
it, and there is a test asserting no compiled pattern escapes the manifest.

WHAT IT DOES NOT COVER, stated plainly because a digest people over-trust is
worse than none: logic written inline rather than as data. Changing
`if len(x) > 3` to `> 5` inside a check's `run` moves verdicts without moving
the digest. The mitigation is a convention — thresholds live in module
constants, where this can see them — not a guarantee. Bytecode hashing would
close it and would also change with every Python release, which would make the
digest useless for the thing it exists for.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from enum import Enum
from typing import Any

from mcpscan.checks.registry import active_checks, check_catalogue

#: Shape of the manifest, not of the rules. Bump when the structure below
#: changes in a way that would make two manifests incomparable.
RULESET_VERSION = "1"

#: Constants that describe the module rather than the rules.
_IGNORED_CONSTANT_NAMES = frozenset({"TYPE_CHECKING"})


def _canonical(value: Any) -> Any:
    """A JSON-safe, order-stable rendering of rule data."""
    if isinstance(value, re.Pattern):
        # UNICODE is implicit for str patterns and its numeric value has moved
        # between Python releases; masking it keeps the digest stable across
        # interpreters without hiding a flag anyone actually set.
        flags = int(value.flags) & ~int(re.UNICODE)
        return {"regex": value.pattern, "flags": flags}
    if isinstance(value, Enum):
        return {"enum": value.__class__.__name__, "value": value.value}
    if isinstance(value, (set, frozenset)):
        # Sorted by canonical JSON, not by the values themselves: a set of
        # compiled patterns canonicalises to dicts, which are unorderable.
        return {"set": sorted((_canonical(item) for item in value), key=_sort_key)}
    if isinstance(value, (list, tuple)):
        # Order is preserved: for an ordered rule list it is part of the rule.
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {
            "map": [
                [str(k), _canonical(v)] for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            ]
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return {"repr": f"{type(value).__module__}.{type(value).__qualname__}"}


def _sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


#: `_UPPER_CASE` is the module-private convention, and a private pattern
#: decides verdicts exactly as much as a public one. The first version of this
#: filter skipped them, which left every rule in config_surface.py — four
#: checks' worth — outside the digest. A test now asserts no compiled pattern
#: escapes, so the filter cannot silently narrow again.
_RULE_NAME = re.compile(r"^_?[A-Z][A-Z0-9_]*$")


def _is_rule_constant(name: str, value: Any) -> bool:
    if not _RULE_NAME.match(name) or name in _IGNORED_CONSTANT_NAMES:
        return False
    if callable(value) or isinstance(value, type):
        return False
    return isinstance(
        value, (re.Pattern, str, int, float, bool, tuple, list, set, frozenset, dict, Enum)
    )


def module_rule_data(module_name: str) -> dict[str, Any]:
    module = importlib.import_module(module_name)
    return {
        name: _canonical(value)
        for name, value in sorted(vars(module).items())
        if _is_rule_constant(name, value)
    }


def check_signature(check: Any) -> dict[str, Any]:
    """Everything about a check that can change what it decides."""
    return {
        "id": check.id,
        "title": check.title,
        "severity": check.severity.value,
        "capability": check.default_capability.value,
        "owasp_mcp": check.owasp_mcp,
        "status": check.status,
        "scope": check.scope.value,
        "requires": sorted(tier.value for tier in check.requires),
        "module": type(check).__module__,
        "rules": module_rule_data(type(check).__module__),
    }


def ruleset_manifest() -> dict[str, Any]:
    """The full ruleset, sorted by check id.

    Sorted, so reordering the registry does not change the digest — the order
    checks run in does not change what any of them decides.
    """
    return {
        "ruleset_version": RULESET_VERSION,
        "checks": [check_signature(check) for check in sorted(active_checks(), key=lambda c: c.id)],
        # Catalogue-only entries (drift) carry no runtime rule data but do carry
        # metadata a consumer compares against.
        "catalogue": [
            {
                "id": entry.id,
                "severity": entry.severity.value,
                "capability": entry.capability.value,
                "owasp_mcp": entry.owasp_mcp,
                "status": entry.status,
            }
            for entry in check_catalogue()
        ],
    }


def canonical_manifest_json(manifest: dict[str, Any] | None = None) -> str:
    return json.dumps(
        manifest if manifest is not None else ruleset_manifest(),
        sort_keys=True,
        separators=(",", ":"),
    )


def ruleset_digest(manifest: dict[str, Any] | None = None) -> str:
    return hashlib.sha256(canonical_manifest_json(manifest).encode("utf-8")).hexdigest()
