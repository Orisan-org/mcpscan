"""Guard against running mcpscan on an mcp SDK it was not built for.

Slice D of BRIEF-0.1.1.md, bug 3.

mcpscan 0.1.0 declared ``mcp[cli]>=1.0.0`` with no upper bound. PyPI resolved that to
mcp 2.0.0, which renamed ``streamablehttp_client`` to ``streamable_http_client`` and
removed ``mcp.server.fastmcp`` outright, with no aliases for either. The remote
connector caught the resulting ImportError and reported "Streamable HTTP transport is
not available in the installed mcp SDK." — wording indistinguishable from a transport
that was simply never built. Remote scanning was dead on every fresh install and
nothing said so.

The version pin in ``pyproject.toml`` is the fix. This module is the backstop for when
the pin is bypassed — a pre-existing environment, a force-install, a resolver override.
It refuses to scan and names the version, rather than degrading into an answer this
build cannot stand behind.

The pin is deliberately conservative: mcpscan does not yet speak the mcp 2.0 API.
Adapting to it is Slice F, with its own test surface.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

from mcpscan.errors import McpScanError

#: Kept in lockstep with the ``mcp[cli]`` requirement in pyproject.toml.
MCP_SDK_REQUIREMENT = ">=1.0.0,<2"
MCP_SDK_MIN = (1, 0, 0)
MCP_SDK_MAX_EXCLUSIVE = (2, 0, 0)


class SdkCompatibilityError(McpScanError):
    """The installed mcp SDK is outside the range mcpscan was built against."""


def installed_mcp_version() -> str | None:
    """The installed mcp SDK version, or None if mcp is not installed at all."""
    try:
        return _package_version("mcp")
    except PackageNotFoundError:
        return None


def mcp_sdk_description() -> str:
    found = installed_mcp_version()
    return f"mcp {found}" if found else "mcp not installed"


def mcp_sdk_problem() -> str | None:
    """Return a human-readable problem with the installed mcp SDK, or None if it is fine."""
    found = installed_mcp_version()
    if found is None:
        return (
            f"mcpscan requires the mcp SDK {MCP_SDK_REQUIREMENT}, but mcp is not installed. "
            "Reinstall mcpscan in a clean environment: pip install orisan-mcpscan"
        )

    parsed = _parse_version(found)
    if not parsed:
        # Unparseable version: say so rather than guessing it is fine.
        return (
            f"mcpscan requires the mcp SDK {MCP_SDK_REQUIREMENT}, but the installed mcp "
            f"reports version {found!r}, which mcpscan cannot interpret."
        )

    if parsed < MCP_SDK_MIN:
        return (
            f"mcpscan requires the mcp SDK {MCP_SDK_REQUIREMENT}, but mcp {found} is "
            "installed. Reinstall mcpscan in a clean environment: pip install orisan-mcpscan"
        )

    if parsed >= MCP_SDK_MAX_EXCLUSIVE:
        return (
            f"mcpscan requires the mcp SDK {MCP_SDK_REQUIREMENT}, but mcp {found} is "
            "installed. mcp 2.0 renamed streamablehttp_client and removed "
            "mcp.server.fastmcp, so remote scanning does not work against it. mcpscan "
            "refuses to scan rather than report a result it cannot stand behind. "
            "Reinstall in a clean environment: pip install orisan-mcpscan "
            "(or pin directly: pip install 'mcp[cli]>=1.0.0,<2')"
        )

    return None


def verify_mcp_sdk() -> None:
    """Raise if the installed mcp SDK is outside the supported range."""
    problem = mcp_sdk_problem()
    if problem is not None:
        raise SdkCompatibilityError(problem)


def _parse_version(raw: str) -> tuple[int, ...]:
    """Leading numeric release components of a version string.

    ``"1.29.0"`` -> ``(1, 29, 0)``; ``"2.0.0rc1"`` -> ``(2, 0, 0)``. Returns an empty
    tuple when nothing numeric can be read, which the caller treats as a problem rather
    than as a pass.
    """
    parts: list[int] = []
    for chunk in raw.strip().split("."):
        digits = ""
        for char in chunk:
            if not char.isdigit():
                break
            digits += char
        if not digits:
            break
        parts.append(int(digits))
    if not parts:
        return ()
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])
