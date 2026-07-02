"""Packaging guard: the package version must have a single source of truth.

``mcpscan.__version__`` (src/mcpscan/__init__.py) and ``project.version`` in
pyproject.toml are maintained by hand in two places. This test fails if they drift,
so a release can never ship a binary whose reported version disagrees with its
package metadata.
"""

import pathlib
import tomllib

import mcpscan


def test_version_matches_pyproject():
    root = pathlib.Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    declared = pyproject["project"]["version"]
    assert mcpscan.__version__ == declared, (
        f"version drift: mcpscan.__version__={mcpscan.__version__!r} "
        f"but pyproject project.version={declared!r}"
    )
