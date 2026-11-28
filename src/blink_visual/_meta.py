"""Package identity: the PyPI distribution name differs from the import package (ADR 0005)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

DIST_NAME = "blink-checkout"
"""The PyPI distribution. The import package stays ``blink_visual`` and the CLI ``blink``."""


def dist_version() -> str:
    try:
        return version(DIST_NAME)
    except PackageNotFoundError:  # pragma: no cover - running from an uninstalled checkout
        return "0+unknown"
