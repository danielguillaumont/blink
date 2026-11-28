"""Shared fixtures: the in-process localhost lab and a reusable Chromium capturer."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml


def _browser_skip_reason() -> str | None:
    if os.environ.get("BLINK_SKIP_BROWSER") == "1":
        return "BLINK_SKIP_BROWSER=1 (browser tests run on Linux CI)"
    try:
        import playwright  # noqa: F401
    except ImportError:
        return "the [capture] extra (Playwright) is not installed"
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("browser") is not None:
        reason = _browser_skip_reason()
        if reason:
            pytest.skip(reason)


@pytest.fixture(scope="session")
def lab() -> Iterator[Any]:
    pytest.importorskip("fastapi", reason="the lab needs the [server] extra")
    from blink_visual.lab.server import Lab

    with Lab() as running:
        yield running


@pytest.fixture
def clean_lab(lab: Any) -> Iterator[Any]:
    """The shared lab, reset to the clean scenario before and after the test."""
    lab.set_scenario("clean")
    yield lab
    lab.set_scenario("clean")


@pytest.fixture(scope="session")
def capturer() -> Iterator[Any]:
    reason = _browser_skip_reason()
    if reason:
        pytest.skip(reason)
    from blink_visual.capture.browser import Capturer
    from blink_visual.errors import CaptureError

    try:
        with Capturer() as running:
            yield running
    except CaptureError as exc:
        pytest.skip(f"Chromium is not available: {exc}")


@pytest.fixture
def write_project(tmp_path: Path) -> Callable[..., Path]:
    """Write a blink.yaml with the given targets into a temporary project."""

    def write(targets: list[dict[str, Any]], **extra: Any) -> Path:
        path = tmp_path / "blink.yaml"
        path.write_text(yaml.safe_dump({"version": 1, "targets": targets, **extra}), "utf-8")
        return path

    return write
