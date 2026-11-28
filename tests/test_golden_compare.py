"""Golden test: the 1.0 ``blink compare`` contract must stay byte-for-byte unchanged.

The files in ``tests/golden`` were produced by the untouched 1.0.0 code before any
2.0 work started. Text and JSON output are compared as exact bytes; exported PNG
evidence is compared by decoded pixels (PNG compression may legitimately differ
between Pillow/zlib builds, the evidence itself must not).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from blink_visual.cli import main

GOLDEN = Path(__file__).parent / "golden"

CASES = {
    "text": [],
    "json": ["--json"],
    "json_t0_m2": ["--json", "--threshold", "0", "--min-region-pixels", "2"],
    "gate_fail": ["--fail-above", "1"],
    "gate_pass_json": ["--json", "--fail-above", "5"],
}


def _read(name: str) -> str:
    return (GOLDEN / name).read_bytes().decode("utf-8")


@pytest.fixture
def pair(tmp_path: Path) -> list[str]:
    paths = []
    for name in ("before.png", "after.png"):
        shutil.copyfile(GOLDEN / name, tmp_path / name)
        paths.append(str(tmp_path / name))
    return paths


@pytest.mark.parametrize("case", sorted(CASES))
def test_compare_output_is_byte_identical(
    case: str, pair: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["compare", *pair, *CASES[case]])
    captured = capsys.readouterr()
    assert str(code) == _read(f"{case}.exit")
    assert captured.out == _read(f"{case}.stdout")
    assert captured.err == _read(f"{case}.stderr")


def _pixels(path: Path) -> np.ndarray:
    with Image.open(path) as image:
        return np.asarray(image.convert("RGB"))


@pytest.mark.parametrize("boxes", [True, False])
def test_compare_evidence_is_unchanged(pair: list[str], tmp_path: Path, boxes: bool) -> None:
    out = tmp_path / "evidence"
    extra = [] if boxes else ["--no-region-bounds"]
    assert main(["compare", *pair, "--output-dir", str(out), *extra]) == 0
    assert (out / "report.json").read_bytes().decode("utf-8") == _read("json.stdout")
    overlay = "overlay.png" if boxes else "overlay_nobox.png"
    assert np.array_equal(_pixels(out / "overlay.png"), _pixels(GOLDEN / overlay))
    assert np.array_equal(_pixels(out / "heatmap.png"), _pixels(GOLDEN / "heatmap.png"))
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["schema_version"] == 1
