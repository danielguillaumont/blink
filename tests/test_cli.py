import json
import subprocess
import sys

import numpy as np
import pytest
from PIL import Image

from blink_visual.cli import main


@pytest.fixture
def pair(tmp_path):
    before = np.zeros((10, 10, 3), dtype=np.uint8)
    after = before.copy()
    after[1:3, 2:4] = 200
    paths = [tmp_path / "before.png", tmp_path / "after.png"]
    for array, path in zip((before, after), paths):
        Image.fromarray(array).save(path)
    return [str(p) for p in paths]


def test_text(pair, capsys):
    assert main(["compare", *pair]) == 0
    assert "4.000%" in capsys.readouterr().out


def test_json(pair, capsys):
    assert main(["compare", *pair, "--json"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["changed_pixels"] == 4
    assert report["threshold"] == 15
    assert report["total_regions"] == 1
    assert captured.err == ""


@pytest.mark.parametrize("limit,code", [("0", 1), ("3.999", 1), ("4", 0), ("100", 0)])
def test_gate(pair, capsys, limit, code):
    assert main(["compare", *pair, "--json", "--fail-above", limit]) == code
    captured = capsys.readouterr()
    assert json.loads(captured.out)["changed_percentage"] == 4
    assert ("FAIL" if code else "PASS") in captured.err


@pytest.mark.parametrize(
    "option,value",
    [
        ("--threshold", "-1"),
        ("--threshold", "256"),
        ("--threshold", "1.5"),
        ("--min-region-pixels", "0"),
        ("--fail-above", "nan"),
        ("--fail-above", "inf"),
        ("--fail-above", "-1"),
        ("--fail-above", "101"),
    ],
)
def test_invalid_arguments(pair, option, value):
    with pytest.raises(SystemExit) as error:
        main(["compare", *pair, option, value])
    assert error.value.code == 2


def test_exports_on_gate_failure(pair, tmp_path, capsys):
    output = tmp_path / "evidence"
    assert main(["compare", *pair, "--json", "--fail-above", "2", "--output-dir", str(output)]) == 1
    assert json.loads(capsys.readouterr().out) == json.loads((output / "report.json").read_text())
    for name in ("overlay.png", "heatmap.png"):
        with Image.open(output / name) as image:
            assert image.size == (10, 10)
    assert main(["compare", *pair, "--output-dir", str(output)]) == 2
    assert json.loads((output / "report.json").read_text())["changed_pixels"] == 4


def test_no_boxes(pair, tmp_path):
    output = tmp_path / "nobox"
    assert main(["compare", *pair, "--output-dir", str(output), "--no-region-bounds"]) == 0
    with Image.open(output / "overlay.png") as image:
        assert image.getpixel((2, 1)) != (255, 82, 123)


def test_filter_and_threshold(pair, capsys):
    assert main(["compare", *pair, "--json", "--min-region-pixels", "5"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["changed_pixels"] == 4 and result["total_regions"] == 0
    assert main(["compare", *pair, "--json", "--threshold", "200"]) == 0
    assert json.loads(capsys.readouterr().out)["changed_pixels"] == 0


@pytest.mark.parametrize("kind", ["missing", "corrupt", "mismatch", "transparent", "oversize"])
def test_input_errors(pair, tmp_path, capsys, kind):
    path = tmp_path / "bad.png"
    if kind == "corrupt":
        path.write_bytes(b"not an image")
    elif kind == "mismatch":
        Image.new("RGB", (2, 2)).save(path)
    elif kind == "transparent":
        Image.new("RGBA", (10, 10)).save(path)
    elif kind == "oversize":
        Image.new("RGB", (2001, 2000)).save(path)
    assert main(["compare", pair[0], str(path), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "blink:" in captured.err


def test_tiny_image(tmp_path, capsys):
    path = tmp_path / "tiny.png"
    Image.new("RGB", (1, 1)).save(path)
    assert main(["compare", str(path), str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ssim"] is None


def test_module_entry(pair):
    completed = subprocess.run(
        [sys.executable, "-m", "blink_visual", "compare", *pair, "--json"],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["changed_pixels"] == 4
