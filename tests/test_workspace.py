import json
from io import BytesIO

import numpy as np
import pytest
from PIL import Image

from blink_visual import analyze_pixels
from blink_visual.workspace import demo_pair, decode_upload, png_bytes, report_bytes, split_image


def test_demo_is_deterministic():
    before, after = demo_pair()
    b2, a2 = demo_pair()
    assert before.shape == after.shape == (540, 960, 3)
    assert np.array_equal(before, b2) and np.array_equal(after, a2)
    result = analyze_pixels(before, after, threshold=15)
    assert 0 < result.pixels.changed_percentage < 10
    assert result.total_regions >= 3


def test_png_roundtrip():
    a, _ = demo_pair()
    assert np.array_equal(a, decode_upload(png_bytes(a)))


@pytest.mark.parametrize('mode', ['RGBA', 'P'])
def test_unsupported_modes(mode):
    buf = BytesIO()
    Image.new(mode, (5, 5)).save(buf, format='PNG')
    with pytest.raises(ValueError):
        decode_upload(buf.getvalue())


def test_oversized_image():
    buf = BytesIO()
    Image.new('RGB', (2001, 2000)).save(buf, format='PNG')
    with pytest.raises(ValueError, match='4 million'):
        decode_upload(buf.getvalue())


def test_empty_upload():
    with pytest.raises(ValueError):
        decode_upload(b'')


def test_split_boundaries():
    a = np.zeros((4, 8, 3), dtype=np.uint8)
    b = np.full_like(a, 120)
    assert np.array_equal(np.array(split_image(a, b, 0)), b)
    assert np.array_equal(np.array(split_image(a, b, 100)), a)
    mid = np.array(split_image(a, b, 50))
    assert np.array_equal(mid[:, :4], a[:, :4])
    assert np.array_equal(mid[:, 5:], b[:, 5:])
    assert np.all(mid[:, 4] == 255)


def test_report_matches_engine():
    a, b = demo_pair()
    result = analyze_pixels(a, b, threshold=15)
    assert json.loads(report_bytes(result)) == result.to_dict()
