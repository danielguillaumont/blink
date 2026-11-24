import numpy as np
import pytest
from PIL import Image

from blink_visual import compare, compare_pixels, load_rgb


def rgb(height=4, width=5):
    return np.zeros((height, width, 3), dtype=np.uint8)


def test_identical():
    a = rgb()
    result = compare_pixels(a, a)
    assert (result.width, result.height, result.total_pixels) == (5, 4, 20)
    assert result.changed_pixels == 0
    assert result.changed_percentage == 0.0
    assert not result.changed_mask.any()


def test_known_difference():
    a = rgb()
    b = a.copy()
    b[1:3, 2:4] = [20, 40, 80]
    result = compare_pixels(a, b)
    assert result.changed_pixels == 4
    assert result.changed_percentage == 20.0
    assert result.magnitude[1, 2] == 80
    assert result.changed_mask[2, 3]
    assert not result.changed_mask[0, 0]
    assert not result.magnitude.flags.writeable
    assert not result.changed_mask.flags.writeable
    assert not a.any()


def test_unsigned_subtraction_does_not_wrap():
    a = np.array([[[0, 255, 12]]], dtype=np.uint8)
    b = np.array([[[255, 0, 12]]], dtype=np.uint8)
    assert compare_pixels(a, b).magnitude.item() == 255
    assert compare_pixels(b, a).magnitude.item() == 255


@pytest.mark.parametrize("threshold,expected", [(0, 2), (14, 2), (15, 1), (16, 0), (255, 0)])
def test_threshold_boundary(threshold, expected):
    a = rgb(1, 2)
    b = a.copy()
    b[0, 0, 0] = 15
    b[0, 1, 2] = 16
    assert compare_pixels(a, b, threshold=threshold).changed_pixels == expected


@pytest.mark.parametrize("threshold", [-1, 256, 0.5, True, "2", None])
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="Threshold"):
        compare_pixels(rgb(), rgb(), threshold=threshold)


def test_mismatched_dimensions():
    with pytest.raises(ValueError, match="dimensions must match"):
        compare_pixels(rgb(), rgb(5, 4))


@pytest.mark.parametrize("bad", [np.zeros((2, 2)), np.zeros((2, 2, 4), dtype=np.uint8), np.zeros((0, 2, 3), dtype=np.uint8), np.zeros((2, 2, 3), dtype=np.float32)])
def test_invalid_arrays(bad):
    with pytest.raises(ValueError):
        compare_pixels(bad, rgb())


def test_png_file_comparison(tmp_path):
    a = rgb()
    b = a.copy()
    b[0, 0] = 255
    first, second = tmp_path / "a.png", tmp_path / "b.png"
    Image.fromarray(a).save(first)
    Image.fromarray(b).save(second)
    assert compare(first, second).changed_percentage == 5.0


def test_grayscale_png(tmp_path):
    path = tmp_path / "gray.png"
    Image.new("L", (3, 2), 15).save(path)
    result = load_rgb(path)
    assert result.shape == (2, 3, 3)
    assert np.all(result == 15)


def test_jpeg(tmp_path):
    path = tmp_path / "sample.jpg"
    Image.new("RGB", (4, 3), (80, 80, 80)).save(path)
    assert compare(path, path).changed_pixels == 0


def test_transparency_rejected(tmp_path):
    path = tmp_path / "alpha.png"
    Image.new("RGBA", (2, 2), (255, 0, 0, 0)).save(path)
    with pytest.raises(ValueError, match="Transparent"):
        load_rgb(path)


def test_unsupported_format(tmp_path):
    path = tmp_path / "sample.bmp"
    Image.new("RGB", (2, 2)).save(path)
    with pytest.raises(ValueError, match="PNG and JPEG"):
        load_rgb(path)


def test_invalid_image(tmp_path):
    path = tmp_path / "invalid.png"
    path.write_text("not an image")
    with pytest.raises(OSError):
        load_rgb(path)


def test_exif_orientation(tmp_path):
    path = tmp_path / "rotated.jpg"
    im = Image.new("RGB", (4, 2))
    exif = im.getexif()
    exif[274] = 6
    im.save(path, exif=exif)
    assert load_rgb(path).shape == (4, 2, 3)
