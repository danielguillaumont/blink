"""Exact, thresholded RGB differences without resizing or silent alignment."""

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps


@dataclass(frozen=True)
class PixelComparison:
    """Pixel statistics and read-only arrays in original image coordinates."""

    width: int
    height: int
    threshold: int
    changed_pixels: int
    total_pixels: int
    changed_percentage: float
    magnitude: np.ndarray
    changed_mask: np.ndarray


def load_rgb(path: str | Path) -> np.ndarray:
    """Read an opaque, single-frame PNG/JPEG, honoring EXIF orientation.

    BL01 intentionally rejects transparency, animation and non-RGB/grayscale
    source modes instead of silently losing information. No color-profile
    conversion is performed; comparisons use decoded RGB channel values.
    """
    with Image.open(path) as source:
        if source.format not in {"PNG", "JPEG"}:
            raise ValueError("Only PNG and JPEG images are supported.")
        if getattr(source, "n_frames", 1) != 1:
            raise ValueError("Animated or multi-frame images are not supported.")
        if "A" in source.getbands() or "transparency" in source.info:
            raise ValueError("Transparent images are not supported in BL01.")
        if source.mode not in {"RGB", "L"}:
            raise ValueError("Only 8-bit RGB and grayscale images are supported in BL01.")
        return np.array(ImageOps.exif_transpose(source).convert("RGB"), dtype=np.uint8)


def compare_pixels(
    before: np.ndarray, after: np.ndarray, *, threshold: int = 0
) -> PixelComparison:
    """Compare equal-sized uint8 RGB arrays using max channel difference.

    A pixel is changed if any channel differs by strictly more than threshold.
    The threshold must be an integer from 0 through 255 inclusive.
    """
    if isinstance(threshold, (bool, np.bool_)) or not isinstance(threshold, (int, np.integer)):
        raise ValueError("Threshold must be an integer from 0 to 255.")
    if not 0 <= threshold <= 255:
        raise ValueError("Threshold must be an integer from 0 to 255.")
    for array in (before, after):
        if not isinstance(array, np.ndarray) or array.dtype != np.uint8:
            raise ValueError("Images must be uint8 NumPy arrays.")
        if array.ndim != 3 or array.shape[2] != 3 or min(array.shape[:2]) == 0:
            raise ValueError("Images must have non-empty shape (height, width, 3).")
    if before.shape != after.shape:
        raise ValueError("Image dimensions must match; Blink does not resize images.")

    # Widen before subtraction: uint8 subtraction can wrap around.
    delta = np.abs(before.astype(np.int16) - after.astype(np.int16))
    magnitude = delta.max(axis=2).astype(np.uint8)
    changed_mask = magnitude > threshold
    height, width = magnitude.shape
    total = height * width
    count = int(np.count_nonzero(changed_mask))
    magnitude.setflags(write=False)
    changed_mask.setflags(write=False)
    return PixelComparison(
        width=width, height=height, threshold=int(threshold),
        changed_pixels=count, total_pixels=total,
        changed_percentage=100.0 * count / total,
        magnitude=magnitude, changed_mask=changed_mask,
    )


def compare(
    before: str | Path, after: str | Path, *, threshold: int = 0
) -> PixelComparison:
    """Compare two supported local image files."""
    return compare_pixels(load_rgb(before), load_rgb(after), threshold=threshold)
