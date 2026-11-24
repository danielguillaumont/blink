"""Render comparison evidence as RGB Pillow images without altering inputs."""
import numpy as np
from PIL import Image, ImageDraw

from .analysis import Analysis

PINK = (255, 82, 123)


def difference_overlay(after: np.ndarray, result: Analysis, *, boxes: bool = True) -> Image.Image:
    p = result.pixels
    if not isinstance(after, np.ndarray) or after.dtype != np.uint8 or after.shape != (p.height, p.width, 3):
        raise ValueError("Overlay image must match the analyzed RGB dimensions.")
    out = after.copy()
    mask = p.changed_mask
    out[mask] = np.rint(out[mask] * 0.35 + np.array(PINK) * 0.65).astype(np.uint8)
    image = Image.fromarray(out)
    if boxes:
        draw = ImageDraw.Draw(image)
        for r in result.regions:
            draw.rectangle((r.x, r.y, r.x+r.width-1, r.y+r.height-1), outline=PINK)
    return image


def heatmap(result: Analysis) -> Image.Image:
    """Absolute max-channel magnitude, black at zero and pink at 255.

    Fixed scale, independent of threshold and other image pairs.
    """
    mag = result.pixels.magnitude.astype(np.float32) / 255
    rgb = np.rint(mag[..., None] * np.array(PINK)).astype(np.uint8)
    return Image.fromarray(rgb)
