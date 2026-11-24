"""Structural similarity, connected regions and serializable analysis results."""
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy import ndimage
from skimage.metrics import structural_similarity

from .compare import PixelComparison, compare_pixels, load_rgb


@dataclass(frozen=True)
class Region:
    x: int
    y: int
    width: int
    height: int
    changed_pixels: int

    def to_dict(self) -> dict:
        return dict(x=self.x, y=self.y, width=self.width, height=self.height,
                    changed_pixels=self.changed_pixels)


@dataclass(frozen=True)
class Analysis:
    pixels: PixelComparison
    ssim: float | None
    regions: tuple[Region, ...]
    min_region_pixels: int
    total_regions: int

    def to_dict(self) -> dict:
        p = self.pixels
        return {
            "schema_version": 1, "width": p.width, "height": p.height,
            "threshold": p.threshold, "total_pixels": p.total_pixels,
            "changed_pixels": p.changed_pixels,
            "changed_percentage": p.changed_percentage, "ssim": self.ssim,
            "min_region_pixels": self.min_region_pixels,
            "total_regions": self.total_regions, "reported_regions": len(self.regions),
            "regions": [r.to_dict() for r in self.regions],
        }


def analyze_pixels(before: np.ndarray, after: np.ndarray, *, threshold: int = 0,
                   min_region_pixels: int = 1) -> Analysis:
    """Analyze matching RGB arrays. SSIM is independent of the pixel threshold.

    8-connected regions are ranked by area, then top/left. At most 100 are
    reported; total_regions counts all qualifying regions. Region filtering
    does not change pixel statistics. SSIM is unavailable below 3x3 pixels.
    """
    if (isinstance(min_region_pixels, (bool, np.bool_)) or
            not isinstance(min_region_pixels, (int, np.integer)) or min_region_pixels < 1):
        raise ValueError("min_region_pixels must be a positive integer.")
    p = compare_pixels(before, after, threshold=threshold)
    shortest = min(p.width, p.height)
    score = None
    if shortest >= 3:
        window = min(7, shortest if shortest % 2 else shortest - 1)
        score = float(structural_similarity(before, after, channel_axis=-1,
                                            data_range=255, win_size=window))
    labels, count = ndimage.label(p.changed_mask, structure=np.ones((3, 3), dtype=bool))
    areas = np.bincount(labels.ravel(), minlength=count + 1)
    candidates = np.flatnonzero(areas[1:] >= min_region_pixels) + 1
    # Labels are assigned in scan order. Stable sorting preserves that order for ties.
    selected = candidates[np.argsort(-areas[candidates], kind="stable")[:100]]
    regions = []
    if selected.size:
        # Remap only selected components, avoiding a Python object for every speckle.
        mapping = np.zeros(count + 1, dtype=np.int32)
        mapping[selected] = np.arange(1, len(selected) + 1, dtype=np.int32)
        for label, bounds in zip(selected, ndimage.find_objects(mapping[labels], max_label=len(selected))):
            y, x = bounds
            regions.append(Region(x.start, y.start, x.stop-x.start, y.stop-y.start,
                                  int(areas[label])))
    regions.sort(key=lambda r: (-r.changed_pixels, r.y, r.x))
    return Analysis(p, score, tuple(regions), int(min_region_pixels), int(candidates.size))


def analyze(before: str | Path, after: str | Path, *, threshold: int = 0,
            min_region_pixels: int = 1) -> Analysis:
    return analyze_pixels(load_rgb(before), load_rgb(after), threshold=threshold,
                          min_region_pixels=min_region_pixels)
