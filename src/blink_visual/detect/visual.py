"""Visual detector: the Blink 1.0 engine on the masked payment-region screenshots."""

from __future__ import annotations

from io import BytesIO

import numpy as np
from PIL import Image

from ..analysis import analyze_pixels
from ..errors import StoreError
from ..findings import Finding
from ..render import difference_overlay, heatmap
from ..workspace import png_bytes
from .base import DetectionContext

MAX_REGIONS = 20


def _decode(data: bytes) -> np.ndarray:
    with Image.open(BytesIO(data)) as image:
        return np.asarray(image.convert("RGB"), dtype=np.uint8).copy()


class VisualDetector:
    name = "visual"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        role = "region_screenshot"
        if role not in ctx.baseline.blobs or role not in ctx.current.blobs:
            return []
        try:
            before = _decode(ctx.store.get_blob(ctx.baseline.blobs[role]))
            after = _decode(ctx.store.get_blob(ctx.current.blobs[role]))
        except StoreError:
            return []
        settings = ctx.target.visual
        resized = before.shape != after.shape
        if resized:
            # Blink never resizes; compare the overlapping area and report the size change.
            height = min(before.shape[0], after.shape[0])
            width = min(before.shape[1], after.shape[1])
            before, after = before[:height, :width].copy(), after[:height, :width].copy()
        result = analyze_pixels(
            before,
            after,
            threshold=settings.threshold,
            min_region_pixels=settings.min_region_pixels,
        )
        percent = result.pixels.changed_percentage
        if not resized and (result.total_regions == 0 or percent < settings.min_change_percent):
            return []
        overlay = ctx.put_evidence(png_bytes(difference_overlay(after, result)), "image/png")
        heat = ctx.put_evidence(png_bytes(heatmap(result)), "image/png")
        return [
            Finding(
                detector=self.name,
                change_type="region_changed",
                subject=ctx.target.payment_region or "payment-region",
                title=f"Payment region rendering changed ({percent:.2f}% of pixels, "
                f"{result.total_regions} region(s))",
                attributes={
                    "changed_percentage": round(percent, 4),
                    "regions": result.total_regions,
                    "ssim": None if result.ssim is None else round(result.ssim, 4),
                    "resized": resized,
                },
                evidence={
                    "baseline_blob": ctx.baseline.blobs[role],
                    "current_blob": ctx.current.blobs[role],
                    "overlay_blob": overlay,
                    "heatmap_blob": heat,
                    "threshold": settings.threshold,
                    "min_region_pixels": settings.min_region_pixels,
                    "compared_size": [int(after.shape[1]), int(after.shape[0])],
                    "regions": [r.to_dict() for r in result.regions[:MAX_REGIONS]],
                },
            )
        ]
