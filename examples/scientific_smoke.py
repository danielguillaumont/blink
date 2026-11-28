"""Generate deterministic comparison evidence with a known ground truth."""

import json
from pathlib import Path

import numpy as np
from PIL import Image

from blink_visual import analyze_pixels, difference_overlay, heatmap

out = Path(__file__).resolve().parents[1] / "outputs" / "bl02"
out.mkdir(parents=True, exist_ok=True)
a = np.full((100, 160, 3), 35, dtype=np.uint8)
a[10:90, 10:40] = 65
a[10:45, 50:150] = 80
a[55:90, 50:150] = 60
b = a.copy()
b[15:25, 60:80] = (198, 246, 92)
b[65:75, 110:120] = (255, 82, 123)
r = analyze_pixels(a, b, threshold=15)
assert r.pixels.changed_pixels == 300
assert r.pixels.changed_percentage == 1.875
assert r.total_regions == 2
assert r.ssim is not None and r.ssim < 1
Image.fromarray(a).save(out / "before.png")
Image.fromarray(b).save(out / "after.png")
difference_overlay(b, r).save(out / "overlay.png")
heatmap(r).save(out / "heatmap.png")
(out / "report.json").write_text(
    json.dumps(r.to_dict(), indent=2, allow_nan=False) + "\n", encoding="utf-8"
)
print("BLINK. | BL02 scientific smoke test")
print(
    f"Changed: {r.pixels.changed_pixels}/{r.pixels.total_pixels} ({r.pixels.changed_percentage:.3f}%)"
)
print(f"SSIM: {r.ssim:.6f}\nRegions: {r.total_regions}\nEvidence: {out}")
print("PASS: scientific comparison evidence verified")
