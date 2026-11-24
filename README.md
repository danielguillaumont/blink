<p align="center">
  <img src="assets/logo.svg" alt="Blink. See what changed." width="360">
</p>

# Blink

A local-first visual comparison toolkit for detecting and measuring differences between images.

**Development status:** BL03 visual workspace. The scientific engine and local UI are implemented; CLI is planned.

## Quick start

Requires Python 3.11 or newer (3.12 recommended).

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python examples/smoke.py
```

The smoke test generates two synthetic PNGs under `outputs/bl01/` and verifies exactly 200 changed pixels out of 16,000 (1.25%).

## Python API

```python
from blink_visual import compare

result = compare("before.png", "after.png", threshold=15)
print(result.changed_pixels, result.changed_percentage)
```

The threshold is an integer from 0 to 255. A pixel is counted if its largest absolute RGB channel difference exceeds the threshold. Files must have equal decoded dimensions. The current loader supports single-frame opaque 8-bit RGB or grayscale PNG/JPEG images, honors EXIF orientation and does not perform color-profile conversion. Other modes and transparency are rejected rather than silently discarded. Images are processed locally; the API makes no network requests.

See [development plan](docs/roadmap.md) for the deliberately small release scope. MIT licensed.

## Scientific comparison

```python
from blink_visual import analyze, difference_overlay, heatmap, load_rgb

result = analyze("before.png", "after.png", threshold=15, min_region_pixels=4)
print(result.to_dict())
difference_overlay(load_rgb("after.png"), result).save("overlay.png")
heatmap(result).save("heatmap.png")
```

Run `python examples/scientific_smoke.py` to generate verified sample images, an overlay, heatmap and JSON report under `outputs/bl02/`.

SSIM uses decoded RGB values, a fixed data range of 255 and an odd window up to 7 pixels. It is independent of the threshold and is `None` for images smaller than 3 pixels on either axis. Changed regions use eight-neighbor connectivity; the largest 100 qualifying regions are reported, with pixel coordinates and exact changed-pixel counts. Region filtering does not alter the overall changed-pixel count. Heatmaps encode absolute max-channel magnitude on a fixed 0–255 scale, independent of threshold. No automatic alignment, resizing, transparency compositing or color-profile conversion is performed.

## Local visual workspace

```bash
python -m pip install -e ".[dev,ui]"
python -m streamlit run app.py
```

Open the loopback URL printed by Streamlit. Start with the built-in synthetic dashboard or select **Your images**. Compare matching opaque PNG/JPEG files (up to 20 MiB and 4 million pixels each). The workspace offers threshold controls, region filtering, overlays, a slider-controlled split, manual Blink switching, heatmap and side-by-side views. Export PNG evidence and JSON without writing to the repository. Streamlit binds to loopback and usage telemetry is disabled by the included configuration. Run from the repository root to use that configuration.
