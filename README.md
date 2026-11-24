<p align="center">
  <img src="assets/logo.svg" alt="Blink. See what changed." width="360">
</p>

# Blink

A local-first visual comparison toolkit for detecting and measuring differences between images.

**Development status:** BL01 foundation. The numerical pixel comparison API is implemented; structural similarity, visual overlays, workspace and CLI are planned, not available yet.

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
