"""Create a deterministic image pair and verify a known 1.25% difference."""

from pathlib import Path

import numpy as np
from PIL import Image

from blink_visual import compare


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "outputs" / "bl01"
    output.mkdir(parents=True, exist_ok=True)
    before = np.full((100, 160, 3), 24, dtype=np.uint8)
    before[12:88, 12:46] = (50, 50, 50)
    before[12:40, 55:148] = (72, 72, 72)
    before[50:88, 55:148] = (54, 54, 54)
    after = before.copy()
    after[60:70, 100:120] = (198, 246, 92)
    before_path, after_path = output / "before.png", output / "after.png"
    Image.fromarray(before).save(before_path)
    Image.fromarray(after).save(after_path)
    result = compare(before_path, after_path)
    print("BLINK. | BL01 foundation smoke test")
    print(f"Dimensions:     {result.width} x {result.height}")
    print(f"Changed pixels: {result.changed_pixels} / {result.total_pixels}")
    print(f"Changed:        {result.changed_percentage:.2f}%")
    print(f"Threshold:      {result.threshold}")
    if result.changed_pixels != 200 or result.changed_percentage != 1.25:
        raise SystemExit("FAIL: unexpected comparison result")
    print(f"Images:         {output}")
    print("PASS: known pixel difference verified")


if __name__ == "__main__":
    main()
