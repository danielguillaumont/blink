"""Pure workspace helpers; no Streamlit dependency or filesystem writes."""
from io import BytesIO
import json

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from .compare import load_rgb
from .analysis import Analysis

MAX_PIXELS = 4_000_000
MAX_BYTES = 20 * 1024 * 1024


def decode_upload(data: bytes) -> np.ndarray:
    """Validate image size before decoding; keep the engine's format rules."""
    if not data or len(data) > MAX_BYTES:
        raise ValueError('Choose a non-empty image no larger than 20 MiB.')
    with Image.open(BytesIO(data)) as image:
        if image.width * image.height > MAX_PIXELS:
            raise ValueError('Images must contain at most 4 million pixels.')
    return load_rgb(BytesIO(data))


def png_bytes(image: Image.Image | np.ndarray) -> bytes:
    if isinstance(image, np.ndarray):
        image = Image.fromarray(image)
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    return buffer.getvalue()


def report_bytes(result: Analysis) -> bytes:
    return (json.dumps(result.to_dict(), indent=2, allow_nan=False) + '\n').encode('utf-8')


def split_image(before: np.ndarray, after: np.ndarray, percent: int) -> Image.Image:
    """Compose at native resolution: original left, modified right."""
    if before.shape != after.shape or not 0 <= percent <= 100:
        raise ValueError('Matching dimensions and a split from 0 to 100 are required.')
    x = round(before.shape[1] * percent / 100)
    out = after.copy()
    out[:, :x] = before[:, :x]
    image = Image.fromarray(out)
    if 0 < x < before.shape[1]:
        ImageDraw.Draw(image).line((x, 0, x, before.shape[0] - 1), fill='white', width=1)
    return image


def demo_pair() -> tuple[np.ndarray, np.ndarray]:
    """Original synthetic dashboard, with three deliberately edited areas."""
    def make(modified: bool) -> np.ndarray:
        im = Image.new('RGB', (960, 540), '#17191d')
        d = ImageDraw.Draw(im)
        def text(x, y, value, size=18, color='#e8e9ed'):
            d.text((x, y), value, font=ImageFont.load_default(size=size), fill=color)
        d.rectangle((0, 0, 184, 539), fill='#202329')
        text(24, 30, 'studio.', 30, '#c6f65c')
        for i, name in enumerate(('Overview', 'Activity', 'Reports', 'Settings')):
            y = 112 + i * 48
            if i == 0:
                d.rounded_rectangle((14, y-8, 170, y+30), 8, fill='#343942')
            text(28, y, name, 17, '#dadde3' if i == 0 else '#a0a6b0')
        text(208, 28, 'Overview', 31)
        text(208, 69, 'Workspace / Weekly summary', 16, '#a0a6b0')
        d.rounded_rectangle((800, 30, 934, 74), 9, fill='#c6f65c' if modified else '#8494e5')
        text(820, 42, 'New report', 16, '#17191d')
        for x, label, value in ((208, 'Visitors', '12,480'), (454, 'Sessions', '8,214'), (700, 'Conversion', '4.8%')):
            d.rounded_rectangle((x, 108, x+230, 216), 12, fill='#252932')
            text(x+15, 125, label, 17, '#a0a6b0')
            text(x+15, 160, value, 29)
        d.rounded_rectangle((208, 236, 930, 418), 12, fill='#252932')
        text(224, 250, 'Activity over time', 19)
        for y in (296, 330, 364, 398):
            d.line((230, y, 908, y), fill='#414650')
        pts = [(238, 381), (350, 355), (462, 369), (574, 320), (686, 342), (796, 305), (904, 321)]
        if modified:
            pts[3] = (574, 300)
        d.line(pts, fill='#c6f65c', width=4)
        d.rounded_rectangle((208, 438, 930, 516), 12, fill='#252932')
        text(225, 453, 'Report status', 18, '#a0a6b0')
        d.rounded_rectangle((730, 455, 911, 499), 8, fill='#40552f' if modified else '#343942')
        text(748, 468, 'Published' if modified else 'Draft', 18)
        return np.array(im, dtype=np.uint8)
    return make(False), make(True)
