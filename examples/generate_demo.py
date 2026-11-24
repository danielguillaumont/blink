"""Generate a branded, engine-rendered demo GIF using synthetic data only.

Run from the repository root: python examples/generate_demo.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from blink_visual import analyze_pixels, difference_overlay, heatmap
from blink_visual.workspace import demo_pair


def generate_demo(destination: Path) -> None:
    before, after = demo_pair()
    result = analyze_pixels(before, after, threshold=15)
    frames = []
    modes = [
        ('01 / ORIGINAL', Image.fromarray(before)),
        ('02 / MODIFIED', Image.fromarray(after)),
        ('03 / DIFFERENCE', difference_overlay(after, result)),
        ('04 / HEATMAP', heatmap(result)),
    ]
    for label, image in modes:
        frame = Image.new('RGB', (1000, 670), '#141414')
        draw = ImageDraw.Draw(frame)
        def text(x, y, value, size, fill):
            draw.text((x, y), value, font=ImageFont.load_default(size=size), fill=fill)
        text(20, 14, 'blink.', 34, '#c6f65c')
        text(20, 56, 'SEE WHAT CHANGED. / SYNTHETIC DEMO', 15, '#bdbdbd')
        text(760, 35, label, 18, '#f4f4f2')
        frame.paste(image, (20, 82))
        text(20, 640, f'{result.pixels.changed_percentage:.3f}% changed  |  SSIM {result.ssim:.4f}  |  {result.total_regions} regions  |  Threshold 15', 18, '#f4f4f2')
        frames.append(frame)
    destination.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(destination, save_all=True, append_images=frames[1:], duration=[1500, 1500, 2200, 1800], loop=0, disposal=2)


if __name__ == '__main__':
    path = Path('assets/demo.gif')
    generate_demo(path)
    print(f'Generated {path} from Blink engine results.')
