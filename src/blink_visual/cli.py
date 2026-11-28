"""Command-line access to Blink's scientific comparison engine."""

import argparse
import math
import sys
from importlib.metadata import version
from pathlib import Path

from PIL import Image

from .analysis import analyze_pixels
from .render import difference_overlay, heatmap
from .workspace import MAX_BYTES, decode_upload, png_bytes, report_bytes


def bounded_int(low, high=None):
    def parse(value):
        number = int(value)
        if number < low or (high is not None and number > high):
            raise argparse.ArgumentTypeError(
                f"expected {low}–{high}" if high is not None else f"expected at least {low}"
            )
        return number

    return parse


def percentage(value):
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 100:
        raise argparse.ArgumentTypeError("expected a finite percentage from 0 to 100")
    return number


def parser():
    root = argparse.ArgumentParser(prog="blink", description="Blink. See what changed.")
    root.add_argument("--version", action="version", version=f"blink {version('blink-visual')}")
    commands = root.add_subparsers(dest="command", required=True)
    compare = commands.add_parser("compare", help="Compare two equal-sized PNG/JPEG images")
    compare.add_argument("before", type=Path, help="Original image")
    compare.add_argument("after", type=Path, help="Modified image")
    compare.add_argument(
        "--threshold",
        type=bounded_int(0, 255),
        default=15,
        help="Max-channel difference cutoff (default: 15)",
    )
    compare.add_argument(
        "--min-region-pixels",
        type=bounded_int(1),
        default=1,
        help="Minimum changed pixels in a reported region (default: 1)",
    )
    compare.add_argument(
        "--fail-above",
        type=percentage,
        metavar="PERCENT",
        help="Exit 1 if the unrounded changed percentage exceeds this limit",
    )
    compare.add_argument("--json", action="store_true", help="Write only the JSON report to stdout")
    compare.add_argument(
        "--output-dir",
        type=Path,
        help="New directory for overlay.png, heatmap.png and report.json; never overwrite",
    )
    compare.add_argument(
        "--no-region-bounds", action="store_true", help="Omit bounding boxes from exported overlay"
    )
    return root


def read_image(path):
    with path.open("rb") as source:
        return decode_upload(source.read(MAX_BYTES + 1))


def export(directory, after, result, report, boxes):
    # Prepare all evidence before creating a directory. Refuse existing paths,
    # including empty directories, to avoid overwriting prior evidence.
    payloads = {
        "overlay.png": png_bytes(difference_overlay(after, result, boxes=boxes)),
        "heatmap.png": png_bytes(heatmap(result)),
        "report.json": report,
    }
    directory.mkdir(parents=True, exist_ok=False)
    for name, payload in payloads.items():
        with (directory / name).open("xb") as destination:
            destination.write(payload)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        before, after = read_image(args.before), read_image(args.after)
        result = analyze_pixels(
            before, after, threshold=args.threshold, min_region_pixels=args.min_region_pixels
        )
        report = report_bytes(result)
        if args.output_dir is not None:
            export(args.output_dir, after, result, report, not args.no_region_bounds)
    except (OSError, ValueError, Image.DecompressionBombError) as exc:
        print(f"blink: {exc}", file=sys.stderr)
        return 2

    p = result.pixels
    if args.json:
        print(report.decode("utf-8"), end="")
    else:
        score = "Unavailable (image too small)" if result.ssim is None else f"{result.ssim:.6f}"
        print("BLINK. | See what changed.")
        print(f"Dimensions:     {p.width} x {p.height}")
        print(f"Threshold:      {p.threshold}")
        print(f"Changed pixels: {p.changed_pixels:,} / {p.total_pixels:,}")
        print(f"Difference:     {p.changed_percentage:.3f}%")
        print(f"SSIM:           {score}")
        print(f"Regions:        {result.total_regions} ({len(result.regions)} reported)")
        if args.output_dir is not None:
            print(f"Evidence:       {args.output_dir}")
    if args.fail_above is not None:
        failed = p.changed_percentage > args.fail_above
        print(
            f"Quality gate: {'FAIL' if failed else 'PASS'} "
            f"({p.changed_percentage:.6g}% vs limit {args.fail_above:g}%)",
            file=sys.stderr,
        )
        return int(failed)
    return 0
