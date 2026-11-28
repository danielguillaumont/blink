"""``blink record URL``: draft a journey with Playwright's recorder (codegen)."""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 - runs Playwright's own CLI with a fixed argument list
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..config import validate_url
from ..errors import BlinkError, ConfigError, MissingExtraError


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    record = subparsers.add_parser(
        "record",
        parents=[common],
        help="Draft a journey YAML by clicking through the checkout (Playwright codegen)",
        description=(
            "Opens a browser with Playwright's recorder. Click through to the payment page, "
            "close the browser, and Blink prints a draft `targets:` entry with a journey. "
            "Clicks that look like placing the order are dropped, and typed card numbers and "
            "e-mail addresses become canary/faker placeholders. Review every selector before "
            "use. With --from-file, convert an existing codegen Python script instead."
        ),
    )
    record.add_argument("url", help="where the journey starts (a product page, usually)")
    record.add_argument("--name", default="checkout", help="target name for the draft")
    record.add_argument("--out", type=Path, help="write the draft here instead of stdout")
    record.add_argument(
        "--from-file", type=Path, help="convert this Playwright codegen Python file"
    )
    record.set_defaults(handler=run_record)


def _codegen(url: str) -> str:
    try:
        import playwright  # noqa: F401
    except ImportError:
        raise MissingExtraError("capture", "blink record") from None
    with tempfile.TemporaryDirectory(prefix="blink-record-") as tmp:
        out = Path(tmp) / "recorded.py"
        print("Recording: click through to the payment page, then close the browser window.")
        result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [
                sys.executable,
                "-m",
                "playwright",
                "codegen",
                "--target",
                "python",
                "-o",
                str(out),
                url,
            ],
            check=False,
        )
        if result.returncode != 0 or not out.exists():
            raise BlinkError(
                f"Playwright codegen exited with code {result.returncode}",
                hint="it needs a display; run `blink record` on a desktop, not over SSH",
            )
        return out.read_text(encoding="utf-8")


def run_record(args: argparse.Namespace) -> int:
    from ..journey.record import codegen_to_steps, draft_yaml

    try:
        url = validate_url(args.url)
    except ValueError as exc:
        raise ConfigError(f"url: {exc}") from None
    if args.from_file:
        try:
            source = args.from_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise BlinkError(f"cannot read {args.from_file}: {exc.strerror or exc}") from None
    else:
        source = _codegen(url)
    try:
        steps = codegen_to_steps(source)
    except SyntaxError as exc:
        raise BlinkError(f"cannot parse the recorded script: {exc}") from None
    text = draft_yaml(args.name, url, steps)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"Draft journey written to {args.out}; review it, then paste it into blink.yaml.")
    else:
        print(text, end="")
    return 0
