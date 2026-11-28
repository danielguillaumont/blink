"""Blink 2.0 subcommands. ``blink compare`` stays in :mod:`blink_visual.cli` unchanged."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..errors import BlinkError


def config_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="path to blink.yaml (default: ./blink.yaml or $BLINK_CONFIG)",
    )
    return parent


def register(subparsers: Any) -> None:
    from . import capture, doctor, init, inventory, lab, ops, record, report, scan, serve

    common = config_parent()
    for module in (init, capture, lab, scan, inventory, ops, serve, report, doctor, record):
        module.add_parser(subparsers, common)


def dispatch(args: argparse.Namespace) -> int:
    try:
        code: int = args.handler(args)
        return code
    except BlinkError as exc:
        print(f"blink: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("blink: interrupted", file=sys.stderr)
        return 130
