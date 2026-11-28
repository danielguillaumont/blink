"""``blink doctor``: diagnose the installation and the project, and print fixes."""

from __future__ import annotations

import argparse
import json
from typing import Any

SYMBOLS = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    doctor = subparsers.add_parser(
        "doctor",
        parents=[common],
        help="Check Python, extras, Chromium, the config, the store, keys and baselines",
        description=(
            "Diagnose this host and project and print a fix for each problem. Exit 0 when "
            "nothing failed (warnings are allowed), 1 when a check failed."
        ),
    )
    doctor.add_argument("--json", action="store_true", help="machine-readable output")
    doctor.add_argument(
        "--no-browser", action="store_true", help="skip the Chromium check (it starts Playwright)"
    )
    doctor.set_defaults(handler=run_doctor)


def run_doctor(args: argparse.Namespace) -> int:
    from ..doctor import FAIL, run_checks

    checks = run_checks(args.config, browser=not args.no_browser)
    failed = any(c.status == FAIL for c in checks)
    if args.json:
        print(json.dumps({"ok": not failed, "checks": [c.to_dict() for c in checks]}, indent=2))
    else:
        width = max(len(c.name) for c in checks)
        for check in checks:
            print(f"{SYMBOLS[check.status]}  {check.name:<{width}}  {check.detail}")
            if check.fix and check.status != "ok":
                print(f"      {'':<{width}}  fix: {check.fix}")
        print(
            "\nAll checks passed." if not failed else "\nSome checks failed; see the fixes above."
        )
    return 1 if failed else 0
