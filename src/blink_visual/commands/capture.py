"""``blink capture TARGET``: capture one snapshot bundle per profile."""

from __future__ import annotations

import argparse
import json
from typing import Any

from ..project import Project


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "capture",
        parents=[common],
        help="Capture a snapshot bundle of a target (or URL)",
        description=(
            "Capture screenshot, normalized DOM, scripts (SHA-384), HAR, headers, forms, "
            "iframes, cookie names/flags and TLS identity, and store them under .blink/. "
            "Exit code 3 means the target could not be captured."
        ),
    )
    parser.add_argument("target", help="target name from blink.yaml, or an http(s) URL")
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        metavar="NAME",
        help="browser profile (repeatable; default: the target's profiles)",
    )
    parser.add_argument("--json", action="store_true", help="print snapshot manifests as JSON")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    from ..capture.service import capture_target
    from ..serde import to_jsonable

    project = Project.load(args.config, required=False)
    target = project.resolve_target(args.target)
    if args.profiles:
        for name in args.profiles:
            project.config.profile(name)
    with project.open_store() as store:
        snapshots = capture_target(project, target, store, profiles=args.profiles)
    if args.json:
        print(json.dumps([to_jsonable(s) for s in snapshots], indent=2))
        return 0
    for snap in snapshots:
        print(f"Captured {snap.target} [{snap.profile}] -> snapshot {snap.id}")
        print(f"  URL:      {snap.final_url} (HTTP {snap.status})")
        print(
            f"  Scripts:  {len(snap.scripts)}  Requests: {len(snap.requests)}  "
            f"Forms: {len(snap.forms)}  Iframes: {len(snap.iframes)}"
        )
        print(f"  DOM hash: {snap.dom_hash[:16]}  ({snap.duration_ms} ms)")
        for warning in snap.warnings:
            print(f"  warning:  {warning}")
    return 0
