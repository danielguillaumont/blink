"""``blink baseline`` and ``blink scan``."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path
from typing import Any

from ..config import TargetConfig
from ..errors import BlinkError, ConfigError
from ..findings import SEVERITY_LABELS, Severity
from ..project import Project


def fail_on(value: str) -> Severity | None:
    if value.lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _targets_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="target names (default: all)")
    parser.add_argument("--all", action="store_true", help="every configured target")
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        metavar="NAME",
        help="limit to this browser profile (repeatable)",
    )


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    baseline = subparsers.add_parser(
        "baseline",
        parents=[common],
        help="Capture targets and mark them as the known-good baseline",
        description="Capture each target/profile and record the snapshot as its baseline.",
    )
    _targets_argument(baseline)
    baseline.add_argument("--reason", default="", help="why this baseline was (re)recorded")
    baseline.set_defaults(handler=run_baseline)

    scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="Capture targets and report changes against their baselines",
        description=(
            "Exit codes: 0 clean or gate passed, 1 findings at or above --fail-on, "
            "2 usage/config error or missing baseline, 3 capture failed."
        ),
    )
    _targets_argument(scan)
    scan.add_argument(
        "--fail-on",
        type=fail_on,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help=f"exit 1 when a finding is at or above this ({', '.join(SEVERITY_LABELS)}, none; "
        "default: high)",
    )
    scan.add_argument("--json", action="store_true", help="print the findings report (schema v2)")
    scan.add_argument("--output", type=Path, help="also write the JSON report to this new file")
    scan.set_defaults(handler=run_scan)


def select_targets(project: Project, names: list[str]) -> list[TargetConfig]:
    if not project.config.targets:
        raise ConfigError(
            f"no targets configured in {project.config_path}",
            hint="add one under `targets:` or run `blink init --url URL`",
        )
    if not names:
        return list(project.config.targets)
    return [project.config.target(name) for name in names]


def _check_profiles(project: Project, profiles: list[str] | None) -> None:
    for name in profiles or []:
        project.config.profile(name)


def run_baseline(args: argparse.Namespace) -> int:
    from ..capture.browser import Capturer
    from ..scan import establish_baseline

    project = Project.load(args.config)
    targets = select_targets(project, args.targets)
    _check_profiles(project, args.profiles)
    with project.open_store() as store, Capturer() as capturer:
        for target in targets:
            for snap in establish_baseline(
                project, store, target, capturer, profiles=args.profiles, reason=args.reason
            ):
                print(f"Baseline {snap.target} [{snap.profile}] = snapshot {snap.id}")
                print(
                    f"  {len(snap.scripts)} scripts, {len(snap.forms)} forms, "
                    f"{len(snap.iframes)} iframes, {len(snap.requests)} requests"
                )
                for warning in snap.warnings:
                    print(f"  warning: {warning}")
    return 0


def print_report(report: Any) -> None:
    print(f"Blink scan {report.run_id}")
    by_target: dict[tuple[str, str], list[Any]] = {}
    for finding in report.findings:
        by_target.setdefault((finding.target, finding.profile), []).append(finding)
    for result in report.results:
        label = f"{result.target} [{result.profile}]"
        if result.status != "ok":
            print(f"\n{label}: {result.status.upper()} - {result.error}")
            continue
        findings = by_target.get((result.target, result.profile), [])
        print(f"\n{label}: {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f.severity.label.upper():<8} {f.detector}.{f.change_type}  [{f.id}]")
            print(textwrap.indent(textwrap.fill(f.title, 92), "           "))
            print(textwrap.indent(textwrap.fill(f"why: {f.why}", 92), "           "))
    if report.fail_on is None:
        print("\nGate: skipped (--fail-on none)")
    else:
        hits = sum(1 for f in report.findings if f.severity >= report.fail_on)
        verdict = "FAILED" if report.gate_failed else "passed"
        print(f"\nGate: {verdict} ({hits} finding(s) at or above {report.fail_on.label})")


def run_scan(args: argparse.Namespace) -> int:
    from ..capture.browser import Capturer
    from ..scan import scan

    project = Project.load(args.config)
    targets = select_targets(project, args.targets)
    _check_profiles(project, args.profiles)
    if args.output is not None and args.output.exists():
        raise BlinkError(f"{args.output} already exists; Blink never overwrites evidence")
    with project.open_store() as store, Capturer() as capturer:
        report = scan(
            project, store, targets, capturer, profiles=args.profiles, fail_on=args.fail_on
        )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(report.to_json())
    if args.json:
        print(report.to_json(), end="")
    else:
        print_report(report)
    code: int = report.exit_code
    return code
