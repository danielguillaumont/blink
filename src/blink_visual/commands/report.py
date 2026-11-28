"""``blink report`` and ``blink verify-report``: signed audit evidence for 6.4.3 / 11.6.1."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..errors import BlinkError
from ..project import Project
from ..store.ledger import key_path

REPORT_HTML = "report.html"
REPORT_PDF = "report.pdf"
REPORT_JSON = "report.json"


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    report = subparsers.add_parser(
        "report",
        parents=[common],
        help="Write the signed audit evidence report (HTML, PDF and report.json)",
        description=(
            "Audit evidence for PCI DSS 6.4.3 and 11.6.1: scope, script inventory with "
            "justification and authorization, integrity method, evaluation log with the longest "
            "gap, findings and their resolution, ledger verification, methodology and "
            "limitations. report.json is signed with the ledger key. Exits 1 if the ledger "
            "fails verification (the report is still written, with a failure banner)."
        ),
    )
    report.add_argument(
        "--out",
        type=Path,
        default=Path("blink-report"),
        help="output directory (default: ./blink-report)",
    )
    report.add_argument(
        "--days", type=int, default=90, help="report on the last N days (default: 90)"
    )
    report.add_argument("--since", help="period start, ISO date or time (overrides --days)")
    report.add_argument("--until", help="period end, ISO date or time (default: now)")
    report.add_argument(
        "--no-pdf",
        action="store_true",
        help="skip the PDF (needs the [capture] extra and Chromium)",
    )
    report.add_argument(
        "--public-key",
        type=Path,
        help="verify the ledger against this pinned ed25519 public key file",
    )
    report.set_defaults(handler=run_report)

    verify = subparsers.add_parser(
        "verify-report",
        parents=[common],
        help="Check a report.json signature and the HTML/PDF hashes it lists",
        description=(
            "Verifies the ed25519 signature of report.json and that report.html and report.pdf "
            "next to it are unchanged. Pass --public-key with the pinned ledger public key to "
            "prove who signed it. Exit 0 if valid, 1 if not."
        ),
    )
    verify.add_argument("path", type=Path, help="report.json, or the directory holding it")
    verify.add_argument("--public-key", type=Path, help="expected ed25519 public key file")
    verify.add_argument("--json", action="store_true", help="machine-readable output")
    verify.set_defaults(handler=run_verify_report)


def parse_moment(text: str, *, end_of_day: bool = False) -> datetime:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise BlinkError(
            f"'{text}' is not an ISO date or time", hint="use e.g. 2026-09-01 or 2026-09-01T12:00Z"
        ) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    if end_of_day and len(text) == 10:
        moment += timedelta(days=1) - timedelta(seconds=1)
    return moment


def _public_key(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise BlinkError(f"cannot read {path}: {exc.strerror or exc}") from None


def run_report(args: argparse.Namespace) -> int:
    from ..report import Period, build_report, render_html, render_pdf, sha256_file, sign_report

    if args.days < 1:
        raise BlinkError("--days must be at least 1")
    now = datetime.now(UTC)
    end = parse_moment(args.until, end_of_day=True) if args.until else now
    start = parse_moment(args.since) if args.since else end - timedelta(days=args.days)
    pinned = _public_key(args.public_key)
    project = Project.load(args.config)
    with project.open_store() as store:
        report = build_report(project, store, period=Period(start, end), now=now, public_key=pinned)
        out: Path = args.out
        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BlinkError(f"cannot create {out}: {exc.strerror or exc}") from None
        html = render_html(report)
        (out / REPORT_HTML).write_text(html, encoding="utf-8")
        artifacts = {REPORT_HTML: sha256_file(out / REPORT_HTML)}
        if not args.no_pdf:
            (out / REPORT_PDF).write_bytes(render_pdf(html))
            artifacts[REPORT_PDF] = sha256_file(out / REPORT_PDF)
        sidecar = sign_report(report, project.store_dir, artifacts)
        (out / REPORT_JSON).write_text(
            json.dumps(sidecar, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        store.ledger.append(
            "report.generated",
            {
                "period": report["period"],
                "report_json_sha256": sha256_file(out / REPORT_JSON),
                "artifacts": artifacts,
                "ledger_ok": report["ledger"]["ok"],
            },
            at=report["generated_at"],
        )
    for name in (REPORT_HTML, REPORT_PDF, REPORT_JSON):
        if (out / name).exists() and (name != REPORT_PDF or not args.no_pdf):
            print(f"wrote {out / name}")
    evaluations = report["evaluations"]
    gap = evaluations["max_gap_hours"]
    print(
        f"period {report['period']['from']} to {report['period']['to']}: "
        f"{len(report['findings']['items'])} distinct findings "
        f"({report['findings']['unresolved']} unresolved); longest evaluation gap "
        f"{'n/a' if gap is None else f'{gap} h'}"
    )
    if not report["ledger"]["ok"]:
        print("LEDGER VERIFICATION FAILED; the report says so on its first page:", file=sys.stderr)
        for problem in report["ledger"]["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"ledger verified; verify the report with: blink verify-report {out / REPORT_JSON} "
        f"--public-key {key_path(project.store_dir).with_suffix('.pub')}"
    )
    return 0


def run_verify_report(args: argparse.Namespace) -> int:
    from ..report import verify_sidecar

    path: Path = args.path
    if path.is_dir():
        path = path / REPORT_JSON
    try:
        sidecar = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BlinkError(f"cannot read {path}: {exc.strerror or exc}") from None
    except ValueError as exc:
        raise BlinkError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(sidecar, dict):
        raise BlinkError(f"{path} is not a Blink report")
    check = verify_sidecar(sidecar, directory=path.parent, public_key=_public_key(args.public_key))
    if args.json:
        print(
            json.dumps(
                {
                    "ok": check.ok,
                    "problems": list(check.problems),
                    "public_key_fingerprint": check.fingerprint,
                },
                indent=2,
            )
        )
    elif check.ok:
        pinned = (
            "" if args.public_key else " (embedded key only; pass --public-key to prove origin)"
        )
        print(f"report signature valid, signed by {check.fingerprint}{pinned}")
    else:
        print("report verification FAILED:")
        for problem in check.problems:
            print(f"  - {problem}")
    return 0 if check.ok else 1
